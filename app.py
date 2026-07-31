import requests
import random
import string
import itertools
import subprocess
import os
import time
import json
import threading
import re
import sys
import glob
from collections import deque
from flask import Flask, render_template, jsonify, request, Response, stream_with_context
from flask_cors import CORS
import queue

app = Flask(__name__)
CORS(app)

# Default proxy pool (local Tor instances) — replaced by user proxies when provided
PROXY_POOL = [
    "socks5://127.0.0.1:9050",
    "socks5://127.0.0.1:9051",
    "socks5://127.0.0.1:9052",
    "socks5://127.0.0.1:9053",
    "socks5://127.0.0.1:9054",
]

TOR_INSTANCES = []
VIEW_COUNT = 0
VIEW_LOCK = threading.Lock()
TOR_AVAILABLE = False

# ── Bot state (shared, thread-safe) ────────────────────────────────────
BOT_LOCK = threading.Lock()
BOT_STOP = threading.Event()
BOT_LOG_ID = [0]
BOT_LOGS = deque(maxlen=300)
BOT_STATE = {
    "running": False,
    "browser_count": 0,
    "engine": "idle",          # playwright | chrome | requests
    "views_sent": 0,           # verified real page loads
    "attempts": 0,
    "errors": 0,
    "started_at": None,
    "workers": {},             # id -> {status, views, errors, last, last_at}
}

# ── Global request pacing (Discord checker) ────────────────────────────
PACE_LOCK = threading.Lock()
PACE_LAST = [0.0]


def pace_requests(min_interval=0.4):
    """Throttle aggregate request rate across all checker workers."""
    with PACE_LOCK:
        now = time.time()
        wait = min_interval - (now - PACE_LAST[0])
        if wait > 0:
            time.sleep(wait)
        PACE_LAST[0] = time.time()


def bot_log(level, msg):
    with BOT_LOCK:
        BOT_LOG_ID[0] += 1
        BOT_LOGS.append({
            "id": BOT_LOG_ID[0],
            "t": time.strftime("%H:%M:%S"),
            "level": level,
            "msg": msg,
        })


# ── Tor (real circuit rotation) ────────────────────────────────────────

TOR_LOCK = threading.Lock()
TOR_STARTED = False
TOR_READY = [False] * 5      # per-instance SOCKS readiness
TOR_ROTATIONS = [0] * 5      # circuit rotation counter per instance
TOR_EXIT_IPS = [None] * 5    # last seen exit IP per instance
TOR_EXIT_IP_TTL = [0.0] * 5


def _tor_binary():
    """Locate the tor binary."""
    for cand in ["/usr/sbin/tor", "/usr/bin/tor", "/bin/tor"]:
        if os.path.exists(cand):
            return cand
    try:
        subprocess.run(["tor", "--version"], capture_output=True, timeout=5, check=True)
        return "tor"
    except Exception:
        return None


def _port_open(port, host="127.0.0.1", timeout=1.5):
    import socket
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def _tor_instance_config(i):
    port = 9050 + i
    control_port = 9050 + i + 10000
    tor_dir = f"/tmp/tor_{i}"
    os.makedirs(tor_dir, exist_ok=True)
    return port, control_port, tor_dir


def ensure_tor_instances():
    """Start Tor instances once (thread-safe). Returns True if any SOCKS port is up."""
    global TOR_AVAILABLE, TOR_STARTED
    with TOR_LOCK:
        if TOR_STARTED:
            return TOR_AVAILABLE
        TOR_STARTED = True

    binary = _tor_binary()
    if not binary:
        bot_log("error", "tor binary not found — install it (apt install tor) to enable rotation")
        return False

    TOR_INSTANCES.clear()
    for i in range(5):
        try:
            port, control_port, tor_dir = _tor_instance_config(i)
            torrc_path = f"{tor_dir}/torrc"
            with open(torrc_path, "w") as f:
                f.write(
                    f"SocksPort {port}\n"
                    f"ControlPort {control_port}\n"
                    f"DataDirectory {tor_dir}\n"
                    f"MaxCircuitDirtiness 120\n"
                    f"NewCircuitPeriod 60\n"
                    f"ExitRelay 0\n"
                )
            proc = subprocess.Popen(
                [binary, "-f", torrc_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            TOR_INSTANCES.append(proc)
        except Exception as e:
            bot_log("warn", f"tor instance {i} failed to start: {e}")

    # Give them a moment to open SOCKS ports, then poll readiness.
    deadline = time.time() + 60
    while time.time() < deadline:
        any_up = False
        for i in range(5):
            if not TOR_READY[i]:
                port, _, _ = _tor_instance_config(i)
                if _port_open(port):
                    TOR_READY[i] = True
            any_up = any_up or TOR_READY[i]
        if any_up:
            break
        time.sleep(1)

    ready = sum(1 for r in TOR_READY if r)
    if ready:
        TOR_AVAILABLE = True
        bot_log("info", f"Tor ready: {ready}/5 instances listening")
    else:
        TOR_AVAILABLE = False
        bot_log("error", "Tor instances failed to open SOCKS ports — rotation unavailable")
    return TOR_AVAILABLE


def _read_control_reply(sock, timeout=3):
    import socket
    sock.settimeout(timeout)
    buf = b""
    try:
        while b"250 OK" not in buf and len(buf) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except Exception:
        pass
    return buf


def tor_exit_ip(instance_idx):
    """Return the current exit IP for a Tor instance via a quick proxied request (cached 10s)."""
    now = time.time()
    if now - TOR_EXIT_IP_TTL[instance_idx] < 10 and TOR_EXIT_IPS[instance_idx]:
        return TOR_EXIT_IPS[instance_idx]
    try:
        proxy = f"socks5h://127.0.0.1:{9050 + instance_idx}"
        r = requests.get(
            "https://api.ipify.org",
            proxies={"http": proxy, "https": proxy},
            timeout=8,
        )
        ip = r.text.strip()
        if ip:
            TOR_EXIT_IPS[instance_idx] = ip
            TOR_EXIT_IP_TTL[instance_idx] = now
            return ip
    except Exception:
        pass
    return TOR_EXIT_IPS[instance_idx]


def rotate_tor_circuit(instance_idx, verify_ip=True):
    """Force a NEW circuit (new exit IP) on a Tor instance via its control port."""
    if not (0 <= instance_idx < 5) or not TOR_READY[instance_idx]:
        return False
    import socket
    port, control_port, _ = _tor_instance_config(instance_idx)
    try:
        s = socket.create_connection(("127.0.0.1", control_port), timeout=5)
        s.sendall(b'AUTHENTICATE ""\r\n')
        _read_control_reply(s)
        s.sendall(b"SIGNAL NEWNYM\r\n")
        _read_control_reply(s)
        s.sendall(b"QUIT\r\n")
        s.close()
        TOR_ROTATIONS[instance_idx] += 1

        if verify_ip:
            # Wait for the new circuit to come up (new exit IP).
            old = TOR_EXIT_IPS[instance_idx]
            deadline = time.time() + 20
            while time.time() < deadline:
                new = tor_exit_ip(instance_idx)
                if new and new != old:
                    break
                time.sleep(2)
            TOR_EXIT_IP_TTL[instance_idx] = 0.0
        return True
    except Exception:
        return False


# ── Discord checker ────────────────────────────────────────────────────

def _build_discord_headers(auth_token):
    return {
        "authority": "discord.com",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.9",
        "authorization": auth_token,
        "content-type": "application/json",
        "origin": "https://discord.com",
        "referer": "https://discord.com/channels/@me",
        "sec-ch-ua": '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "x-debug-options": "bugReporterEnabled",
        "x-discord-locale": "en-US",
        "x-discord-timezone": "America/New_York",
        "x-super-properties": (
            "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAg"
            "KFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwOS4wLjAuMCBTYWZhcmkvNTM3LjM2I"
            "iwiYnJvd3Nlcl92ZXJzaW9uIjoiMTA5LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiJodHRwczovL3d3dy5nb29nbGUuY29tLyIsInJlZmVycmluZ19kb21ha"
            "W4iOiJ3d3cuZ29vZ2xlLmNvbSIsInNlYXJjaF9lbmdpbmUiOiJnb29nbGUiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVs"
            "ZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTc1OTE3LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
        ),
    }


def check_discord_username(username, auth_token, proxy_url=None, use_proxy=True):
    """Returns {"available": bool|None, "status": int|None, "discord_msg": str|None}"""
    headers = _build_discord_headers(auth_token)
    payload = {"username": username}

    def _do(s):
        if s == "proxy":
            return requests.post(
                "https://discord.com/api/v9/users/@me/pomelo",
                headers=headers, json=payload, timeout=10,
                proxies={"http": proxy_url, "https": proxy_url},
            )
        return requests.post("https://discord.com/api/v9/users/@me/pomelo", headers=headers, json=payload, timeout=10)

    strategies = []
    if use_proxy and proxy_url and TOR_AVAILABLE:
        strategies.append("proxy")
    strategies.append("direct")

    for s in strategies:
        try:
            resp = _do(s)
            code = resp.status_code
            if code == 200:
                data = resp.json()
                return {"available": data.get("taken") is False, "status": 200, "discord_msg": None}
            if code == 401:
                return {"available": None, "status": 401, "discord_msg": "Token rejected (401) — invalid or expired user token. Make sure it's a USER token, not a bot token."}
            if code == 429:
                return {"available": None, "status": 429, "discord_msg": "Rate limited (429) — Discord is throttling requests"}
            if code == 403:
                return {"available": None, "status": 403, "discord_msg": "Forbidden (403) — token lacks permissions or account is flagged"}
            try:
                body = resp.json()
                err = body.get("message", str(body))
            except Exception:
                err = resp.text[:200]
            return {"available": None, "status": code, "discord_msg": f"HTTP {code}: {err}"}
        except requests.exceptions.Timeout:
            if s == "direct":
                return {"available": None, "status": None, "discord_msg": "Timed out — Discord unreachable"}
        except Exception as e:
            if s == "direct":
                return {"available": None, "status": None, "discord_msg": f"Connection error: {str(e)[:150]}"}
    return {"available": None, "status": None, "discord_msg": "All connection attempts failed"}


# ── guns.lol view bot engine ───────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

CHALLENGE_MARKERS = ["just a moment", "cf-challenge", "checking your browser", "attention required", "cloudflare"]


def _chrome_available():
    for name in ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"]:
        try:
            subprocess.run([name, "--version"], capture_output=True, timeout=5, check=True)
            return True
        except Exception:
            continue
    return False


def _playwright_cache_dirs():
    """All plausible locations where Playwright's browsers may live (HOME differs per runner)."""
    dirs = []
    env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env:
        dirs.append(env)
    home = os.path.expanduser("~")
    dirs.append(os.path.join(home, ".cache", "ms-playwright"))
    dirs.append("/root/.cache/ms-playwright")
    dirs.append("/ms-playwright")
    try:
        dirs += glob.glob("/home/*/.cache/ms-playwright")
    except Exception:
        pass
    seen, out = set(), []
    for d in dirs:
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _playwright_browser_ready():
    """True when playwright is installed AND a chromium browser was downloaded anywhere on disk."""
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    for base in _playwright_cache_dirs():
        try:
            for d in os.listdir(base):
                if "chromium" in d:
                    return True
        except OSError:
            continue
    return False


def _find_chromium_executable():
    """Locate a real chromium executable from Playwright's caches (for the chrome engine fallback)."""
    for base in _playwright_cache_dirs():
        try:
            entries = os.listdir(base)
        except OSError:
            continue
        for d in entries:
            if "chromium" not in d:
                continue
            try:
                subs = os.listdir(os.path.join(base, d))
            except OSError:
                continue
            for sub in subs:
                for name in ("chrome", "headless_shell", "chromium"):
                    exe = os.path.join(base, d, sub, name)
                    if os.path.exists(exe):
                        return exe
    return None


# ── Engine probe: verify a browser REALLY launches before using it ─────
ENGINE_PROBE_RESULT = [None]      # None = not probed yet; else playwright|chrome|requests
ENGINE_PROBE_LOCK = threading.Lock()
CHROME_LAUNCH_LOCK = threading.Lock()
BROWSER_INSTALL_STATE = [None]    # None | installing | done | failed
BROWSER_INSTALL_AT = [0.0]


def _ensure_browser_install():
    """Kick off a background Playwright Chromium install when no engine works (idempotent)."""
    with ENGINE_PROBE_LOCK:
        state = BROWSER_INSTALL_STATE[0]
        if state == "installing" or state == "done":
            return
        if state == "failed" and time.time() - BROWSER_INSTALL_AT[0] < 1800:
            return  # don't hammer a failing install — retry at most every 30 min
        BROWSER_INSTALL_STATE[0] = "installing"
    threading.Thread(target=_auto_provision_browser, daemon=True).start()


def _auto_provision_browser():
    """Install Playwright + bundled Chromium so the app self-heals to a real browser."""
    bot_log("info", "No browser engine found — installing Playwright Chromium in the background (~120MB download)...")
    try:
        try:
            import playwright  # noqa: F401
        except ImportError:
            bot_log("info", "Installing playwright pip package...")
            subprocess.run([sys.executable, "-m", "pip", "install", "playwright"],
                           capture_output=True, timeout=600)
        bot_log("info", "Downloading Chromium browser (one-time, background)...")
        r = subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"],
                           capture_output=True, timeout=1200)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or r.stdout or b"")[-300:].decode(errors="replace").strip())
        # System libs — needs root; tolerable if it fails (some bases already have them).
        try:
            subprocess.run([sys.executable, "-m", "playwright", "install-deps", "chromium"],
                           capture_output=True, timeout=900)
        except Exception:
            pass
    except Exception as e:
        BROWSER_INSTALL_STATE[0] = "failed"
        BROWSER_INSTALL_AT[0] = time.time()
        bot_log("error", f"Browser auto-install failed: {str(e)[:150]}")
        return
    BROWSER_INSTALL_STATE[0] = "done"
    BROWSER_INSTALL_AT[0] = time.time()
    bot_log("info", "Chromium installed — re-probing the engine...")
    with ENGINE_PROBE_LOCK:
        ENGINE_PROBE_RESULT[0] = None
    _run_engine_probe()


def _run_engine_probe():
    """Launch a real browser against a neutral page once; cache the verdict."""
    if ENGINE_PROBE_RESULT[0]:
        return ENGINE_PROBE_RESULT[0]
    with ENGINE_PROBE_LOCK:
        if ENGINE_PROBE_RESULT[0]:
            return ENGINE_PROBE_RESULT[0]
        verdict = "requests"
        # 1) Playwright's bundled Chromium is the most reliable — no system deps.
        try:
            if _playwright_browser_ready():
                ok, _ = _send_playwright_view("https://example.com", None)
                if ok:
                    verdict = "playwright"
        except Exception:
            pass
        # 2) undetected_chromedriver — only if a launchable Chrome exists.
        if verdict == "requests":
            try:
                ok, _ = _send_chrome_view("https://example.com", None)
                if ok:
                    verdict = "chrome"
            except Exception:
                pass
        ENGINE_PROBE_RESULT[0] = verdict
        bot_log(
            "info",
            f"Engine probe complete → {verdict}"
            + (" (real browser verified)" if verdict != "requests" else "")
            + (" — raw HTTP fallback, views may not count" if verdict == "requests" else ""),
        )
    # No usable engine → make the app install one in the background.
    if verdict == "requests":
        _ensure_browser_install()
    return verdict


def probe_engine(block=True, timeout=60):
    """Return the verified engine, probing on first call (runs in a background thread)."""
    if not ENGINE_PROBE_RESULT[0]:
        t = threading.Thread(target=_run_engine_probe, daemon=True)
        t.start()
        if block:
            t.join(timeout=timeout)
    return ENGINE_PROBE_RESULT[0] or detect_engine()


def detect_engine():
    if ENGINE_PROBE_RESULT[0]:
        return ENGINE_PROBE_RESULT[0]
    if _playwright_browser_ready():
        return "playwright"
    if _chrome_available():
        return "chrome"
    return "requests"


def _browser_proxy(proxy_url):
    """Convert a proxy URL into (server, username, password) Chromium/Playwright can use.

    Chromium does NOT understand requests-style 'socks5h://' (remote DNS) or 'socks4a://'
    schemes — it throws net::ERR_NO_SUPPORTED_PROXIES. Map them to schemes it accepts,
    and peel out any embedded credentials for Playwright's proxy options.
    """
    if not proxy_url:
        return None, None, None
    server, username, password = proxy_url, None, None
    if "://" in server:
        scheme, rest = server.split("://", 1)
        scheme = scheme.lower()
        if scheme == "socks5h":
            scheme = "socks5"
        elif scheme == "socks4a":
            scheme = "socks4"
        if "@" in rest:
            creds, host = rest.rsplit("@", 1)
            if ":" in creds:
                username, password = creds.split(":", 1)
            else:
                username = creds
            rest = host
        server = f"{scheme}://{rest}"
    return server, username, password


def _send_playwright_view(target_url, proxy_url):
    from playwright.sync_api import sync_playwright
    ua = random.choice(USER_AGENTS)
    viewport = random.choice([(1366, 768), (1440, 900), (1536, 864), (1920, 1080), (1280, 720)])
    launch_opts = {
        "headless": True,
        "args": [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-blink-features=AutomationControlled",
            "--lang=en-US",
        ],
    }
    if proxy_url:
        server, user, pw = _browser_proxy(proxy_url)
        if server:
            launch_opts["proxy"] = {"server": server}
            if user:
                launch_opts["proxy"]["username"] = user
            if pw:
                launch_opts["proxy"]["password"] = pw
    with sync_playwright() as p:
        browser = p.chromium.launch(**launch_opts)
        try:
            context = browser.new_context(
                user_agent=ua,
                viewport={"width": viewport[0], "height": viewport[1]},
                locale="en-US",
                timezone_id=random.choice(["America/New_York", "Europe/London", "Asia/Tokyo", "Australia/Sydney"]),
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9", "Referer": "https://www.google.com/"},
            )
            page = context.new_page()
            t0 = time.time()
            resp = page.goto(target_url, timeout=30000, wait_until="domcontentloaded")
            # human-ish behavior: scroll, dwell
            page.wait_for_timeout(random.randint(2500, 6000))
            for _ in range(random.randint(1, 3)):
                page.mouse.wheel(0, random.randint(200, 800))
                page.wait_for_timeout(random.randint(400, 1200))
            title = (page.title() or "").lower()
            status = resp.status if resp else None
            if status and status >= 400:
                return False, f"HTTP {status} from server"
            if any(m in title for m in CHALLENGE_MARKERS):
                return False, "Blocked by challenge/Cloudflare"
            context.close()
            return True, f"HTTP {status or 200} · {time.time()-t0:.1f}s · real browser"
        finally:
            try:
                browser.close()
            except Exception:
                pass


def _send_chrome_view(target_url, proxy_url):
    import undetected_chromedriver as uc
    from selenium.webdriver.chrome.options import Options
    opts = Options()
    if proxy_url:
        server, _, _ = _browser_proxy(proxy_url)
        if server:
            opts.add_argument(f"--proxy-server={server}")
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument(f"--user-agent={random.choice(USER_AGENTS)}")
    opts.add_experimental_option("prefs", {"disk_cache_size": 0})
    # No system Chrome? Point undetected_chromedriver at the Chromium we already
    # have from Playwright. The engine probe verifies this combo actually works.
    if not _chrome_available():
        exe = _find_chromium_executable()
        if exe:
            opts.binary_location = exe
    with CHROME_LAUNCH_LOCK:
        driver = uc.Chrome(options=opts)
    try:
        driver.set_page_load_timeout(30)
        t0 = time.time()
        driver.get(target_url)
        time.sleep(random.uniform(2.5, 6))
        title = (driver.title or "").lower()
        if any(m in title for m in CHALLENGE_MARKERS):
            return False, "Blocked by challenge/Cloudflare"
        return True, f"Loaded in {time.time()-t0:.1f}s · real browser"
    finally:
        try:
            driver.quit()
        except Exception:
            pass


def _send_requests_view(target_url, proxy_url):
    """Last-resort fallback — raw HTTP, no JS. Often NOT counted by sites."""
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.google.com/",
        "Upgrade-Insecure-Requests": "1",
    }
    kwargs = {"headers": headers, "timeout": 15}
    if proxy_url:
        kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}
    r = requests.get(target_url, **kwargs)
    if r.status_code >= 400:
        return False, f"HTTP {r.status_code} from server"
    if len(r.content) < 500:
        return False, "Empty response (likely blocked)"
    return True, f"HTTP {r.status_code} · raw HTTP (no JS — may not count)"


def _is_retryable_conn_error(e):
    """True when an exception is a connection-level reset we can survive by rotating the circuit."""
    msg = f"{type(e).__name__}: {e}"
    hay = msg.lower()
    markers = (
        "remotedisconnected", "remote end closed", "connection aborted",
        "connection reset", "broken pipe", "connectionerror", "proxyerror",
        "readtimeout", "connecttimeout", "timeout", "max retries exceeded",
        "err_connection", "err_name_not_resolved", "err_tunnel", "networkerror",
        "target page, context or browser has been closed", "browser has been closed",
        "net::err", "dead proxy", "socks", "temporarily unavailable",
    )
    return any(m in hay for m in markers)


FATAL_ENGINE_MARKERS = (
    "sessionnotcreated", "cannot connect to chrome", "webdriverexception",
    "text file busy", "no such file or directory", "executable doesn't exist",
    "chromedriver", "could not find chrome", "no chrome binary", "browserexception",
    "session not created", "invalid argument",
)


def _is_fatal_engine_error(e):
    """True when the browser engine itself is broken (driver/launch failures), not the network."""
    hay = f"{type(e).__name__}: {e}".lower()
    return any(m in hay for m in FATAL_ENGINE_MARKERS)


def _downgrade_engine(engine):
    return {"chrome": "playwright", "playwright": "requests"}.get(engine, "requests")


def guns_worker(target_url, proxies, worker_id, stop_event):
    use_tor = BOT_STATE.get("use_tor", False)
    tor_idx = worker_id % 5 if use_tor else None
    consecutive_fails = 0

    while not stop_event.is_set():
        # Re-derive the verified engine every round so an engine that just finished
        # installing (or got upgraded) is picked up without a restart.
        engine = ENGINE_PROBE_RESULT[0] or probe_engine(block=False) or "requests"
        if engine == "requests":
            _ensure_browser_install()
        proxy = proxies[worker_id % len(proxies)] if proxies else None
        if use_tor:
            proxy = f"socks5h://127.0.0.1:{9050 + tor_idx}"

        # Before every attempt, rotate the circuit so each view comes from a fresh exit IP.
        if use_tor:
            rotate_tor_circuit(tor_idx, verify_ip=False)

        ok, detail = None, None
        max_retries = 3 if use_tor else 2
        for attempt in range(max_retries):
            if stop_event.is_set():
                return
            try:
                if engine == "playwright":
                    ok, detail = _send_playwright_view(target_url, proxy)
                elif engine == "chrome":
                    ok, detail = _send_chrome_view(target_url, proxy)
                else:
                    ok, detail = _send_requests_view(target_url, proxy)
                break  # got a definitive answer
            except Exception as e:
                detail = f"{type(e).__name__}: {str(e)[:100]}"
                if _is_fatal_engine_error(e) and engine != "requests":
                    # Engine is broken (missing chrome, driver mismatch…) — switch to the
                    # next working engine instead of hammering the broken one.
                    new_engine = _downgrade_engine(engine)
                    bot_log("warn", f"worker {worker_id+1} · {type(e).__name__} — engine {engine} broken, falling back to {new_engine}")
                    engine = new_engine
                    ENGINE_PROBE_RESULT[0] = new_engine  # keep probe cache in sync
                    if engine == "requests":
                        bot_log("warn", f"worker {worker_id+1} · raw HTTP fallback — views may not be counted")
                    continue
                if _is_retryable_conn_error(e):
                    # Connection reset / dead circuit → rotate and retry on a fresh exit IP.
                    if use_tor:
                        rotate_tor_circuit(tor_idx, verify_ip=False)
                    time.sleep(1.5 + attempt * 1.5)
                    continue
                break  # non-connection error (e.g. bad URL) — don't retry

        if ok is None:
            ok, detail = False, detail or "no result"

        with BOT_LOCK:
            BOT_STATE["attempts"] += 1
            w = BOT_STATE["workers"].setdefault(
                str(worker_id), {"status": "started", "views": 0, "errors": 0, "last": "—", "last_at": None, "circuit": 0, "exit_ip": None}
            )
            if ok:
                BOT_STATE["views_sent"] += 1
                w["views"] += 1
                w["status"] = "ok"
                consecutive_fails = 0
            else:
                BOT_STATE["errors"] += 1
                w["errors"] += 1
                w["status"] = "fail"
                consecutive_fails += 1
            w["last"] = detail
            w["last_at"] = time.strftime("%H:%M:%S")
            if use_tor:
                w["circuit"] = TOR_ROTATIONS[tor_idx]
                ip = tor_exit_ip(tor_idx)
                if ip:
                    w["exit_ip"] = ip
        bot_log("ok" if ok else "error", f"worker {worker_id+1} · {detail}")

        # Back off harder after repeated failures (dead circuit / blocked IP).
        if consecutive_fails >= 3:
            time.sleep(random.uniform(10, 20))
            if use_tor:
                rotate_tor_circuit(tor_idx, verify_ip=True)
        else:
            time.sleep(random.uniform(3, 8))


# ── Routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/validate_token", methods=["POST"])
def validate_token():
    data = request.get_json(silent=True) or {}
    token = (data.get("auth_token") or "").strip()
    if not token:
        return jsonify({"valid": False, "error": "No token provided"})

    headers = _build_discord_headers(token)
    try:
        resp = requests.get("https://discord.com/api/v9/users/@me", headers=headers, timeout=10)
        if resp.status_code == 200:
            user = resp.json()
            return jsonify({
                "valid": True,
                "username": user.get("username"),
                "discriminator": user.get("discriminator", "0"),
                "id": user.get("id"),
            })
        if resp.status_code == 401:
            return jsonify({"valid": False, "error": "Token rejected (401) — invalid or expired. Make sure it's a USER token from Discord's dev tools, not a bot token."})
        if resp.status_code == 429:
            return jsonify({"valid": False, "error": "Rate limited by Discord. Wait a minute and try again."})
        try:
            body = resp.json()
            msg = body.get("message", str(resp.status_code))
        except Exception:
            msg = f"HTTP {resp.status_code}"
        return jsonify({"valid": False, "error": msg})
    except requests.exceptions.Timeout:
        return jsonify({"valid": False, "error": "Timed out — Discord unreachable"})
    except Exception as e:
        return jsonify({"valid": False, "error": f"Connection error: {str(e)[:200]}"})


@app.route("/check_usernames", methods=["POST"])
def check_usernames():
    data = request.get_json(silent=True) or {}
    length = int(data.get("length", 3))
    auth_token = (data.get("auth_token") or "").strip()
    use_proxy = bool(data.get("use_proxy", True))

    if not auth_token:
        return jsonify({"error": "Discord auth token is required"}), 400
    if length not in (2, 3, 4):
        return jsonify({"error": "Length must be 2, 3, or 4"}), 400

    letters = string.ascii_lowercase
    combinations = ["".join(p) for p in itertools.product(letters, repeat=length)]
    random.shuffle(combinations)

    total = len(combinations)
    result_queue = queue.Queue()
    stop_event = threading.Event()
    checked_count = [0]
    available_list = []
    fatal_error = [None]

    def worker(combo_batch, proxy_url):
        for combo in combo_batch:
            if stop_event.is_set():
                return
            pace_requests(min_interval=0.4)  # aggregate rate cap (~2.5 req/s)
            res = check_discord_username(combo, auth_token, proxy_url, use_proxy)
            checked_count[0] += 1

            if res["available"] is True:
                available_list.append(combo)
                result_queue.put({"type": "found", "username": combo})
            elif res["status"] is not None and res["status"] >= 400:
                fatal_error[0] = res["discord_msg"]
                result_queue.put({"type": "fatal", "message": res["discord_msg"], "status": res["status"]})
                stop_event.set()
                return
        result_queue.put({"type": "done"})

    num_workers = min(5, len(combinations))
    batch_size = max(1, total // num_workers)

    threads = []
    for i in range(num_workers):
        start_idx = i * batch_size
        end_idx = start_idx + batch_size if i < num_workers - 1 else total
        batch = combinations[start_idx:end_idx]
        proxy = PROXY_POOL[i]
        t = threading.Thread(target=worker, args=(batch, proxy), daemon=True)
        threads.append(t)
        t.start()

    def generate():
        done_workers = 0
        while done_workers < num_workers:
            try:
                msg = result_queue.get(timeout=60)
                if msg["type"] == "found":
                    yield f"data: {json.dumps({'event': 'found', 'username': msg['username'], 'checked': checked_count[0], 'total': total})}\n\n"
                elif msg["type"] == "fatal":
                    yield f"data: {json.dumps({'event': 'fatal', 'message': msg['message'], 'status': msg.get('status'), 'checked': checked_count[0], 'total': total})}\n\n"
                    done_workers = num_workers
                elif msg["type"] == "done":
                    done_workers += 1
            except queue.Empty:
                yield f"data: {json.dumps({'event': 'progress', 'checked': checked_count[0], 'total': total})}\n\n"

        if fatal_error[0] is None:
            yield f"data: {json.dumps({'event': 'complete', 'available': available_list, 'checked': checked_count[0], 'total': total})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


def _normalize_proxies(raw):
    proxies = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if "://" not in line:
            line = "http://" + line  # assume http when scheme omitted
        if not re.match(r"^(https?|socks5h?|socks4)://", line):
            continue
        if line not in proxies:
            proxies.append(line)
    return proxies


@app.route("/start_guns_lol", methods=["POST"])
def start_guns_lol():
    global BOT_STATE
    data = request.get_json(silent=True) or {}
    target = (data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "no url provided"}), 400
    if not target.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    num_browsers = max(1, min(int(data.get("browsers", 3)), 8))
    proxies = _normalize_proxies(data.get("proxies"))
    use_tor = bool(data.get("use_tor", True))

    # Lazily bring Tor up if requested and it isn't running yet.
    if use_tor and not TOR_AVAILABLE:
        ensure_tor_instances()

    if use_tor and TOR_AVAILABLE:
        proxies = []  # workers build socks5h://127.0.0.1:port from tor_idx directly
        bot_log("info", "Tor rotation enabled — each view will use a fresh exit IP.")
    elif not proxies:
        bot_log("warn", "No proxies configured and Tor unavailable — using direct connection (one IP).")

    # Verify a browser really launches before spawning workers (cached after first probe).
    engine = probe_engine(block=True, timeout=60)

    BOT_STOP.clear()
    with BOT_LOCK:
        BOT_STATE = {
            "running": True,
            "browser_count": num_browsers,
            "engine": engine,
            "use_tor": use_tor and TOR_AVAILABLE,
            "views_sent": 0,
            "attempts": 0,
            "errors": 0,
            "started_at": time.strftime("%H:%M:%S"),
            "workers": {str(i): {"status": "starting", "views": 0, "errors": 0, "last": "—", "last_at": None, "circuit": 0, "exit_ip": None} for i in range(num_browsers)},
        }

    bot_log("info", f"Starting {num_browsers} worker(s) · engine={engine} · tor={BOT_STATE['use_tor']} · proxies={len(proxies)}")
    if engine == "requests":
        bot_log("warn", "No browser found (Playwright/Chrome missing) — installing one in the background. Views start counting once it's ready.")
        _ensure_browser_install()

    for i in range(num_browsers):
        t = threading.Thread(target=guns_worker, args=(target, proxies, i, BOT_STOP), daemon=True)
        t.start()

    return jsonify({
        "status": "started",
        "browsers": num_browsers,
        "engine": engine,
        "proxies": len(proxies),
        "tor": BOT_STATE["use_tor"],
    })


@app.route("/stop_guns_lol", methods=["POST"])
def stop_guns_lol():
    BOT_STOP.set()
    with BOT_LOCK:
        BOT_STATE["running"] = False
    bot_log("info", "Bot stopped by user.")
    return jsonify({"status": "stopped"})


@app.route("/bot_status")
def bot_status():
    with BOT_LOCK:
        state = dict(BOT_STATE)
        state["logs"] = list(BOT_LOGS)[-80:]
        state["browser_install"] = BROWSER_INSTALL_STATE[0]
        return jsonify(state)


@app.route("/view_count")
def view_count():
    with VIEW_LOCK:
        return jsonify({"views": BOT_STATE.get("views_sent", 0)})


@app.route("/status")
def status():
    # Lazily start Tor when the page loads so rotation is ready when the user hits Start.
    if not TOR_STARTED and not TOR_AVAILABLE:
        threading.Thread(target=ensure_tor_instances, daemon=True).start()
    # Also verify the browser engine in the background so Start is instant later.
    if not ENGINE_PROBE_RESULT[0]:
        threading.Thread(target=_run_engine_probe, daemon=True).start()
    if detect_engine() == "requests":
        _ensure_browser_install()
    exit_ips = []
    if TOR_AVAILABLE:
        for i in range(5):
            if TOR_READY[i]:
                ip = tor_exit_ip(i)
                if ip:
                    exit_ips.append(ip)
    return jsonify({
        "tor_available": TOR_AVAILABLE,
        "tor_instances": sum(1 for r in TOR_READY if r),
        "tor_rotations": sum(TOR_ROTATIONS),
        "tor_exit_ips": exit_ips,
        "engine": detect_engine(),
        "browser_install": BROWSER_INSTALL_STATE[0],
        "views": BOT_STATE.get("views_sent", 0),
    })


if __name__ == "__main__":
    # Start Tor in the background so circuits are ready by the time the UI loads.
    threading.Thread(target=ensure_tor_instances, daemon=True).start()
    # Probe the browser engine in the background too.
    threading.Thread(target=_run_engine_probe, daemon=True).start()
    if detect_engine() == "requests":
        _ensure_browser_install()
    app.run(host="0.0.0.0", port=8080, threaded=True)

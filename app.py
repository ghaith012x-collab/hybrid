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

# ── Live cams (per-worker latest frame, thread-safe) ───────────────────
CAM_LOCK = threading.Lock()
CAM_BUFFER = {}  # worker_id -> {"data": bytes, "mime": str, "ts": float, "label": str}


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


# ── Single-IP direct mode pacing (don't burst-trigger the target's rate limiter) ──
SINGLE_IP_LOCK = threading.Lock()
SINGLE_IP_LAST = [0.0]


def pace_single_ip(min_interval=6.0):
    """Throttle aggregate views when running direct on ONE IP so the target's
    rate limiter doesn't gate the IP after a short burst."""
    with SINGLE_IP_LOCK:
        now = time.time()
        wait = min_interval - (now - SINGLE_IP_LAST[0])
        if wait > 0:
            time.sleep(wait)
        SINGLE_IP_LAST[0] = time.time()


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


def tor_target_probe(target_url, max_instances=2):
    """One real-browser view through Tor to check if the target accepts Tor exits.

    Returns (True, detail) when a Tor view loads, (False, detail) when the target
    blocks Tor (403/challenge), or (None, 'inconclusive') when it couldn't tell.
    """
    if not TOR_AVAILABLE:
        return None, "tor unavailable"
    tried = 0
    for i in range(5):
        if not TOR_READY[i]:
            continue
        tried += 1
        try:
            rotate_tor_circuit(i, verify_ip=False)
            ok, detail = _send_playwright_view(target_url, f"socks5h://127.0.0.1:{9050 + i}")
            low = detail.lower()
            if "403" in detail or "challenge" in low or "flagged" in low or "blocked" in low:
                return False, detail
            if ok:
                return True, detail
        except Exception:
            pass
        if tried >= max_instances:
            break
    return None, "inconclusive"


# ── Discord checker (browser-based, no token) ──────────────────────────

# Discord register page username input selectors (tried in order)
DISCORD_USERNAME_SELECTORS = [
    "input[name='username']",
    "input[aria-label*='username' i]",
    "input[aria-label*='display' i]",
    "input[type='text']:not([name='email']):not([aria-label*='email' i])",
]

# Text markers that indicate a username is TAKEN (unavailable)
DISCORD_UNAVAILABLE_MARKERS = [
    "unavailable",
    "username is unavailable",
    "you can't use this username",
    "already taken",
    "too many users have this username",
]

# Text markers that indicate a username is AVAILABLE
DISCORD_AVAILABLE_MARKERS = [
    "you're good to go",
    "username is available",
    "available",
]


def _check_username_via_register(username, proxy_url=None, cam_id=None):
    """Check one Discord username by filling the register form in a real browser.

    Navigates to https://discord.com/register, types the username, waits for
    Discord's inline validation, and reads whether it shows 'unavailable' or
    the green 'available' indicator.

    Returns {"available": bool|None, "detail": str}
    """
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
            "--disable-application-cache",
            "--aggressive-cache-discard",
            "--disable-features=BackForwardCache",
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

    t0 = time.time()
    try:
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
                try:
                    context.clear_cookies()
                except Exception:
                    pass

                page = context.new_page()
                resp = page.goto("https://discord.com/register", timeout=30000, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)

                input_el = None
                for sel in DISCORD_USERNAME_SELECTORS:
                    try:
                        el = page.query_selector(sel)
                        if el and el.is_visible():
                            input_el = el
                            break
                    except Exception:
                        continue

                if input_el is None:
                    try:
                        all_inputs = page.query_selector_all("input[type='text']")
                        for inp in all_inputs:
                            try:
                                if inp.is_visible():
                                    input_el = inp
                                    break
                            except Exception:
                                continue
                    except Exception:
                        pass

                if input_el is None:
                    context.close()
                    return {"available": None, "detail": "Could not find username input on register page"}

                try:
                    input_el.click()
                    page.wait_for_timeout(300)
                    input_el.fill("")
                    page.wait_for_timeout(200)
                    input_el.type(username, delay=random.randint(40, 100))
                except Exception:
                    context.close()
                    return {"available": None, "detail": "Could not type username into register form"}

                page.wait_for_timeout(random.randint(1800, 3000))

                try:
                    body_text = (page.content() or "").lower()
                except Exception:
                    body_text = ""

                for marker in DISCORD_UNAVAILABLE_MARKERS:
                    if marker in body_text:
                        context.close()
                        elapsed = time.time() - t0
                        return {"available": False, "detail": f"Taken ({marker}) · {elapsed:.1f}s"}

                for marker in DISCORD_AVAILABLE_MARKERS:
                    if marker in body_text:
                        context.close()
                        elapsed = time.time() - t0
                        return {"available": True, "detail": f"Available · {elapsed:.1f}s"}

                try:
                    aria_invalid = input_el.get_attribute("aria-invalid")
                    if aria_invalid == "true":
                        context.close()
                        elapsed = time.time() - t0
                        return {"available": False, "detail": f"Taken (aria-invalid=true) · {elapsed:.1f}s"}
                except Exception:
                    pass

                try:
                    error_els = page.query_selector_all("[class*='error'], [class*='Error'], [class*='invalid']")
                    for e in error_els:
                        try:
                            txt = (e.text_content() or "").lower()
                            if any(m in txt for m in DISCORD_UNAVAILABLE_MARKERS):
                                context.close()
                                elapsed = time.time() - t0
                                return {"available": False, "detail": f"Taken (error element) · {elapsed:.1f}s"}
                        except Exception:
                            continue
                except Exception:
                    pass

                context.close()
                elapsed = time.time() - t0
                return {"available": False, "detail": f"Likely taken (no availability indicator) · {elapsed:.1f}s"}

            finally:
                try:
                    browser.close()
                except Exception:
                    pass

    except Exception as e:
        elapsed = time.time() - t0
        msg = f"{type(e).__name__}: {str(e)[:120]}"
        return {"available": None, "detail": f"Browser error: {msg} · {elapsed:.1f}s"}

# ── guns.lol view bot engine ───────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

CHALLENGE_MARKERS = ["just a moment", "cf-challenge", "checking your browser", "attention required", "cloudflare", "please wait a moment"]


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


# guns.lol shows a "Click to enter" gate over profile pages. A real visitor waits,
# then clicks it (or the center of the page) — only then is the visit treated as a
# genuine profile view. The bot now mimics exactly that.
GATE_TEXT_MARKERS = (
    "click to enter", "click here to enter", "click to continue",
    "click to view", "click to open", "click to enter the profile",
    "enter the profile", "show profile", "click to unlock",
)

# X / close buttons (popups, modals, overlays) to dismiss before clicking through.
CLOSE_BUTTON_SELECTORS = (
    "[aria-label=\"Close\"]",
    "[aria-label=\"close\"]",
    "[aria-label=\"Close dialog\"]",
    "button[class*=\"close\"]",
    "button[class*=\"Close\"]",
    ".close",
    ".close-btn",
    ".modal-close",
    "[data-close]",
    "[data-testid=\"close\"]",
    "button:has-text(\"✕\")",
    "button:has-text(\"×\")",
    "svg[aria-label=\"Close\"]",
)


def _click_close_buttons(page):
    """Click any X / close button on the page (popups, modals, overlays)."""
    clicked = 0
    for sel in CLOSE_BUTTON_SELECTORS:
        try:
            els = page.query_selector_all(sel)
            for e in els[:3]:
                try:
                    if e.is_visible():
                        e.click(timeout=1500)
                        clicked += 1
                except Exception:
                    continue
        except Exception:
            continue
    return clicked


def _find_gate_element(page):
    """Find the 'Click to enter' gate element if it's mounted and visible."""
    for m in GATE_TEXT_MARKERS:
        try:
            els = page.query_selector_all(f"text={m}")
            for e in els:
                try:
                    if e.is_visible():
                        return e
                except Exception:
                    continue
        except Exception:
            continue
    return None


def _snap_cam(cam_id, page, label):
    """Capture the current page state into the live-cam buffer for this worker (Playwright)."""
    if cam_id is None:
        return
    try:
        data = page.screenshot(type="jpeg", quality=60)
        with CAM_LOCK:
            CAM_BUFFER[str(cam_id)] = {"data": data, "mime": "image/jpeg", "ts": time.time(), "label": label}
    except Exception:
        pass


def _snap_cam_chrome(cam_id, driver, label):
    """Capture the current page state into the live-cam buffer (Selenium/Chrome)."""
    if cam_id is None:
        return
    try:
        data = driver.get_screenshot_as_png()
        with CAM_LOCK:
            CAM_BUFFER[str(cam_id)] = {"data": data, "mime": "image/png", "ts": time.time(), "label": label}
    except Exception:
        pass


def _click_through_gate(page, width, height, on_frame=None):
    """guns.lol shows a 'Click to enter' gate. Dismiss any popups (X buttons),
    wait ~3s, then click the gate ONCE (or the page center).
    Returns (clicks_done, gate_found)."""
    if on_frame:
        try:
            on_frame("closing popups")
        except Exception:
            pass
    try:
        _click_close_buttons(page)
    except Exception:
        pass
    try:
        page.wait_for_timeout(3000)
    except Exception:
        pass
    clicks = 0
    gate_found = False
    try:
        el = _find_gate_element(page)
        if el is not None:
            gate_found = True
            box = el.bounding_box()
            if box and box.get("width") and box.get("height"):
                page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
            else:
                page.mouse.click(width // 2, height // 2)
        else:
            page.mouse.click(width // 2, height // 2)
        clicks = 1
    except Exception:
        try:
            page.mouse.click(width // 2, height // 2)
            clicks = 1
        except Exception:
            pass
    # dismiss anything that popped up after the click
    try:
        _click_close_buttons(page)
    except Exception:
        pass
    if on_frame:
        try:
            on_frame("gate clicked" if gate_found else "center clicked")
        except Exception:
            pass
    return clicks, gate_found


def _send_playwright_view(target_url, proxy_url, cam_id=None):
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
            "--disable-application-cache",
            "--aggressive-cache-discard",
            "--disable-features=BackForwardCache",
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
            # fresh identity per view: wipe any cookies/storage so guns.lol can't
            # dedupe this visit against a previous one from the same context.
            try:
                context.clear_cookies()
            except Exception:
                pass
            page = context.new_page()
            cam_id_str = str(cam_id) if cam_id is not None else None

            def on_frame(label):
                if cam_id_str is not None:
                    _snap_cam(cam_id_str, page, label)

            # guns.lol counts a view when its analytics beacon fires on page load
            # (sa.guns.lol/simple.gif?...type=pageview). Detecting it is hard proof the view registered.
            beacons = []

            def _track_beacon(r):
                try:
                    u = r.url
                    if "sa.guns.lol" in u or ("simple.gif" in u and "pageview" in u):
                        beacons.append(u)
                except Exception:
                    pass

            page.on("response", _track_beacon)
            t0 = time.time()
            resp = page.goto(target_url, timeout=30000, wait_until="domcontentloaded")
            on_frame("loaded")
            # human-ish behavior: scroll, dwell (cam frame every ~2s)
            dwell = random.randint(2500, 6000)
            while dwell > 0:
                step = min(2000, dwell)
                page.wait_for_timeout(step)
                dwell -= step
                on_frame("viewing")
            for _ in range(random.randint(1, 3)):
                page.mouse.wheel(0, random.randint(200, 800))
                page.wait_for_timeout(random.randint(400, 1200))
                on_frame("scrolling")
            title = (page.title() or "").lower()
            status = resp.status if resp else None
            if status and status >= 400:
                # Enrich the reason so logs are actionable (Cloudflare/IP block vs plain error).
                try:
                    body = (page.content() or "")[:4000].lower()
                except Exception:
                    body = ""
                if "403" in str(status) and any(m in body for m in ("cloudflare", "cf-", "access denied", "error 1009", "temporary block", "forbidden", "just a moment", "please wait a moment")):
                    on_frame("blocked 403")
                    return False, "Blocked (HTTP 403 — challenge/IP flagged)"
                if status == 401:
                    if any(m in body for m in ("captcha", "verify", "human", "suspended", "rate limit", "too many")):
                        on_frame("gated 401")
                        return False, "HTTP 401 — IP gated (captcha/rate-limit)"
                    on_frame("gated 401")
                    return False, "HTTP 401 — IP gated (rate-limited)"
                on_frame(f"http {status}")
                return False, f"HTTP {status} from server"
            # Cloudflare interstitial ("Just a moment…") — wait for it to auto-clear before failing.
            if any(m in title for m in CHALLENGE_MARKERS):
                deadline = time.time() + 15
                while time.time() < deadline:
                    page.wait_for_timeout(1500)
                    try:
                        new_title = (page.title() or "").lower()
                    except Exception:
                        new_title = ""
                    if not any(m in new_title for m in CHALLENGE_MARKERS):
                        on_frame("challenge cleared")
                        beacon_tag = " · beacon ✓ view registered" if beacons else " · ⚠ no analytics beacon"
                        return True, f"Challenge cleared · {time.time()-t0:.1f}s · real browser{beacon_tag}"
                on_frame("challenge stuck")
                return False, "Blocked by challenge/Cloudflare"
            gate_note = ""
            if "guns.lol" in (target_url or "").lower():
                # Honesty first: guns.lol serves bots a fake 'Username not found'
                # page. The analytics beacon still fires on it — so those were being
                # counted as views without any profile ever loading (the 'larp').
                try:
                    body_low = (page.content() or "").lower()
                except Exception:
                    body_low = ""
                if "username not found" in body_low or "claim this username" in body_low:
                    on_frame("username not found")
                    return False, "Not counted — guns.lol served 'Username not found' (bot-detected 404 or wrong handle)"
                # Real profile → click the 'Click to enter' gate like a human.
                before = len(beacons)
                clicks, gate_found = _click_through_gate(page, viewport[0], viewport[1], on_frame=on_frame)
                gained = len(beacons) - before
                if gate_found:
                    gate_note = f" · gate ✓ clicked {clicks}x"
                elif clicks > 0:
                    gate_note = f" · center clicked {clicks}x (no gate found)"
                if gained > 0:
                    gate_note += f" · +{gained} beacon(s) after click"
            on_frame("done")
            context.close()
            beacon_tag = " · beacon ✓ view registered" if beacons else " · ⚠ no analytics beacon"
            return True, f"HTTP {status or 200} · {time.time()-t0:.1f}s · real browser{beacon_tag}{gate_note}"
        finally:
            try:
                browser.close()
            except Exception:
                pass


def _send_chrome_view(target_url, proxy_url, cam_id=None):
    import undetected_chromedriver as uc
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
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
        _snap_cam_chrome(cam_id, driver, "loaded")
        time.sleep(random.uniform(2.5, 6))
        title = (driver.title or "").lower()
        if any(m in title for m in CHALLENGE_MARKERS):
            _snap_cam_chrome(cam_id, driver, "challenge stuck")
            return False, "Blocked by challenge/Cloudflare"
        gate_note = ""
        if "guns.lol" in (target_url or "").lower():
            try:
                body = (driver.page_source or "").lower()
                if "username not found" in body or "claim this username" in body:
                    _snap_cam_chrome(cam_id, driver, "username not found")
                    return False, "Not counted — guns.lol served 'Username not found' (bot-detected 404 or wrong handle)"
            except Exception:
                pass
            time.sleep(3)
            # dismiss X / close buttons, then click the gate once
            try:
                for xsel in ["[aria-label='Close']", "[aria-label='close']", "button[class*='close']", ".close", ".modal-close", "[data-close]"]:
                    for el in driver.find_elements(By.CSS_SELECTOR, xsel):
                        try:
                            el.click()
                        except Exception:
                            pass
            except Exception:
                pass
            try:
                els = driver.find_elements(By.XPATH, "//*[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'click to enter')]")
                if els:
                    els[-1].click()
                else:
                    driver.execute_script("document.elementFromPoint(960, 540).click();")
            except Exception:
                pass
            _snap_cam_chrome(cam_id, driver, "gate clicked")
            gate_note = " · gate clicked"
        _snap_cam_chrome(cam_id, driver, "done")
        return True, f"Loaded in {time.time()-t0:.1f}s · real browser{gate_note}"
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
    tor_403_streak = 0
    tor_block_warned = False
    rate_limit_streak = 0
    proxy_round = 0  # rotates through the proxy list so every view uses a fresh IP

    while not stop_event.is_set():
        # Re-derive the verified engine every round so an engine that just finished
        # installing (or got upgraded) is picked up without a restart.
        engine = ENGINE_PROBE_RESULT[0] or probe_engine(block=False) or "requests"
        if engine == "requests":
            _ensure_browser_install()

        # The target keeps rejecting Tor exits (403)? Fall back to the user's proxies —
        # or direct (which usually works) — instead of wasting attempts on a blocked network.
        if use_tor and tor_403_streak >= 2:
            use_tor = False
            with BOT_LOCK:
                BOT_STATE["tor_blocked"] = True
            if not tor_block_warned:
                tor_block_warned = True
                if proxies:
                    bot_log("warn", f"worker {worker_id+1} · Target blocks Tor exit IPs (403) — switching to your proxies for the rest of this run.")
                else:
                    bot_log("warn", f"worker {worker_id+1} · Target blocks Tor exit IPs (403) — switching to direct. Tor views won't count on this target; add residential proxies for real views.")

        if use_tor:
            proxy = f"socks5h://127.0.0.1:{9050 + tor_idx}"
            # Before every attempt, rotate the circuit so each view comes from a fresh exit IP.
            rotate_tor_circuit(tor_idx, verify_ip=False)
        elif proxies:
            # ROTATE: every view uses the NEXT proxy in the list so each load comes
            # from a different IP. (guns.lol dedupes per unique session/IP — hammering
            # one proxy means repeat views never count.)
            proxy = proxies[(worker_id + proxy_round) % len(proxies)]
            proxy_round += 1
        else:
            proxy = None

        # Single-IP direct mode: pace globally so a swarm of workers on one IP
        # doesn't burst-trigger the target's rate limiter and get gated.
        if not use_tor and not proxies:
            pace_single_ip(6.0)

        ok, detail = None, None
        max_retries = 3 if use_tor else 2
        for attempt in range(max_retries):
            if stop_event.is_set():
                return
            # On a retry, also hop to the next proxy so a dead/blocked IP doesn't get reused.
            if not use_tor and proxies and attempt > 0:
                proxy = proxies[(worker_id + proxy_round) % len(proxies)]
                proxy_round += 1
            try:
                if engine == "playwright":
                    ok, detail = _send_playwright_view(target_url, proxy, cam_id=worker_id)
                elif engine == "chrome":
                    ok, detail = _send_chrome_view(target_url, proxy, cam_id=worker_id)
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
                rate_limit_streak = 0
                if use_tor:
                    tor_403_streak = 0
                    BOT_STATE["tor_blocked"] = False
            else:
                BOT_STATE["errors"] += 1
                w["errors"] += 1
                w["status"] = "fail"
                consecutive_fails += 1
                if "401" in (detail or ""):
                    rate_limit_streak += 1
                else:
                    rate_limit_streak = max(0, rate_limit_streak - 1)
                if use_tor and "403" in (detail or ""):
                    tor_403_streak += 1
                elif not use_tor:
                    tor_403_streak = 0
            w["last"] = detail
            w["last_at"] = time.strftime("%H:%M:%S")
            if use_tor:
                w["circuit"] = TOR_ROTATIONS[tor_idx]
                ip = tor_exit_ip(tor_idx)
                if ip:
                    w["exit_ip"] = ip
        bot_log("ok" if ok else "error", f"worker {worker_id+1} · {detail}")

        # Back off harder after repeated failures (dead circuit / blocked IP).
        if rate_limit_streak >= 2:
            if rate_limit_streak == 2:
                bot_log("warn", f"worker {worker_id+1} · Target is gating this IP (HTTP 401) — backing off 45–90s so the limit resets. Proxies give you many IPs to bypass this.")
            time.sleep(random.uniform(45, 90))
        elif consecutive_fails >= 3:
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
    """Token validation is no longer needed — the checker uses browser-based registration form now."""
    return jsonify({"valid": True, "username": "browser-mode", "note": "No token needed — checker uses discord.com/register via browser"})


@app.route("/check_usernames", methods=["POST"])
def check_usernames():
    """Browser-based username checker — types names into discord.com/register form.

    No token required. 5 browser workers. Numbers + letters. Every 20 checks
    per worker, the browser restarts fresh (clear cache, new IP via proxy rotation).
    """
    data = request.get_json(silent=True) or {}
    try:
        length = int(data.get("length", 3))
    except (TypeError, ValueError):
        return jsonify({"error": "Length must be 2, 3, or 4"}), 400
    if length not in (2, 3, 4):
        return jsonify({"error": "Length must be 2, 3, or 4"}), 400

    proxy_list = _normalize_proxies(data.get("proxies"))
    use_proxy = bool(proxy_list) and data.get("use_proxy", True)

    # Generate usernames: letters + digits (e.g. "a0", "x9", "ab", "12")
    chars = string.ascii_lowercase + string.digits
    combinations = ["".join(p) for p in itertools.product(chars, repeat=length)]
    random.shuffle(combinations)

    total = len(combinations)
    result_queue = queue.Queue()
    stop_event = threading.Event()
    checked_count = [0]
    available_list = []
    # Live, mutually exclusive username-result counters. A retryable result is
    # visible as "Retrying" so the UI never presents a blocked route as invalid.
    check_stats = {
        "checked": 0,
        "invalid": 0,
        "available": 0,
        "retrying": 0,
    }
    fatal_error = [None]
    stats_lock = threading.Lock()
    fatal_lock = threading.Lock()
    warning_sent = [False]

    BROWSER_RECYCLE_EVERY = 20  # restart browser + rotate IP every N checks per worker

    def worker(combo_batch, worker_id):
        checks_since_recycle = 0
        for position, combo in enumerate(combo_batch):
            if stop_event.is_set():
                return

            # Every 20 checks: pause briefly so the new browser context gets a clean slate,
            # then rotate to the next proxy (or stay direct) for a fresh IP appearance.
            if checks_since_recycle >= BROWSER_RECYCLE_EVERY:
                checks_since_recycle = 0
                time.sleep(random.uniform(3, 6))  # cooldown between browser sessions

            proxy_url = None
            if use_proxy and proxy_list:
                idx = (worker_id + position) % len(proxy_list)
                # Also rotate on recycle for a fresh IP
                if checks_since_recycle == 0 and position > 0:
                    idx = (worker_id + position + 1) % len(proxy_list)
                proxy_url = proxy_list[idx]

            # Each check opens a fresh browser (via _check_username_via_register).
            # Playwright creates a new context per call, so cookies/cache are inherently fresh.
            result = _check_username_via_register(combo, proxy_url, cam_id=str(worker_id))
            checks_since_recycle += 1

            avail = result.get("available")
            detail = result.get("detail", "")

            with stats_lock:
                checked_count[0] += 1
                check_stats["checked"] += 1
                if avail is True:
                    check_stats["available"] += 1
                elif avail is False:
                    check_stats["invalid"] += 1
                else:
                    check_stats["retrying"] += 1

            result_queue.put({"type": "progress"})

            if avail is True:
                with stats_lock:
                    available_list.append(combo)
                result_queue.put({"type": "found", "username": combo})
            elif avail is None:
                # Browser-level error — warn once, keep going
                with fatal_lock:
                    if not warning_sent[0]:
                        warning_sent[0] = True
                        result_queue.put({
                            "type": "warning",
                            "message": f"Browser errors detected (e.g. {detail[:80]}). Continuing with next names. Check proxies if errors persist.",
                        })

            # Small jitter between checks to avoid pattern detection
            time.sleep(random.uniform(0.8, 2.2))

        result_queue.put({"type": "done"})

    num_workers = min(5, len(combinations))
    batch_size = max(1, total // num_workers)

    threads = []
    for i in range(num_workers):
        start_idx = i * batch_size
        end_idx = start_idx + batch_size if i < num_workers - 1 else total
        batch = combinations[start_idx:end_idx]
        t = threading.Thread(target=worker, args=(batch, i), daemon=True)
        threads.append(t)
        t.start()

    def generate():
        done_workers = 0
        while done_workers < num_workers:
            try:
                msg = result_queue.get(timeout=60)
                with stats_lock:
                    snapshot = dict(check_stats)
                snapshot["total"] = total

                if msg["type"] == "found":
                    snapshot.update({"event": "found", "username": msg["username"]})
                    yield f"data: {json.dumps(snapshot)}\n\n"
                elif msg["type"] == "fatal":
                    snapshot.update({"event": "fatal", "message": msg["message"], "status": msg.get("status")})
                    yield f"data: {json.dumps(snapshot)}\n\n"
                    return
                elif msg["type"] == "warning":
                    snapshot.update({"event": "warning", "message": msg["message"]})
                    yield f"data: {json.dumps(snapshot)}\n\n"
                elif msg["type"] == "progress":
                    snapshot["event"] = "progress"
                    yield f"data: {json.dumps(snapshot)}\n\n"
                elif msg["type"] == "done":
                    done_workers += 1
            except queue.Empty:
                with stats_lock:
                    snapshot = dict(check_stats)
                snapshot.update({"event": "progress", "total": total})
                yield f"data: {json.dumps(snapshot)}\n\n"

        if fatal_error[0] is None:
            with stats_lock:
                snapshot = dict(check_stats)
            snapshot.update({"event": "complete", "available_names": list(available_list), "total": total})
            yield f"data: {json.dumps(snapshot)}\n\n"

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

    # Pre-flight: check whether this target actually accepts Tor exits before
    # spawning a swarm that would just rack up 403s. Falls back to proxies/direct.
    tor_blocked = False
    if use_tor and TOR_AVAILABLE:
        bot_log("info", "Probing target through Tor (one test view)…")
        probe_ok, probe_detail = tor_target_probe(target)
        if probe_ok is False:
            tor_blocked = True
            bot_log("warn", f"Target rejects Tor exits ({probe_detail}) — starting WITHOUT Tor. " + ("Using your proxies instead." if proxies else "Using direct (single IP). Add residential proxies for real views."))
        elif probe_ok is True:
            bot_log("info", f"Tor probe passed — exits accepted ({probe_detail}).")
        else:
            bot_log("warn", "Tor probe inconclusive — starting with Tor rotation; workers auto-fallback if blocked.")

    if use_tor and TOR_AVAILABLE and not tor_blocked:
        proxies = []  # workers build socks5h://127.0.0.1:port from tor_idx directly
        bot_log("info", "Tor rotation enabled — each view will use a fresh exit IP.")
    elif not proxies:
        bot_log("warn", "No proxies configured — using direct connection (single IP). Views will be limited; add residential proxies.")

    # Verify a browser really launches before spawning workers (cached after first probe).
    engine = probe_engine(block=True, timeout=60)

    BOT_STOP.clear()
    with BOT_LOCK:
        BOT_STATE = {
            "running": True,
            "browser_count": num_browsers,
            "engine": engine,
            "use_tor": use_tor and TOR_AVAILABLE and not tor_blocked,
            "tor_blocked": tor_blocked,
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
    with CAM_LOCK:
        state["cams"] = {k: {"ts": v.get("ts", 0), "label": v.get("label", "")} for k, v in CAM_BUFFER.items()}
    return jsonify(state)


@app.route("/cam/<int:worker_id>")
def cam_frame(worker_id):
    """Latest live frame for a worker (JPEG/PNG). 404 until the first frame exists."""
    with CAM_LOCK:
        f = CAM_BUFFER.get(str(worker_id))
    if not f:
        return "", 404
    resp = Response(f["data"], mimetype=f.get("mime", "image/jpeg"))
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Cam-Label"] = f.get("label", "")
    resp.headers["X-Cam-Ts"] = str(int(f.get("ts", 0)))
    return resp


@app.route("/view_count")
def view_count():
    with VIEW_LOCK:
        return jsonify({"views": BOT_STATE.get("views_sent", 0)})


@app.route("/verify_views", methods=["POST"])
def verify_views():
    """Self-test: load the target N times with the real engine and report whether
    guns.lol's own analytics beacon fires — that's what increments the view counter."""
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    count = max(1, min(int(data.get("views", 3)), 6))
    if not url or not url.startswith(("http://", "https://")):
        return jsonify({"error": "valid url required"}), 400

    engine = probe_engine(block=True, timeout=60)
    results, ok_count, beacon_count = [], 0, 0
    for _ in range(count):
        try:
            if engine == "playwright":
                ok, detail = _send_playwright_view(url, None)
            elif engine == "chrome":
                ok, detail = _send_chrome_view(url, None)
            else:
                ok, detail = _send_requests_view(url, None)
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {str(e)[:120]}"
        results.append({"ok": ok, "detail": detail})
        if ok:
            ok_count += 1
            if "beacon" in detail and "⚠" not in detail:
                beacon_count += 1
        time.sleep(1.5)

    if beacon_count > 0:
        verdict = "Views ARE being registered — guns.lol's analytics beacon fired on successful loads."
    elif ok_count > 0:
        verdict = "Pages load but no analytics beacon detected — views may NOT be counted (IP likely gated)."
    else:
        verdict = "No views loaded — check the target URL and engine."
    return jsonify({
        "engine": engine,
        "ok_count": ok_count,
        "beacon_count": beacon_count,
        "results": results,
        "verdict": verdict,
    })


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

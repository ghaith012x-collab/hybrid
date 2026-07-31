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


# ── Tor ────────────────────────────────────────────────────────────────

def start_tor_instances():
    global TOR_AVAILABLE
    try:
        subprocess.run(["tor", "--version"], capture_output=True, timeout=5, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print("[tor] tor binary not found — proxies disabled")
        return
    for i in range(5):
        try:
            port = 9050 + i
            control_port = 9050 + i + 10000
            tor_dir = f"/tmp/tor_{i}"
            os.makedirs(tor_dir, exist_ok=True)
            torrc_path = f"{tor_dir}/torrc"
            with open(torrc_path, "w") as f:
                f.write(f"SocksPort {port}\nControlPort {control_port}\nDataDirectory {tor_dir}\nMaxCircuitDirtiness 10\nNewCircuitPeriod 15\n")
            proc = subprocess.Popen(["tor", "-f", torrc_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            TOR_INSTANCES.append(proc)
            time.sleep(1.5)
        except Exception as e:
            print(f"[tor] instance {i} failed: {e}")
    if TOR_INSTANCES:
        TOR_AVAILABLE = True
        print(f"[tor] started {len(TOR_INSTANCES)} instances")
    else:
        print("[tor] no instances started")


def rotate_proxy(proxy_url):
    if not TOR_AVAILABLE or "127.0.0.1" not in proxy_url:
        return
    try:
        port = int(proxy_url.split(":")[-1])
        s = socket_connect((port + 10000))
    except Exception:
        pass


def socket_connect(control_port):
    import socket
    s = socket.socket()
    s.settimeout(5)
    s.connect(("127.0.0.1", control_port))
    s.send(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
    s.close()


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
    for name in ["google-chrome", "chromium", "chromium-browser", "google-chrome-stable"]:
        try:
            subprocess.run([name, "--version"], capture_output=True, timeout=5, check=True)
            return True
        except Exception:
            continue
    return False


def _playwright_browser_ready():
    """True when playwright is installed AND a chromium browser was downloaded."""
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    candidates = [
        os.environ.get("PLAYWRIGHT_BROWSERS_PATH"),
        os.path.expanduser("~/.cache/ms-playwright"),
    ]
    for base in candidates:
        if base and os.path.isdir(base):
            for d in os.listdir(base):
                if "chromium" in d:
                    return True
    return False


def detect_engine():
    if _playwright_browser_ready():
        return "playwright"
    if _chrome_available():
        return "chrome"
    return "requests"


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
        launch_opts["proxy"] = {"server": proxy_url}
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
        opts.add_argument(f"--proxy-server={proxy_url}")
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument(f"--user-agent={random.choice(USER_AGENTS)}")
    opts.add_experimental_option("prefs", {"disk_cache_size": 0})
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


def guns_worker(target_url, proxies, worker_id, stop_event):
    engine = BOT_STATE["engine"]
    while not stop_event.is_set():
        proxy = proxies[worker_id % len(proxies)] if proxies else None
        try:
            if engine == "playwright":
                ok, detail = _send_playwright_view(target_url, proxy)
            elif engine == "chrome":
                ok, detail = _send_chrome_view(target_url, proxy)
            else:
                ok, detail = _send_requests_view(target_url, proxy)
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {str(e)[:120]}"

        with BOT_LOCK:
            BOT_STATE["attempts"] += 1
            w = BOT_STATE["workers"].setdefault(str(worker_id), {"status": "started", "views": 0, "errors": 0, "last": "—", "last_at": None})
            if ok:
                BOT_STATE["views_sent"] += 1
                w["views"] += 1
                w["status"] = "ok"
            else:
                BOT_STATE["errors"] += 1
                w["errors"] += 1
                w["status"] = "fail"
            w["last"] = detail
            w["last_at"] = time.strftime("%H:%M:%S")
        bot_log("ok" if ok else "error", f"worker {worker_id+1} · {detail}")
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
    if not proxies:
        proxies = list(PROXY_POOL) if TOR_AVAILABLE else []
        if not proxies:
            bot_log("warn", "No proxies configured — using direct connection (one IP).")

    engine = detect_engine()

    BOT_STOP.clear()
    with BOT_LOCK:
        BOT_STATE = {
            "running": True,
            "browser_count": num_browsers,
            "engine": engine,
            "views_sent": 0,
            "attempts": 0,
            "errors": 0,
            "started_at": time.strftime("%H:%M:%S"),
            "workers": {str(i): {"status": "starting", "views": 0, "errors": 0, "last": "—", "last_at": None} for i in range(num_browsers)},
        }

    bot_log("info", f"Starting {num_browsers} worker(s) · engine={engine} · proxies={len(proxies)}")
    if engine == "requests":
        bot_log("warn", "No browser found (Playwright/Chrome missing). Falling back to raw HTTP — many sites won't count these views.")

    for i in range(num_browsers):
        t = threading.Thread(target=guns_worker, args=(target, proxies, i, BOT_STOP), daemon=True)
        t.start()

    return jsonify({"status": "started", "browsers": num_browsers, "engine": engine, "proxies": len(proxies)})


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
        return jsonify(state)


@app.route("/view_count")
def view_count():
    with VIEW_LOCK:
        return jsonify({"views": BOT_STATE.get("views_sent", 0)})


@app.route("/status")
def status():
    return jsonify({
        "tor_available": TOR_AVAILABLE,
        "tor_instances": len(TOR_INSTANCES),
        "engine": detect_engine(),
        "views": BOT_STATE.get("views_sent", 0),
    })


if __name__ == "__main__":
    start_tor_instances()
    app.run(host="0.0.0.0", port=8080, threaded=True)

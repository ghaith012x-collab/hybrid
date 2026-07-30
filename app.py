import requests
import random
import string
import itertools
import subprocess
import os
import time
import json
import threading
import socks
import socket
from flask import Flask, render_template, jsonify, request, Response, stream_with_context
from flask_cors import CORS
import queue

app = Flask(__name__)
CORS(app)

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
SOCKET_LOCK = threading.Lock()
TOR_AVAILABLE = False

# shared state so frontend can poll bot status
BOT_STATE = {"running": False, "browser_count": 0, "mode": "idle", "errors": 0}
BOT_LOCK = threading.Lock()


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
    if not TOR_AVAILABLE:
        return
    try:
        port = int(proxy_url.split(":")[-1])
        s = socket.socket()
        s.settimeout(5)
        s.connect(("127.0.0.1", port + 10000))
        s.send(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
        s.close()
        time.sleep(1.5)
    except Exception:
        pass


def _make_socks_request(method, url, headers, json_data, proxy_url, timeout):
    host = proxy_url.replace("socks5://", "").split(":")[0]
    port = int(proxy_url.replace("socks5://", "").split(":")[1])
    with SOCKET_LOCK:
        old_socket = socket.socket
        socks.set_default_proxy(socks.SOCKS5, host, port)
        socket.socket = socks.socksocket
    try:
        resp = requests.request(method, url, headers=headers, json=json_data, timeout=timeout)
    finally:
        with SOCKET_LOCK:
            socket.socket = old_socket
    return resp


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
            return _make_socks_request("POST", "https://discord.com/api/v9/users/@me/pomelo", headers, payload, proxy_url, 10)
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


def _chrome_available():
    """Check if Chrome/chromium binary actually exists on the system."""
    for name in ["google-chrome", "chromium", "chromium-browser", "google-chrome-stable"]:
        try:
            subprocess.run([name, "--version"], capture_output=True, timeout=5, check=True)
            return True
        except Exception:
            continue
    return False


def guns_lol_bot(target_url, proxy_url, browser_id):
    global VIEW_COUNT

    chrome_ok = False
    try:
        import undetected_chromedriver as uc  # noqa: F811
        from selenium.webdriver.chrome.options import Options
        chrome_ok = _chrome_available()
    except ImportError:
        pass

    mode = "selenium" if chrome_ok else "requests"
    print(f"[bot {browser_id}] mode={mode} target={target_url}")

    with BOT_LOCK:
        BOT_STATE["mode"] = mode

    while True:
        driver = None
        try:
            if chrome_ok:
                host = proxy_url.replace("socks5://", "").split(":")[0]
                port = int(proxy_url.replace("socks5://", "").split(":")[1])
                opts = Options()
                opts.add_argument(f"--proxy-server=socks5://{host}:{port}")
                opts.add_argument("--headless=new")
                opts.add_argument("--no-sandbox")
                opts.add_argument("--disable-dev-shm-usage")
                opts.add_argument("--disable-gpu")
                opts.add_argument("--disable-blink-features=AutomationControlled")
                opts.add_argument("--window-size=1920,1080")
                opts.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                opts.add_argument("--incognito")
                opts.add_experimental_option("prefs", {"disk_cache_size": 0})

                driver = uc.Chrome(options=opts)
                driver.set_page_load_timeout(30)
                driver.get(target_url)
                time.sleep(random.uniform(3, 7))
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight / 2);")
                time.sleep(random.uniform(1, 3))

                with VIEW_LOCK:
                    VIEW_COUNT += 1

                driver.delete_all_cookies()
                driver.execute_script("window.localStorage.clear();")
                driver.execute_script("window.sessionStorage.clear();")
                driver.quit()
                driver = None
            else:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                }
                requests.get(target_url, headers=headers, timeout=15)
                time.sleep(random.uniform(3, 7))
                with VIEW_LOCK:
                    VIEW_COUNT += 1
                print(f"[bot {browser_id}] view #{VIEW_COUNT}")

            rotate_proxy(proxy_url)
            time.sleep(random.uniform(2, 5))

        except Exception as e:
            print(f"[bot {browser_id}] error: {e}")
            with BOT_LOCK:
                BOT_STATE["errors"] += 1
            if driver is not None:
                try:
                    driver.quit()
                except Exception:
                    pass
                driver = None
            time.sleep(5)


# ── Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/validate_token", methods=["POST"])
def validate_token():
    """Quick check: does this Discord token work?"""
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
            res = check_discord_username(combo, auth_token, proxy_url, use_proxy)
            checked_count[0] += 1

            if res["available"] is True:
                available_list.append(combo)
                result_queue.put({"type": "found", "username": combo})
            elif res["status"] is not None and res["status"] >= 400:
                # got an HTTP error from Discord
                fatal_error[0] = res["discord_msg"]
                result_queue.put({"type": "fatal", "message": res["discord_msg"], "status": res["status"]})
                stop_event.set()
                return

            if not (use_proxy and TOR_AVAILABLE):
                time.sleep(0.15)
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


@app.route("/start_guns_lol", methods=["POST"])
def start_guns_lol():
    data = request.get_json(silent=True) or {}
    target = (data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "no url provided"}), 400

    num_browsers = int(data.get("browsers", 3))
    num_browsers = max(1, min(num_browsers, 5))

    with BOT_LOCK:
        BOT_STATE["running"] = True
        BOT_STATE["browser_count"] = num_browsers
        BOT_STATE["errors"] = 0

    for i in range(num_browsers):
        proxy = PROXY_POOL[i]
        t = threading.Thread(target=guns_lol_bot, args=(target, proxy, i), daemon=True)
        t.start()

    return jsonify({"status": "started", "browsers": num_browsers})


@app.route("/bot_status")
def bot_status():
    with BOT_LOCK:
        return jsonify(dict(BOT_STATE))


@app.route("/view_count")
def view_count():
    with VIEW_LOCK:
        return jsonify({"views": VIEW_COUNT})


@app.route("/status")
def status():
    return jsonify({
        "tor_available": TOR_AVAILABLE,
        "tor_instances": len(TOR_INSTANCES),
        "views": VIEW_COUNT,
    })


if __name__ == "__main__":
    start_tor_instances()
    app.run(host="0.0.0.0", port=8080, threaded=True)

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


def start_tor_instances():
    """Try to start Tor instances. Sets TOR_AVAILABLE flag on success."""
    global TOR_AVAILABLE
    try:
        subprocess.run(["tor", "--version"], capture_output=True, timeout=5, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print("[tor] tor binary not found — proxies disabled, using direct connections")
        return

    for i in range(5):
        try:
            port = 9050 + i
            control_port = 9050 + i + 10000
            tor_dir = f"/tmp/tor_{i}"
            os.makedirs(tor_dir, exist_ok=True)

            torrc_content = (
                f"SocksPort {port}\n"
                f"ControlPort {control_port}\n"
                f"DataDirectory {tor_dir}\n"
                f"MaxCircuitDirtiness 10\n"
                f"NewCircuitPeriod 15\n"
            )
            torrc_path = f"{tor_dir}/torrc"
            with open(torrc_path, "w") as f:
                f.write(torrc_content)

            proc = subprocess.Popen(
                ["tor", "-f", torrc_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            TOR_INSTANCES.append(proc)
            time.sleep(1.5)
        except Exception as e:
            print(f"[tor] failed to start instance {i}: {e}")

    if len(TOR_INSTANCES) > 0:
        TOR_AVAILABLE = True
        print(f"[tor] started {len(TOR_INSTANCES)} tor instances")
    else:
        print("[tor] no instances started — proxies disabled")


def rotate_proxy(proxy_url):
    """Tell a Tor instance to rotate its circuit for a fresh IP."""
    if not TOR_AVAILABLE:
        return
    try:
        parts = proxy_url.split(":")
        port = int(parts[-1])
        control_port = port + 10000
        s = socket.socket()
        s.settimeout(5)
        s.connect(("127.0.0.1", control_port))
        s.send(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
        s.close()
        time.sleep(1.5)
    except Exception:
        pass


def _make_socks_request(method, url, headers, json_data, proxy_url, timeout):
    """Thread-safe SOCKS5 proxied request. Restores global socket state."""
    proxy_parts = proxy_url.replace("socks5://", "").split(":")
    proxy_host = proxy_parts[0]
    proxy_port = int(proxy_parts[1])

    with SOCKET_LOCK:
        old_socket = socket.socket
        socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
        socket.socket = socks.socksocket

    try:
        resp = requests.request(method, url, headers=headers, json=json_data, timeout=timeout)
    finally:
        with SOCKET_LOCK:
            socket.socket = old_socket
    return resp


def check_discord_username(username, auth_token, proxy_url=None, use_proxy=True):
    """Check if a Discord username is available via the pomelo endpoint."""
    headers = {
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
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
        ),
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

    payload = {"username": username}

    # try proxy first, fall back to direct
    strategies = []
    if use_proxy and proxy_url and TOR_AVAILABLE:
        strategies.append("proxy")
    strategies.append("direct")

    for strategy in strategies:
        try:
            if strategy == "proxy":
                resp = _make_socks_request(
                    "POST",
                    "https://discord.com/api/v9/users/@me/pomelo",
                    headers,
                    payload,
                    proxy_url,
                    10,
                )
            else:
                resp = requests.post(
                    "https://discord.com/api/v9/users/@me/pomelo",
                    headers=headers,
                    json=payload,
                    timeout=10,
                )

            if resp.status_code == 200:
                data = resp.json()
                if data.get("taken") is False:
                    return True
            elif resp.status_code == 401:
                # auth token invalid — don't retry
                return None
            return False
        except Exception as e:
            if strategy == "direct":
                # both failed
                pass
            # else: proxy failed, try direct
    return None


def guns_lol_bot(target_url, proxy_url, browser_id):
    """View bot that uses undetected_chromedriver if available, falls back to requests."""
    global VIEW_COUNT

    # try importing Chrome driver
    try:
        import undetected_chromedriver as uc
        from selenium.webdriver.chrome.options import Options
        HAS_SELENIUM = True
    except ImportError:
        HAS_SELENIUM = False
        print(f"[bot {browser_id}] selenium not available — using requests-only mode")

    while True:
        try:
            if HAS_SELENIUM:
                proxy_parts = proxy_url.replace("socks5://", "").split(":")
                proxy_host = proxy_parts[0]
                proxy_port = int(proxy_parts[1])

                chrome_options = Options()
                chrome_options.add_argument(f"--proxy-server=socks5://{proxy_host}:{proxy_port}")
                chrome_options.add_argument("--headless=new")
                chrome_options.add_argument("--no-sandbox")
                chrome_options.add_argument("--disable-dev-shm-usage")
                chrome_options.add_argument("--disable-gpu")
                chrome_options.add_argument("--disable-blink-features=AutomationControlled")
                chrome_options.add_argument("--window-size=1920,1080")
                chrome_options.add_argument(
                    "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                )
                chrome_options.add_argument("--disable-extensions")
                chrome_options.add_argument("--incognito")

                prefs = {
                    "profile.default_content_setting_values": {
                        "cookies": 2, "images": 2, "plugins": 2, "popups": 2,
                        "geolocation": 2, "notifications": 2, "media_stream": 2,
                    },
                    "disk_cache_size": 0,
                }
                chrome_options.add_experimental_option("prefs", prefs)

                try:
                    driver = uc.Chrome(options=chrome_options, version_main=109)
                except Exception:
                    # try without version pin
                    driver = uc.Chrome(options=chrome_options)

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
            else:
                # requests-only fallback
                headers = {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                }
                requests.get(target_url, headers=headers, timeout=15)
                time.sleep(random.uniform(3, 7))

                with VIEW_LOCK:
                    VIEW_COUNT += 1
                print(f"[bot {browser_id}] view #{VIEW_COUNT} via requests")

            rotate_proxy(proxy_url)
            time.sleep(random.uniform(2, 5))

        except Exception as e:
            print(f"[bot {browser_id}] error: {e}")
            try:
                driver.quit()
            except Exception:
                pass
            time.sleep(5)


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check_usernames", methods=["POST"])
def check_usernames():
    """Check 3-letter or 4-letter Discord usernames — returns live SSE stream."""
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
    random.shuffle(combinations)  # mix it up so we don't hit rate limits in order

    total = len(combinations)
    result_queue = queue.Queue()
    stop_event = threading.Event()
    checked_count = [0]
    available_list = []

    def worker(combo_batch, proxy_url):
        for combo in combo_batch:
            if stop_event.is_set():
                return
            result = check_discord_username(combo, auth_token, proxy_url, use_proxy)
            checked_count[0] += 1
            if result is True:
                available_list.append(combo)
                result_queue.put({"type": "found", "username": combo})
            elif result is None:
                # fatal error (e.g. bad auth, rate limited)
                result_queue.put({"type": "error", "message": f"Auth rejected or rate-limited at {combo}"})
                stop_event.set()
                return
            # small delay between checks to avoid rate limits when direct
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
                elif msg["type"] == "error":
                    yield f"data: {json.dumps({'event': 'error', 'message': msg['message'], 'checked': checked_count[0], 'total': total})}\n\n"
                    done_workers = num_workers  # abort on fatal error
                elif msg["type"] == "done":
                    done_workers += 1
            except queue.Empty:
                # send progress heartbeat
                yield f"data: {json.dumps({'event': 'progress', 'checked': checked_count[0], 'total': total})}\n\n"

        yield f"data: {json.dumps({'event': 'complete', 'available': available_list, 'checked': checked_count[0], 'total': total})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/start_guns_lol", methods=["POST"])
def start_guns_lol():
    data = request.get_json(silent=True) or {}
    target = (data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "no url provided"}), 400

    num_browsers = int(data.get("browsers", 3))
    num_browsers = max(1, min(num_browsers, 5))

    for i in range(num_browsers):
        proxy = PROXY_POOL[i]
        t = threading.Thread(target=guns_lol_bot, args=(target, proxy, i), daemon=True)
        t.start()

    return jsonify({"status": "started", "browsers": num_browsers})


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

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
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# proxy pool - add your own residential proxies here
PROXY_POOL = [
    "socks5://127.0.0.1:9050",
    "socks5://127.0.0.1:9051",
    "socks5://127.0.0.1:9052",
    "socks5://127.0.0.1:9053",
    "socks5://127.0.0.1:9054",
]

TOR_INSTANCES = []
AVAILABLE_USERNAMES = []
VIEW_COUNT = 0
VIEW_LOCK = threading.Lock()

def start_tor_instances():
    for i in range(5):
        port = 9050 + i
        control_port = 9050 + i + 10000
        tor_dir = f"/tmp/tor_{i}"
        os.makedirs(tor_dir, exist_ok=True)
        
        torrc_content = f"""
SocksPort {port}
ControlPort {control_port}
DataDirectory {tor_dir}
MaxCircuitDirtiness 10
NewCircuitPeriod 15
"""
        torrc_path = f"{tor_dir}/torrc"
        with open(torrc_path, "w") as f:
            f.write(torrc_content)
        
        proc = subprocess.Popen(
            ["tor", "-f", torrc_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        TOR_INSTANCES.append(proc)
        time.sleep(2)
    
    print(f"started {len(TOR_INSTANCES)} tor instances")

def rotate_proxy(proxy_url):
    parts = proxy_url.split(":")
    port = int(parts[-1])
    control_port = port + 10000
    try:
        s = socket.socket()
        s.connect(("127.0.0.1", control_port))
        s.send(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
        s.close()
        time.sleep(2)
    except:
        pass

def check_discord_username(username, proxy_url):
    headers = {
        "authority": "discord.com",
        "method": "POST",
        "path": "/api/v9/users/@me/pomelo",
        "scheme": "https",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.9",
        "authorization": request.headers.get("authorization", ""),
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
        "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwOS4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTA5LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiJodHRwczovL3d3dy5nb29nbGUuY29tLyIsInJlZmVycmluZ19kb21haW4iOiJ3d3cuZ29vZ2xlLmNvbSIsInNlYXJjaF9lbmdpbmUiOiJnb29nbGUiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTc1OTE3LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
    }
    
    payload = {"username": username}
    
    try:
        proxy_parts = proxy_url.replace("socks5://", "").split(":")
        proxy_host = proxy_parts[0]
        proxy_port = int(proxy_parts[1])
        
        old_socket = socket.socket
        socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
        socket.socket = socks.socksocket
        
        resp = requests.post(
            "https://discord.com/api/v9/users/@me/pomelo",
            headers=headers,
            json=payload,
            timeout=10
        )
        
        socket.socket = old_socket
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get("taken") is False:
                return True
        return False
    except Exception as e:
        print(f"error checking {username}: {e}")
        return None

def guns_lol_bot(target_url, proxy_url, browser_id):
    global VIEW_COUNT
    
    import undetected_chromedriver as uc
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    
    while True:
        try:
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
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-plugins")
            chrome_options.add_argument("--incognito")
            
            prefs = {
                "profile.default_content_setting_values": {
                    "cookies": 2,
                    "images": 2,
                    "plugins": 2,
                    "popups": 2,
                    "geolocation": 2,
                    "notifications": 2,
                    "auto_select_certificate": 2,
                    "fullscreen": 2,
                    "mouselock": 2,
                    "mixed_script": 2,
                    "media_stream": 2,
                    "media_stream_mic": 2,
                    "media_stream_camera": 2,
                    "protocol_handlers": 2,
                    "ppapi_broker": 2,
                    "automatic_downloads": 2,
                    "midi_sysex": 2,
                    "push_messaging": 2,
                    "ssl_cert_decisions": 2,
                    "metro_switch_to_desktop": 2,
                    "protected_media_identifier": 2,
                    "app_banner": 2,
                    "site_engagement": 2,
                    "durable_storage": 2
                },
                "profile.managed_default_content_settings": {"images": 2},
                "disk_cache_size": 0,
                "clear_data": {
                    "on_exit": {
                        "history": True,
                        "cookies": True,
                        "cache": True,
                        "formData": True,
                        "downloads": True,
                        "passwords": True,
                        "serverBoundCertificates": True
                    }
                }
            }
            chrome_options.add_experimental_option("prefs", prefs)
            
            driver = uc.Chrome(options=chrome_options, version_main=109)
            driver.set_page_load_timeout(30)
            
            driver.get(target_url)
            time.sleep(random.uniform(3, 7))
            
            # scroll to simulate real user
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight / 2);")
            time.sleep(random.uniform(1, 3))
            
            with VIEW_LOCK:
                VIEW_COUNT += 1
            
            # clear everything
            driver.execute_cdp_cmd("Network.clearBrowserCache", {})
            driver.execute_cdp_cmd("Network.clearBrowserCookies", {})
            driver.execute_cdp_cmd("Storage.clearDataForOrigin", {
                "origin": target_url,
                "storageTypes": "all"
            })
            
            driver.delete_all_cookies()
            driver.execute_script("window.localStorage.clear();")
            driver.execute_script("window.sessionStorage.clear();")
            
            driver.quit()
            
            # rotate tor circuit for new ip
            rotate_proxy(proxy_url)
            
            time.sleep(random.uniform(2, 5))
            
        except Exception as e:
            print(f"browser {browser_id} error: {e}")
            try:
                driver.quit()
            except:
                pass
            time.sleep(5)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check_3letters")
def check_3letters():
    letters = string.ascii_lowercase
    combinations = [''.join(p) for p in itertools.product(letters, repeat=3)]
    results = []
    
    def worker(combo_batch, proxy):
        for combo in combo_batch:
            result = check_discord_username(combo, proxy)
            if result is True:
                AVAILABLE_USERNAMES.append(combo)
                results.append({"username": combo, "available": True})
            rotate_proxy(proxy)
    
    threads = []
    batch_size = len(combinations) // 5
    for i in range(5):
        batch = combinations[i * batch_size:(i + 1) * batch_size]
        t = threading.Thread(target=worker, args=(batch, PROXY_POOL[i]))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    return jsonify({"available": AVAILABLE_USERNAMES, "checked": len(combinations)})

@app.route("/check_4letters")
def check_4letters():
    letters = string.ascii_lowercase
    combinations = [''.join(p) for p in itertools.product(letters, repeat=4)]
    results = []
    
    def worker(combo_batch, proxy):
        for combo in combo_batch:
            result = check_discord_username(combo, proxy)
            if result is True:
                AVAILABLE_USERNAMES.append(combo)
                results.append({"username": combo, "available": True})
            rotate_proxy(proxy)
    
    threads = []
    batch_size = len(combinations) // 5
    for i in range(5):
        batch = combinations[i * batch_size:(i + 1) * batch_size]
        t = threading.Thread(target=worker, args=(batch, PROXY_POOL[i]))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    return jsonify({"available": AVAILABLE_USERNAMES, "checked": len(combinations)})

@app.route("/start_guns_lol", methods=["POST"])
def start_guns_lol():
    target = request.json.get("url")
    if not target:
        return jsonify({"error": "no url provided"}), 400
    
    for i in range(3):
        proxy = PROXY_POOL[i]
        t = threading.Thread(target=guns_lol_bot, args=(target, proxy, i))
        t.daemon = True
        t.start()
    
    return jsonify({"status": "started", "browsers": 3})

@app.route("/view_count")
def view_count():
    with VIEW_LOCK:
        return jsonify({"views": VIEW_COUNT})

if __name__ == "__main__":
    start_tor_instances()
    app.run(host="0.0.0.0", port=8080, threaded=True)

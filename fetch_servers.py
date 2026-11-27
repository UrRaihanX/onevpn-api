import re
import csv
import json
import time
import socket
import base64
import requests
from io import StringIO
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

HEALTH_CHECK_TIMEOUT = 2
MAX_WORKERS = 30

GITHUB_REPOS = [
    "https://api.github.com/repos/Zoult/.ovpn/contents/",
]

SIMPLE_SCRAPE_SITES = [
    {"name": "IPSpeed", "url": "https://ipspeed.info/freevpn_openvpn.php"},
    {"name": "OpenProxyList", "url": "https://openproxylist.com/openvpn/"},
]

BROWSER_SCRAPE_SITES = [
    {"name": "HuntVPN", "url": "https://huntvpn.dev/servers"},
    {"name": "PublicVPNList", "url": "https://publicvpnlist.com/openvpn-configs/"},
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}


def country_code_to_emoji(cc: str) -> str:
    """US -> 🇺🇸 এভাবে কান্ট্রি কোডকে পতাকার ইমোজি বানায়"""
    if not cc or len(cc) != 2 or cc.upper() == "XX":
        return "🌐"
    return "".join(chr(127397 + ord(c)) for c in cc.upper())


def country_code_to_flag_url(cc: str) -> str:
    """অ্যান্ড্রয়েড অ্যাপের জন্য পতাকার PNG ছবির লিংক"""
    if not cc or len(cc) != 2 or cc.upper() == "XX":
        return ""
    return f"https://flagcdn.com/w80/{cc.lower()}.png"


def extract_ip_port(ovpn_text: str):
    match = re.search(
        r"^remote\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+(\d+)",
        ovpn_text,
        re.MULTILINE,
    )
    if match:
        return match.group(1), int(match.group(2))
    return None, None


def check_tcp_health(ip: str, port: int):
    start_time = time.time()
    try:
        with socket.create_connection((ip, port), timeout=HEALTH_CHECK_TIMEOUT):
            ping_ms = int((time.time() - start_time) * 1000)
            return True, ping_ms
    except Exception:
        return False, None


def enrich_with_geoip(servers: list):
    """একবারে ১০০টি করে IP-র আসল দেশ, কোড, পতাকা ও ISP বের করে"""
    batch_size = 100
    for i in range(0, len(servers), batch_size):
        batch = servers[i:i + batch_size]
        payload = [{"query": s["ip"], "fields": "status,country,countryCode,isp"} for s in batch]
        try:
            res = requests.post("http://ip-api.com/batch", json=payload, timeout=15)
            if res.status_code == 200:
                geo_results = res.json()
                for server, geo in zip(batch, geo_results):
                    if geo.get("status") == "success":
                        cc = geo.get("countryCode", server["country_code"])
                        server["country"] = geo.get("country", server["country"])
                        server["country_code"] = cc
                        server["isp"] = geo.get("isp", "Unknown")
                        server["flag_emoji"] = country_code_to_emoji(cc)
                        server["flag_url"] = country_code_to_flag_url(cc)
        except Exception as e:
            print(f"GeoIP Batch Error: {e}")

        # ফ্রি API-র লিমিট ঠিক রাখতে সামান্য বিরতি
        if i + batch_size < len(servers):
            time.sleep(1.5)


def fetch_vpngate():
    candidates = []
    try:
        res = requests.get("https://www.vpngate.net/api/iphone/", headers=HEADERS, timeout=20)
        lines = res.text.splitlines()
        if len(lines) < 3:
            return candidates
        csv_data = "\n".join(lines[2:])
        reader = csv.reader(StringIO(csv_data))
        for row in reader:
            if len(row) < 15 or not row[14]:
                continue
            try:
                ovpn_text = base64.b64decode(row[14]).decode("utf-8", errors="ignore")
                candidates.append({
                    "ovpn_text": ovpn_text,
                    "country": row[5] or "Unknown",
                    "country_code": row[6] or "XX",
                    "source": "VPNGate",
                })
            except Exception:
                continue
    except Exception as e:
        print(f"VPNGate Error: {e}")
    return candidates


def fetch_github():
    candidates = []
    for api_url in GITHUB_REPOS:
        try:
            res = requests.get(api_url, headers=HEADERS, timeout=15)
            if res.status_code != 200:
                continue
            for f in res.json()[:30]:
                if f.get("name", "").endswith(".ovpn") and f.get("download_url"):
                    ovpn_res = requests.get(f["download_url"], headers=HEADERS, timeout=10)
                    if ovpn_res.status_code == 200:
                        candidates.append({
                            "ovpn_text": ovpn_res.text,
                            "country": "Unknown",
                            "country_code": "XX",
                            "source": "GitHub",
                        })
        except Exception as e:
            print(f"GitHub Error: {e}")
    return candidates


def fetch_simple_sites():
    candidates = []
    for site in SIMPLE_SCRAPE_SITES:
        try:
            res = requests.get(site["url"], headers=HEADERS, timeout=15)
            soup = BeautifulSoup(res.text, "html.parser")
            ovpn_urls = list({
                urljoin(site["url"], a["href"])
                for a in soup.find_all("a", href=True)
                if ".ovpn" in a["href"].lower()
            })[:20]

            for url in ovpn_urls:
                try:
                    file_res = requests.get(url, headers=HEADERS, timeout=10)
                    if "remote " in file_res.text:
                        candidates.append({
                            "ovpn_text": file_res.text,
                            "country": "Unknown",
                            "country_code": "XX",
                            "source": site["name"],
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"{site['name']} Error: {e}")
    return candidates


def fetch_with_playwright():
    candidates = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(user_agent=HEADERS["User-Agent"])
            page = context.new_page()

            for site in BROWSER_SCRAPE_SITES:
                try:
                    print(f"Opening {site['name']} in browser...")
                    page.goto(site["url"], wait_until="networkidle", timeout=30000)
                    page.wait_for_timeout(3000)

                    links = page.eval_on_selector_all(
                        "a[href]",
                        "elements => elements.map(el => el.href)"
                    )
                    ovpn_urls = list({
                        url for url in links
                        if ".ovpn" in url.lower() or "download" in url.lower()
                    })[:20]

                    for url in ovpn_urls:
                        try:
                            response = context.request.get(url, timeout=10000)
                            text = response.text()
                            if "remote " in text and "dev " in text:
                                candidates.append({
                                    "ovpn_text": text,
                                    "country": "Unknown",
                                    "country_code": "XX",
                                    "source": site["name"],
                                })
                        except Exception:
                            continue
                except Exception as e:
                    print(f"Playwright Error ({site['name']}): {e}")

            browser.close()
    except Exception as e:
        print(f"Browser Launch Error: {e}")
    return candidates


def process_server(item):
    alive, ping_ms = check_tcp_health(item["ip"], item["port"])
    if not alive:
        return None
    cc = item["country_code"]
    return {
        "ip": item["ip"],
        "port": item["port"],
        "country": item["country"],
        "country_code": cc,
        "flag_emoji": country_code_to_emoji(cc),
        "flag_url": country_code_to_flag_url(cc),
        "isp": "Unknown",
        "ping_ms": ping_ms,
        "source": item["source"],
        "ovpn_base64": base64.b64encode(item["ovpn_text"].encode("utf-8")).decode("utf-8"),
    }


def main():
    raw_candidates = []
    raw_candidates.extend(fetch_vpngate())
    raw_candidates.extend(fetch_github())
    raw_candidates.extend(fetch_simple_sites())
    raw_candidates.extend(fetch_with_playwright())

    # ডুপ্লিকেট IP বাদ দেওয়া
    unique_map = {}
    for item in raw_candidates:
        ip, port = extract_ip_port(item["ovpn_text"])
        if ip and ip not in unique_map:
            item["ip"] = ip
            item["port"] = port
            unique_map[ip] = item

    # সচল সার্ভার চেক করা
    healthy_servers = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for res in executor.map(process_server, unique_map.values()):
            if res:
                healthy_servers.append(res)

    # সব সচল সার্ভারের আসল দেশ, পতাকা ও ISP বের করা
    print(f"Running GeoIP lookup for {len(healthy_servers)} live servers...")
    enrich_with_geoip(healthy_servers)

    healthy_servers.sort(key=lambda x: x["ping_ms"])

    output = {
        "app": "OneVPN",
        "last_updated_unix": int(time.time()),
        "total_servers": len(healthy_servers),
        "servers": healthy_servers,
    }

    with open("servers.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Done! Saved {len(healthy_servers)} live unique servers with GeoIP.")


if __name__ == "__main__":
    main()

import os
import re
import csv
import json
import time
import shutil
import socket
import base64
import threading
import requests
from io import StringIO
from collections import Counter
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

HEALTH_CHECK_TIMEOUT = float(os.environ.get("HEALTH_CHECK_TIMEOUT", "2.0"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "30"))
MIN_SERVERS_THRESHOLD = int(os.environ.get("MIN_SERVERS_THRESHOLD", "5"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "dist")
DATA_BRANCH = os.environ.get("DATA_BRANCH", "data")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "UrRaihanX/onevpn-api")
CDN_BASE_URL = f"https://cdn.jsdelivr.net/gh/{GITHUB_REPOSITORY}@{DATA_BRANCH}"

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
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

INVALID_COUNTRY_CODES = {"", "XX", "UN", "ZZ", "UNKNOWN"}
IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
REMOTE_RE = re.compile(
    r"^\s*remote\s+([^\s#;]+)\s+(\d+)(?:\s+(tcp|udp)\S*)?",
    re.IGNORECASE | re.MULTILINE,
)
PROTO_RE = re.compile(r"^\s*proto\s+(tcp|udp)\S*", re.IGNORECASE | re.MULTILINE)
TLS_KEY_RE = re.compile(
    r"^\s*(?:tls-auth|tls-crypt|<tls-auth>|<tls-crypt>)",
    re.IGNORECASE | re.MULTILINE,
)

_dns_cache = {}
_dns_lock = threading.Lock()


def normalize_country_code(cc: str) -> str:
    """অবৈধ বা UN কান্ট্রি কোডকে নিরাপদভাবে XX হিসেবে নরমালাইজ করে।"""
    if not cc or not isinstance(cc, str):
        return "XX"
    cleaned = cc.strip().upper()
    if len(cleaned) != 2 or not cleaned.isalpha() or cleaned in INVALID_COUNTRY_CODES:
        return "XX"
    return cleaned


def country_code_to_emoji(cc: str) -> str:
    """US -> 🇺🇸 ফ্ল্যাগ ইমোজি তৈরি করে।"""
    cleaned = normalize_country_code(cc)
    if cleaned == "XX":
        return "🌐"
    return "".join(chr(127397 + ord(c)) for c in cleaned)


def country_code_to_flag_url(cc: str) -> str:
    """কান্ট্রি কোড থেকে FlagCDN PNG লিংক তৈরি করে।"""
    cleaned = normalize_country_code(cc)
    if cleaned == "XX":
        return ""
    return f"https://flagcdn.com/w80/{cleaned.lower()}.png"


def make_server_id(ip: str, port: int, proto: str) -> str:
    """প্রতিটি সার্ভারের জন্য ইউনিক ও ফাইল-নিরাপদ ID তৈরি করে।"""
    return f"{ip.replace('.', '_')}_{port}_{proto}"


def is_valid_ipv4(host: str) -> bool:
    match = IPV4_RE.match(host)
    if not match:
        return False
    return all(0 <= int(part) <= 255 for part in match.groups())


def resolve_host(host: str):
    """IPv4 হলে সরাসরি রিটার্ন করে, আর ডোমেইন নেম হলে DNS রিজলভ করে IPv4 বের করে।"""
    if is_valid_ipv4(host):
        return host
    with _dns_lock:
        if host in _dns_cache:
            return _dns_cache[host]
    try:
        resolved_ip = socket.gethostbyname(host)
        if not is_valid_ipv4(resolved_ip):
            resolved_ip = None
    except Exception:
        resolved_ip = None
    with _dns_lock:
        _dns_cache[host] = resolved_ip
    return resolved_ip


def extract_server_endpoint(ovpn_text: str):
    """OVPN কনফিগ থেকে IP/Hostname, পোর্ট, প্রোটোকল (tcp/udp) এবং TLS-key ফ্ল্যাগ বের করে।"""
    match = REMOTE_RE.search(ovpn_text)
    if not match:
        return None, None, None, False

    raw_host = match.group(1).strip()
    try:
        port = int(match.group(2))
    except ValueError:
        return None, None, None, False

    if not (1 <= port <= 65535):
        return None, None, None, False

    ip = resolve_host(raw_host)
    if not ip:
        return None, None, None, False

    proto = match.group(3).lower() if match.group(3) else None
    if not proto:
        proto_match = PROTO_RE.search(ovpn_text)
        proto = proto_match.group(1).lower() if proto_match else "udp"

    has_tls_key = bool(TLS_KEY_RE.search(ovpn_text))
    return ip, port, proto, has_tls_key


def check_tcp_health(ip: str, port: int):
    start_time = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=HEALTH_CHECK_TIMEOUT):
            ping_ms = max(1, int((time.monotonic() - start_time) * 1000))
            return True, ping_ms
    except Exception:
        return False, None


def check_udp_health(ip: str, port: int, has_tls_key: bool = False):
    """OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 প্যাকেট পাঠিয়ে UDP সার্ভারের হেলথ চেক করে।"""
    probe_packet = b"\x38" + os.urandom(8) + b"\x00\x00\x00\x00\x00"
    start_time = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(HEALTH_CHECK_TIMEOUT)
    try:
        sock.connect((ip, port))
        sock.send(probe_packet)
        data = sock.recv(1024)
        if data:
            ping_ms = max(1, int((time.monotonic() - start_time) * 1000))
            return True, ping_ms
    except ConnectionRefusedError:
        return False, None
    except socket.timeout:
        if has_tls_key:
            return check_tcp_health(ip, port)
        return False, None
    except Exception:
        return False, None
    finally:
        sock.close()
    return False, None


def check_server_health(ip: str, port: int, proto: str, has_tls_key: bool = False):
    if proto == "tcp":
        return check_tcp_health(ip, port)
    return check_udp_health(ip, port, has_tls_key=has_tls_key)


def enrich_with_geoip(servers: list):
    """সক্রিয় সার্ভারগুলোর IP থেকে ব্যাচ GeoIP লুকআপ করে দেশ, ফ্ল্যাগ ও ISP আপডেট করে।"""
    batch_size = 100
    for i in range(0, len(servers), batch_size):
        batch = servers[i:i + batch_size]
        payload = [{"query": s["ip"], "fields": "status,country,countryCode,isp"} for s in batch]
        try:
            res = requests.post("http://ip-api.com/batch", json=payload, timeout=15)
            if res.status_code == 429:
                wait_sec = int(res.headers.get("X-Ttl", "5")) + 1
                print(f"GeoIP rate limited; waiting {wait_sec}s before retry...")
                time.sleep(min(wait_sec, 65))
                res = requests.post("http://ip-api.com/batch", json=payload, timeout=15)

            if res.status_code == 200:
                geo_results = res.json()
                for server, geo in zip(batch, geo_results):
                    if geo.get("status") == "success":
                        cc = normalize_country_code(geo.get("countryCode", server["country_code"]))
                        server["country"] = geo.get("country") or server["country"]
                        server["country_code"] = cc
                        server["isp"] = geo.get("isp") or "Unknown"
                        server["flag_emoji"] = country_code_to_emoji(cc)
                        server["flag_url"] = country_code_to_flag_url(cc)
        except Exception as e:
            print(f"GeoIP Batch Error: {e}")

        if i + batch_size < len(servers):
            time.sleep(1.5)


def fetch_vpngate():
    candidates = []
    try:
        res = requests.get("https://www.vpngate.net/api/iphone/", headers=HEADERS, timeout=20)
        res.raise_for_status()
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
                    "country_code": normalize_country_code(row[6]),
                    "source": "VPNGate",
                })
            except Exception:
                continue
    except Exception as e:
        print(f"VPNGate Error: {e}")
    return candidates


def fetch_github():
    candidates = []
    github_headers = {
        **HEADERS,
        "Accept": "application/vnd.github+json",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        github_headers["Authorization"] = f"Bearer {token}"

    for api_url in GITHUB_REPOS:
        try:
            res = requests.get(api_url, headers=github_headers, timeout=15)
            if res.status_code in (403, 429):
                print(f"GitHub API rate limit hit ({res.status_code}) for {api_url}")
                continue
            if res.status_code != 200:
                print(f"GitHub API returned {res.status_code} for {api_url}")
                continue
            for f in res.json()[:30]:
                if f.get("name", "").endswith(".ovpn") and f.get("download_url"):
                    try:
                        ovpn_res = requests.get(f["download_url"], headers=HEADERS, timeout=10)
                        if ovpn_res.status_code == 200:
                            candidates.append({
                                "ovpn_text": ovpn_res.text,
                                "country": "Unknown",
                                "country_code": "XX",
                                "source": "GitHub",
                            })
                    except Exception:
                        continue
        except Exception as e:
            print(f"GitHub Error: {e}")
    return candidates


def fetch_simple_sites():
    candidates = []
    for site in SIMPLE_SCRAPE_SITES:
        try:
            res = requests.get(site["url"], headers=HEADERS, timeout=15)
            res.raise_for_status()
            soup = BeautifulSoup(res.text, "html.parser")
            ovpn_urls = list({
                urljoin(site["url"], a["href"])
                for a in soup.find_all("a", href=True)
                if ".ovpn" in a["href"].lower()
            })[:20]

            for url in ovpn_urls:
                try:
                    file_res = requests.get(url, headers=HEADERS, timeout=10)
                    if file_res.status_code == 200 and "remote " in file_res.text:
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
                        "elements => elements.map(el => el.href)",
                    )
                    ovpn_urls = list({
                        url for url in links
                        if ".ovpn" in url.lower() or "download" in url.lower()
                    })[:20]

                    for url in ovpn_urls:
                        try:
                            response = context.request.get(url, timeout=10000)
                            if response.ok:
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
    alive, ping_ms = check_server_health(
        item["ip"],
        item["port"],
        item["protocol"],
        has_tls_key=item.get("has_tls_key", False),
    )
    if not alive or ping_ms is None:
        return None
    cc = normalize_country_code(item["country_code"])
    server_id = make_server_id(item["ip"], item["port"], item["protocol"])
    config_path = f"configs/{server_id}.ovpn"
    return {
        "id": server_id,
        "ip": item["ip"],
        "port": item["port"],
        "protocol": item["protocol"],
        "country": item["country"],
        "country_code": cc,
        "flag_emoji": country_code_to_emoji(cc),
        "flag_url": country_code_to_flag_url(cc),
        "isp": "Unknown",
        "ping_ms": ping_ms,
        "source": item["source"],
        "config_path": config_path,
        "config_url": f"{CDN_BASE_URL}/{config_path}",
        "_ovpn_text": item["ovpn_text"],
    }


def write_output_bundle(healthy_servers: list, output_dir: str) -> None:
    """লাইটওয়েট servers_meta.json, আলাদা configs/*.ovpn এবং ব্যাকওয়ার্ড-কম্প্যাটিবল servers.json তৈরি করে।"""
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    configs_dir = os.path.join(output_dir, "configs")
    os.makedirs(configs_dir, exist_ok=True)

    now_unix = int(time.time())
    meta_servers = []
    full_servers = []

    for server in healthy_servers:
        ovpn_text = server.pop("_ovpn_text")
        ovpn_file = os.path.join(output_dir, server["config_path"])
        with open(ovpn_file, "w", encoding="utf-8") as f:
            f.write(ovpn_text)

        meta_servers.append(server)
        full_servers.append({
            **server,
            "ovpn_base64": base64.b64encode(ovpn_text.encode("utf-8")).decode("utf-8"),
        })

    meta_payload = {
        "app": "OneVPN",
        "last_updated_unix": now_unix,
        "total_servers": len(meta_servers),
        "cdn_base_url": CDN_BASE_URL,
        "servers": meta_servers,
    }
    full_payload = {
        "app": "OneVPN",
        "last_updated_unix": now_unix,
        "total_servers": len(full_servers),
        "cdn_base_url": CDN_BASE_URL,
        "servers": full_servers,
    }

    with open(os.path.join(output_dir, "servers_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta_payload, f, separators=(",", ":"), ensure_ascii=False)

    with open(os.path.join(output_dir, "servers.json"), "w", encoding="utf-8") as f:
        json.dump(full_payload, f, separators=(",", ":"), ensure_ascii=False)


def main():
    raw_candidates = []
    raw_candidates.extend(fetch_vpngate())
    raw_candidates.extend(fetch_github())
    raw_candidates.extend(fetch_simple_sites())
    raw_candidates.extend(fetch_with_playwright())

    raw_counts = Counter(item["source"] for item in raw_candidates)
    print(f"Fetched raw candidates by source: {dict(raw_counts)}")

    unique_map = {}
    for item in raw_candidates:
        ip, port, proto, has_tls_key = extract_server_endpoint(item["ovpn_text"])
        key = (ip, port, proto)
        if ip and key not in unique_map:
            item["ip"] = ip
            item["port"] = port
            item["protocol"] = proto
            item["has_tls_key"] = has_tls_key
            unique_map[key] = item

    print(f"Checking health for {len(unique_map)} unique endpoints (TCP + UDP)...")
    healthy_servers = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for res in executor.map(process_server, unique_map.values()):
            if res:
                healthy_servers.append(res)

    live_counts = Counter(s["source"] for s in healthy_servers)
    print(f"Live servers by source: {dict(live_counts)}")

    if len(healthy_servers) < MIN_SERVERS_THRESHOLD:
        print(
            f"Safety guard triggered: only {len(healthy_servers)} live servers found "
            f"(minimum required: {MIN_SERVERS_THRESHOLD}). Skipping output generation."
        )
        return

    print(f"Running GeoIP lookup for {len(healthy_servers)} live servers...")
    enrich_with_geoip(healthy_servers)

    healthy_servers.sort(key=lambda x: x["ping_ms"])
    write_output_bundle(healthy_servers, OUTPUT_DIR)

    meta_kb = os.path.getsize(os.path.join(OUTPUT_DIR, "servers_meta.json")) / 1024
    full_kb = os.path.getsize(os.path.join(OUTPUT_DIR, "servers.json")) / 1024
    print(
        f"Done! Saved {len(healthy_servers)} servers -> "
        f"servers_meta.json ({meta_kb:.1f} KB), servers.json ({full_kb:.1f} KB), "
        f"and {len(healthy_servers)} individual .ovpn files in {OUTPUT_DIR}/configs/."
    )


if __name__ == "__main__":
    main()

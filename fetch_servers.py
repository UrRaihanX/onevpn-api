import os
import re
import csv
import json
import time
import shutil
import socket
import base64
import threading
import subprocess
import tempfile
import ipaddress
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
    {"name": "OpenProxyList", "url": "https://openproxylist.com/openvpn/"},
]

# IPSpeed permits one profile download every 10 seconds. Use a browser session
# and enforce that limit. HuntVPN and PublicVPNList require approved access
# before automated collection or permanent republication.
BROWSER_SCRAPE_SITES = [
    {"name": "IPSpeed", "url": "https://ipspeed.info/free-openvpn.php"},
]

POLICY_RESTRICTED_SOURCES = {
    "HuntVPN": "automated scraping and mirroring are prohibited by the site's terms",
    "PublicVPNList": "API access requires an issued key and permanent automated mirroring is prohibited",
}

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
    """Require an OpenVPN TCP control-channel response, not merely an open TCP port."""
    start_time = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=HEALTH_CHECK_TIMEOUT) as sock:
            sock.settimeout(HEALTH_CHECK_TIMEOUT)
            # TCP transport frames each OpenVPN packet with a 2-byte network-order length.
            session_id = os.urandom(8)
            packet = b"\x38" + session_id + b"\x00\x00\x00\x01\x00"
            sock.sendall(len(packet).to_bytes(2, "big") + packet)

            header = b""
            while len(header) < 2:
                chunk = sock.recv(2 - len(header))
                if not chunk:
                    return False, None
                header += chunk

            response_length = int.from_bytes(header, "big")
            if response_length < 1 or response_length > 4096:
                return False, None

            response = b""
            while len(response) < response_length:
                chunk = sock.recv(response_length - len(response))
                if not chunk:
                    return False, None
                response += chunk

            # Server hard-reset or control packet: evidence of an OpenVPN listener.
            opcode = (response[0] >> 3) & 0x1F
            if opcode not in (4, 8):
                return False, None

            ping_ms = max(1, int((time.monotonic() - start_time) * 1000))
            return True, ping_ms
    except Exception:
        return False, None



def check_udp_health(ip: str, port: int, has_tls_key: bool = False):
    """OpenVPN UDP control-channel probe; retry before declaring the endpoint unreachable."""
    start_time = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(min(HEALTH_CHECK_TIMEOUT, 1.5))
    try:
        sock.connect((ip, port))
        # OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2:
        # opcode/key-id, 8-byte session-id, 4-byte packet-id, ack-count.
        session_id = os.urandom(8)
        for packet_id in range(1, 4):
            probe_packet = b"\x38" + session_id + packet_id.to_bytes(4, "big") + b"\x00"
            try:
                sock.send(probe_packet)
                data = sock.recv(2048)
                if data and ((data[0] >> 3) & 0x1F) in (4, 8):
                    ping_ms = max(1, int((time.monotonic() - start_time) * 1000))
                    return True, ping_ms
            except socket.timeout:
                if packet_id < 3:
                    continue
                return False, None
            except ConnectionRefusedError:
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
    """Fetch direct .ovpn links from static source pages with bounded retries."""
    candidates = []
    session = requests.Session()
    session.headers.update(HEADERS)

    for site in SIMPLE_SCRAPE_SITES:
        for attempt in range(3):
            try:
                res = session.get(site["url"], timeout=20)
                if res.status_code in (403, 429, 500, 502, 503, 504):
                    print(f"{site['name']} source temporarily unavailable (HTTP {res.status_code}), attempt {attempt + 1}/3")
                    if attempt < 2:
                        time.sleep(1.5 * (attempt + 1))
                        continue
                    break
                res.raise_for_status()
                soup = BeautifulSoup(res.text, "html.parser")
                links = set()

                for a in soup.find_all("a", href=True):
                    href = urljoin(res.url, a["href"].strip())
                    label = a.get_text(" ", strip=True).lower()
                    if (
                        ".ovpn" in href.lower()
                        or ".ovpn" in label
                        or any(word in label for word in ("download", "config", "openvpn"))
                        or any(word in href.lower() for word in ("download", "config", "profile"))
                    ):
                        links.add(href)

                for element in soup.select("[data-href], [data-url], [data-download-url], [data-download]"):
                    for attr in ("data-href", "data-url", "data-download-url", "data-download"):
                        value = element.get(attr)
                        if value:
                            links.add(urljoin(res.url, value.strip()))

                for url in list(links)[:40]:
                    try:
                        file_res = session.get(url, timeout=15)
                        if not file_res.ok:
                            continue
                        body = file_res.text.lstrip("\ufeff")
                        if "remote " in body.lower() and ("dev tun" in body.lower() or "dev tap" in body.lower()):
                            candidates.append({
                                "ovpn_text": body,
                                "country": "Unknown",
                                "country_code": "XX",
                                "source": site["name"],
                            })
                    except Exception as e:
                        print(f"{site['name']} download error: {e}")
                print(f"{site['name']}: collected {sum(1 for c in candidates if c['source'] == site['name'])} configs")
                break
            except Exception as e:
                print(f"{site['name']} Error (attempt {attempt + 1}/3): {e}")
                if attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
    return candidates


def fetch_with_playwright():
    """Collect IPSpeed profiles through a browser while respecting its download limit."""
    candidates = []
    for source_name, reason in POLICY_RESTRICTED_SOURCES.items():
        print(f"{source_name}: skipped; {reason}. Request approved bulk access before enabling.")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=HEADERS["User-Agent"],
                accept_downloads=True,
            )

            for site in BROWSER_SCRAPE_SITES:
                page = context.new_page()
                try:
                    print(f"Opening {site['name']} in browser...")
                    response = page.goto(site["url"], wait_until="domcontentloaded", timeout=45000)
                    if response and response.status >= 400:
                        print(f"{site['name']} page returned HTTP {response.status}")
                        continue
                    page.wait_for_timeout(2500)

                    extracted = page.evaluate("""() => {
                      const out = [];
                      for (const el of document.querySelectorAll('a[href],button,[data-url],[data-href],[data-download-url]')) {
                        const attrs = ['href','data-url','data-href','data-download-url','data-download','onclick'];
                        const values = attrs.map(k => el.getAttribute(k)).filter(Boolean);
                        out.push({text: (el.innerText || el.textContent || '').trim(), values});
                      }
                      for (const script of document.scripts) {
                        if (script.textContent) out.push({text:'script', values:[script.textContent]});
                      }
                      return out;
                    }""")

                    urls = set()
                    for item in extracted:
                        label = (item.get("text") or "").lower()
                        for value in item.get("values", []):
                            for match in re.findall(r"""(?:https?://[^\s"'<>\\]+|/(?:[^\s"'<>\\]*?(?:download|config|profile|\.ovpn)[^\s"'<>\\]*))""", value, re.I):
                                clean = match.rstrip("),;]")
                                if clean.startswith("/"):
                                    clean = urljoin(site["url"], clean)
                                if clean.startswith(("http://", "https://")):
                                    urls.add(clean)
                            if value.startswith(("http://", "https://")):
                                urls.add(value)
                        # Some sites expose server-detail pages whose download action is rendered there.
                        if any(word in label for word in ("download", "connect", "details", "view server")):
                            for value in item.get("values", []):
                                if value.startswith("/") or value.startswith("http"):
                                    urls.add(urljoin(site["url"], value))

                    # Prefer direct .ovpn links. IPSpeed limits profile downloads to
                    # one every 10 seconds; cap each run to six profiles and honour it.
                    candidate_urls = sorted(
                        urls,
                        key=lambda value: (".ovpn" not in value.lower(), value),
                    )
                    if site["name"] == "IPSpeed":
                        candidate_urls = [u for u in candidate_urls if ".ovpn" in u.lower()][:6]
                    else:
                        candidate_urls = candidate_urls[:60]

                    checked = 0
                    last_download_at = None
                    for url in candidate_urls:
                        if checked >= 60:
                            break
                        if site["name"] == "IPSpeed" and last_download_at is not None:
                            delay = 10.0 - (time.monotonic() - last_download_at)
                            if delay > 0:
                                time.sleep(delay)
                        checked += 1
                        try:
                            result = context.request.get(url, timeout=20000)
                            if site["name"] == "IPSpeed":
                                last_download_at = time.monotonic()
                            if not result.ok:
                                continue
                            body = result.text().lstrip("\ufeff")
                            if "remote " in body.lower() and ("dev tun" in body.lower() or "dev tap" in body.lower()):
                                candidates.append({
                                    "ovpn_text": body,
                                    "country": "Unknown",
                                    "country_code": "XX",
                                    "source": site["name"],
                                })
                                continue

                            # A detail page may contain the final download link.
                            if "<html" in body[:500].lower() or "<!doctype" in body[:500].lower():
                                detail = BeautifulSoup(body, "html.parser")
                                for anchor in detail.find_all("a", href=True):
                                    href = urljoin(url, anchor["href"].strip())
                                    text = anchor.get_text(" ", strip=True).lower()
                                    if ".ovpn" in href.lower() or any(w in text for w in ("download", "config")):
                                        try:
                                            file_result = context.request.get(href, timeout=12000)
                                            if file_result.ok:
                                                config = file_result.text().lstrip("\ufeff")
                                                if "remote " in config.lower() and ("dev tun" in config.lower() or "dev tap" in config.lower()):
                                                    candidates.append({
                                                        "ovpn_text": config,
                                                        "country": "Unknown",
                                                        "country_code": "XX",
                                                        "source": site["name"],
                                                    })
                                        except Exception:
                                            continue
                        except Exception as e:
                            print(f"{site['name']} candidate error: {e}")

                    print(f"{site['name']}: collected {sum(1 for c in candidates if c['source'] == site['name'])} configs from {checked} candidate URLs")
                except Exception as e:
                    print(f"Playwright Error ({site['name']}): {e}")
                finally:
                    page.close()

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

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

SIMPLE_SCRAPE_SITES = [
    {"name": "OpenProxyList", "url": "https://openproxylist.com/openvpn/"},
]

# IPSpeed permits one profile download every 10 seconds. Use a browser session
# and enforce that limit. HuntVPN and PublicVPNList require approved access
# before automated collection or permanent republication.
BROWSER_SCRAPE_SITES = [
    {"name": "IPSpeed", "url": "https://ipspeed.info/free-openvpn.php", "fallback_urls": ["https://ipspeed.info/tr/free-openvpn.php", "https://ipspeed.info/es/free-openvpn.php"]},
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


def patch_ovpn_config(ovpn_text: str, requires_auth: bool) -> str:
    """Normalize third-party profiles for modern OpenVPN and Android openvpn_flutter."""
    output = []
    skip_inline_auth = False
    seen = set()
    removed = {"script-security", "up", "down", "block-outside-dns", "register-dns"}
    for raw_line in ovpn_text.splitlines():
        stripped = raw_line.strip()
        if skip_inline_auth:
            if stripped.lower() == "</auth-user-pass>":
                skip_inline_auth = False
            continue
        if not stripped or stripped.startswith(("#", ";")):
            output.append(raw_line)
            continue
        if stripped.lower() == "<auth-user-pass>":
            skip_inline_auth = True
            continue
        parts = stripped.split(None, 1)
        directive = parts[0].lower()
        if directive == "auth-user-pass":
            continue
        if directive in removed:
            continue
        if directive in {"data-ciphers", "data-ciphers-fallback"}:
            if directive not in seen:
                # Use the requested compatibility set consistently across providers.
                value = (
                    "AES-256-GCM:AES-128-GCM:AES-128-CBC:CHACHA20-POLY1305"
                    if directive == "data-ciphers"
                    else "AES-128-CBC"
                )
                output.append(f"{directive} {value}")
                seen.add(directive)
            continue
        output.append(raw_line)
        seen.add(directive)

    required = [
        ('data-ciphers', "data-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC:CHACHA20-POLY1305"),
        ('data-ciphers-fallback', "data-ciphers-fallback AES-128-CBC"),
        ('pull-filter-route-ipv6', 'pull-filter ignore "route-ipv6"'),
        ('pull-filter-ifconfig-ipv6', 'pull-filter ignore "ifconfig-ipv6"'),
        ('dhcp-option-dns-1.1.1.1', "dhcp-option DNS 1.1.1.1"),
        ('dhcp-option-dns-8.8.8.8', "dhcp-option DNS 8.8.8.8"),
        ('persist-key', "persist-key"),
        ('persist-tun', "persist-tun"),
    ]
    existing = set()
    for line in output:
        value = line.strip().lower()
        if value.startswith("pull-filter ignore") and "route-ipv6" in value:
            existing.add('pull-filter-route-ipv6')
        elif value.startswith("pull-filter ignore") and "ifconfig-ipv6" in value:
            existing.add('pull-filter-ifconfig-ipv6')
        elif value == "dhcp-option dns 1.1.1.1":
            existing.add('dhcp-option-dns-1.1.1.1')
        elif value == "dhcp-option dns 8.8.8.8":
            existing.add('dhcp-option-dns-8.8.8.8')
        elif value in {"persist-key", "persist-tun"}:
            existing.add(value)
    for key, line in required:
        if key not in existing and not (key in seen):
            output.append(line)
    if requires_auth:
        output.append("auth-user-pass")
    return "\n".join(output).rstrip() + "\n"

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
                    "username": "vpn",
                    "password": "vpn",
                    "requires_auth": True,
                })
            except Exception:
                continue
    except Exception as e:
        print(f"VPNGate Error: {e}")
    return candidates




def fetch_riseup():
    """Fetch Riseup's official LEAP API and create self-contained OpenVPN profiles."""
    candidates = []
    ca_url = "https://raw.githubusercontent.com/leapcode/bitmask-vpn/main/providers/riseup/riseup-ca.crt"
    api = "https://api.black.riseup.net/3"
    try:
        with tempfile.TemporaryDirectory(prefix="onevpn-riseup-") as temp_dir:
            ca_path = os.path.join(temp_dir, "riseup-ca.crt")
            ca_response = requests.get(ca_url, headers=HEADERS, timeout=25)
            ca_response.raise_for_status()
            ca_pem = ca_response.text.strip()
            if "BEGIN CERTIFICATE" not in ca_pem:
                raise ValueError("Riseup CA endpoint did not return a PEM certificate")
            with open(ca_path, "w", encoding="utf-8") as handle:
                handle.write(ca_pem + "\n")

            gateways_response = requests.get(
                f"{api}/config/eip-service.json", headers=HEADERS,
                timeout=30,
            )
            gateways_response.raise_for_status()
            service = gateways_response.json()
            gateways = service.get("gateways", [])
            if not isinstance(gateways, list) or not gateways:
                raise ValueError("Riseup API returned no gateways")

            cert_response = requests.get(
                f"{api}/cert", headers=HEADERS, timeout=30,
            )
            cert_response.raise_for_status()
            credential_bundle = cert_response.text
            cert_match = re.search(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                credential_bundle, re.S,
            )
            key_match = re.search(
                r"-----BEGIN (?:[A-Z ]* )?PRIVATE KEY-----.*?-----END (?:[A-Z ]* )?PRIVATE KEY-----",
                credential_bundle, re.S,
            )
            if not cert_match or not key_match:
                raise ValueError("Riseup /3/cert response lacks a PEM client certificate or private key")
            client_cert = cert_match.group(0).strip()
            client_key = key_match.group(0).strip()
            locations = service.get("locations", {}) or {}
            openvpn_options = service.get("openvpn_configuration", {}) or {}

            for gateway in gateways:
                caps = gateway.get("capabilities", {}) or {}
                host = gateway.get("ip_address") or gateway.get("host")
                if not host:
                    continue
                transport_entries = caps.get("transport") or []
                endpoints = []
                for transport in transport_entries:
                    if str(transport.get("type", "")).lower() != "openvpn":
                        continue
                    for proto in transport.get("protocols", ["udp"]):
                        for port in transport.get("ports", []):
                            endpoints.append((str(proto).lower(), int(port)))
                # Compatibility with older EIP-service v3 gateway payloads.
                if not endpoints and "ports" in caps:
                    for proto in caps.get("protocols", ["udp"]):
                        for port in caps.get("ports", []):
                            endpoints.append((str(proto).lower(), int(port)))
                location = gateway.get("location") or "Unknown"
                location_info = locations.get(location, {}) if isinstance(locations, dict) else {}
                country = location_info.get("name") or location
                country_code = normalize_country_code(location_info.get("country_code"))
                for proto, port in endpoints:
                    if proto not in {"tcp", "udp"} or not (1 <= port <= 65535):
                        continue
                    lines = [
                        "client", "dev tun", f"proto {proto}-client" if proto == "tcp" else "proto udp",
                        f"remote {host} {port}", "resolv-retry infinite", "nobind",
                        "persist-key", "persist-tun", "remote-cert-tls server",
                    ]
                    for option, value in openvpn_options.items():
                        name = str(option).strip().lower()
                        if name in {"dev", "proto", "remote", "auth-user-pass", "script-security", "up", "down"}:
                            continue
                        if isinstance(value, bool):
                            if value:
                                lines.append(name)
                        elif value is not None and str(value).strip():
                            lines.append(f"{name} {value}")
                    lines.extend([
                        "<ca>", ca_pem, "</ca>",
                        "<cert>", client_cert, "</cert>",
                        "<key>", client_key, "</key>",
                    ])
                    candidates.append({
                        "ovpn_text": "\n".join(lines) + "\n",
                        "country": country,
                        "country_code": country_code,
                        "source": "riseup",
                        "username": "",
                        "password": "",
                        "requires_auth": False,
                    })
            print(f"RiseupVPN: collected {len(candidates)} OpenVPN gateway profiles")
    except Exception as exc:
        print(f"RiseupVPN Error: {exc}")
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
                    page_url = None
                    for candidate_page_url in [site["url"], *site.get("fallback_urls", [])]:
                        try:
                            response = page.goto(candidate_page_url, wait_until="domcontentloaded", timeout=45000)
                        except Exception as exc:
                            print(f"{site['name']} page navigation failed for {candidate_page_url}: {exc}")
                            continue
                        if response and response.status >= 400:
                            headers = response.headers
                            print(
                                f"{site['name']} page returned HTTP {response.status} "
                                f"(server={headers.get('server', 'unknown')}, "
                                f"content-type={headers.get('content-type', 'unknown')}, "
                                f"retry-after={headers.get('retry-after', 'none')})"
                            )
                            continue
                        page_url = candidate_page_url
                        break
                    if not page_url:
                        print(f"{site['name']}: all published language pages rejected the CI browser request; source needs provider-side access approval or allowlisting.")
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
                                    clean = urljoin(page_url, clean)
                                if clean.startswith(("http://", "https://")):
                                    urls.add(clean)
                            if value.startswith(("http://", "https://")):
                                urls.add(value)
                        # Some sites expose server-detail pages whose download action is rendered there.
                        if any(word in label for word in ("download", "connect", "details", "view server")):
                            for value in item.get("values", []):
                                if value.startswith("/") or value.startswith("http"):
                                    urls.add(urljoin(page_url, value))

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


def install_openvpn_client():
    """Install OpenVPN on an ephemeral CI runner if it is not already available."""
    if shutil.which("openvpn"):
        return True
    if not shutil.which("sudo") or not shutil.which("apt-get"):
        print("VPN E2E skipped: OpenVPN CLI is unavailable on this runner.")
        return False
    try:
        update = subprocess.run(
            ["sudo", "apt-get", "update", "-qq"],
            capture_output=True, text=True, timeout=120,
        )
        if update.returncode != 0:
            print("VPN E2E skipped: package index update failed.")
            return False
        install = subprocess.run(
            ["sudo", "apt-get", "install", "-y", "-qq", "openvpn", "curl", "iproute2"],
            capture_output=True, text=True, timeout=180,
        )
        if install.returncode != 0 or not shutil.which("openvpn"):
            print("VPN E2E skipped: OpenVPN client installation failed.")
            return False
        return True
    except Exception as exc:
        print(f"VPN E2E skipped: could not prepare OpenVPN client ({exc}).")
        return False


def make_safe_test_profile(ovpn_text: str):
    """Strip executable hooks and route-changing directives from third-party profiles."""
    output = []
    in_inline_block = False
    skip_inline_block = False
    for raw_line in ovpn_text.splitlines():
        stripped = raw_line.strip()
        if in_inline_block:
            if stripped.startswith("</"):
                in_inline_block = False
                if not skip_inline_block:
                    output.append(raw_line)
                skip_inline_block = False
            elif not skip_inline_block:
                output.append(raw_line)
            continue
        if not stripped or stripped.startswith(("#", ";")):
            output.append(raw_line)
            continue
        if stripped.startswith("<") and not stripped.startswith("</"):
            block_name = stripped[1:].split(">", 1)[0].strip().lower()
            skip_inline_block = block_name == "auth-user-pass"
            in_inline_block = True
            if not skip_inline_block:
                output.append(raw_line)
            continue

        parts = stripped.split(None, 1)
        directive = parts[0].lower()
        if directive in {
            "auth-user-pass", "daemon", "log", "log-append", "writepid",
            "management", "plugin", "config", "up", "down", "route-up",
            "ipchange", "client-connect", "client-disconnect", "learn-address",
            "tls-verify", "script-security", "user", "group", "route",
            "route-ipv6", "redirect-gateway", "redirect-private", "dhcp-option",
            "setenv", "setenv-safe", "askpass", "auth-nocache",
        }:
            continue
        if directive == "dev" and len(parts) > 1 and parts[1].strip().lower().startswith("tap"):
            return None, "TAP profiles are not supported by this isolated test"
        output.append(raw_line)

    output.extend([
        "",
        "# OneVPN isolated end-to-end test overrides",
        "route-nopull",
        "script-security 0",
        "auth-nocache",
        "nobind",
        "persist-key",
        "persist-tun",
        "verb 3",
    ])
    return "\n".join(output) + "\n", None


def run_openvpn_end_to_end(item: dict):
    """Establish a real tunnel and verify HTTPS egress without changing the default route."""
    profile, reason = make_safe_test_profile(item["_ovpn_text"])
    if not profile:
        return False, reason
    needs_auth = bool(re.search(
        r"(?im)^\s*auth-user-pass(?:\s|$)|<auth-user-pass>",
        item["_ovpn_text"],
    ))
    username = str(item.get("username") or "")
    password = str(item.get("password") or "")
    if needs_auth and (not username or not password):
        return False, "profile requires credentials that are not available"
    if not os.path.exists("/dev/net/tun"):
        return False, "runner has no /dev/net/tun device"

    with tempfile.TemporaryDirectory(prefix="onevpn-e2e-") as temp_dir:
        config_path = os.path.join(temp_dir, "test.ovpn")
        if needs_auth:
            auth_path = os.path.join(temp_dir, "auth.txt")
            with open(auth_path, "w", encoding="utf-8") as auth_file:
                auth_file.write(username + "\\n" + password + "\\n")
            os.chmod(auth_path, 0o600)
            profile += f"auth-user-pass {auth_path}\\n"
        log_path = os.path.join(temp_dir, "openvpn.log")
        pid_path = os.path.join(temp_dir, "openvpn.pid")
        with open(config_path, "w", encoding="utf-8") as handle:
            handle.write(profile)
        # Pre-create the log as the runner user so the non-root Python process
        # can read it after OpenVPN (started via sudo) writes to the same file.
        with open(log_path, "w", encoding="utf-8"):
            pass
        os.chmod(log_path, 0o666)
        # Keep the PID file runner-readable for reliable cleanup of the sudo child.
        with open(pid_path, "w", encoding="utf-8"):
            pass
        os.chmod(pid_path, 0o666)

        process = None
        route_ip = None
        route_added = False
        try:
            process = subprocess.Popen(
                [
                    "sudo", "openvpn", "--config", config_path,
                    "--route-nopull", "--script-security", "0",
                    "--connect-retry-max", "1", "--connect-timeout", "12",
                    "--verb", "3", "--log", log_path, "--writepid", pid_path,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )

            deadline = time.monotonic() + 28
            connected = False
            while time.monotonic() < deadline:
                if os.path.exists(log_path):
                    with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                        log_text = handle.read()
                    if "Initialization Sequence Completed" in log_text:
                        connected = True
                        break
                    if any(marker in log_text for marker in (
                        "AUTH_FAILED", "Exiting due to fatal error", "Options error",
                    )):
                        return False, "OpenVPN rejected the profile or authentication"
                if process.poll() is not None:
                    break
                time.sleep(0.5)

            if not connected:
                return False, "OpenVPN tunnel did not initialize within 28 seconds"

            links = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True, text=True, timeout=5,
            )
            match = re.search(r"\d+:\s+(tun\d+):", links.stdout)
            if not match:
                return False, "OpenVPN connected but no TUN interface was found"
            tun_device = match.group(1)

            route_ip = socket.gethostbyname("api.ipify.org")
            route_result = subprocess.run(
                ["sudo", "ip", "route", "add", f"{route_ip}/32", "dev", tun_device],
                capture_output=True, text=True, timeout=5,
            )
            if route_result.returncode != 0:
                return False, "tunnel came up but an isolated egress route could not be added"
            route_added = True

            # Pin curl to the exact address routed above. Without --resolve,
            # curl performs a second DNS lookup which may return a different
            # address (for example, behind a CDN) that has no tunnel route.
            route_check = subprocess.run(
                ["ip", "-4", "route", "get", route_ip],
                capture_output=True, text=True, timeout=5,
            )
            if route_check.returncode != 0 or not re.search(
                rf"\bdev\s+{re.escape(tun_device)}\b", route_check.stdout
            ):
                route_detail = route_check.stdout.strip() or route_check.stderr.strip()
                return False, (
                    "isolated egress route does not resolve through the TUN interface"
                    + (f" ({route_detail[:180]})" if route_detail else "")
                )

            egress = subprocess.run(
                [
                    "curl", "-4", "--resolve", f"api.ipify.org:443:{route_ip}",
                    "--noproxy", "*", "--fail", "--silent", "--show-error",
                    "--connect-timeout", "8", "--max-time", "12",
                    "https://api.ipify.org",
                ],
                capture_output=True, text=True, timeout=15,
            )
            if egress.returncode != 0:
                error_detail = (egress.stderr or egress.stdout).strip()
                return False, (
                    "tunnel route verified but pinned HTTPS egress failed"
                    + (f" (curl exit {egress.returncode}: {error_detail[:180]})" if error_detail else "")
                )
            try:
                exit_ip = ipaddress.ip_address(egress.stdout.strip())
            except ValueError:
                return False, "tunnel returned an invalid egress-IP response"
            if not exit_ip.is_global:
                return False, "tunnel egress did not return a public IP"
            return True, f"tunnel and HTTPS egress verified ({exit_ip})"
        except Exception as exc:
            return False, f"end-to-end test error: {exc}"
        finally:
            if route_added and route_ip:
                try:
                    subprocess.run(
                        ["sudo", "ip", "route", "del", f"{route_ip}/32"],
                        capture_output=True, timeout=5,
                    )
                except Exception:
                    pass
            try:
                openvpn_pid = ""
                if os.path.exists(pid_path):
                    with open(pid_path, "r", encoding="utf-8") as handle:
                        openvpn_pid = handle.read().strip()
                if openvpn_pid.isdigit():
                    subprocess.run(
                        ["sudo", "kill", "-TERM", openvpn_pid],
                        capture_output=True, timeout=5,
                    )
                elif process and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
            except Exception:
                if process and process.poll() is None:
                    process.kill()


def run_end_to_end_checks(healthy_servers: list):
    """Test one real TCP and one real UDP tunnel when candidates are available."""
    if os.environ.get("RUN_E2E_TESTS", "1").strip().lower() in {"0", "false", "no"}:
        print("VPN E2E checks disabled by RUN_E2E_TESTS.")
        return
    if not healthy_servers:
        print("VPN E2E checks skipped: no health-checked servers.")
        return
    if not install_openvpn_client():
        return

    checked_protocols = set()
    passed = 0
    for server in healthy_servers:
        proto = server["protocol"]
        if proto not in {"tcp", "udp"} or proto in checked_protocols:
            continue
        checked_protocols.add(proto)
        ok, detail = run_openvpn_end_to_end(server)
        print(
            f"VPN E2E {'PASS' if ok else 'FAIL'}: {server['source']} "
            f"{proto.upper()} {server['ip']}:{server['port']} - {detail}"
        )
        if ok:
            passed += 1
        if len(checked_protocols) >= 2:
            break
    print(f"VPN E2E summary: {passed}/{len(checked_protocols)} protocol tunnel checks passed.")

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
        "username": item.get("username", ""),
        "password": item.get("password", ""),
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
    source_fetchers = [
        ("VPNGate", fetch_vpngate),
        ("RiseupVPN", fetch_riseup),
        ("OpenProxyList", fetch_simple_sites),
        ("IPSpeed", fetch_with_playwright),
    ]
    for source_name, fetcher in source_fetchers:
        try:
            fetched = fetcher()
            for candidate in fetched:
                candidate["requires_auth"] = bool(candidate.get("requires_auth", re.search(
                    r"(?im)^\s*auth-user-pass(?:\s|$)", candidate.get("ovpn_text", "")
                )))
                candidate.setdefault("username", "")
                candidate.setdefault("password", "")
                candidate["ovpn_text"] = patch_ovpn_config(
                    candidate["ovpn_text"], candidate["requires_auth"]
                )
            raw_candidates.extend(fetched)
            print(f"{source_name}: source completed with {len(fetched)} profiles")
        except Exception as exc:
            print(f"{source_name} source failed independently: {exc}")

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

    run_end_to_end_checks(healthy_servers)

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

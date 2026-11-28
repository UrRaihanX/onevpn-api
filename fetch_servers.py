import os
import re
import csv
import json
import time
import shutil
import socket
import base64
import hashlib
import ssl
import threading
import subprocess
import tempfile
import ipaddress
from urllib.parse import quote
import requests
from io import StringIO
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

HEALTH_CHECK_TIMEOUT = float(os.environ.get("HEALTH_CHECK_TIMEOUT", "2.0"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "30"))
MIN_SERVERS_THRESHOLD = int(os.environ.get("MIN_SERVERS_THRESHOLD", "5"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "dist")
DATA_BRANCH = os.environ.get("DATA_BRANCH", "data")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "UrRaihanX/onevpn-api")
CDN_BASE_URL = f"https://cdn.jsdelivr.net/gh/{GITHUB_REPOSITORY}@{DATA_BRANCH}"

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


def make_server_id(ip: str, port: int, proto: str, source: str = "vpngate") -> str:
    """প্রতিটি সার্ভারের জন্য ইউনিক ও ফাইল-নিরাপদ ID তৈরি করে।"""
    endpoint_id = f"{ip.replace('.', '_')}_{port}_{proto}"
    source_key = re.sub(r"[^a-z0-9]+", "", str(source).lower())
    return endpoint_id if source_key == "vpngate" else f"{source_key}_{endpoint_id}"



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


def check_tcp_health(ip: str, port: int, has_tls_key: bool = False):
    """Check TCP reachability; TLS-keyed listeners cannot answer unauthenticated probes."""
    start_time = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=HEALTH_CHECK_TIMEOUT) as sock:
            if has_tls_key:
                return True, max(1, int((time.monotonic() - start_time) * 1000))
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(min(HEALTH_CHECK_TIMEOUT, 1.5))
    try:
        sock.connect((ip, port))
        # TLS-keyed servers silently discard unauthenticated hard resets.
        # Their authenticated profiles are verified by the OpenVPN E2E check.
        if has_tls_key:
            started = time.monotonic()
            sock.send(b"\x38" + os.urandom(8) + b"\x00" + (1).to_bytes(4, "big"))
            return True, max(1, int((time.monotonic() - started) * 1000))
        session_id = os.urandom(8)
        for packet_id in range(1, 4):
            start_time = time.monotonic()
            probe_packet = b"\x38" + session_id + b"\x00" + packet_id.to_bytes(4, "big")
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
        return check_tcp_health(ip, port, has_tls_key=has_tls_key)
    return check_udp_health(ip, port, has_tls_key=has_tls_key)


def enrich_with_geoip(servers: list):
    """সক্রিয় সার্ভারগুলোর IP থেকে ব্যাচ GeoIP লুকআপ করে দেশ, ফ্ল্যাগ ও ISP আপডেট করে।"""
    batch_size = 100
    for i in range(0, len(servers), batch_size):
        batch = servers[i:i + batch_size]
        payload = [{"query": s["ip"], "fields": "status,country,countryCode,continent,continentCode,isp"} for s in batch]
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
                        server["continent"] = geo.get("continent") or server.get("continent", "Unknown")
                        server["continent_code"] = geo.get("continentCode") or server.get("continent_code", "XX")
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
                    "AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC:CHACHA20-POLY1305"
                    if directive == "data-ciphers"
                    else "AES-256-CBC:AES-128-CBC"
                )
                output.append(f"{directive} {value}")
                seen.add(directive)
            continue
        output.append(raw_line)
        seen.add(directive)

    required = [
        ('data-ciphers', "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC:CHACHA20-POLY1305"),
        ('data-ciphers-fallback', "data-ciphers-fallback AES-256-CBC:AES-128-CBC"),
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
                try:
                    speed_mbps = round(float(row[4]) / 1_000_000, 2)
                    if speed_mbps < 0: speed_mbps = 0.0
                except (TypeError, ValueError, IndexError):
                    speed_mbps = 0.0
                candidates.append({
                    "speed_mbps": speed_mbps,
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




def fetch_leap_provider(provider_name: str, provider_url: str, source_slug: str):
    """Discover a LEAP provider dynamically and build Android-compatible OpenVPN profiles."""
    candidates = []
    ca_path = None
    try:
        try:
            provider_response = requests.get(provider_url, headers=HEADERS, timeout=(8, 20))
            provider_response.raise_for_status()
            provider = provider_response.json()
        except Exception:
            if source_slug != "calyx":
                raise
            # Calyx's legacy provider.json currently returns 404; retain its
            # documented LEAP API bootstrap endpoints as a fallback.
            provider = {
                "api_uri": "https://api.calyx.net:4430",
                "api_version": "3",
                "ca_cert_uri": "https://calyx.net/ca.crt",
            }

        api_uri = str(provider["api_uri"]).rstrip("/")
        api_version = str(provider.get("api_version", "3") or "3").strip("/")
        ca_cert_uri = str(provider["ca_cert_uri"])
        if not api_uri.startswith("https://") or not ca_cert_uri.startswith("https://"):
            raise ValueError(f"{provider_name} provider.json contains a non-HTTPS API or CA URL")

        ca_response = requests.get(ca_cert_uri, headers=HEADERS, timeout=(8, 25))
        ca_response.raise_for_status()
        ca_pem = ca_response.text.strip()
        if "-----BEGIN CERTIFICATE-----" not in ca_pem:
            raise ValueError(f"{provider_name} CA endpoint did not return a PEM certificate")

        # Use a real .crt file for requests' CA bundle verification and always unlink it.
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".crt",
            prefix=f"onevpn-{source_slug}-", delete=False,
        ) as ca_file:
            ca_file.write(ca_pem + "\n")
            ca_path = ca_file.name

        api_root = f"{api_uri}/{api_version}"
        gateways_response = requests.get(
            f"{api_root}/config/eip-service.json",
            headers=HEADERS, timeout=(8, 30), verify=True,
        )
        gateways_response.raise_for_status()
        service = gateways_response.json()
        gateways = service.get("gateways", [])
        if not isinstance(gateways, list) or not gateways:
            raise ValueError(f"{provider_name} API returned no gateways")

        # Request one shared client credential bundle per provider, not per gateway.
        cert_response = requests.get(
            f"{api_root}/cert", headers=HEADERS, timeout=(8, 30), verify=True,
        )
        cert_response.raise_for_status()
        cert_bundle = cert_response.text
        cert_match = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            cert_bundle, re.S,
        )
        key_match = re.search(
            r"-----BEGIN (?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----.*?"
            r"-----END (?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----",
            cert_bundle, re.S,
        )
        if not cert_match or not key_match:
            raise ValueError(
                f"{provider_name} /cert response lacks a PEM certificate or supported private key"
            )
        client_cert = cert_match.group(0).strip()
        client_key = key_match.group(0).strip()

        locations = service.get("locations", {}) or {}
        openvpn_options = service.get("openvpn_configuration", {}) or {}
        if not isinstance(openvpn_options, dict):
            raise ValueError(f"{provider_name} openvpn_configuration is not an object")

        for gateway in gateways:
            capabilities = gateway.get("capabilities", {}) or {}
            transports = capabilities.get("transport", []) or []
            openvpn_transports = [item for item in transports if str(item.get("type", "")).lower() == "openvpn"]
            if openvpn_transports:
                merged_protocols = []
                merged_ports = []
                for item in openvpn_transports:
                    values = item.get("protocols") or [item.get("protocol", "")]
                    merged_protocols.extend(str(value).lower() for value in values if str(value).lower() in {"udp", "tcp"})
                    ports = item.get("ports", []) or []
                    merged_ports.extend(ports if isinstance(ports, list) else [ports])
                transports = [{"type": "openvpn", "protocols": merged_protocols, "ports": merged_ports}]
            for transport in transports:
                if str(transport.get("type", "")).lower() != "openvpn":
                    continue

                protocols = [
                    str(proto).lower()
                    for proto in (transport.get("protocols") or [])
                    if str(proto).lower() in {"udp", "tcp"}
                ]
                if not protocols:
                    protocol_value = str(transport.get("protocol", "")).lower()
                    if protocol_value in {"udp", "tcp"}:
                        protocols = [protocol_value]
                if not protocols:
                    continue

                # One endpoint per gateway: UDP is preferred, TCP is the fallback.
                proto = "udp" if "udp" in protocols else "tcp"
                ports = transport.get("ports", []) or []
                if isinstance(ports, (int, str)):
                    ports = [ports]
                valid_ports = []
                for raw_port in ports:
                    try:
                        port = int(raw_port)
                        if 1 <= port <= 65535:
                            valid_ports.append(port)
                    except (TypeError, ValueError):
                        continue
                if not valid_ports:
                    continue

                host = gateway.get("ip_address") or gateway.get("host")
                if not host:
                    continue
                location = gateway.get("location") or "Unknown"
                location_info = locations.get(location, {}) if isinstance(locations, dict) else {}
                country = ""
                country_code = normalize_country_code(location_info.get("country_code"))

                lines = [
                    "client", "dev tun",
                    f"proto {proto}-client" if proto == "tcp" else "proto udp",
                    f"remote {host} {valid_ports[0]}",
                    "resolv-retry infinite", "nobind", "persist-key", "persist-tun",
                    "remote-cert-tls server", "auth-nocache",
                ]
                for option, value in openvpn_options.items():
                    name = str(option).strip().lower().replace("_", "-")
                    if not name or name in {
                        "client", "dev", "proto", "remote", "auth-user-pass",
                        "script-security", "up", "down", "ca", "cert", "key",
                    }:
                        continue
                    if isinstance(value, bool):
                        if value:
                            lines.append(name)
                    elif isinstance(value, (list, tuple)):
                        for option_value in value:
                            if option_value is not None and str(option_value).strip():
                                lines.append(f"{name} {option_value}")
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
                    "source": source_slug,
                    "username": "",
                    "password": "",
                    "requires_auth": False,
                    "publishable": True,
                })
                # Only the preferred OpenVPN transport is emitted for this gateway.
                break

        print(f"{provider_name}: collected {len(candidates)} OpenVPN gateway profiles")
    except Exception as exc:
        print(f"{provider_name} Error: {exc}")
    finally:
        if ca_path and os.path.exists(ca_path):
            try:
                os.remove(ca_path)
            except OSError as exc:
                print(f"{provider_name}: could not remove temporary CA file: {exc}")
    return candidates


def fetch_riseup():
    return fetch_leap_provider(
        "RiseupVPN", "https://riseup.net/provider.json", "riseup"
    )


def fetch_calyx():
    return fetch_leap_provider(
        "CalyxVPN", "https://calyx.net/provider.json", "calyx"
    )


def fetch_github_ovpn_repository(repository: str, source_name: str):
    """Fetch public .ovpn files from a GitHub repository using only requests."""
    candidates = []
    github_headers = dict(HEADERS)
    if os.environ.get("GITHUB_TOKEN"):
        github_headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    try:
        repo_response = requests.get(
            f"https://api.github.com/repos/{repository}",
            headers=github_headers, timeout=(8, 20),
        )
        repo_response.raise_for_status()
        default_branch = repo_response.json().get("default_branch") or "main"

        tree_response = requests.get(
            f"https://api.github.com/repos/{repository}/git/trees/{default_branch}?recursive=1",
            headers=github_headers, timeout=(8, 30),
        )
        tree_response.raise_for_status()
        tree = tree_response.json()
        if tree.get("truncated"):
            print(f"{source_name}: GitHub tree was truncated; only returned .ovpn files will be used.")

        paths = [
            entry.get("path", "")
            for entry in tree.get("tree", [])
            if entry.get("type") == "blob"
            and entry.get("path", "").lower().endswith(".ovpn")
        ][:100]

        def download_profile(path):
            try:
                raw_url = f"https://raw.githubusercontent.com/{repository}/{quote(default_branch, safe='')}/{quote(path, safe='/')}"
                response = requests.get(raw_url, headers=github_headers, timeout=(8, 20))
                response.raise_for_status()
                profile = response.text
                if re.search(r"(?im)^\s*remote\s+\S+\s+\d+", profile) and re.search(r"(?im)^\s*dev\s+\S+", profile):
                    return {"ovpn_text": profile, "country": "Unknown", "country_code": "XX", "source": source_name, "username": "", "password": "", "requires_auth": bool(re.search(r"(?im)^\s*auth-user-pass(?:\s|$)", profile)), "publishable": True}
            except Exception as exc:
                print(f"{source_name}: skipped {path}: {exc}")
            return None
        with ThreadPoolExecutor(max_workers=min(12, max(1, len(paths)))) as pool:
            candidates.extend(item for item in pool.map(download_profile, paths) if item)
    except Exception as exc:
        print(f"{source_name} Error: {exc}")
    print(f"{source_name}: collected {len(candidates)} public .ovpn profiles")
    return candidates


def fetch_fox3000foxy():
    return fetch_github_ovpn_repository(
        "fox3000foxy/OVPN-Configs-scraper",
        "fox3000foxy/OVPN-Configs-scraper",
    )

def install_openvpn_client():
    """Install OpenVPN on an ephemeral CI runner if it is not already available."""
    if all(shutil.which(binary) for binary in ("openvpn", "ip", "curl")):
        return True
    if not shutil.which("sudo") or not shutil.which("apt-get"):
        print("VPN E2E skipped: OpenVPN CLI is unavailable on this runner.")
        return False
    try:
        update = subprocess.run(
            ["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update", "-qq"],
            capture_output=True, text=True, timeout=120,
        )
        if update.returncode != 0:
            print("VPN E2E skipped: package index update failed.")
            return False
        install = subprocess.run(
            ["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-qq", "openvpn", "curl", "iproute2"],
            capture_output=True, text=True, timeout=180,
        )
        if install.returncode != 0 or not all(shutil.which(x) for x in ("openvpn", "ip", "curl")):
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
                auth_file.write(username + "\n" + password + "\n")
            os.chmod(auth_path, 0o600)
            profile += f"auth-user-pass {auth_path}\n"
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

            try:
                route_ip = socket.gethostbyname("api.ipify.org")
            except OSError as exc:
                return False, f"could not resolve api.ipify.org: {exc}"
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
        return healthy_servers
    if not healthy_servers:
        print("VPN E2E checks skipped: no health-checked servers.")
        return healthy_servers
    if not install_openvpn_client():
        print("VPN E2E checks skipped because the OpenVPN client is unavailable; continuing other sources.")
        return healthy_servers

    passed = 0
    checked = 0
    failed_server_ids = set()

    # Exercise each provider independently so one provider's success cannot mask
    # broken credentials, endpoint metadata, or profile generation from another.
    grouped = {}
    for server in healthy_servers:
        if not server.get("_publishable", True):
            continue
        key = (str(server.get("source", "")).lower(), server.get("protocol"))
        if key[1] in {"tcp", "udp"}:
            grouped.setdefault(key, []).append(server)

    for (source, proto), candidates in sorted(grouped.items()):
        checked += 1
        protocol_passed = False
        for server in candidates[:2]:
            ok, detail = run_openvpn_end_to_end(server)
            print(f"{source.upper()} E2E {'PASS' if ok else 'ATTEMPT FAILED'}: "
                  f"{proto.upper()} {server['ip']}:{server['port']} - {detail}")
            if not ok:
                failed_server_ids.add(server.get("id"))
            if ok:
                passed += 1
                protocol_passed = True
                break
        if not protocol_passed:
            print(f"{source.upper()} E2E FAIL: no working {proto.upper()} tunnel "
                  f"found in {min(len(candidates), 2)} attempted endpoint(s).")

    print(f"VPN E2E summary: {passed}/{checked} provider/protocol checks passed.")
    if failed_server_ids:
        before = len(healthy_servers)
        healthy_servers = [server for server in healthy_servers if server.get("id") not in failed_server_ids]
        print(f"Excluded {before - len(healthy_servers)} individual profiles that failed E2E checks.")
    return healthy_servers

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
    server_id = make_server_id(item["ip"], item["port"], item["protocol"], item.get("source", "vpngate"))
    config_path = f"configs/{server_id}.ovpn"
    return {
        "id": server_id,
        "ip": item["ip"],
        "port": item["port"],
        "protocol": item["protocol"],
        "country": item["country"],
        "country_code": cc,
        "continent": item.get("continent", "Unknown"),
        "continent_code": item.get("continent_code", "XX"),
        "flag_emoji": country_code_to_emoji(cc),
        "flag_url": country_code_to_flag_url(cc),
        "isp": "Unknown",
        "ping_ms": ping_ms,
        "speed_mbps": float(item.get("speed_mbps", 0.0) or 0.0),
        "source": item["source"],
        "_publishable": bool(item.get("publishable", True)),
        "username": item.get("username", ""),
        "password": item.get("password", ""),
        "config_path": config_path,
        "config_url": f"{CDN_BASE_URL}/{config_path}",
        "_ovpn_text": item["ovpn_text"],
    }


def write_output_bundle(healthy_servers: list, output_dir: str) -> None:
    """লাইটওয়েট servers_meta.json, আলাদা configs/*.ovpn এবং ব্যাকওয়ার্ড-কম্প্যাটিবল servers.json তৈরি করে।"""
    # Fail closed before touching the existing output. These three providers are
    # approved for public .ovpn distribution; Bitmask credentials refresh each run.
    for server in healthy_servers:
        source = str(server.get("source", "")).strip().lower()
        if source not in {"vpngate", "riseup", "calyx", "fox3000foxy/ovpn-configs-scraper"} or not server.get("_publishable", True):
            raise ValueError(
                f"Refusing to publish non-approved/private source: {server.get('source', 'unknown')}"
            )
        # Embedded client keys are required by these providers' OpenVPN profiles.
    parent_dir = os.path.dirname(os.path.abspath(output_dir))
    os.makedirs(parent_dir, exist_ok=True)
    staging_dir = tempfile.mkdtemp(prefix=".onevpn-staging-", dir=parent_dir)
    backup_dir = None
    configs_dir = os.path.join(staging_dir, "configs")
    os.makedirs(configs_dir, exist_ok=True)

    now_unix = int(time.time())
    meta_servers = []
    full_servers = []

    for original in healthy_servers:
        server = {key: value for key, value in original.items() if key not in {"_ovpn_text", "_publishable"}}
        ovpn_text = original["_ovpn_text"]
        ovpn_file = os.path.join(staging_dir, server["config_path"])
        os.makedirs(os.path.dirname(ovpn_file), exist_ok=True)
        with open(ovpn_file, "w", encoding="utf-8") as f:
            f.write(ovpn_text)
        meta_servers.append(server)
        full_servers.append({**server, "ovpn_base64": base64.b64encode(ovpn_text.encode("utf-8")).decode("utf-8")})

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

    with open(os.path.join(staging_dir, "servers_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta_payload, f, separators=(",", ":"), ensure_ascii=False)
    with open(os.path.join(staging_dir, "servers.json"), "w", encoding="utf-8") as f:
        json.dump(full_payload, f, separators=(",", ":"), ensure_ascii=False)
    try:
        if os.path.exists(output_dir):
            backup_dir = output_dir + ".backup-" + str(os.getpid())
            os.replace(output_dir, backup_dir)
        os.replace(staging_dir, output_dir)
        if backup_dir and os.path.exists(backup_dir): shutil.rmtree(backup_dir)
    except Exception:
        if backup_dir and os.path.exists(backup_dir) and not os.path.exists(output_dir): os.replace(backup_dir, output_dir)
        raise
    finally:
        if os.path.exists(staging_dir): shutil.rmtree(staging_dir, ignore_errors=True)


def deduplicate_candidates(raw_candidates):
    """Keep one record per endpoint, preferring first-party approved providers."""
    source_priority = {"vpngate": 0, "riseup": 1, "calyx": 2, "fox3000foxy/ovpn-configs-scraper": 3}
    unique_map = {}
    for item in raw_candidates:
        ip, port, proto, has_tls_key = extract_server_endpoint(item["ovpn_text"])
        if not ip:
            continue
        key = (ip, port, proto)
        item.update({"ip": ip, "port": port, "protocol": proto, "has_tls_key": has_tls_key})
        previous = unique_map.get(key)
        priority = source_priority.get(str(item.get("source", "")).lower(), 99)
        old_priority = source_priority.get(str(previous.get("source", "")).lower(), 100) if previous else 100
        if previous is None or priority < old_priority:
            unique_map[key] = item
    return unique_map


def main():
    raw_candidates = []
    source_fetchers = [
        ("VPNGate", fetch_vpngate),
        ("fox3000foxy/OVPN-Configs-scraper", fetch_fox3000foxy),
        ("RiseupVPN", fetch_riseup),
        ("CalyxVPN", fetch_calyx),
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

    unique_map = deduplicate_candidates(raw_candidates)

    print(f"Checking health for {len(unique_map)} unique endpoints (TCP + UDP)...")
    healthy_servers = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for res in executor.map(process_server, unique_map.values()):
            if res:
                healthy_servers.append(res)

    live_counts = Counter(s["source"] for s in healthy_servers)
    print(f"Live servers by source: {dict(live_counts)}")

    healthy_servers = run_end_to_end_checks(healthy_servers)

    publishable_servers = [server for server in healthy_servers if server.get("_publishable", True)]
    source_counts = Counter(str(server.get("source", "")).lower() for server in publishable_servers)
    print("Per-source publishable servers: " + ", ".join(f"{label}={source_counts.get(slug, 0)}" for label, slug in (("VPNGate", "vpngate"), ("RiseupVPN", "riseup"), ("CalyxVPN", "calyx"), ("fox3000foxy", "fox3000foxy/ovpn-configs-scraper"))))

    if len(publishable_servers) < MIN_SERVERS_THRESHOLD:
        print(
            f"Safety guard triggered: only {len(publishable_servers)} publishable live servers found "
            f"(minimum required: {MIN_SERVERS_THRESHOLD}). Skipping output generation."
        )
        return

    print(f"Running GeoIP lookup for {len(publishable_servers)} publishable live servers...")
    enrich_with_geoip(publishable_servers)

    publishable_servers.sort(key=lambda x: x["ping_ms"])
    write_output_bundle(publishable_servers, OUTPUT_DIR)

    meta_kb = os.path.getsize(os.path.join(OUTPUT_DIR, "servers_meta.json")) / 1024
    full_kb = os.path.getsize(os.path.join(OUTPUT_DIR, "servers.json")) / 1024
    print(
        f"Done! Saved {len(publishable_servers)} publishable servers -> "
        f"servers_meta.json ({meta_kb:.1f} KB), servers.json ({full_kb:.1f} KB), "
        f"and {len(publishable_servers)} individual .ovpn files in {OUTPUT_DIR}/configs/."
    )


if __name__ == "__main__":
    main()

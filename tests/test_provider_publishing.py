import json
import os
import tempfile
import unittest
from unittest import mock

import fetch_servers


class ProviderPublishingTests(unittest.TestCase):
    def test_provider_ids_do_not_collide(self):
        endpoint = ("198.51.100.10", 1194, "udp")
        ids = {
            fetch_servers.make_server_id(*endpoint, source="vpngate"),
            fetch_servers.make_server_id(*endpoint, source="riseup"),
            fetch_servers.make_server_id(*endpoint, source="calyx"),
        }
        self.assertEqual(len(ids), 3)

    def test_android_profile_patch_preserves_inline_credentials(self):
        profile = """client
dev tun
proto udp
remote 198.51.100.10 1194
<ca>
-----BEGIN CERTIFICATE-----
TEST
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
CLIENT
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
KEY
-----END PRIVATE KEY-----
</key>
"""
        patched = fetch_servers.patch_ovpn_config(profile, False)
        self.assertIn("<ca>", patched)
        self.assertIn("<cert>", patched)
        self.assertIn("<key>", patched)
        self.assertIn("persist-tun", patched)
        self.assertNotIn("auth-user-pass", patched)

    def test_output_bundle_publishes_all_approved_sources(self):
        records = []
        for source in ("vpngate", "riseup", "calyx"):
            server_id = fetch_servers.make_server_id("198.51.100.10", 1194, "udp", source)
            records.append({
                "id": server_id, "ip": "198.51.100.10", "port": 1194,
                "protocol": "udp", "country": "Test", "country_code": "US",
                "flag_emoji": "🇺🇸", "flag_url": "", "isp": "Test",
                "ping_ms": 10, "source": source, "_publishable": False,
                "username": "", "password": "", "config_path": f"configs/{server_id}.ovpn",
                "config_url": f"{fetch_servers.CDN_BASE_URL}/configs/{server_id}.ovpn",
                "_ovpn_text": "client\ndev tun\nproto udp\nremote 198.51.100.10 1194\n",
            })
        with tempfile.TemporaryDirectory() as temp:
            output = os.path.join(temp, "dist")
            original_records = [dict(record) for record in records]
            fetch_servers.write_output_bundle(records, output)
            self.assertEqual(records, original_records)
            with open(os.path.join(output, "servers_meta.json"), encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual({item["source"] for item in payload["servers"]},
                             {"vpngate", "riseup", "calyx"})
            self.assertEqual(payload["total_servers"], 3)
            self.assertEqual(len(os.listdir(os.path.join(output, "configs"))), 3)

    def test_tcp_ping_uses_connect_rtt_not_openvpn_reply_delay(self):
        fake = mock.MagicMock()
        fake.__enter__.return_value = fake
        fake.recv.side_effect = [b"\x00\x01", b"\x20"]
        with mock.patch.object(fetch_servers.socket, "create_connection", return_value=fake), mock.patch.object(fetch_servers.time, "monotonic", side_effect=[10.0, 10.125]):
            alive, ping = fetch_servers.check_tcp_health("198.51.100.1", 443)
        self.assertTrue(alive)
        self.assertEqual(ping, 125)

    def test_udp_probe_packet_format_and_retry_rtt(self):
        class FakeSocket:
            def __init__(self): self.sent = []; self.calls = 0
            def settimeout(self, value): pass
            def connect(self, address): pass
            def send(self, packet): self.sent.append(packet)
            def recv(self, size):
                self.calls += 1
                if self.calls == 1: raise __import__("socket").timeout()
                return b"\x20"
            def close(self): pass
        fake = FakeSocket()
        ticks = iter([0.0, 1.5, 1.53])
        with mock.patch.object(fetch_servers.socket, "socket", return_value=fake), \
             mock.patch.object(fetch_servers.time, "monotonic", side_effect=lambda: next(ticks)), \
             mock.patch.object(fetch_servers.os, "urandom", return_value=b"12345678"):
            alive, ping = fetch_servers.check_udp_health("198.51.100.1", 1194)
        self.assertTrue(alive)
        self.assertEqual(fake.sent[0], b"\x38" + b"12345678" + b"\x00" + (1).to_bytes(4, "big"))
        self.assertEqual(ping, 30)

    def test_vpngate_speed_mbps(self):
        import base64
        row = [""] * 15
        row[4] = "25000000"
        row[5] = "Test"
        row[6] = "US"
        row[14] = base64.b64encode(b"client\nremote 198.51.100.1 1194 udp").decode()
        response = mock.Mock(text="header\n#comment\n" + ",".join(row))
        response.raise_for_status.return_value = None
        with mock.patch.object(fetch_servers.requests, "get", return_value=response):
            results = fetch_servers.fetch_vpngate()
        self.assertEqual(results[0]["speed_mbps"], 25.0)

    def test_endpoint_deduplication_prefers_approved_source(self):
        profile = "client\nremote 198.51.100.1 1194 udp\n"
        records = [
            {"ovpn_text": profile, "source": "fox3000foxy/OVPN-Configs-scraper"},
            {"ovpn_text": profile, "source": "VPNGate"},
        ]
        unique = fetch_servers.deduplicate_candidates(records)
        self.assertEqual(len(unique), 1)
        self.assertEqual(next(iter(unique.values()))["source"], "VPNGate")

    def test_aes_256_cbc_is_preserved(self):
        patched = fetch_servers.patch_ovpn_config("client\ncipher AES-256-CBC\n", False)
        self.assertIn("AES-256-CBC", patched)
        self.assertIn("AES-128-CBC", patched)
        self.assertIn("data-ciphers-fallback AES-256-CBC", patched)
        self.assertNotIn("data-ciphers-fallback AES-256-CBC:AES-128-CBC", patched)

    def test_aes_128_cbc_is_selected_as_single_fallback_when_declared(self):
        patched = fetch_servers.patch_ovpn_config("client\ncipher AES-128-CBC\n", False)
        self.assertIn("data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC:CHACHA20-POLY1305", patched)
        self.assertIn("data-ciphers-fallback AES-128-CBC", patched)
    def test_leap_provider_emits_both_udp_and_tcp_profiles(self):
        provider = mock.Mock()
        provider.json.return_value = {
            "api_uri": "https://riseup.example",
            "api_version": "3",
            "ca_cert_uri": "https://riseup.example/ca.crt",
        }
        ca = mock.Mock(text="-----BEGIN CERTIFICATE-----\\nCA\\n-----END CERTIFICATE-----")
        gateways = mock.Mock()
        gateways.json.return_value = {
            "gateways": [{
                "ip_address": "198.51.100.10",
                "location": "test",
                "capabilities": {"transport": [{
                    "type": "openvpn",
                    "protocols": ["udp", "tcp"],
                    "ports": [1194, 443],
                }]},
            }],
            "locations": {},
            "openvpn_configuration": {},
        }
        cert = mock.Mock(text=(
            "-----BEGIN CERTIFICATE-----\\nCLIENT\\n-----END CERTIFICATE-----\\n"
            "-----BEGIN PRIVATE KEY-----\\nKEY\\n-----END PRIVATE KEY-----"
        ))
        for response in (provider, ca, gateways, cert):
            response.raise_for_status.return_value = None
        with mock.patch.object(fetch_servers.requests, "get",
                               side_effect=(provider, ca, gateways, cert)):
            profiles = fetch_servers.fetch_leap_provider(
                "RiseupVPN", "https://riseup.example/provider.json", "riseup"
            )
        self.assertEqual({fetch_servers.extract_server_endpoint(p["ovpn_text"])[2]
                          for p in profiles}, {"udp", "tcp"})
        self.assertEqual(len(profiles), 2)

    def test_private_or_unknown_source_is_rejected(self):
        record = {
            "source": "unknown", "_publishable": True,
        }
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                fetch_servers.write_output_bundle([record], os.path.join(temp, "dist"))


if __name__ == "__main__":
    unittest.main()

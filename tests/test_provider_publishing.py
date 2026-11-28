import json
import os
import tempfile
import unittest

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
                "ping_ms": 10, "source": source, "_publishable": True,
                "username": "", "password": "", "config_path": f"configs/{server_id}.ovpn",
                "config_url": f"{fetch_servers.CDN_BASE_URL}/configs/{server_id}.ovpn",
                "_ovpn_text": "client\ndev tun\nproto udp\nremote 198.51.100.10 1194\n",
            })
        with tempfile.TemporaryDirectory() as temp:
            output = os.path.join(temp, "dist")
            fetch_servers.write_output_bundle(records, output)
            with open(os.path.join(output, "servers_meta.json"), encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual({item["source"] for item in payload["servers"]},
                             {"vpngate", "riseup", "calyx"})
            self.assertEqual(payload["total_servers"], 3)
            self.assertEqual(len(os.listdir(os.path.join(output, "configs"))), 3)

    def test_private_or_unknown_source_is_rejected(self):
        record = {
            "source": "unknown", "_publishable": True,
        }
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                fetch_servers.write_output_bundle([record], os.path.join(temp, "dist"))


if __name__ == "__main__":
    unittest.main()

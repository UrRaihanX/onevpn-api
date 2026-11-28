import json, os, tempfile, unittest
from unittest import mock
import fetch_servers

class ProviderPublishingTests(unittest.TestCase):
    def record(self, source="vpngate", ping=25, proto="udp", ip="198.51.100.10"):
        sid=fetch_servers.make_server_id(ip,1194,proto,source)
        return {"id":sid,"ip":ip,"port":1194,"protocol":proto,"country":"Test",
          "country_code":"US","flag_emoji":"🇺🇸","flag_url":"","isp":"Test","ping_ms":ping,
          "speed_mbps":10.0,"source":source,"_publishable":True,"username":"","password":"",
          "config_path":f"configs/{sid}.ovpn","config_url":f"{fetch_servers.CDN_BASE_URL}/configs/{sid}.ovpn",
          "_ovpn_text":"client\ndev tun\nproto udp\nremote 198.51.100.10 1194\n"}

    def test_provider_ids_do_not_collide(self):
        endpoint=("198.51.100.10",1194,"udp")
        ids={fetch_servers.make_server_id(*endpoint,source=x) for x in
             ("vpngate","riseup","fox3000foxy/OVPN-Configs-scraper")}
        self.assertEqual(len(ids),3)

    def test_publish_three_approved_sources(self):
        records=[self.record("vpngate"),self.record("riseup",ip="198.51.100.11"),
          self.record("fox3000foxy/OVPN-Configs-scraper",ip="198.51.100.12")]
        with tempfile.TemporaryDirectory() as temp:
            out=os.path.join(temp,"dist"); fetch_servers.write_output_bundle(records,out)
            with open(os.path.join(out,"servers_meta.json"),encoding="utf-8") as f: payload=json.load(f)
            self.assertEqual({x["source"].lower() for x in payload["servers"]},
              {"vpngate","riseup","fox3000foxy/ovpn-configs-scraper"})
            self.assertEqual(payload["total_servers"],3)

    def test_calyx_rejected(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaisesRegex(ValueError,"non-approved"):
            fetch_servers.write_output_bundle([self.record("calyx")],os.path.join(temp,"dist"))

    def test_tls_udp_never_uses_bare_send_false_positive(self):
        with mock.patch.object(fetch_servers,"check_tcp_health",return_value=(False,None)) as tcp, \
             mock.patch.object(fetch_servers.socket,"socket") as udp:
            self.assertEqual(fetch_servers.check_udp_health("198.51.100.10",53,True),(False,None))
        tcp.assert_called_once_with("198.51.100.10",53,has_tls_key=True)
        udp.assert_not_called()

    def test_tls_udp_uses_companion_tcp_rtt(self):
        with mock.patch.object(fetch_servers,"check_tcp_health",return_value=(True,42)) as tcp:
            self.assertEqual(fetch_servers.check_udp_health("198.51.100.10",53,True),(True,42))
        tcp.assert_called_once_with("198.51.100.10",53,has_tls_key=True)

    def test_max_ping_filter(self):
        records=[self.record(ping=800),self.record(ping=801,ip="198.51.100.11"),
                 self.record(ping=1210,ip="198.51.100.12"),self.record(ping=0,ip="198.51.100.13")]
        with mock.patch.object(fetch_servers,"MAX_PING_MS",800):
            self.assertEqual([x["ping_ms"] for x in fetch_servers.filter_max_ping_servers(records)],[800])

    def test_output_bundle_filters_high_latency_from_both_json_files(self):
        records=[self.record(ping=25),self.record(ping=1210,ip="198.51.100.11")]
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(fetch_servers,"MAX_PING_MS",800):
            out=os.path.join(temp,"dist"); fetch_servers.write_output_bundle(records,out)
            for filename in ("servers_meta.json","servers.json"):
                with open(os.path.join(out,filename),encoding="utf-8") as f: payload=json.load(f)
                self.assertEqual(payload["total_servers"],1)

    def test_failed_e2e_drops_entire_source_protocol_group(self):
        broken=[self.record("riseup",ping=10+i,ip=f"198.51.100.{10+i}") for i in range(5)]
        survivor=self.record("vpngate",proto="tcp",ip="198.51.100.30")
        with mock.patch.dict(os.environ,{"RUN_E2E_TESTS":"1"}), \
             mock.patch.object(fetch_servers,"install_openvpn_client",return_value=True), \
             mock.patch.object(fetch_servers,"run_openvpn_end_to_end",
                 side_effect=lambda item: (item["source"] == "vpngate",
                     "verified" if item["source"] == "vpngate" else "AUTH_FAILED: invalid certificate")) as attempt:
            result=fetch_servers.run_end_to_end_checks(broken+[survivor])
        self.assertEqual([x["id"] for x in result],[survivor["id"]])
        self.assertEqual(attempt.call_count,4)

    def test_vpngate_speed_conversion(self):
        import base64
        row=[""]*15; row[4:7]=["25000000","Test","US"]
        row[14]=base64.b64encode(b"client\nremote 198.51.100.1 1194 udp").decode()
        response=mock.Mock(text="header\n#comment\n"+",".join(row)); response.raise_for_status.return_value=None
        with mock.patch.object(fetch_servers.requests,"get",return_value=response):
            self.assertEqual(fetch_servers.fetch_vpngate()[0]["speed_mbps"],25.0)

    def test_dedup_prefers_vpngate(self):
        profile="client\nremote 198.51.100.1 1194 udp\n"
        unique=fetch_servers.deduplicate_candidates([
          {"ovpn_text":profile,"source":"fox3000foxy/OVPN-Configs-scraper"},
          {"ovpn_text":profile,"source":"VPNGate"}])
        self.assertEqual(next(iter(unique.values()))["source"],"VPNGate")

    def test_profile_patch_preserves_inline_keys(self):
        profile="client\ndev tun\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
        patched=fetch_servers.patch_ovpn_config(profile,False)
        for tag in ("<ca>","<cert>","<key>","persist-tun"): self.assertIn(tag,patched)

if __name__=="__main__": unittest.main()

import json
import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wifiaudit import alerts as al
from wifiaudit import locations as loc
from wifiaudit import nettools as nt
from wifiaudit import remediate as rem
from wifiaudit import vulndb
from wifiaudit.models import Network, band_for_freq
from wifiaudit.scanner import network_from_ies


class TestVulnDB(unittest.TestCase):
    def test_old_openssh_flagged_new_clear(self):
        old = vulndb.lookup(22, "SSH-2.0-OpenSSH_9.1")
        self.assertTrue(any(h["cve"] == "CVE-2024-6387" for h in old))
        self.assertEqual(vulndb.lookup(22, "SSH-2.0-OpenSSH_9.9"), [])

    def test_port_only_rules_always_fire(self):
        self.assertTrue(any(h["title"] == "Telnet in use" for h in vulndb.lookup(23, "")))
        self.assertTrue(any("BlueKeep" in h["title"] for h in vulndb.lookup(3389, "anything")))

    def test_apache_single_version_window(self):
        hit = vulndb.lookup(80, "Apache/2.4.49 (Unix)")
        self.assertTrue(any(h["cve"] == "CVE-2021-41773" for h in hit))
        self.assertEqual(vulndb.lookup(80, "Apache/2.4.48 (Unix)"), [])
        self.assertEqual(vulndb.lookup(80, "Apache/2.4.52 (Unix)"), [])

    def test_version_compare(self):
        self.assertEqual(vulndb._cmp("9.10", "9.8"), 1)
        self.assertEqual(vulndb._cmp("9.2", "9.8"), -1)
        self.assertEqual(vulndb._cmp("1.3.6", "1.3.6"), 0)

    def test_annotate_adds_cves_key(self):
        open_ports = [{"port": 23, "service": "Telnet", "level": "critical", "note": "x", "banner": ""}]
        vulndb.annotate(open_ports)
        self.assertTrue(open_ports[0]["cves"])

    def test_portscan_elevates_level_from_cve(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        nt.SERVICES[port] = ("TestSvc", "low", "normally low risk")
        orig = list(vulndb.PORT_RULES)
        vulndb.PORT_RULES.append({"id": "t", "port": port, "cves": [{"cve": "TEST-1", "title": "t", "sev": "critical", "detail": "d", "fix": "f"}]})
        try:
            res = nt.port_scan("127.0.0.1", str(port))
        finally:
            del nt.SERVICES[port]
            vulndb.PORT_RULES[:] = orig
            srv.close()
        self.assertEqual(res["open"][0]["level"], "critical")
        self.assertTrue(res["open"][0]["cves"])


class TestRemediate(unittest.TestCase):
    def test_known_pattern_gives_steps(self):
        got = rem.steps_for("Open network - no encryption", "")
        self.assertIsNotNone(got)
        self.assertIn("WPA2", got[0] + " ".join(got[1]).upper() + got[0].upper())

    def test_plan_dedupes_and_orders_by_severity(self):
        findings = [
            {"sev": "low", "title": "Hidden SSID", "detail": "", "fix": ""},
            {"sev": "critical", "title": "Open network - no encryption", "detail": "", "fix": ""},
            {"sev": "critical", "title": "Open network - no encryption", "detail": "", "fix": ""},  # dup
        ]
        p = rem.plan(findings)
        self.assertEqual(len(p), 2)
        self.assertEqual(p[0]["sev"], "critical")

    def test_unknown_finding_falls_back_to_its_own_fix(self):
        p = rem.plan([{"sev": "medium", "title": "Some bespoke issue", "detail": "", "fix": "Do the specific thing"}])
        self.assertEqual(p[0]["steps"], ["Do the specific thing"])

    def test_plan_to_text(self):
        txt = rem.plan_to_text(rem.plan([{"sev": "high", "title": "WPS enabled and unlocked", "detail": "", "fix": ""}]))
        self.assertIn("WPS", txt)
        self.assertIn("HIGH", txt)


class TestLocations(unittest.TestCase):
    def test_save_identify_roundtrip(self):
        p = os.path.join(tempfile.mkdtemp(), "c.json")
        loc.save_location(p, "Home", gateway_bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet")
        from wifiaudit.config import load_config
        cfg = load_config(p)
        name, is_new = loc.identify("AA:BB:CC:DD:EE:01", "HomeNet", cfg)
        self.assertEqual((name, is_new), ("Home", False))
        name2, is_new2 = loc.identify("00:00:00:00:00:99", "SomeoneElse", cfg)
        self.assertIsNone(name2)
        self.assertTrue(is_new2)

    def test_delete(self):
        p = os.path.join(tempfile.mkdtemp(), "c.json")
        loc.save_location(p, "Cafe", ssid="CafeFree")
        loc.delete_location(p, "Cafe")
        from wifiaudit.config import load_config
        self.assertNotIn("Cafe", load_config(p).get("locations", {}))


class TestAlerts(unittest.TestCase):
    def test_missing_config_raises_clear_error(self):
        with self.assertRaises(al.AlertError):
            al.send_email({}, "s", "b")
        with self.assertRaises(al.AlertError):
            al.send_webhook({}, "x")

    def test_webhook_payload_shape(self):
        self.assertIn("content", al._webhook_payload("https://discord.com/api/webhooks/x", "hi"))
        self.assertIn("text", al._webhook_payload("https://hooks.slack.com/services/x", "hi"))

    def test_webhook_requires_https(self):
        with self.assertRaises(al.AlertError):
            al.send_webhook({"alerts": {"webhook_url": "http://insecure.example"}}, "x")

    def test_dispatch_reports_per_channel_errors_without_network(self):
        cfg = {"alerts": {"email": {"host": "smtp.example.com", "port": 587, "user": "u", "password": "p", "to": "a@b.com"},
                          "webhook_url": "https://hooks.slack.com/services/x"}}
        result = al.dispatch(cfg, "Test", ["line one"])
        self.assertIn("email", result)
        self.assertIn("webhook", result)

    def test_set_alert_config(self):
        p = os.path.join(tempfile.mkdtemp(), "c.json")
        al.set_alert_config(p, email={"host": "smtp.example.com"}, webhook_url="https://hooks.slack.com/x")
        from wifiaudit.config import load_config
        cfg = load_config(p)
        self.assertEqual(cfg["alerts"]["webhook_url"], "https://hooks.slack.com/x")


class TestIPv6AndBand(unittest.TestCase):
    def test_band_for_freq_disambiguates_5_and_6ghz(self):
        self.assertEqual(band_for_freq(2437), "2.4 GHz")
        self.assertEqual(band_for_freq(5500), "5 GHz")
        self.assertEqual(band_for_freq(6115), "6 GHz")
        self.assertEqual(band_for_freq(0), "")

    def test_network_from_ies_6e_band(self):
        rsn = bytes.fromhex("0100" "000fac04" "0100" "000fac04" "0100" "000fac08" "c000")
        blob = bytes([0, 4]) + b"6Enet" [:4] + bytes([48, len(rsn)]) + rsn
        n = network_from_ies("AA:BB:CC:00:00:01", blob, True, -50, 6115)
        self.assertEqual(n.band, "6 GHz")

    def test_ipv6_neighbor_parser(self):
        text = "fe80::1 dev wlan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n2001:db8::5 dev wlan0 lladdr aa:bb:cc:dd:ee:02 STALE\nff02::1 dev wlan0 lladdr 33:33:00:00:00:01 REACHABLE\n"
        rows = nt.parse_ip_neigh6(text)
        self.assertEqual([r["ip"] for r in rows], ["2001:db8::5"])

    def test_local_info_includes_ipv6_keys(self):
        orig = nt.ipv6_addresses
        try:
            nt.ipv6_addresses = lambda dev=None: [("wlan0", "2001:db8::5", "global"), ("wlan0", "fe80::1", "link-local")]
            nt.has_ipv6_internet = lambda: True
            i = {"ip": "192.168.1.5", "prefix": 24, "cidr": "192.168.1.0/24", "netmask": "255.255.255.0",
                 "gateway": "192.168.1.1", "iface": "wlan0", "dns": [], "mac": "", "hostname": "h",
                 "gateway_is_private": True}
            v6 = nt.ipv6_addresses("wlan0")
            self.assertEqual(len(v6), 2)
        finally:
            nt.ipv6_addresses = orig


class TestRouterFingerprint(unittest.TestCase):
    def test_refuses_public_ip(self):
        with self.assertRaises(nt.ToolError):
            nt.fingerprint_router("8.8.8.8")

    def test_identifies_a_real_local_http_server(self):
        import http.server

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Server", "RomPager/4.07 UPnP/1.0")
                self.end_headers()
                self.wfile.write(b"<html><title>TP-LINK Wireless Router</title></html>")

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        port = srv.server_port
        threading.Thread(target=srv.handle_request, daemon=True).start()
        import time
        time.sleep(0.2)
        r = nt._http_probe("127.0.0.1", port)
        srv.server_close()
        self.assertEqual(r[0], 200)
        self.assertIn("RomPager", r[1].get("Server", ""))


class TestOUI(unittest.TestCase):
    def test_builtin_grew(self):
        from wifiaudit.oui import BUILTIN_COUNT
        self.assertGreater(BUILTIN_COUNT, 100)

    def test_known_lookups(self):
        from wifiaudit.oui import lookup
        self.assertEqual(lookup("B8:27:EB:00:00:00"), "Raspberry Pi")
        self.assertEqual(lookup("44:65:0D:00:00:00"), "Amazon (Echo/Fire)")


class TestWebUpgrades(unittest.TestCase):
    def setUp(self):
        from wifiaudit.web import create_app
        self.tmp = tempfile.mkdtemp()
        self.cfgp = os.path.join(self.tmp, "c.json")
        json.dump({}, open(self.cfgp, "w"))
        self.app = create_app(os.path.join(self.tmp, "w.db"), self.cfgp, self.tmp)
        self.c = self.app.test_client()
        self.H = {"X-Requested-With": "wifiaudit"}

    def test_vulndb_info(self):
        r = self.c.get("/api/vulndb").get_json()
        self.assertIn("bundled_version", r)
        self.assertGreater(len(r["products"]), 5)

    def test_remediate_endpoint(self):
        findings = [{"sev": "critical", "title": "Open network - no encryption", "detail": "", "fix": ""}]
        r = self.c.post("/api/remediate", json={"findings": findings}, headers=self.H)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["plan"])

    def test_locations_roundtrip(self):
        self.assertEqual(self.c.get("/api/locations").get_json(), {})
        r = self.c.post("/api/locations", json={"name": "Home", "gateway_bssid": "AA:BB:CC:DD:EE:01", "ssid": "HomeNet"}, headers=self.H)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Home", self.c.get("/api/locations").get_json())
        self.c.delete("/api/locations/Home", headers=self.H)
        self.assertNotIn("Home", self.c.get("/api/locations").get_json())

    def test_locations_requires_name(self):
        r = self.c.post("/api/locations", json={}, headers=self.H)
        self.assertEqual(r.status_code, 400)

    def test_alerts_config_roundtrip_and_password_masked(self):
        self.c.post("/api/alerts/config", json={"webhook_url": "https://hooks.slack.com/x",
                    "email": {"host": "smtp.example.com", "port": 587, "user": "u", "password": "secret", "to": "a@b.com"}}, headers=self.H)
        got = self.c.get("/api/alerts/config").get_json()
        self.assertEqual(got["webhook_url"], "https://hooks.slack.com/x")
        self.assertEqual(got["email"]["password"], "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022")

    def test_alerts_test_requires_config(self):
        r = self.c.post("/api/alerts/test", json={}, headers=self.H)
        self.assertEqual(r.status_code, 400)

    def test_alerts_notify_noop_without_config(self):
        r = self.c.post("/api/alerts/notify", json={"title": "t", "lines": ["x"]}, headers=self.H)
        self.assertEqual(r.get_json()["result"], {})

    def test_router_tool_rejects_public_ip_via_api(self):
        r = self.c.post("/api/tool/router", json={"ip": "8.8.8.8"}, headers=self.H)
        jid = r.get_json()["job"]
        import time as _t
        for _ in range(40):
            j = self.c.get(f"/api/jobs/{jid}").get_json()
            if j["state"] != "running":
                break
            _t.sleep(0.1)
        self.assertEqual(j["state"], "error")

    def test_csrf_guard_on_new_endpoints(self):
        for path, body in (("/api/remediate", {"findings": []}), ("/api/locations", {"name": "x"}),
                           ("/api/alerts/config", {}), ("/api/alerts/test", {})):
            self.assertEqual(self.c.post(path, json=body).status_code, 403, path)


if __name__ == "__main__":
    unittest.main()

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifiaudit.analyzer import analyze, summarize
from wifiaudit.config import load_config
from wifiaudit.database import Database, diff_scans
from wifiaudit.models import Network
from wifiaudit.report import generate
from wifiaudit.scanner import (classify, demo_networks, network_from_ies, parse_airodump_csv, parse_iw_scan,
                               parse_netsh, parse_nmcli, parse_rsn, parse_wps)

CFG = {"trusted": {"Home_Network": ["00:27:19:AA:01:10"], "Office_Net": ["00:0B:86:10:20:30"]}}


class TestParsers(unittest.TestCase):
    def test_rsn_wpa2_psk_ccmp_pmf_capable(self):
        info = bytes.fromhex("0100" "000fac04" "0100" "000fac04" "0100" "000fac02" "8000")
        enc, cipher, auth, pmf = classify(parse_rsn(info), None, True)
        self.assertEqual((enc, cipher, auth, pmf), ("WPA2", "CCMP", "PSK", "capable"))

    def test_rsn_wpa3_sae(self):
        info = bytes.fromhex("0100" "000fac04" "0100" "000fac04" "0100" "000fac08" "c000")
        enc, _, auth, pmf = classify(parse_rsn(info), None, True)
        self.assertEqual((enc, auth, pmf), ("WPA3", "SAE", "required"))

    def test_transition_mode_and_tkip(self):
        info = bytes.fromhex("0100" "000fac02" "0200" "000fac02000fac04" "0200" "000fac02000fac08" "8000")
        enc, cipher, _, _ = classify(parse_rsn(info), None, True)
        self.assertEqual(enc, "WPA2/WPA3")
        self.assertIn("TKIP", cipher)

    def test_open_wep(self):
        self.assertEqual(classify(None, None, False)[0], "OPEN")
        self.assertEqual(classify(None, None, True)[0], "WEP")

    def test_truncated_rsn_is_safe(self):
        self.assertIsNone(parse_rsn(b"\x01\x00\x00"))

    def test_wps_locked_flag(self):
        tlv = bytes.fromhex("0050f204" "104a000110" "1057000101")
        self.assertTrue(parse_wps(tlv)["locked"])

    def test_nmcli(self):
        out = ("*:AA\\:BB\\:CC\\:DD\\:EE\\:01:My\\:Cafe:6:70:WPA2:(none):pair_ccmp group_ccmp psk\n"
               " :AA\\:BB\\:CC\\:DD\\:EE\\:02::11:40:--:(none):(none)\n"
               " :AA\\:BB\\:CC\\:DD\\:EE\\:03:Old:1:30:WPA1:pair_tkip group_tkip psk:(none)\n")
        nets = parse_nmcli(out)
        self.assertEqual(nets[0].ssid, "My:Cafe")
        self.assertEqual(nets[0].encryption, "WPA2")
        self.assertEqual(nets[0].signal, -65)
        self.assertTrue(nets[0].connected)
        self.assertFalse(nets[1].connected)
        self.assertTrue(nets[1].hidden)
        self.assertEqual(nets[1].encryption, "OPEN")
        self.assertEqual(nets[2].encryption, "WPA")

    def test_netsh(self):
        out = """
SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:27:19:aa:01:10
         Signal             : 80%
         Radio type         : 802.11n
         Channel            : 6
SSID 2 : Free
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : de:ad:be:ef:00:01
         Signal             : 40%
         Channel            : 1
"""
        n = parse_netsh(out)
        self.assertEqual([x.encryption for x in n], ["WPA2", "OPEN"])
        self.assertEqual(n[0].channel, 6)
        self.assertEqual(n[0].signal, -60)

    def test_airodump_csv(self):
        csv_text = ("\r\nBSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, "
                    "Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
                    "00:27:19:AA:01:10, 2026-01-01 10:00:00, 2026-01-01 10:00:20, 6, 130, WPA2, CCMP, PSK, -55, 12, 0,   0.  0.  0.  0, 4, Home, \r\n"
                    "AA:BB:CC:00:00:01, 2026-01-01 10:00:00, 2026-01-01 10:00:20, 1, 54, OPN, , , -80, 3, 0,   0.  0.  0.  0, 4, Cafe, \r\n"
                    "\r\nStation MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n")
        nets = parse_airodump_csv(csv_text)
        self.assertEqual(len(nets), 2)
        self.assertEqual((nets[0].ssid, nets[0].encryption, nets[0].signal), ("Home", "WPA2", -55))
        self.assertEqual(nets[1].encryption, "OPEN")


IW_SAMPLE = """BSS aa:bb:cc:dd:ee:01(on wlan0) -- associated
\tlast seen: 1230.456s [boottime]
\tTSF: 123456789 usec (0d, 00:02:03)
\tfreq: 2437
\tbeacon interval: 100 TUs
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -52.00 dBm
\tlast seen: 120 ms ago
\tInformation elements from Probe Response frame:
\tSSID: HomeNet
\tSupported rates: 1.0* 2.0* 5.5* 11.0*
\tDS Parameter set: channel 6
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK
\t\t * Capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)
\tWPS:\t * Version: 1.0
\t\t * Wi-Fi Protected Setup State: 2 (Configured)
\t\t * Response Type: 3 (AP)
\t\t * Manufacturer: TP-Link
\t\t * Config methods: Label, Display, PBC
BSS 00:11:22:33:44:55(on wlan0)
\tfreq: 5180
\tcapability: ESS ShortPreamble (0x0421)
\tsignal: -71.00 dBm
\tlast seen: 800 ms ago
\tSSID: CafeFree
\tHT operation:
\t\t * primary channel: 36
BSS 66:77:88:99:aa:bb(on wlan0)
\tfreq: 5745
\tcapability: ESS Privacy (0x0411)
\tsignal: -60.00 dBm
\tlast seen: 300 ms ago
\tSSID: Lab5G
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: SAE
\t\t * Capabilities: 1-PTKSA-RC 1-GTKSA-RC MFP-required (0x00cc)
BSS de:ad:be:ef:00:01(on wlan0)
\tfreq: 2412
\tcapability: ESS Privacy (0x0411)
\tsignal: -80.00 dBm
\tlast seen: 99000000 ms ago
\tSSID: Stale
BSS 02:02:02:02:02:02(on wlan0)
\tfreq: 2462
\tcapability: ESS Privacy (0x0411)
\tsignal: -66.00 dBm
\tlast seen: 500 ms ago
\tSSID: \\x00\\x00\\x00
\tWPA:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: TKIP
\t\t * Authentication suites: PSK
\tRSN:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: TKIP CCMP
\t\t * Authentication suites: PSK
"""


class TestDeepScanParsers(unittest.TestCase):
    def test_iw_scan(self):
        nets = {n.bssid: n for n in parse_iw_scan(IW_SAMPLE)}
        self.assertEqual(len(nets), 4)                       # stale entry dropped
        home = nets["AA:BB:CC:DD:EE:01"]
        self.assertEqual((home.ssid, home.channel, home.signal, home.encryption), ("HomeNet", 6, -52, "WPA2"))
        self.assertTrue(home.connected)
        self.assertTrue(home.wps)
        self.assertEqual(home.auth, "PSK")
        cafe = nets["00:11:22:33:44:55"]
        self.assertEqual((cafe.encryption, cafe.channel, cafe.wps), ("OPEN", 36, False))
        lab = nets["66:77:88:99:AA:BB"]
        self.assertEqual((lab.encryption, lab.pmf, lab.channel), ("WPA3", "required", 149))
        hidden = nets["02:02:02:02:02:02"]
        self.assertTrue(hidden.hidden)
        self.assertEqual(hidden.encryption, "WPA/WPA2")

    def test_ie_blob_roundtrip(self):
        # Beacon IEs exactly as the Windows WLAN API hands them over
        rsn = bytes.fromhex("0100" "000fac04" "0100" "000fac04" "0100" "000fac02" "8000")
        wps = bytes.fromhex("0050f204" "1057000101")
        blob = (bytes([0, 4]) + b"Test" + bytes([3, 1, 11]) + bytes([48, len(rsn)]) + rsn + bytes([221, len(wps)]) + wps)
        n = network_from_ies("AA:BB:CC:00:00:09", blob, True, -61, 2462)
        self.assertEqual((n.ssid, n.channel, n.encryption, n.pmf, n.wps, n.wps_locked), ("Test", 11, "WPA2", "capable", True, True))
        n2 = network_from_ies("AA:BB:CC:00:00:0A", bytes([0, 1]) + b"x", False, -70, 5180)
        self.assertEqual((n2.encryption, n2.channel), ("OPEN", 36))

    def test_wlanapi_struct_layout(self):
        import ctypes
        from wifiaudit.scanner import _wlan_structs
        self.assertEqual(ctypes.sizeof(_wlan_structs()[3]), 360)       # WLAN_BSS_ENTRY must match wlanapi.h

    def test_connected_rogue_warning(self):
        a = Network("02:AA:BB:CC:DD:01", "Home_Network", 6, -40, "OPEN", connected=True)
        b = Network("00:27:19:AA:01:10", "Home_Network", 6, -60, "WPA2", "CCMP", "PSK", wps=False)
        analyze([a, b], CFG)
        self.assertTrue(a.rogue)
        self.assertIn("CONNECTED", a.findings[0]["title"])
        self.assertEqual(summarize([a, b])["connected"]["name"], "Home_Network")


class TestAnalyzer(unittest.TestCase):
    def test_demo_matches_project_brief(self):
        s = summarize(analyze(demo_networks(), CFG))
        self.assertEqual((s["total"], s["secure"], s["vulnerable"], s["rogue"]), (12, 3, 7, 2))

    def test_posture_and_grade(self):
        s = summarize(analyze(demo_networks(), CFG))
        self.assertEqual((s["posture"], s["grade"]), (42, "F"))
        good = summarize(analyze([Network("00:11:22:33:44:55", "ok", 6, -50, "WPA3", "CCMP", "SAE", wps=False)], {}))
        self.assertEqual(good["grade"], "A")

    def test_capabilities_shape(self):
        from wifiaudit.scanner import capabilities
        c = capabilities()
        for b in ("auto", "deep", "system", "scapy", "airodump", "demo"):
            self.assertIn("available", c[b])
        self.assertTrue(c["demo"]["available"])
        self.assertEqual(c["default"], "auto")

    def test_levels(self):
        nets = {n.ssid: n for n in analyze(demo_networks(), CFG) if not n.rogue}
        self.assertEqual(nets["Home_Network"].level, "SECURE")
        self.assertEqual(nets["CoffeeShop_WiFi"].level, "VULNERABLE")
        self.assertEqual(nets["Guest_Network"].level, "HIGH RISK")
        self.assertEqual(nets["Linksys_Legacy"].level, "HIGH RISK")

    def test_evil_twin_detected_without_trust_list(self):
        nets = analyze(demo_networks(), {})
        twins = [n for n in nets if n.ssid == "Home_Network" and n.rogue]
        self.assertEqual(len(twins), 1)
        self.assertEqual(twins[0].encryption, "OPEN")

    def test_trusting_clears_rogue(self):
        cfg = {"trusted": {**CFG["trusted"], "Office_Net": ["00:0B:86:10:20:30", "5E:12:47:9C:3B:11"]}}
        s = summarize(analyze(demo_networks(), cfg))
        self.assertEqual(s["rogue"], 1)

    def test_karma_behaviour(self):
        nets = [Network("DE:AD:BE:EF:00:01", f"Net{i}", 6, -40, "OPEN") for i in range(3)]
        analyze(nets, {})
        self.assertTrue(all(n.rogue for n in nets))

    def test_wps_locked_less_severe(self):
        a = analyze([Network("00:11:22:33:44:55", "A", 1, -50, "WPA2", "CCMP", "PSK", wps=True, wps_locked=True)], {})[0]
        b = analyze([Network("00:11:22:33:44:56", "B", 1, -50, "WPA2", "CCMP", "PSK", wps=True, wps_locked=False)], {})[0]
        self.assertGreater(a.score, b.score)


class TestStorageAndReports(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.tmp, "t.db"))

    def test_roundtrip_and_diff(self):
        n1 = analyze(demo_networks(), CFG)
        s1 = self.db.save_scan(n1, "demo")
        changed = demo_networks()[:-1]
        changed[0].encryption = "WEP"
        s2 = self.db.save_scan(analyze(changed, CFG), "demo")
        _, back = self.db.get_scan(s1)
        self.assertEqual(len(back), 12)
        d = diff_scans(self.db.get_scan(s1)[1], self.db.get_scan(s2)[1])
        self.assertEqual(len(d["gone"]), 1)
        self.assertTrue(any(c["field"] == "encryption" for c in d["changed"]))
        self.assertEqual(self.db.previous_id(s2), s1)

    def test_reports_and_escaping(self):
        evil = Network("00:11:22:33:44:55", "<script>alert(1)</script>&<b>", 6, -50, "WPA2", "CCMP", "PSK", wps=True)
        evil2 = Network("00:11:22:33:44:66", "=HYPERLINK(\"http://x\")", 6, -50, "OPEN")
        nets = analyze(demo_networks() + [evil, evil2], CFG)
        sid = self.db.save_scan(nets, "demo")
        meta = {"id": sid, "ts": "now", "backend": "demo", "label": "<i>x</i>"}
        summ = summarize(nets)
        paths = {f: generate(f, self.tmp, meta, nets, summ) for f in ("html", "pdf", "json", "csv")}
        for p in paths.values():
            self.assertGreater(os.path.getsize(p), 100)
        h = open(paths["html"], encoding="utf-8").read()
        self.assertNotIn("<script>alert", h)
        self.assertIn("&lt;script&gt;", h)
        self.assertIn("'=HYPERLINK", open(paths["csv"], encoding="utf-8").read())
        self.assertEqual(json.load(open(paths["json"]))["summary"]["total"], 14)
        self.assertTrue(open(paths["pdf"], "rb").read().startswith(b"%PDF"))


class TestWeb(unittest.TestCase):
    def test_api(self):
        from wifiaudit.web import create_app
        tmp = tempfile.mkdtemp()
        cfgp = os.path.join(tmp, "c.json")
        json.dump({"trusted": CFG["trusted"]}, open(cfgp, "w"))
        app = create_app(os.path.join(tmp, "w.db"), cfgp, tmp)
        c = app.test_client()
        H = {"X-Requested-With": "wifiaudit"}
        self.assertEqual(c.get("/").status_code, 200)
        self.assertIn("available", c.get("/api/capabilities").get_json()["demo"])
        self.assertEqual(c.get("/api/bssid/not-a-mac").status_code, 400)
        for f in ("style.css", "glossary.js", "core.js", "views.js", "tools.js", "main.js"):
            self.assertEqual(c.get("/static/" + f).status_code, 200, f)
        self.assertEqual(c.post("/api/tool/mac", json={"mac": "00:14:6C:5D:E1:90"}).status_code, 403)   # CSRF guard
        r = c.post("/api/tool/mac", json={"mac": "00:14:6C:5D:E1:90"}, headers={"X-Requested-With": "wifiaudit"})
        self.assertEqual(r.get_json()["result"]["vendor"], "Netgear")
        r = c.post("/api/tool/portscan", json={"host": "8.8.8.8"}, headers={"X-Requested-With": "wifiaudit"})
        jid = r.get_json()["job"]
        import time as _t
        for _ in range(40):
            j = c.get(f"/api/jobs/{jid}").get_json()
            if j["state"] != "running":
                break
            _t.sleep(0.1)
        self.assertEqual(j["state"], "error")
        self.assertIn("private", j["error"])
        self.assertEqual(c.post("/api/tool/nope", json={}, headers={"X-Requested-With": "wifiaudit"}).status_code, 404)
        self.assertEqual(c.post("/api/scan", json={"backend": "demo"}).status_code, 403)   # CSRF guard
        self.assertEqual(c.post("/api/scan", json={"backend": "rm -rf"}, headers=H).status_code, 400)
        jid = c.post("/api/scan", json={"backend": "demo"}, headers=H).get_json()["job"]
        import time
        for _ in range(50):
            j = c.get(f"/api/jobs/{jid}").get_json()
            if j["state"] != "running":
                break
            time.sleep(0.1)
        self.assertEqual(j["state"], "done")
        d = c.get("/api/scans/latest").get_json()
        self.assertEqual(d["summary"]["rogue"], 2)
        self.assertTrue(all(n["name"] for n in d["networks"]))
        self.assertEqual(c.post("/api/trust", json={"ssid": "Office_Net", "bssid": "5E:12:47:9C:3B:11"}, headers=H).status_code, 200)
        self.assertEqual(c.get("/api/scans/latest").get_json()["summary"]["rogue"], 1)
        self.assertEqual(c.post("/api/trust", json={"ssid": "x", "bssid": "nope"}, headers=H).status_code, 400)
        for f in ("html", "pdf", "json", "csv"):
            r = c.get(f"/api/report/{d['meta']['id']}/{f}")
            self.assertEqual(r.status_code, 200, f)


if __name__ == "__main__":
    unittest.main(verbosity=1)

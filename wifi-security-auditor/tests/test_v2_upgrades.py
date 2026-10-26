import datetime
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wifiaudit import coverage as cov
from wifiaudit import history_db as hdb
from wifiaudit import nettools as nt
from wifiaudit import remediate as rem
from wifiaudit.report import generate, render_remediation_pdf


class TestDistance(unittest.TestCase):
    def test_closer_signal_means_shorter_distance(self):
        near, _ = cov.estimate_distance(-40)
        far, _ = cov.estimate_distance(-80)
        self.assertLess(near, far)

    def test_reference_signal_is_about_1_metre(self):
        meters, _ = cov.estimate_distance(cov.DEFAULT_REF_DBM_AT_1M, "open")
        self.assertAlmostEqual(meters, 1.0, delta=0.2)

    def test_none_signal_handled(self):
        self.assertEqual(cov.estimate_distance(None), (None, "No signal reading available."))

    def test_environments_change_the_estimate(self):
        # A denser environment attenuates signal faster per metre, so the SAME weak reading
        # implies a shorter real distance there than in open air.
        open_m, _ = cov.estimate_distance(-70, "open")
        dense_m, _ = cov.estimate_distance(-70, "dense")
        self.assertGreater(open_m, dense_m)


class TestCoverageMap(unittest.TestCase):
    def setUp(self):
        self.db = cov.CoverageMap(os.path.join(tempfile.mkdtemp(), "cov.db"))

    def test_add_and_list(self):
        self.db.add_point("Home", 0.2, 0.3, -55, ssid="HomeNet")
        self.db.add_point("Home", 0.8, 0.1, -75, ssid="HomeNet")
        pts = self.db.points("Home")
        self.assertEqual(len(pts), 2)
        s = cov.summarize(pts)
        self.assertEqual(s["count"], 2)
        self.assertEqual(s["worst"]["dbm"], -75)

    def test_rejects_out_of_range_coords(self):
        with self.assertRaises(ValueError):
            self.db.add_point("Home", 1.5, 0.5, -60)

    def test_locations_separate(self):
        self.db.add_point("Home", 0.1, 0.1, -50)
        self.db.add_point("Office", 0.1, 0.1, -60)
        self.assertEqual(len(self.db.points("Home")), 1)
        self.assertEqual(len(self.db.points("Office")), 1)
        names = {l["location"] for l in self.db.locations()}
        self.assertEqual(names, {"Home", "Office"})

    def test_clear_and_delete(self):
        pid = self.db.add_point("Home", 0.1, 0.1, -50)
        self.db.add_point("Home", 0.2, 0.2, -60)
        self.db.delete_point(pid)
        self.assertEqual(len(self.db.points("Home")), 1)
        self.db.clear("Home")
        self.assertEqual(len(self.db.points("Home")), 0)

    def test_summarize_empty(self):
        self.assertEqual(cov.summarize([]), {"count": 0})


class TestSignalHistory(unittest.TestCase):
    def setUp(self):
        self.db = hdb.SignalHistory(os.path.join(tempfile.mkdtemp(), "sig.db"))

    def test_log_and_fetch(self):
        self.db.log("AA:BB:CC:DD:EE:01", "HomeNet", -55)
        self.db.log("AA:BB:CC:DD:EE:01", "HomeNet", -58)
        pts = self.db.history("AA:BB:CC:DD:EE:01")
        self.assertEqual(len(pts), 2)

    def test_ignores_missing_dbm(self):
        self.db.log("AA:BB:CC:DD:EE:01", "HomeNet", None)
        self.assertEqual(self.db.history(), [])

    def test_known_networks(self):
        self.db.log("AA:BB:CC:DD:EE:01", "HomeNet", -55)
        self.db.log("AA:BB:CC:DD:EE:02", "OfficeNet", -60)
        names = {n["bssid"] for n in self.db.known_networks()}
        self.assertEqual(names, {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"})

    def test_rollup_keeps_table_bounded(self):
        hdb.MAX_ROWS_ORIG = hdb.MAX_ROWS
        hdb.MAX_ROWS = 5
        try:
            old_ts = (datetime.datetime.now() - datetime.timedelta(days=2)).isoformat(timespec="seconds")
            with self.db._conn() as c:
                for i in range(10):
                    c.execute("INSERT INTO signal_log(ts, bssid, ssid, dbm) VALUES(?,?,?,?)",
                             (old_ts, "AA:BB:CC:DD:EE:01", "HomeNet", -50 - i))
            self.db.log("AA:BB:CC:DD:EE:01", "HomeNet", -55)
            with self.db._conn() as c:
                n = c.execute("SELECT COUNT(*) n FROM signal_log").fetchone()["n"]
            self.assertLess(n, 11)
        finally:
            hdb.MAX_ROWS = hdb.MAX_ROWS_ORIG


class TestScheduler(unittest.TestCase):
    def test_daily_next_run_today_or_tomorrow(self):
        now = datetime.datetime(2026, 1, 1, 8, 0)
        nxt = hdb.next_run({"frequency": "daily", "time": "09:00"}, now)
        self.assertEqual(nxt, datetime.datetime(2026, 1, 1, 9, 0))
        now2 = datetime.datetime(2026, 1, 1, 10, 0)
        nxt2 = hdb.next_run({"frequency": "daily", "time": "09:00"}, now2)
        self.assertEqual(nxt2, datetime.datetime(2026, 1, 2, 9, 0))

    def test_weekly_next_run(self):
        now = datetime.datetime(2026, 1, 1, 8, 0)   # a Thursday
        nxt = hdb.next_run({"frequency": "weekly", "time": "09:00", "weekday": 0}, now)   # next Monday
        self.assertEqual(nxt.weekday(), 0)
        self.assertGreater(nxt, now)

    def test_hourly_next_run(self):
        now = datetime.datetime(2026, 1, 1, 8, 15)
        nxt = hdb.next_run({"frequency": "hourly"}, now)
        self.assertEqual(nxt, datetime.datetime(2026, 1, 1, 9, 0))

    def test_is_due_logic(self):
        sched = {"enabled": True, "frequency": "daily", "time": "09:00"}
        self.assertTrue(hdb.is_due(sched, None))
        last = datetime.datetime(2026, 1, 1, 9, 5).isoformat(timespec="seconds")
        self.assertFalse(hdb.is_due(sched, last, datetime.datetime(2026, 1, 1, 10, 0)))
        self.assertTrue(hdb.is_due(sched, last, datetime.datetime(2026, 1, 2, 9, 1)))

    def test_disabled_never_due(self):
        self.assertFalse(hdb.is_due({"enabled": False}, None))


class TestSpeedTestMath(unittest.TestCase):
    def test_mbps_calc(self):
        self.assertEqual(nt._mbps(12_500_000, 1.0), 100.0)
        self.assertEqual(nt._mbps(0, 1.0), 0.0)
        self.assertEqual(nt._mbps(1000, 0), 0.0)

    def test_speed_test_raises_cleanly_offline(self):
        with self.assertRaises(nt.ToolError):
            nt.speed_test(max_seconds=1)


class TestGuestCheck(unittest.TestCase):
    def test_guest_name_detection_and_verdict_bands(self):
        orig_link, orig_discover = nt.current_link, nt.discover
        try:
            nt.current_link = lambda: {"connected": True, "ssid": "Office_Guest"}
            nt.discover = lambda cidr=None: {"devices": [
                {"ip": "192.168.1.1", "is_self": False, "is_gateway": True},
                {"ip": "192.168.1.5", "is_self": True, "is_gateway": False}]}
            r = nt.guest_network_check()
            self.assertTrue(r["looks_like_guest_name"])
            self.assertEqual(r["risk"], "ok")

            nt.discover = lambda cidr=None: {"devices": [
                {"ip": "192.168.1.1", "is_self": False, "is_gateway": True},
                {"ip": "192.168.1.5", "is_self": True, "is_gateway": False},
                {"ip": "192.168.1.9", "is_self": False, "is_gateway": False},
                {"ip": "192.168.1.10", "is_self": False, "is_gateway": False},
                {"ip": "192.168.1.11", "is_self": False, "is_gateway": False}]}
            r2 = nt.guest_network_check()
            self.assertEqual(r2["risk"], "high")
        finally:
            nt.current_link, nt.discover = orig_link, orig_discover


class TestNetworkActivity(unittest.TestCase):
    def test_dedupes_and_categorizes_and_excludes_private(self):
        orig = nt.parse_ss
        try:
            nt.parse_ss = lambda text: [
                {"local_port": 1, "remote": "93.184.216.34", "remote_port": 443, "state": "ESTAB"},
                {"local_port": 2, "remote": "93.184.216.34", "remote_port": 443, "state": "ESTAB"},   # dup
                {"local_port": 3, "remote": "192.168.1.1", "remote_port": 80, "state": "ESTAB"},       # private, excluded
                {"local_port": 4, "remote": "1.2.3.4", "remote_port": 25, "state": "ESTAB"}]
            nt.shutil_which_bak = nt.shutil.which
            nt.shutil.which = lambda x: "/bin/ss" if x == "ss" else None
            nt.IS_WIN = False
            r = nt.network_activity()
            self.assertEqual(r["total"], 2)
            self.assertEqual(r["by_category"].get("Web (encrypted)"), 1)
            self.assertEqual(r["by_category"].get("Email"), 1)
        finally:
            nt.parse_ss = orig
            nt.shutil.which = nt.shutil_which_bak


class TestRemediationPDF(unittest.TestCase):
    def test_renders_valid_pdf(self):
        plan = rem.plan([{"sev": "critical", "title": "Open network - no encryption", "detail": "", "fix": ""}])
        path = os.path.join(tempfile.mkdtemp(), "plan.pdf")
        render_remediation_pdf(path, plan)
        with open(path, "rb") as f:
            data = f.read()
        self.assertTrue(data.startswith(b"%PDF"))
        self.assertGreater(len(data), 500)

    def test_renders_empty_plan(self):
        path = os.path.join(tempfile.mkdtemp(), "plan.pdf")
        render_remediation_pdf(path, [])
        self.assertTrue(open(path, "rb").read().startswith(b"%PDF"))


class TestWebV2(unittest.TestCase):
    def setUp(self):
        from wifiaudit.web import create_app
        self.tmp = tempfile.mkdtemp()
        self.cfgp = os.path.join(self.tmp, "c.json")
        json.dump({}, open(self.cfgp, "w"))
        self.app = create_app(os.path.join(self.tmp, "w.db"), self.cfgp, self.tmp)
        self.c = self.app.test_client()
        self.H = {"X-Requested-With": "wifiaudit"}

    def test_coverage_roundtrip(self):
        self.assertEqual(self.c.get("/api/coverage/Home").get_json()["points"], [])
        r = self.c.post("/api/coverage/Home", json={"x": 0.4, "y": 0.6, "dbm": -60}, headers=self.H)
        self.assertEqual(r.status_code, 200)
        pts = self.c.get("/api/coverage/Home").get_json()["points"]
        self.assertEqual(len(pts), 1)
        self.c.delete(f"/api/coverage/Home/{pts[0]['id']}", headers=self.H)
        self.assertEqual(self.c.get("/api/coverage/Home").get_json()["points"], [])

    def test_coverage_rejects_bad_input(self):
        r = self.c.post("/api/coverage/Home", json={"x": 2, "y": 0.5, "dbm": -60}, headers=self.H)
        self.assertEqual(r.status_code, 400)
        r2 = self.c.post("/api/coverage/Home", json={"x": "nope"}, headers=self.H)
        self.assertEqual(r2.status_code, 400)

    def test_signal_history_endpoint(self):
        r = self.c.get("/api/signal-history")
        self.assertEqual(r.status_code, 200)
        self.assertIn("points", r.get_json())

    def test_schedule_endpoints(self):
        r = self.c.post("/api/schedule", json={"enabled": True, "frequency": "daily", "time": "09:00"}, headers=self.H)
        self.assertTrue(r.get_json()["sched"]["enabled"])
        self.assertIsNotNone(r.get_json()["next_run"])
        got = self.c.get("/api/schedule").get_json()
        self.assertEqual(got["frequency"], "daily")

    def test_compare_endpoint_needs_two_valid_scans(self):
        r = self.c.get("/api/compare?a=1&b=2")
        self.assertEqual(r.status_code, 404)
        r2 = self.c.get("/api/compare")
        self.assertEqual(r2.status_code, 400)

    def test_remediate_pdf_download(self):
        r = self.c.post("/api/remediate/pdf", json={"findings": [{"sev": "high", "title": "WPS enabled and unlocked", "detail": "", "fix": ""}]}, headers=self.H)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data.startswith(b"%PDF"))

    def test_new_tools_require_csrf_header(self):
        for name in ("speedtest", "guestcheck", "activity"):
            self.assertEqual(self.c.post(f"/api/tool/{name}", json={}).status_code, 403)

    def test_guestcheck_tool_runs_as_job(self):
        r = self.c.post("/api/tool/guestcheck", json={}, headers=self.H)
        self.assertIn("job", r.get_json())

    def test_csrf_guard_covers_all_new_mutating_endpoints(self):
        for path in ("/api/coverage/Home", "/api/schedule", "/api/schedule/run-now", "/api/remediate/pdf"):
            self.assertEqual(self.c.post(path, json={}).status_code, 403, path)


if __name__ == "__main__":
    unittest.main()

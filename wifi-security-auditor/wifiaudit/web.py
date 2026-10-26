"""Flask dashboard: run scans, browse history, inspect findings, trust BSSIDs, export reports."""
from __future__ import annotations

import os
import re
import tempfile
import time
import threading
import uuid

from flask import Flask, Response, jsonify, request, send_file

from .config import load_config, save_config, set_known_device, trust
from .database import Database, diff_scans, diff_to_dict
from .engine import load_analyzed, run_scan, scheduled_report
from .report import FORMATS, generate, render_remediation_pdf
from . import alerts as al
from . import coverage as covmod
from . import history_db as hdb
from . import locations as loc
from . import nettools as nt
from . import remediate as rem
from . import vulndb
from .scanner import BACKENDS, ScanError, capabilities, list_wifi_interfaces

MAC_RE = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"


STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def create_app(db_path, cfg_path, out_dir=None, seed_demo=False):
    app = Flask(__name__)
    db = Database(db_path)
    jobs = {}
    out_dir = out_dir or tempfile.gettempdir()
    if seed_demo and db.latest_id() is None:               # first launch: something to look at immediately
        run_scan(db, load_config(cfg_path), "demo", label="Sample data")

    @app.before_request
    def csrf_guard():
        # Custom header can't be sent cross-origin without CORS preflight -> blocks drive-by POSTs.
        if request.method in ("POST", "PUT", "DELETE") and request.headers.get("X-Requested-With") != "wifiaudit":
            return jsonify(error="missing X-Requested-With header"), 403

    @app.after_request
    def sec_headers(r):
        if request.path.startswith("/static/"):
            r.headers["Cache-Control"] = "no-cache"
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["X-Frame-Options"] = "DENY"
        r.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
        return r

    @app.get("/")
    def index():
        with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
            r = Response(f.read(), mimetype="text/html")
        r.headers["Cache-Control"] = "no-store"
        return r

    baseline = os.path.join(os.path.dirname(os.path.abspath(db_path)), "arp_baseline.json")
    var_dir = os.path.dirname(os.path.abspath(db_path))
    sig_hist = hdb.SignalHistory(os.path.join(var_dir, "signal_history.db"))
    cov_db = covmod.CoverageMap(os.path.join(var_dir, "coverage.db"))

    def _link_and_log(p):
        link = nt.current_link()
        if link.get("connected"):
            sig_hist.log(link.get("bssid", ""), link.get("ssid", ""), link.get("signal_dbm"))
            meters, note = covmod.estimate_distance(link.get("signal_dbm"), p.get("environment", "home"))
            link["estimated_distance_m"] = meters
            link["estimated_distance_note"] = note
        return link

    # name -> (function, runs_inline).  Slow tools run as background jobs and are polled via /api/jobs/<id>.
    tools = {
        "info": (lambda p: nt.local_info(), True),
        "link": (lambda p: _link_and_log(p), True),
        "speedtest": (lambda p: nt.speed_test(), False),
        "guestcheck": (lambda p: nt.guest_network_check(p.get("cidr") or None), False),
        "activity": (lambda p: nt.network_activity(), True),
        "arp": (lambda p: nt.arp_health(baseline), True),
        "arp-baseline": (lambda p: nt.save_baseline(baseline), True),
        "mac": (lambda p: nt.mac_info(p.get("mac", "")), True),
        "discover": (lambda p: nt.discover(p.get("cidr") or None, load_config(cfg_path).get("known_devices", {})), False),
        "portscan": (lambda p: nt.port_scan(p.get("host", ""), p.get("ports") or "quick"), False),
        "quality": (lambda p: nt.connection_quality(), False),
        "internet": (lambda p: nt.internet_health(), False),
        "saved": (lambda p: nt.saved_profiles(), False),
        "router": (lambda p: nt.fingerprint_router(p.get("ip") or None), False),
        "ipv6": (lambda p: {"local": nt.local_info(), "neighbors": nt.ipv6_neighbors()}, True),
    }

    @app.post("/api/tool/<name>")
    def run_tool(name):
        if name not in tools:
            return jsonify(error="unknown tool"), 404
        fn, inline = tools[name]
        params = request.get_json(silent=True) or {}
        if inline:
            try:
                return jsonify(result=fn(params))
            except nt.ToolError as e:
                return jsonify(error=str(e), hint=e.hint), 400
        jid = uuid.uuid4().hex[:10]
        if len(jobs) > 60:
            for k in list(jobs)[:20]:
                jobs.pop(k, None)
        jobs[jid] = {"state": "running", "started": time.time()}

        def work():
            try:
                jobs[jid] = {"state": "done", "result": fn(params)}
            except nt.ToolError as e:
                jobs[jid] = {"state": "error", "error": str(e), "hint": e.hint}
            except Exception as e:
                jobs[jid] = {"state": "error", "error": f"{type(e).__name__}: {e}"}

        threading.Thread(target=work, daemon=True).start()
        return jsonify(job=jid)

    @app.get("/api/signal-history")
    def signal_history():
        bssid = request.args.get("bssid") or None
        hours = min(int(request.args.get("hours", 24)), 24 * 30)
        return jsonify(points=sig_hist.history(bssid, hours), networks=sig_hist.known_networks())

    @app.get("/api/coverage/locations")
    def coverage_locations():
        return jsonify(cov_db.locations())

    @app.get("/api/coverage/<location>")
    def coverage_points(location):
        pts = cov_db.points(location)
        return jsonify(points=pts, summary=covmod.summarize(pts))

    @app.post("/api/coverage/<location>")
    def coverage_add(location):
        b = request.get_json(silent=True) or {}
        try:
            x, y, dbm = float(b.get("x")), float(b.get("y")), int(b.get("dbm"))
        except (TypeError, ValueError):
            return jsonify(error="x, y (0-1) and dbm are required"), 400
        try:
            pid = cov_db.add_point(location, x, y, dbm, b.get("ssid", ""), b.get("bssid", ""), b.get("label", ""))
        except ValueError as e:
            return jsonify(error=str(e)), 400
        return jsonify(id=pid)

    @app.delete("/api/coverage/<location>/<int:point_id>")
    def coverage_delete_point(location, point_id):
        cov_db.delete_point(point_id)
        return jsonify(ok=True)

    @app.delete("/api/coverage/<location>")
    def coverage_clear(location):
        cov_db.clear(location)
        return jsonify(ok=True)

    @app.get("/api/compare")
    def compare_scans():
        try:
            a_id, b_id = int(request.args["a"]), int(request.args["b"])
        except (KeyError, ValueError):
            return jsonify(error="query params a and b (scan ids) are required"), 400
        cfg = load_config(cfg_path)
        meta_a, nets_a = db.get_scan(a_id)
        meta_b, nets_b = db.get_scan(b_id)
        if not meta_a or not meta_b:
            return jsonify(error="one or both scans not found"), 404
        from .analyzer import analyze, summarize
        nets_a, nets_b = analyze(nets_a, cfg), analyze(nets_b, cfg)
        d = diff_scans(nets_a, nets_b)
        return jsonify(a={"meta": meta_a, "summary": summarize(nets_a)}, b={"meta": meta_b, "summary": summarize(nets_b)},
                       diff=diff_to_dict(d))

    @app.get("/api/schedule")
    def schedule_get():
        return jsonify(load_config(cfg_path).get("schedule", {"enabled": False, "frequency": "daily", "time": "09:00", "format": ["pdf"]}))

    @app.post("/api/schedule")
    def schedule_set():
        b = request.get_json(silent=True) or {}
        cfg = load_config(cfg_path)
        sched = cfg.setdefault("schedule", {})
        for k in ("enabled", "frequency", "time", "weekday", "backend"):
            if k in b:
                sched[k] = b[k]
        if "format" in b and isinstance(b["format"], list):
            sched["format"] = [f for f in b["format"] if f in FORMATS] or ["pdf"]
        save_config(cfg_path, cfg)
        from .history_db import next_run
        return jsonify(sched=sched, next_run=next_run(sched).isoformat() if sched.get("enabled") else None)

    @app.post("/api/schedule/run-now")
    def schedule_run_now():
        cfg = load_config(cfg_path)
        cfg.setdefault("schedule", {})["last_run"] = None
        save_config(cfg_path, cfg)
        r = scheduled_report(db, cfg_path, out_dir)
        return jsonify(result=r)

    @app.post("/api/remediate/pdf")
    def remediate_pdf():
        b = request.get_json(silent=True) or {}
        plan = rem.plan(b.get("findings") or [])
        path = os.path.join(out_dir, f"remediation_plan_{int(time.time())}.pdf")
        render_remediation_pdf(path, plan, b.get("title", "Remediation plan"))
        return send_file(path, as_attachment=True, download_name="remediation_plan.pdf")

    @app.get("/api/vulndb")
    def vulndb_info():
        cache = vulndb.load_cache(os.path.join(os.path.dirname(os.path.abspath(db_path)), "vuln_cache.json"))
        return jsonify(bundled_version=vulndb.BUNDLED_VERSION, products=sorted({e["id"] for e in vulndb.CURATED}),
                       cache=(cache and {"fetched": cache["fetched"], "products": list(cache["products"])}))

    @app.post("/api/vulndb/refresh")
    def vulndb_refresh():
        try:
            r = vulndb.refresh(os.path.join(os.path.dirname(os.path.abspath(db_path)), "vuln_cache.json"))
            return jsonify(result=r)
        except Exception as e:
            return jsonify(error=f"Could not refresh (needs internet access): {e}"), 502

    @app.post("/api/remediate")
    def remediate():
        b = request.get_json(silent=True) or {}
        findings = b.get("findings") or []
        if not isinstance(findings, list):
            return jsonify(error="findings must be a list"), 400
        return jsonify(plan=rem.plan(findings))

    @app.get("/api/locations")
    def locations_list():
        return jsonify(loc.list_locations(load_config(cfg_path)))

    @app.post("/api/locations")
    def locations_save():
        b = request.get_json(silent=True) or {}
        name = str(b.get("name", "")).strip()[:40]
        if not name:
            return jsonify(error="name is required"), 400
        return jsonify(loc.save_location(cfg_path, name, b.get("gateway_bssid"), b.get("ssid")))

    @app.delete("/api/locations/<name>")
    def locations_delete(name):
        loc.delete_location(cfg_path, name)
        return jsonify(ok=True)

    @app.get("/api/alerts/config")
    def alerts_get():
        cfg = load_config(cfg_path)
        a = cfg.get("alerts", {})
        email = dict(a.get("email", {}))
        if email.get("password"):
            email["password"] = "••••••••"
        return jsonify(email=email, webhook_url=a.get("webhook_url", ""))

    @app.post("/api/alerts/config")
    def alerts_set():
        b = request.get_json(silent=True) or {}
        email = b.get("email")
        webhook = b.get("webhook_url")
        if email and email.get("password") == "••••••••":
            cur = load_config(cfg_path).get("alerts", {}).get("email", {})
            email["password"] = cur.get("password", "")
        al.set_alert_config(cfg_path, email, webhook)
        return jsonify(ok=True)

    @app.post("/api/alerts/notify")
    def alerts_notify():
        b = request.get_json(silent=True) or {}
        title = str(b.get("title", "Wi-Fi Auditor alert"))[:120]
        lines = [str(x)[:200] for x in (b.get("lines") or [])][:20]
        if not lines:
            return jsonify(error="lines required"), 400
        cfg = load_config(cfg_path)
        if not cfg.get("alerts", {}).get("email", {}).get("host") and not cfg.get("alerts", {}).get("webhook_url"):
            return jsonify(result={})            # no channel configured - quietly no-op, dashboard already shows it in-app
        return jsonify(result=al.dispatch(cfg, title, lines))

    @app.post("/api/alerts/test")
    def alerts_test():
        cfg = load_config(cfg_path)
        result = al.dispatch(cfg, "Wi-Fi Auditor test alert", ["This is a test message from the dashboard."])
        if not result:
            return jsonify(error="No alert channel is configured yet"), 400
        return jsonify(result=result)

    @app.post("/api/known")
    def known_device():
        b = request.get_json(silent=True) or {}
        mac = str(b.get("mac", ""))
        if not re.match(MAC_RE, mac):
            return jsonify(error="valid MAC required"), 400
        return jsonify(known=set_known_device(cfg_path, mac, str(b.get("label", "")).strip() or None))

    @app.get("/api/capabilities")
    def caps():
        return jsonify(capabilities())

    @app.get("/api/bssid/<bssid>")
    def bssid_history(bssid):
        if not re.match(MAC_RE, bssid):
            return jsonify(error="bad bssid"), 400
        return jsonify(db.bssid_history(bssid))

    @app.get("/api/interfaces")
    def interfaces():
        return jsonify(list_wifi_interfaces())

    @app.post("/api/scan")
    def start_scan():
        body = request.get_json(silent=True) or {}
        backend = body.get("backend", "demo")
        if backend not in BACKENDS:
            return jsonify(error="bad backend"), 400
        try:
            duration = max(5, min(int(body.get("duration", 20)), 300))
        except (TypeError, ValueError):
            return jsonify(error="bad duration"), 400
        jid = uuid.uuid4().hex[:10]
        jobs[jid] = {"state": "running", "started": time.time(),
                     "duration": duration if backend in ("scapy", "airodump") else None}

        def work():
            try:
                sid, _ = run_scan(db, load_config(cfg_path), backend, body.get("iface"), duration,
                                  str(body.get("label", ""))[:80])
                jobs[jid] = {"state": "done", "scan_id": sid}
            except ScanError as e:
                jobs[jid] = {"state": "error", "error": str(e), "hint": getattr(e, "hint", "")}
            except Exception as e:                       # keep the UI informative, not a stack trace
                jobs[jid] = {"state": "error", "error": f"{type(e).__name__}: {e}"}

        threading.Thread(target=work, daemon=True).start()
        return jsonify(job=jid)

    @app.get("/api/jobs/<jid>")
    def job(jid):
        return jsonify(jobs.get(jid, {"state": "unknown"}))

    @app.get("/api/scans")
    def scans():
        return jsonify(db.list_scans(40))

    @app.get("/api/scans/<sid>")
    def scan_detail(sid):
        sid = db.latest_id() if sid == "latest" else int(sid) if sid.isdigit() else None
        if not sid:
            return jsonify(meta=None)
        meta, nets, summ, diff = load_analyzed(db, load_config(cfg_path), sid)
        if not meta:
            return jsonify(error="not found"), 404
        return jsonify(meta=meta, summary=summ, networks=[n.to_dict() for n in nets],
                       diff=diff_to_dict(diff) if diff else None)

    @app.delete("/api/scans/<int:sid>")
    def delete_scan(sid):
        db.delete_scan(sid)
        return jsonify(ok=True)

    @app.post("/api/trust")
    def do_trust():
        b = request.get_json(silent=True) or {}
        ssid, bssid = str(b.get("ssid", "")), str(b.get("bssid", ""))
        if not ssid or not re.match(MAC_RE, bssid):
            return jsonify(error="ssid and a valid BSSID are required"), 400
        trust(cfg_path, ssid, bssid)
        return jsonify(ok=True)

    @app.get("/api/report/<int:sid>/<fmt>")
    def report(sid, fmt):
        if fmt not in FORMATS:
            return jsonify(error="bad format"), 400
        meta, nets, summ, diff = load_analyzed(db, load_config(cfg_path), sid)
        if not meta:
            return jsonify(error="not found"), 404
        path = generate(fmt, out_dir, meta, nets, summ, diff)
        return send_file(path, as_attachment=True, download_name=os.path.basename(path))

    return app



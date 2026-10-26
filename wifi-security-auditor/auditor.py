#!/usr/bin/env python3
"""
Wi-Fi Security Auditor - passive wireless security assessment CLI.

  python auditor.py scan --backend demo --format html pdf
  sudo python auditor.py scan --backend scapy --iface wlan0mon --duration 30 --format pdf
  python auditor.py dashboard
Use only on networks you own or are authorised to assess.
"""
import argparse
import os
import platform
import shutil
import sys
import time

from wifiaudit import __version__
from wifiaudit.analyzer import analyze, summarize
from wifiaudit.config import load_config, trust
from wifiaudit.database import Database, diff_scans
from wifiaudit import alerts as al
from wifiaudit import locations as loc
from wifiaudit import remediate as rem
from wifiaudit import vulndb
from wifiaudit.engine import load_analyzed, run_scan
from wifiaudit.report import FORMATS, generate
from wifiaudit.scanner import BACKENDS, ScanError, list_wifi_interfaces

ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(ROOT, "data", "wifiaudit.db")
CFG_PATH = os.path.join(ROOT, "config.json")
OUT_DIR = os.path.join(ROOT, "reports")

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
COL = {"SECURE": "92", "VULNERABLE": "93", "HIGH RISK": "91", "ROGUE AP": "95;1"}
BANNER = f"""
 __        ___ _____ _       _             _ _ _
 \\ \\      / (_)  ___(_)     / \\  _   _  __| (_) |_ ___  _ __
  \\ \\ /\\ / /| | |_  | |    / _ \\| | | |/ _` | | __/ _ \\| '__|
   \\ V  V / | |  _| | |   / ___ \\ |_| | (_| | | || (_) | |
    \\_/\\_/  |_|_|   |_|  /_/   \\_\\__,_|\\__,_|_|\\__\\___/|_|   v{__version__}
 Passive Wi-Fi security auditor - authorised use only
"""


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


def print_summary(s):
    print(f"\n  {c('NETWORKS', '1')} {s['total']}   {c('SECURE', COL['SECURE'])} {s['secure']}   "
          f"{c('VULNERABLE', COL['VULNERABLE'])} {s['vulnerable']} ({s['high_risk']} high-risk)   "
          f"{c('ROGUE APs', COL['ROGUE AP'])} {s['rogue']}   avg score {s['avg_score']}   "
          f"WPS-enabled {s['wps_enabled']}   open {s['open']}\n")


def print_table(nets):
    hdr = f"{'SSID':<22}{'BSSID':<19}{'CH':>3} {'SIG':>5}  {'ENCRYPTION':<16}{'WPS':<5}{'SCORE':>5}  LEVEL"
    print(c(hdr, "1;4"))
    for n in nets:
        lvl = n.display_level
        sig = "-" if n.signal is None else str(n.signal)
        wps = "-" if n.wps is None else ("Yes" if n.wps else "No")
        print(f"{n.name[:21]:<22}{n.bssid:<19}{n.channel or '-':>3} {sig:>5}  {n.encryption:<16}{wps:<5}"
              f"{n.score:>5}  {c(lvl, COL[lvl])}")


def print_findings(nets, verbose):
    for n in nets:
        items = [f for f in n.findings if verbose or f["sev"] in ("critical", "high", "medium")]
        if not items or (n.level == "SECURE" and not n.rogue and not verbose):
            continue
        print(f"\n{c(n.name, '1')} [{n.bssid}] - {c(n.display_level, COL[n.display_level])}")
        for f in items:
            print(f"   {f['sev'].upper():<8} {f['title']}\n            {f['detail']}\n            -> {f['fix']}")


def emit_reports(formats, meta, nets, summ, diff, out):
    for fmt in formats or []:
        print(f"  {c('saved', '92')} {generate(fmt, out, meta, nets, summ, diff)}")


def cmd_scan(a, db, cfg):
    print(f"[*] Scanning with backend '{a.backend}'" + (f" on {a.iface}" if a.iface else "") +
          (f" for {a.duration}s" if a.backend in ("scapy", "airodump") else "") + " ...")
    sid, nets = run_scan(db, cfg, a.backend, a.iface, a.duration, a.label, save=not a.no_save)
    used = db.get_scan(sid)[0]["backend"] if sid else a.backend
    print(f"[*] Scan complete via {used}")
    summ = summarize(nets)
    print_summary(summ)
    print_table(nets)
    print_findings(nets, a.verbose)
    meta = {"id": sid or "-", "ts": time.strftime("%Y-%m-%d %H:%M:%S"), "backend": used,
            "iface": a.iface, "label": a.label}
    diff = None
    if sid:
        _, _, _, diff = load_analyzed(db, cfg, sid)
        if diff and (diff["new"] or diff["gone"] or diff["changed"]):
            print(f"\n{c('Changes since previous scan:', '1')} +{len(diff['new'])} new, "
                  f"-{len(diff['gone'])} gone, {len(diff['changed'])} changed")
    print()
    emit_reports(a.format, meta, nets, summ, diff, a.out)
    return 2 if summ["rogue"] else 0       # non-zero exit if rogue AP found (CI / cron friendly)


def cmd_watch(a, db, cfg):
    print(f"[*] Watching every {a.interval}s (Ctrl+C to stop). Alerts also logged to {a.alert_log}")
    prev = None
    try:
        while True:
            cfg = load_config(CFG_PATH)
            try:
                sid, nets = run_scan(db, cfg, a.backend, a.iface, a.duration, "watch")
            except ScanError as e:
                print(c(f"[!] {e}" + (f"  ({e.hint})" if e.hint else ""), "91"))
                time.sleep(a.interval)
                continue
            alerts = [f"ROGUE AP: {n.name} {n.bssid} ({'; '.join(n.rogue_reasons)})" for n in nets if n.rogue]
            if prev is not None:
                d = diff_scans(prev, nets)
                alerts += [f"NEW network: {n.name} {n.bssid} [{n.display_level}]" for n in d["new"]]
                alerts += [f"CHANGED {x['ssid']}: {x['field']} {x['old']} -> {x['new']}" for x in d["changed"]
                           if x["field"] in ("encryption", "wps")]
            stamp = time.strftime("%H:%M:%S")
            print(f"[{stamp}] scan #{sid}: {len(nets)} networks, {sum(n.rogue for n in nets)} rogue")
            for item in alerts:
                print(c(f"   ALERT {item}", "91;1"))
                with open(a.alert_log, "a", encoding="utf-8") as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {item}\n")
            if alerts and not a.no_notify:
                res = al.dispatch(cfg, f"Wi-Fi Auditor: {len(alerts)} alert(s)", alerts)
                for ch, outcome in res.items():
                    if outcome is not True:
                        print(c(f"   [{ch} alert failed: {outcome}]", "93"))
            prev = nets
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print("\n[*] stopped")
    return 0


def cmd_history(a, db, cfg):
    rows = db.list_scans(a.limit)
    if not rows:
        print("No scans yet. Try: python auditor.py scan --backend demo")
        return 0
    print(c(f"{'ID':>4}  {'WHEN':<20}{'BACKEND':<10}{'NETS':>5}{'SECURE':>8}{'VULN':>6}{'ROGUE':>7}  LABEL", "1;4"))
    for r in rows:
        print(f"{r['id']:>4}  {r['ts']:<20}{r['backend']:<10}{r['total']:>5}{r['secure']:>8}"
              f"{r['vulnerable']:>6}{r['rogue']:>7}  {r['label']}")
    return 0


def cmd_show(a, db, cfg):
    sid = a.id or db.latest_id()
    meta, nets, summ, diff = load_analyzed(db, cfg, sid)
    if not meta:
        print("Scan not found")
        return 1
    print(f"Scan #{meta['id']} - {meta['ts']} ({meta['backend']})")
    print_summary(summ)
    print_table(nets)
    print_findings(nets, a.verbose)
    emit_reports(a.format, meta, nets, summ, diff, a.out)
    return 0


def cmd_diff(a, db, cfg):
    b = a.b or db.latest_id()
    a_id = a.a or db.previous_id(b)
    if not a_id or not b:
        print("Need two scans to compare")
        return 1
    _, old = db.get_scan(a_id)
    _, new = db.get_scan(b)
    d = diff_scans(analyze(old, cfg), analyze(new, cfg))
    print(f"Diff scan #{a_id} -> #{b}")
    for n in d["new"]:
        print(c(f"  + NEW     {n.name:<22}{n.bssid} {n.encryption} [{n.display_level}]", "92"))
    for n in d["gone"]:
        print(c(f"  - GONE    {n.name:<22}{n.bssid}", "90"))
    for x in d["changed"]:
        print(c(f"  ~ CHANGED {x['ssid']:<22}{x['bssid']} {x['field']}: {x['old']} -> {x['new']}", "93"))
    if not (d["new"] or d["gone"] or d["changed"]):
        print("  no differences")
    return 0


def cmd_trust(a, db, cfg):
    trust(CFG_PATH, a.ssid, a.bssid)
    print(f"Trusted {a.bssid.upper()} for SSID '{a.ssid}'.")
    return 0


def cmd_interfaces(a, db, cfg):
    ifs = list_wifi_interfaces()
    if not ifs:
        print("No wireless interfaces found (Linux: needs `iw` or /sys/class/net/*/wireless).")
    for i in ifs:
        print(f"  {i['name']:<12}{i['mode'] or '?':<10}{i['mac']}")
    print("\nMonitor mode (your own adapter):  sudo airmon-ng start wlan0   |   "
          "sudo ip link set wlan0 down && sudo iw wlan0 set monitor none && sudo ip link set wlan0 up")
    return 0


def cmd_doctor(a, db, cfg):
    from wifiaudit.scanner import capabilities
    caps = capabilities()
    print(f"Scan methods on this machine ({caps['platform']}{', root' if caps['root'] else ''}):")
    for k in ("auto", "deep", "system", "scapy", "airodump"):
        v = caps[k]
        print(f"  [{c('OK', '92') if v['available'] else c('--', '93')}] {k:<9}{v['reason']}" + (f"  -> {v['hint']}" if v['hint'] and not v['available'] else ""))
    print(f"  adapters: {', '.join(x['name'] + ('(' + x['mode'] + ')' if x['mode'] else '') for x in caps['adapters']) or 'none detected'}\n")
    def row(name, ok, hint=""):
        print(f"  [{c('OK', '92') if ok else c('--', '93')}] {name:<22}{'' if ok else hint}")
    print(f"Platform: {platform.system()} {platform.release()}, Python {platform.python_version()}")
    for mod, hint in (("scapy", "pip install scapy"), ("reportlab", "pip install reportlab"),
                      ("flask", "pip install flask"), ("netifaces", "optional: pip install netifaces")):
        try:
            __import__(mod)
            row(mod, True)
        except ImportError:
            row(mod, False, hint)
    for tool in ("nmcli", "iw", "airodump-ng", "wash"):
        row(tool, bool(shutil.which(tool)), "optional external tool not installed")
    row("root privileges", hasattr(os, "geteuid") and os.geteuid() == 0, "needed for scapy/airodump backends")
    return 0


def cmd_net(a, db, cfg):
    """Network toolbox from the terminal (same engine as the dashboard's Toolbox)."""
    from wifiaudit import nettools as nt
    try:
        act = a.action
        if act == "info":
            for k, v in nt.local_info().items():
                print(f"  {k:<18}{', '.join(v) if isinstance(v, list) else v}")
        elif act == "discover":
            r = nt.discover(a.target, cfg.get("known_devices", {}))
            print(f"  {len(r['devices'])} devices on {r['cidr']} ({r['seconds']} s)\n")
            print(c(f"  {'IP':<16}{'MAC':<19}{'MAKER':<18}{'STATUS':<12}NAME", "1;4"))
            for d in r["devices"]:
                st = "this device" if d["is_self"] else "router" if d["is_gateway"] else ("known" if d["known"] else "NEW")
                print(f"  {d['ip']:<16}{d['mac'] or '-':<19}{(d['vendor'] or '-')[:17]:<18}{c(st, '93' if st == 'NEW' else '92'):<12}{d['hostname']}")
        elif act == "ports":
            if not a.target:
                print("usage: auditor.py net ports HOST [--ports quick|common|web|full|22,80]")
                return 1
            r = nt.port_scan(a.target, a.ports)
            print(f"  {r['ip']}: {len(r['open'])} open of {r['scanned']} tried ({r['seconds']} s) - {r['verdict']}\n")
            for o in r["open"]:
                print(f"  {o['port']:<7}{o['service']:<12}{o['level'].upper():<10}{o['note']}" + (f"  [{o['banner']}]" if o["banner"] else ""))
        elif act == "quality":
            r = nt.connection_quality()
            print(f"  Grade {r['grade']}: {r['verdict']}")
            for x in r["results"]:
                print(f"  {x['name']:<24}avg {x['avg']} ms  min {x['min']}  max {x['max']}  jitter {x['jitter']}  loss {x['loss']}%  ({x['method']})")
            for i in r["issues"] + r["tips"]:
                print("   -", i)
        elif act == "internet":
            r = nt.internet_health()
            print(f"  {r['verdict']}")
            for f in r["findings"]:
                print(f"   [{f['sev'].upper()}] {f['title']} - {f['detail']}  -> {f['fix']}")
            print(f"  DNS avg {r['dns']['avg_ms']} ms; servers {', '.join(r['dns']['servers']) or '?'}; "
                  f"HTTPS: " + ", ".join(f"{t['host']}={'ok' if t['ok'] else 'FAILED'}" for t in r["tls"]))
        elif act == "arp":
            r = nt.arp_health(os.path.join(ROOT, "data", "arp_baseline.json"))
            print(f"  {r['verdict']}  (router {r['gateway']} = {r['gateway_mac']})")
            for f in r["findings"]:
                print(f"   [{f['sev'].upper()}] {f['title']} - {f['detail']}")
            if a.target == "save":
                print("  baseline saved:", nt.save_baseline(os.path.join(ROOT, "data", "arp_baseline.json")))
        elif act == "saved":
            r = nt.saved_profiles()
            for p in r["profiles"]:
                print(f"  {p['risk'].upper():<7}{p['name']:<28}{p['security']:<20}{'auto' if p['autoconnect'] else '':<6}{p['note']}")
        elif act == "link":
            print(nt.current_link())
        elif act == "mac":
            print(nt.mac_info(a.target))
        elif act == "speedtest":
            r = nt.speed_test()
            print(f"  {r['mbps']} Mbps ({r['rating']}) via {r['server']} - {r['mb_transferred']} MB in {r['seconds']}s")
            print(f"  {r['note']}")
        elif act == "guestcheck":
            r = nt.guest_network_check(a.target)
            print(f"  {r['verdict']}")
            print(f"  {r['note']}")
        elif act == "activity":
            r = nt.network_activity()
            print(f"  {r['total']} active connection(s): " + ", ".join(f"{k} x{v}" for k, v in r["by_category"].items()))
            for c in r["connections"]:
                print(f"   {c['category']:<18}{c['remote']}:{c['remote_port']}  ({c['state']})")
    except nt.ToolError as e:
        print(c(f"[!] {e}", "91"))
        if e.hint:
            print(c(f"    -> {e.hint}", "93"))
        return 1
    return 0


def cmd_vulndb(a, db, cfg):
    cache_path = os.path.join(ROOT, "data", "vuln_cache.json")
    if a.action == "info":
        print(f"Bundled reference version: {vulndb.BUNDLED_VERSION}  ({len({e['id'] for e in vulndb.CURATED})} products)")
        cache = vulndb.load_cache(cache_path)
        print(f"Live cache: {'fetched ' + cache['fetched'] if cache else 'none yet - run `vulndb refresh`'}")
        return 0
    print("[*] Fetching the latest CVEs for known products from NVD (needs internet access)...")
    r = vulndb.refresh(cache_path)
    print(f"  updated: {', '.join(r['updated']) or 'none'}")
    for e in r["errors"]:
        print(c(f"  [!] {e}", "93"))
    print(f"  cached to {r['cached_at']}")
    return 0


def cmd_remediate(a, db, cfg):
    sid = a.id or db.latest_id()
    meta, nets, summ, diff = load_analyzed(db, cfg, sid)
    if not meta:
        print("Scan not found")
        return 1
    findings = [f for n in nets for f in n.findings if f["sev"] != "info"]
    plan = rem.plan(findings)
    if not plan:
        print("Nothing to fix - this scan looks clean.")
        return 0
    print(rem.plan_to_text(plan, f"Remediation plan for scan #{meta['id']}"))
    return 0


def cmd_location(a, db, cfg):
    path = CFG_PATH
    if a.action == "list":
        locs = loc.list_locations(cfg)
        if not locs:
            print("No saved locations yet.")
        for name, L in locs.items():
            print(f"  {name:<20}SSIDs: {', '.join(L.get('ssids', [])) or '-'}   BSSIDs: {len(L.get('gateway_bssids', []))}")
        return 0
    if not a.name:
        print("A location name is required, e.g.: auditor.py location save Home")
        return 1
    if a.action == "delete":
        loc.delete_location(path, a.name)
        print(f"Deleted '{a.name}'.")
        return 0
    meta, nets, _, _ = load_analyzed(db, cfg, db.latest_id()) if db.latest_id() else (None, [], None, None)
    mine = next((n for n in nets if n.connected), None)
    if not mine:
        print("Run a scan while connected to this network first, so its router can be recorded.")
        return 1
    loc.save_location(path, a.name, gateway_bssid=mine.bssid, ssid=mine.ssid)
    print(f"Saved '{a.name}' = {mine.ssid} ({mine.bssid})")
    return 0


def cmd_alert_config(a, db, cfg):
    if a.action == "show":
        em = cfg.get("alerts", {}).get("email", {})
        print(f"  Email:   {'configured (' + em.get('to', '') + ')' if em.get('host') else 'not configured'}")
        print(f"  Webhook: {cfg.get('alerts', {}).get('webhook_url') or 'not configured'}")
        print("  Set a webhook:  auditor.py alert-config webhook https://hooks.slack.com/services/...")
        print("  Email is set via config.json's alerts.email section (host/port/user/password/to).")
        return 0
    if a.action == "webhook":
        if not a.value:
            print("usage: auditor.py alert-config webhook <https-url>")
            return 1
        al.set_alert_config(CFG_PATH, webhook_url=a.value)
        print("Webhook saved.")
        return 0
    try:
        res = al.dispatch(cfg, "Wi-Fi Auditor test alert", ["This is a test message."])
        if not res:
            print("No alert channel is configured yet.")
            return 1
        for ch, outcome in res.items():
            print(f"  {ch}: {'sent' if outcome is True else outcome}")
    except Exception as e:
        print(c(f"[!] {e}", "91"))
        return 1
    return 0


def cmd_schedule(a, db, cfg):
    from wifiaudit.config import save_config
    from wifiaudit.engine import scheduled_report
    from wifiaudit.history_db import next_run
    sched = cfg.setdefault("schedule", {})
    if a.action == "show":
        if not sched.get("enabled"):
            print("No recurring schedule is enabled.")
        else:
            print(f"  {sched.get('frequency')} at {sched.get('time', '-')}" +
                  (f" on weekday {sched.get('weekday')}" if sched.get("frequency") == "weekly" else ""))
            print(f"  formats: {', '.join(sched.get('format', ['pdf']))}   backend: {sched.get('backend', 'auto')}")
            print(f"  last run: {sched.get('last_run') or 'never'}")
            print(f"  next run: {next_run(sched)}")
        print("\n  Note: this only fires while a Wi-Fi Auditor process (run.py or `dashboard`) is running.")
        print("  For a schedule that works even when the app is closed, use your OS scheduler instead:")
        print("    Linux (crontab -e):   0 9 * * *  cd " + ROOT + " && python3 auditor.py scan -f pdf")
        print("    Windows (Task Scheduler): Action = python.exe, Arguments = auditor.py scan -f pdf, Start in = " + ROOT)
        return 0
    if a.action == "disable":
        sched["enabled"] = False
        save_config(CFG_PATH, cfg)
        print("Schedule disabled.")
        return 0
    if a.action == "enable":
        sched.update(enabled=True, frequency=a.frequency, time=a.time, weekday=a.weekday, format=list(a.format), backend=a.backend)
        save_config(CFG_PATH, cfg)
        print(f"Schedule enabled: {a.frequency} at {a.time}. Next run: {next_run(sched)}")
        print("Keep `python run.py` (or `auditor.py dashboard`) running for this to fire, or use an OS-level cron/Task Scheduler entry instead.")
        return 0
    sched["last_run"] = None
    save_config(CFG_PATH, cfg)
    r = scheduled_report(db, CFG_PATH, OUT_DIR)
    print(f"Ran scan #{r['scan_id']}, saved: {', '.join(r['reports'])}" if r else "Nothing to do (schedule not enabled).")
    return 0


def cmd_dashboard(a, db, cfg):
    from wifiaudit.web import create_app
    app = create_app(DB_PATH, CFG_PATH, OUT_DIR)
    print(f"[*] Dashboard on http://{a.host}:{a.port}  (Ctrl+C to quit)")
    if a.host not in ("127.0.0.1", "localhost"):
        print(c("[!] Binding to a non-local address exposes scan controls to your network.", "93"))
    app.run(host=a.host, port=a.port, debug=False, threaded=True)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="auditor", description="Passive Wi-Fi security auditor")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def scan_opts(sp):
        sp.add_argument("-b", "--backend", choices=BACKENDS, default="auto",
                        help="auto (default) | deep | system | scapy | airodump | demo")
        sp.add_argument("-i", "--iface", help="interface (monitor mode for scapy/airodump)")
        sp.add_argument("-d", "--duration", type=int, default=20, help="capture seconds (scapy/airodump)")

    def rep_opts(sp):
        sp.add_argument("-f", "--format", nargs="+", choices=FORMATS, help="report formats to write")
        sp.add_argument("-o", "--out", default=OUT_DIR, help="report output directory")
        sp.add_argument("-v", "--verbose", action="store_true", help="show low/info findings too")

    s = sub.add_parser("scan", help="run a scan and print/save results")
    scan_opts(s)
    rep_opts(s)
    s.add_argument("-l", "--label", default="", help="free-text label (e.g. location)")
    s.add_argument("--no-save", action="store_true", help="do not store in the database")
    s.set_defaults(fn=cmd_scan)

    w = sub.add_parser("watch", help="continuous monitoring with rogue/new/changed alerts")
    scan_opts(w)
    w.add_argument("--interval", type=int, default=60)
    w.add_argument("--alert-log", default=os.path.join(ROOT, "data", "alerts.log"))
    w.add_argument("--no-notify", action="store_true", help="skip email/webhook delivery, log only")
    w.set_defaults(fn=cmd_watch)

    h = sub.add_parser("history", help="list stored scans")
    h.add_argument("--limit", type=int, default=20)
    h.set_defaults(fn=cmd_history)

    sh = sub.add_parser("show", help="re-display / re-report a stored scan")
    sh.add_argument("id", nargs="?", type=int)
    rep_opts(sh)
    sh.set_defaults(fn=cmd_show)

    d = sub.add_parser("diff", help="compare two stored scans (default: last two)")
    d.add_argument("a", nargs="?", type=int)
    d.add_argument("b", nargs="?", type=int)
    d.set_defaults(fn=cmd_diff)

    t = sub.add_parser("trust", help="add a BSSID to the trusted allow-list for an SSID")
    t.add_argument("ssid")
    t.add_argument("bssid")
    t.set_defaults(fn=cmd_trust)

    sub.add_parser("interfaces", help="list wireless interfaces").set_defaults(fn=cmd_interfaces)
    sub.add_parser("doctor", help="check dependencies and privileges").set_defaults(fn=cmd_doctor)

    n = sub.add_parser("net", help="network toolbox: info, discover, ports, quality, internet, arp, saved, link, mac")
    n.add_argument("action", choices=["info", "discover", "ports", "quality", "internet", "arp", "saved", "link", "mac",
                                       "speedtest", "guestcheck", "activity"])
    n.add_argument("target", nargs="?", help="network (discover), host (ports) or MAC (mac); 'save' for arp")
    n.add_argument("--ports", default="quick", help="quick | common | web | full | 22,80,8000-8100")
    n.set_defaults(fn=cmd_net)

    vd = sub.add_parser("vulndb", help="manage the bundled vulnerability reference")
    vd.add_argument("action", choices=["info", "refresh"])
    vd.set_defaults(fn=cmd_vulndb)

    rp = sub.add_parser("remediate", help="print a step-by-step fix plan for the latest (or given) scan")
    rp.add_argument("id", nargs="?", type=int)
    rp.set_defaults(fn=cmd_remediate)

    lo = sub.add_parser("location", help="save/list/delete trusted-network locations (Home, Office, ...)")
    lo.add_argument("action", choices=["list", "save", "delete"])
    lo.add_argument("name", nargs="?")
    lo.set_defaults(fn=cmd_location)

    al_p = sub.add_parser("alert-config", help="configure or test email/webhook alerts for `watch`")
    al_p.add_argument("action", choices=["show", "webhook", "test"])
    al_p.add_argument("value", nargs="?", help="webhook URL for `webhook`")
    al_p.set_defaults(fn=cmd_alert_config)

    sc = sub.add_parser("schedule", help="scheduled (recurring) scans and reports")
    sc.add_argument("action", choices=["show", "enable", "disable", "run-now"])
    sc.add_argument("--frequency", choices=["hourly", "daily", "weekly"], default="daily")
    sc.add_argument("--time", default="09:00", help="HH:MM, for daily/weekly")
    sc.add_argument("--weekday", type=int, default=0, help="0=Monday .. 6=Sunday, for weekly")
    sc.add_argument("--format", nargs="+", choices=FORMATS, default=["pdf"])
    sc.add_argument("--backend", default="auto")
    sc.set_defaults(fn=cmd_schedule)

    dash = sub.add_parser("dashboard", help="start the web dashboard")
    dash.add_argument("--host", default="127.0.0.1")
    dash.add_argument("--port", type=int, default=5000)
    dash.set_defaults(fn=cmd_dashboard)
    return p


def main():
    args = build_parser().parse_args()
    if args.cmd in ("scan", "watch", "dashboard"):
        print(c(BANNER, "96"))
    db, cfg = Database(DB_PATH), load_config(CFG_PATH)
    try:
        return args.fn(args, db, cfg)
    except ScanError as e:
        print(c(f"[!] {e}", "91"))
        if getattr(e, "hint", ""):
            print(c(f"    -> {e.hint}", "93"))
        return 1


if __name__ == "__main__":
    sys.exit(main())

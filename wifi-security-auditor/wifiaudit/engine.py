"""High-level orchestration shared by the CLI and the web dashboard."""
from .analyzer import analyze, summarize
from .database import Database, diff_scans
from .scanner import run_backend


def run_scan(db: Database, cfg, backend="demo", iface=None, duration=20, label="", save=True):
    used, raw = run_backend(backend, iface=iface, duration=duration)
    nets = analyze(raw, cfg)
    sid = db.save_scan(nets, used, iface, label) if save else None
    return sid, nets


def load_analyzed(db: Database, cfg, sid):
    """Return (meta, analysed networks, summary, diff-vs-previous)."""
    meta, nets = db.get_scan(sid)
    if not meta:
        return None, [], None, None
    nets = analyze(nets, cfg)
    prev = db.previous_id(sid)
    diff = None
    if prev:
        _, old = db.get_scan(prev)
        diff = diff_scans(analyze(old, cfg), nets)
    return meta, nets, summarize(nets), diff


def scheduled_report(db, cfg_path, out_dir):
    """Run one scheduled scan + report, if the configured schedule is due. Call this from a
    timer (web dashboard) or a cron job / Task Scheduler entry (see README) - either is fine,
    calling it when not due is a harmless no-op."""
    from .config import load_config, save_config
    from .history_db import is_due
    cfg = load_config(cfg_path)
    sched = cfg.get("schedule", {})
    if not is_due(sched, sched.get("last_run")):
        return None
    backend = sched.get("backend", "auto")
    sid, nets = run_scan(db, cfg, backend, label="scheduled")
    meta, nets, summ, diff = load_analyzed(db, cfg, sid)
    from .report import generate
    paths = [generate(fmt, out_dir, meta, nets, summ, diff) for fmt in (sched.get("format") or ["pdf"])]
    sched["last_run"] = __import__("datetime").datetime.now().isoformat(timespec="seconds")
    cfg["schedule"] = sched
    save_config(cfg_path, cfg)
    return {"scan_id": sid, "reports": paths}

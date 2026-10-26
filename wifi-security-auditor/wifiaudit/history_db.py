"""Lightweight time-series storage for signal history, plus the scheduler's due-time math."""
from __future__ import annotations

import contextlib
import datetime
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS signal_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, bssid TEXT, ssid TEXT, dbm INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sig_ts ON signal_log(ts);
CREATE INDEX IF NOT EXISTS idx_sig_bssid ON signal_log(bssid);
"""
MAX_ROWS = 50_000   # roll up (downsample) once this many raw samples accumulate


class SignalHistory:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextlib.contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def log(self, bssid, ssid, dbm):
        if dbm is None:
            return
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        with self._conn() as c:
            c.execute("INSERT INTO signal_log(ts, bssid, ssid, dbm) VALUES(?,?,?,?)", (ts, bssid, ssid, dbm))
            n = c.execute("SELECT COUNT(*) n FROM signal_log").fetchone()["n"]
        if n > MAX_ROWS:
            self._rollup()

    def _rollup(self):
        """Collapse everything older than a day into hourly averages, keeping the table bounded."""
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat(timespec="seconds")
        with self._conn() as c:
            rows = c.execute("SELECT * FROM signal_log WHERE ts < ? ORDER BY ts", (cutoff,)).fetchall()
            if not rows:
                return
            buckets = {}
            for r in rows:
                key = (r["ts"][:13], r["bssid"], r["ssid"])   # hour bucket
                buckets.setdefault(key, []).append(r["dbm"])
            c.execute("DELETE FROM signal_log WHERE ts < ?", (cutoff,))
            for (hour, bssid, ssid), vals in buckets.items():
                c.execute("INSERT INTO signal_log(ts, bssid, ssid, dbm) VALUES(?,?,?,?)",
                         (hour + ":30:00", bssid, ssid, round(sum(vals) / len(vals))))

    def history(self, bssid=None, hours=24):
        since = (datetime.datetime.now() - datetime.timedelta(hours=hours)).isoformat(timespec="seconds")
        q = "SELECT ts, bssid, ssid, dbm FROM signal_log WHERE ts >= ?"
        args = [since]
        if bssid:
            q += " AND bssid=?"
            args.append(bssid)
        q += " ORDER BY ts"
        with self._conn() as c:
            return [dict(r) for r in c.execute(q, args)]

    def known_networks(self, hours=168):
        since = (datetime.datetime.now() - datetime.timedelta(hours=hours)).isoformat(timespec="seconds")
        with self._conn() as c:
            rows = c.execute(
                "SELECT bssid, ssid, COUNT(*) n, MAX(ts) last FROM signal_log WHERE ts>=? GROUP BY bssid ORDER BY last DESC",
                (since,)).fetchall()
        return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# Scheduler due-time math (pure functions - easy to unit test without real time passing)
# --------------------------------------------------------------------------- #
def next_run(schedule, now=None):
    """schedule: {"frequency": "hourly"|"daily"|"weekly", "time": "HH:MM", "weekday": 0-6}
    -> the next datetime this schedule should fire, strictly after `now`."""
    now = now or datetime.datetime.now()
    freq = schedule.get("frequency", "daily")
    if freq == "hourly":
        base = now.replace(minute=0, second=0, microsecond=0)
        nxt = base + datetime.timedelta(hours=1)
        return nxt if nxt > now else nxt + datetime.timedelta(hours=1)
    hh, mm = (schedule.get("time") or "09:00").split(":")
    target = now.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
    if freq == "weekly":
        wd = int(schedule.get("weekday", 0))
        days_ahead = (wd - now.weekday()) % 7
        target += datetime.timedelta(days=days_ahead)
        if target <= now:
            target += datetime.timedelta(days=7)
        return target
    if target <= now:                                        # daily
        target += datetime.timedelta(days=1)
    return target


def is_due(schedule, last_run_iso, now=None):
    """True if the schedule should fire now, given when it last ran (or None = never)."""
    now = now or datetime.datetime.now()
    if not schedule.get("enabled"):
        return False
    if not last_run_iso:
        return True
    try:
        last_run = datetime.datetime.fromisoformat(last_run_iso)
    except ValueError:
        return True
    return next_run(schedule, last_run) <= now

"""SQLite storage. Raw observations are stored; analysis is recomputed on read so
that changes to the trusted list / scoring rules apply to historic scans too."""
from __future__ import annotations

import contextlib
import datetime
import os
import sqlite3

from .analyzer import summarize
from .config import fix_owner
from .models import RAW_FIELDS, Network

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, backend TEXT, iface TEXT, label TEXT,
  total INTEGER, secure INTEGER, vulnerable INTEGER, rogue INTEGER, avg_score REAL);
CREATE TABLE IF NOT EXISTS networks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  bssid TEXT, ssid TEXT, channel INTEGER, signal INTEGER, encryption TEXT, cipher TEXT, auth TEXT,
  wps INTEGER, wps_locked INTEGER, pmf TEXT, hidden INTEGER, vendor TEXT, band TEXT, connected INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_net_scan ON networks(scan_id);
CREATE INDEX IF NOT EXISTS idx_net_bssid ON networks(bssid);
"""
_BOOLS = ("wps", "wps_locked", "hidden", "connected")


def _tri(v):
    return None if v is None else int(bool(v))


class Database:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)
            cols = [r["name"] for r in c.execute("PRAGMA table_info(networks)")]
            if "connected" not in cols:                       # upgrade databases created by older versions
                c.execute("ALTER TABLE networks ADD COLUMN connected INTEGER DEFAULT 0")
        fix_owner(os.path.dirname(os.path.abspath(path)))
        fix_owner(path)

    @contextlib.contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # ------------------------------------------------------------------ #
    def save_scan(self, nets, backend="", iface="", label=""):
        s = summarize(nets)
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO scans(ts,backend,iface,label,total,secure,vulnerable,rogue,avg_score) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (ts, backend, iface or "", label or "", s["total"], s["secure"], s["vulnerable"],
                 s["rogue"], s["avg_score"]))
            sid = cur.lastrowid
            rows = []
            for n in nets:
                r = n.raw()
                rows.append((sid,) + tuple(_tri(r[k]) if k in _BOOLS else r[k] for k in RAW_FIELDS))
            c.executemany(
                "INSERT INTO networks(scan_id," + ",".join(RAW_FIELDS) + ") VALUES(?" +
                ",?" * len(RAW_FIELDS) + ")", rows)
        return sid

    def list_scans(self, limit=50):
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))]

    def latest_id(self):
        with self._conn() as c:
            r = c.execute("SELECT MAX(id) m FROM scans").fetchone()
            return r["m"]

    def previous_id(self, sid):
        with self._conn() as c:
            r = c.execute("SELECT MAX(id) m FROM scans WHERE id<?", (sid,)).fetchone()
            return r["m"]

    def get_scan(self, sid):
        with self._conn() as c:
            meta = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
            if not meta:
                return None, []
            rows = c.execute("SELECT * FROM networks WHERE scan_id=?", (sid,)).fetchall()
        nets = []
        for r in rows:
            d = dict(r)
            for k in _BOOLS:
                d[k] = None if d.get(k) is None else bool(d[k])
            d["connected"] = bool(d.get("connected"))
            nets.append(Network.from_raw(d))
        return dict(meta), nets

    def delete_scan(self, sid):
        with self._conn() as c:
            c.execute("DELETE FROM scans WHERE id=?", (sid,))

    def bssid_history(self, bssid):
        with self._conn() as c:
            q = ("SELECT s.id scan_id, s.ts, n.ssid, n.channel, n.signal, n.encryption, n.wps "
                 "FROM networks n JOIN scans s ON s.id=n.scan_id WHERE n.bssid=? ORDER BY s.id")
            return [dict(r) for r in c.execute(q, (bssid.upper(),))]


# ---------------------------------------------------------------------- #
def diff_scans(old, new):
    """Compare two lists of Network -> new / gone / changed security-relevant fields."""
    o, n = {(x.bssid, x.ssid): x for x in old}, {(x.bssid, x.ssid): x for x in new}
    o_b, n_b = {x.bssid: x for x in old}, {x.bssid: x for x in new}
    added = [x for k, x in n.items() if k not in o and x.bssid not in o_b]
    gone = [x for k, x in o.items() if k not in n and x.bssid not in n_b]
    changed = []
    for b, nx in n_b.items():
        ox = o_b.get(b)
        if not ox:
            continue
        for fld in ("ssid", "encryption", "wps", "channel"):
            if getattr(ox, fld) != getattr(nx, fld):
                changed.append({"bssid": b, "ssid": nx.name, "field": fld,
                                "old": getattr(ox, fld), "new": getattr(nx, fld)})
    return {"new": added, "gone": gone, "changed": changed}


def diff_to_dict(d):
    return {"new": [x.to_dict() for x in d["new"]], "gone": [x.to_dict() for x in d["gone"]],
            "changed": d["changed"]}

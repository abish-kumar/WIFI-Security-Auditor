"""
Two related features:

1. estimate_distance() - a rough, clearly-labelled distance estimate from signal strength,
   using the standard log-distance path-loss model. This is an ESTIMATE: walls, floors and
   interference all change the real answer, sometimes a lot. It assumes a typical home
   router's transmit power and a "some obstacles" environment by default.

2. CoverageMap - lets a person click points on a simple canvas while walking around with a
   phone/laptop, logging the signal reading at each click. No floor plan is required or
   stored - just relative x/y positions the user places, which we render as a heatmap.
   Stored per (location, ssid) so Home and Office don't mix.
"""
from __future__ import annotations

import contextlib
import math
import os
import sqlite3
import time

# Reference signal at 1 metre for a typical 2.4/5 GHz home AP (dBm). Real APs vary +/- 10 dB.
DEFAULT_REF_DBM_AT_1M = -40
# Path-loss exponent: 2.0 = free space/open air, 3.0 = typical home with walls, 4.0 = dense/concrete.
ENV_EXPONENTS = {"open": 2.0, "home": 2.8, "office": 3.3, "dense": 4.0}


def estimate_distance(dbm, environment="home", ref_dbm_at_1m=DEFAULT_REF_DBM_AT_1M):
    """-> (meters, confidence_note). None if dbm is missing."""
    if dbm is None:
        return None, "No signal reading available."
    n = ENV_EXPONENTS.get(environment, ENV_EXPONENTS["home"])
    meters = 10 ** ((ref_dbm_at_1m - dbm) / (10 * n))
    meters = round(max(0.3, min(meters, 300)), 1)
    note = ("Rough estimate only - walls, floors and interference can easily make the real "
            "distance quite different. Treat this as 'closer vs. farther', not a measurement.")
    return meters, note


SCHEMA = """
CREATE TABLE IF NOT EXISTS coverage_points(
  id INTEGER PRIMARY KEY AUTOINCREMENT, location TEXT NOT NULL, ssid TEXT, bssid TEXT,
  x REAL NOT NULL, y REAL NOT NULL, dbm INTEGER NOT NULL, ts TEXT NOT NULL,
  label TEXT);
CREATE INDEX IF NOT EXISTS idx_cov_loc ON coverage_points(location);
"""


class CoverageMap:
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

    def add_point(self, location, x, y, dbm, ssid="", bssid="", label=""):
        if not (0 <= x <= 1 and 0 <= y <= 1):
            raise ValueError("x and y must be fractional coordinates between 0 and 1")
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO coverage_points(location, ssid, bssid, x, y, dbm, ts, label) VALUES(?,?,?,?,?,?,?,?)",
                (location, ssid, bssid, x, y, dbm, ts, label))
            return cur.lastrowid

    def points(self, location):
        with self._conn() as c:
            rows = c.execute("SELECT * FROM coverage_points WHERE location=? ORDER BY id", (location,)).fetchall()
        return [dict(r) for r in rows]

    def locations(self):
        with self._conn() as c:
            rows = c.execute("SELECT location, COUNT(*) n, MAX(ts) last FROM coverage_points GROUP BY location").fetchall()
        return [dict(r) for r in rows]

    def clear(self, location):
        with self._conn() as c:
            c.execute("DELETE FROM coverage_points WHERE location=?", (location,))

    def delete_point(self, point_id):
        with self._conn() as c:
            c.execute("DELETE FROM coverage_points WHERE id=?", (point_id,))


def summarize(points):
    """-> quick stats + the weakest spot, for a plain-English readout."""
    if not points:
        return {"count": 0}
    dbms = [p["dbm"] for p in points]
    worst = min(points, key=lambda p: p["dbm"])
    best = max(points, key=lambda p: p["dbm"])
    avg = round(sum(dbms) / len(dbms), 1)
    weak = sum(1 for d in dbms if d < -75)
    return {"count": len(points), "avg_dbm": avg, "best": best, "worst": worst,
            "weak_spots": weak, "weak_pct": round(100 * weak / len(points))}

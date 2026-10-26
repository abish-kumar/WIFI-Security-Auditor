"""
Multi-location trust profiles.

Scanning your office then your home then a cafe used to mean every router looked
"new" each time you switched networks. A location is identified by the gateway's
BSSID (if known) or SSID, and carries its own trusted-device/AP list, so moving
between known places doesn't re-flag your own gear.
"""
from __future__ import annotations

import os

from .config import load_config, save_config


def identify(gateway_bssid, connected_ssid, cfg=None):
    """-> (location_name, is_new) best match for the network you're currently on."""
    cfg = cfg or load_config()
    locs = cfg.get("locations", {})
    for name, loc in locs.items():
        if gateway_bssid and gateway_bssid.upper() in [b.upper() for b in loc.get("gateway_bssids", [])]:
            return name, False
        if connected_ssid and connected_ssid in loc.get("ssids", []):
            return name, False
    return None, True


def save_location(path, name, gateway_bssid=None, ssid=None):
    cfg = load_config(path)
    locs = cfg.setdefault("locations", {})
    loc = locs.setdefault(name, {"gateway_bssids": [], "ssids": []})
    if gateway_bssid and gateway_bssid.upper() not in [b.upper() for b in loc["gateway_bssids"]]:
        loc["gateway_bssids"].append(gateway_bssid.upper())
    if ssid and ssid not in loc["ssids"]:
        loc["ssids"].append(ssid)
    save_config(path, cfg)
    return loc


def delete_location(path, name):
    cfg = load_config(path)
    cfg.get("locations", {}).pop(name, None)
    save_config(path, cfg)


def list_locations(cfg=None):
    cfg = cfg or load_config()
    return cfg.get("locations", {})

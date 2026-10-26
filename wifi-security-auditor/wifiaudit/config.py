"""Configuration: trusted SSID->BSSID allow-list and detection tuning."""
import copy
import json
import os

DEFAULT_CONFIG = {
    # SSID -> list of BSSIDs you own / trust. Anything else using that SSID is flagged.
    "trusted": {},
    "rogue_threshold": 60,        # rogue score >= this  => ROGUE AP
    "suspicious_threshold": 30,   # rogue score >= this  => suspicious finding
    "suspicious_ssid_patterns": [
        r"free[-_ ]?wi-?fi", r"xfinitywifi", r"attwifi", r"starbucks", r"airport",
        r"hotel", r"^wifi$", r"^internet$",
    ],
    "default_ssid_patterns": [
        r"^(TP-?LINK|NETGEAR|linksys|D-?Link|ASUS|Tenda|HUAWEI|Belkin|FRITZ!Box|JioFiber|Airtel|ACT)[-_ ]?\w*$",
    ],
}


def load_config(path=None):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg


def save_config(path, cfg):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)


def trust(path, ssid, bssid):
    """Add a BSSID to the trusted list for an SSID."""
    cfg = load_config(path)
    lst = cfg["trusted"].setdefault(ssid, [])
    if bssid.upper() not in [x.upper() for x in lst]:
        lst.append(bssid.upper())
    save_config(path, cfg)
    return cfg


def fix_owner(path):
    """When started via sudo, hand files back to the invoking user so later non-root runs still work."""
    try:
        uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        if uid and hasattr(os, "geteuid") and os.geteuid() == 0 and os.path.exists(path):
            os.chown(path, int(uid), int(gid or uid))
    except (OSError, ValueError):
        pass


def set_known_device(path, mac, label):
    """Remember a device as 'known' (label=None removes it)."""
    cfg = load_config(path)
    known = cfg.setdefault("known_devices", {})
    mac = mac.upper().replace("-", ":")
    if label:
        known[mac] = label[:60]
    else:
        known.pop(mac, None)
    save_config(path, cfg)
    return known

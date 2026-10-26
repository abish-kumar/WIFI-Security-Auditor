"""Security scoring, rogue-AP detection and aggregate statistics."""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from .config import DEFAULT_CONFIG
from .oui import is_locally_administered

# Higher = stronger. Used to spot "same SSID, weaker security" downgrades.
ENC_RANK = {"OPEN": 0, "WEP": 1, "OWE": 2, "WPA": 2, "WPA/WPA2": 3, "WPA2": 4,
            "WPA2-Enterprise": 5, "WPA2/WPA3": 5, "WPA3": 6}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
LEVELS = ("SECURE", "VULNERABLE", "HIGH RISK", "ROGUE AP")


def _f(sev, title, detail, fix=""):
    return {"sev": sev, "title": title, "detail": detail, "fix": fix}


# --------------------------------------------------------------------------- #
# Per-network assessment
# --------------------------------------------------------------------------- #
def assess(n, cfg):
    score, forced, F = 100, None, []
    enc = n.encryption

    if enc == "OPEN":
        score -= 60
        forced = "HIGH RISK"
        F.append(_f("critical", "Open network - no encryption",
                    "All traffic is sent in cleartext. Anyone in range can sniff it, inject traffic or "
                    "join and attack other clients.",
                    "Enable WPA3-SAE (or WPA2-AES) with a strong passphrase. For public hotspots use "
                    "OWE (Enhanced Open) plus client isolation and a captive portal."))
    elif enc == "WEP":
        score -= 70
        forced = "HIGH RISK"
        F.append(_f("critical", "WEP encryption (broken)",
                    "WEP keys can be recovered in minutes from passively captured traffic.",
                    "Replace with WPA2-AES/WPA3 immediately; replace hardware that cannot support it."))
    elif enc == "WPA":
        score -= 40
        F.append(_f("high", "WPA (v1) / TKIP only",
                    "WPA1 with TKIP is deprecated and vulnerable to known attacks (e.g. Beck-Tews, MIC "
                    "key recovery).",
                    "Move to WPA2-AES (CCMP) at minimum, preferably WPA3."))
    elif enc == "WPA/WPA2":
        score -= 25
        F.append(_f("medium", "Mixed WPA/WPA2 mode",
                    "Legacy WPA/TKIP clients are still accepted, which allows downgrade of the weakest "
                    "link.",
                    "Switch to WPA2-AES only (or WPA2/WPA3 transition mode)."))
    elif enc == "WPA2" and "TKIP" in n.cipher:
        score -= 20
        F.append(_f("medium", "TKIP cipher enabled on WPA2",
                    "TKIP is a legacy cipher with known weaknesses and lowers throughput (802.11n+).",
                    "Set the cipher to AES/CCMP only."))
    elif enc == "OWE":
        score -= 10
        F.append(_f("low", "Opportunistic Wireless Encryption (OWE)",
                    "Traffic is encrypted but the AP is not authenticated.",
                    "Fine for guest hotspots; use WPA3-SAE/Enterprise for private networks."))

    if enc in ("WPA2", "WPA2/WPA3") and n.pmf == "none":
        score -= 5
        F.append(_f("low", "Management-frame protection (802.11w) not enabled",
                    "Without PMF, deauth/disassoc frames can be spoofed to disrupt clients.",
                    "Enable PMF as 'capable' or 'required' on the AP."))
    if enc == "WPA2" and (not n.auth or "PSK" in n.auth):
        F.append(_f("info", "WPA2-PSK exposed to offline dictionary attacks",
                    "A captured 4-way handshake can be cracked offline if the passphrase is weak.",
                    "Use a random passphrase of 14+ characters or migrate to WPA3-SAE / WPA2-Enterprise."))

    cap_vuln = False
    if n.wps:
        if n.wps_locked:
            score -= 10
            F.append(_f("low", "WPS enabled (setup locked)",
                        "The AP reports WPS but has locked setup after failed attempts.",
                        "Disable WPS entirely in the router admin page."))
        else:
            score -= 25
            cap_vuln = True
            F.append(_f("high", "WPS enabled and unlocked",
                        "WPS PIN authentication is vulnerable to online PIN brute-forcing and, on affected "
                        "chipsets, offline Pixie-Dust recovery - bypassing the Wi-Fi passphrase.",
                        "Disable WPS (PIN and push-button) and update router firmware."))

    if n.hidden:
        F.append(_f("info", "Hidden SSID",
                    "Hiding the SSID is not a security control - the name is revealed in probe and "
                    "association frames - and can make clients leak their preferred-network lists.",
                    "Broadcast the SSID and rely on strong encryption instead."))

    for pat in cfg.get("default_ssid_patterns", []):
        if n.ssid and re.match(pat, n.ssid, re.I):
            score -= 5
            F.append(_f("low", "Default / vendor-style SSID",
                        "Factory-style names hint at unchanged defaults (admin password, firmware).",
                        "Rename the SSID, change the admin credentials and update firmware."))
            break

    n.score = max(0, min(100, score))
    n.level = "SECURE" if n.score >= 80 else "VULNERABLE" if n.score >= 30 else "HIGH RISK"
    if forced:
        n.level = forced
    elif cap_vuln and n.level == "SECURE":
        n.level = "VULNERABLE"
    n.findings = F
    return n


# --------------------------------------------------------------------------- #
# Rogue AP / evil-twin detection (weighted heuristics)
# --------------------------------------------------------------------------- #
def detect_rogues(nets, cfg):
    trusted = {s: {b.upper() for b in v} for s, v in (cfg.get("trusted") or {}).items()}
    rogue_t = cfg.get("rogue_threshold", 60)
    sus_pat = [re.compile(p, re.I) for p in cfg.get("suspicious_ssid_patterns", [])]

    by_ssid, ssids_by_bssid = defaultdict(list), defaultdict(set)
    for n in nets:
        if n.ssid:
            by_ssid[n.ssid].append(n)
            ssids_by_bssid[n.bssid].add(n.ssid)

    for n in nets:
        pts, why = 0, []
        n.rogue, n.rogue_score, n.rogue_reasons = False, 0, []
        if n.ssid in trusted and n.bssid in trusted[n.ssid]:
            continue                                   # explicitly trusted by the operator

        grp = by_ssid.get(n.ssid, []) if n.ssid else []
        sibs = [x for x in grp if x is not n]

        if n.ssid in trusted:
            pts += 70
            why.append("SSID is on your trusted list but this BSSID is not (possible evil twin)")

        if sibs:
            ranks = [ENC_RANK.get(x.encryption, 3) for x in grp]
            mine = ENC_RANK.get(n.encryption, 3)
            if mine == min(ranks) and mine < max(ranks):
                best = max(grp, key=lambda x: ENC_RANK.get(x.encryption, 3)).encryption
                pts += 45
                why.append(f"Same SSID is also broadcast with {best}, but this AP offers only "
                           f"{n.encryption} (downgrade / evil-twin pattern)")
            vendors = Counter(x.vendor for x in grp if x.vendor)
            if (len(vendors) > 1 and n.vendor and vendors[n.vendor] == min(vendors.values())
                    and vendors[n.vendor] < max(vendors.values())):
                pts += 15
                why.append(f"Hardware vendor ({n.vendor}) differs from the other APs on this SSID")
            if is_locally_administered(n.bssid):
                pts += 15
                why.append("Locally-administered (spoofed/virtual) BSSID on a duplicated SSID")
            others = [x.signal for x in sibs if x.signal is not None]
            if n.signal is not None and others and n.signal >= max(others) + 15:
                pts += 15
                why.append("Much stronger signal than the legitimate-looking AP(s) with the same SSID")

        if len(ssids_by_bssid[n.bssid]) >= 3:
            pts += 60
            why.append(f"One BSSID advertises {len(ssids_by_bssid[n.bssid])} different SSIDs "
                       "(Karma/MANA-style behaviour)")

        if n.encryption == "OPEN" and n.ssid and any(p.search(n.ssid) for p in sus_pat):
            pts += 20
            why.append("Open network with a lure-style SSID (free/airport/hotel/hotspot)")

        n.rogue_score = min(pts, 100)
        n.rogue_reasons = why
        n.rogue = pts >= rogue_t


def analyze(nets, cfg=None):
    cfg = {**DEFAULT_CONFIG, **(cfg or {})}
    sus_t = cfg.get("suspicious_threshold", 30)
    for n in nets:
        assess(n, cfg)
    detect_rogues(nets, cfg)
    for n in nets:
        if n.rogue:
            n.findings.insert(0, _f(
                "critical", "Possible rogue access point / evil twin", "; ".join(n.rogue_reasons),
                "Locate the device (signal strength + BSSID), check it against your asset list, and "
                "remove it from the network/premises. If it is legitimate, mark the BSSID as trusted."))
        elif n.rogue_score >= sus_t:
            n.findings.insert(0, _f("medium", "Suspicious access point", "; ".join(n.rogue_reasons),
                                    "Verify the device; add its BSSID to the trusted list if it is yours."))
        if n.connected:
            if n.rogue:
                n.findings.insert(0, _f("critical", "YOU ARE CONNECTED TO THIS SUSPECTED ROGUE AP",
                                        "Traffic from this device is passing through an access point that matches evil-twin indicators.",
                                        "Disconnect now, avoid logging in to anything, and reconnect only to a verified AP."))
            else:
                n.findings.append(_f("info", "You are connected to this network",
                                     "This is the access point your device is currently using.", ""))
        n.findings.sort(key=lambda f: SEV_ORDER[f["sev"]])
    nets.sort(key=lambda n: (not n.rogue, n.score, -(n.signal if n.signal is not None else -100)))
    return nets


# --------------------------------------------------------------------------- #
# Aggregate statistics
# --------------------------------------------------------------------------- #
def recommend_channel(nets):
    use = [n.channel for n in nets if 1 <= n.channel <= 14]
    return min((1, 6, 11), key=lambda c: sum(1 for u in use if abs(u - c) < 5))


def summarize(nets):
    rogue = [n for n in nets if n.rogue]
    ok = [n for n in nets if not n.rogue]
    secure = [n for n in ok if n.level == "SECURE"]
    vuln = [n for n in ok if n.level != "SECURE"]
    fixes = Counter()
    for n in nets:
        for f in n.findings:
            if f["sev"] in ("critical", "high", "medium") and f["fix"]:
                fixes[(f["title"], f["fix"])] += 1
    avg = round(sum(n.score for n in nets) / len(nets), 1) if nets else 0
    posture = int(max(0, round(avg - 10 * min(len(rogue), 5)))) if nets else 100
    grade = "A" if posture >= 90 else "B" if posture >= 80 else "C" if posture >= 70 else "D" if posture >= 55 else "F"
    mine = next((n for n in nets if n.connected), None)
    return {
        "connected": ({"name": mine.name, "bssid": mine.bssid, "score": mine.score, "level": mine.display_level,
                       "encryption": mine.encryption} if mine else None),
        "posture": posture,
        "grade": grade,
        "total": len(nets),
        "secure": len(secure),
        "vulnerable": len(vuln),                       # everything not secure and not rogue
        "high_risk": sum(1 for n in vuln if n.level == "HIGH RISK"),
        "rogue": len(rogue),
        "avg_score": round(sum(n.score for n in nets) / len(nets), 1) if nets else 0,
        "wps_enabled": sum(1 for n in nets if n.wps),
        "open": sum(1 for n in nets if n.encryption == "OPEN"),
        "by_encryption": dict(Counter(n.encryption for n in nets)),
        "channels": dict(sorted(Counter(n.channel for n in nets if n.channel).items())),
        "recommended_channel": recommend_channel(nets),
        "top_fixes": [{"title": t, "fix": f, "count": c} for (t, f), c in fixes.most_common(6)],
    }

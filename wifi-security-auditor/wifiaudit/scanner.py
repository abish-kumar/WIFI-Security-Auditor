"""
Wi-Fi discovery backends. ALL backends are PASSIVE (they listen to beacons /
read the OS scan list). Nothing here deauthenticates, injects or attacks.

  auto      - best real method available on this machine (deep, else system)
  deep      - full beacon detail (RSN/WPA/WPS/PMF) WITHOUT monitor mode:
                Windows: native WLAN API (wlanapi.dll)     Linux: `iw scan`
  scapy     - sniff beacon / probe-response frames on a monitor-mode interface
              (full detail: RSN/WPA IEs, WPS state, PMF).      Linux + root
  airodump  - drive `airodump-ng` (+ optional `wash` for WPS).  Linux + root
  system    - OS scan list via nmcli (Linux) or netsh (Windows). no root, no WPS data
  demo      - realistic sample data (matches the project brief) for demos/tests
"""
from __future__ import annotations

import csv
import glob
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import threading
import time

from .models import Network, band_for_freq, freq_to_channel

BACKENDS = ("auto", "deep", "system", "scapy", "airodump", "demo")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,15}$")


class ScanError(RuntimeError):
    """A scan failed. `hint` tells the user how to fix it."""
    def __init__(self, msg, hint=""):
        super().__init__(msg)
        self.hint = hint


def check_iface(iface):
    if not iface or not IFACE_RE.match(iface):
        raise ScanError("Invalid or missing interface name (e.g. wlan0mon)")
    return iface


def pct_to_dbm(pct):
    """Approximate quality-% -> dBm (same mapping NetworkManager/Windows use)."""
    return int(int(pct) / 2 - 100)


# --------------------------------------------------------------------------- #
# 802.11 information-element parsing (RSN / WPA / WPS)
# --------------------------------------------------------------------------- #
CIPHERS = {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 8: "GCMP", 9: "GCMP-256", 10: "CCMP-256"}
AKMS = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256",
        6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE", 11: "Suite-B", 12: "Suite-B-192", 18: "OWE"}


def parse_rsn(info: bytes):
    """Parse the RSN element (ID 48) -> dict or None."""
    try:
        off = 2                                   # version
        group = info[off + 3]
        off += 4
        pc = int.from_bytes(info[off:off + 2], "little")
        off += 2
        pairwise = [info[off + 4 * i + 3] for i in range(pc)]
        off += 4 * pc
        ac = int.from_bytes(info[off:off + 2], "little")
        off += 2
        akm = [info[off + 4 * i + 3] for i in range(ac)]
        off += 4 * ac
        caps = int.from_bytes(info[off:off + 2], "little") if len(info) >= off + 2 else 0
    except (IndexError, ValueError):
        return None
    return {"group": group, "pairwise": pairwise, "akm": akm, "caps": caps}


def parse_wpa(info: bytes):
    """Parse the legacy WPA vendor element (00:50:F2 type 1)."""
    try:
        off = 4 + 2                               # OUI+type, version
        group = info[off + 3]
        off += 4
        pc = int.from_bytes(info[off:off + 2], "little")
        off += 2
        pairwise = [info[off + 4 * i + 3] for i in range(pc)]
        off += 4 * pc
        ac = int.from_bytes(info[off:off + 2], "little")
        off += 2
        akm = [info[off + 4 * i + 3] for i in range(ac)]
    except (IndexError, ValueError):
        return None
    return {"group": group, "pairwise": pairwise, "akm": akm}


def parse_wps(info: bytes):
    """Parse the WPS vendor element (00:50:F2 type 4) TLVs."""
    locked, off = False, 4
    while off + 4 <= len(info):
        t = int.from_bytes(info[off:off + 2], "big")
        ln = int.from_bytes(info[off + 2:off + 4], "big")
        val = info[off + 4:off + 4 + ln]
        if t == 0x1057 and val and val[0] == 1:   # AP Setup Locked
            locked = True
        off += 4 + ln
    return {"locked": locked}


def classify(rsn, wpa, privacy):
    """-> (encryption, cipher, auth, pmf)"""
    ciphers, auths, pmf = set(), set(), None
    akms = set()
    if rsn:
        ciphers |= {CIPHERS.get(c, str(c)) for c in rsn["pairwise"]}
        auths |= {AKMS.get(a, str(a)) for a in rsn["akm"]}
        akms = set(rsn["akm"])
        caps = rsn["caps"]
        pmf = "required" if caps & 0x40 else "capable" if caps & 0x80 else "none"
    if wpa:
        ciphers |= {CIPHERS.get(c, str(c)) for c in wpa["pairwise"]}
        auths |= {AKMS.get(a, str(a)) for a in wpa["akm"]}
    if rsn:
        sae, psk = bool(akms & {8, 9}), bool(akms & {2, 4, 6})
        eap = bool(akms & {1, 3, 5, 11, 12})
        if 18 in akms:
            enc = "OWE"
        elif sae and psk:
            enc = "WPA2/WPA3"
        elif sae:
            enc = "WPA3"
        elif eap and not psk:
            enc = "WPA2-Enterprise"
        else:
            enc = "WPA2"
        if wpa and enc == "WPA2":
            enc = "WPA/WPA2"
    elif wpa:
        enc = "WPA"
    elif privacy:
        enc = "WEP"
    else:
        enc = "OPEN"
    return enc, "/".join(sorted(ciphers)), "/".join(sorted(auths)), pmf


def walk_ies(data):
    """Yield (element_id, payload) from a raw 802.11 information-element blob."""
    i = 0
    while i + 2 <= len(data):
        eid, ln = data[i], data[i + 1]
        yield eid, bytes(data[i + 2:i + 2 + ln])
        i += 2 + ln


def interpret_ies(elements):
    ssid, channel, rsn, wpa, wps = "", 0, None, None, None
    for eid, info in elements:
        if eid == 0:
            ssid = info.decode("utf-8", errors="replace")
        elif eid == 3 and info:
            channel = info[0]
        elif eid == 61 and info and not channel:
            channel = info[0]
        elif eid == 48:
            rsn = parse_rsn(info)
        elif eid == 221 and info.startswith(b"\x00\x50\xf2\x01"):
            wpa = parse_wpa(info)
        elif eid == 221 and info.startswith(b"\x00\x50\xf2\x04"):
            wps = parse_wps(info)
    return {"ssid": ssid, "channel": channel, "rsn": rsn, "wpa": wpa, "wps": wps}


def network_from_ies(bssid, ies_blob, privacy, signal, freq_mhz=0):
    ie = interpret_ies(walk_ies(ies_blob))
    channel = ie["channel"] or (freq_to_channel(freq_mhz) if freq_mhz else 0)
    enc, cipher, auth, pmf = classify(ie["rsn"], ie["wpa"], privacy)
    wps = ie["wps"]
    return Network(bssid=bssid, ssid=ie["ssid"], channel=channel, signal=signal, encryption=enc,
                   cipher=cipher, auth=auth, pmf=pmf, wps=bool(wps), band=band_for_freq(freq_mhz),
                   wps_locked=wps["locked"] if wps else None)


# --------------------------------------------------------------------------- #
# Backend: scapy (monitor mode)
# --------------------------------------------------------------------------- #
_CH24 = list(range(1, 14))
_CH5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
        132, 136, 140, 144, 149, 153, 157, 161, 165]


def scan_scapy(iface, duration=20, hop=True):
    check_iface(iface)
    try:
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, sniff
    except ImportError as e:
        raise ScanError("scapy is not installed (pip install scapy)") from e
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ScanError("Raw 802.11 capture needs root: run with sudo")

    found, stop = {}, threading.Event()

    def hopper():
        chans = _CH24 + _CH5
        while not stop.is_set():
            for ch in chans:
                if stop.is_set():
                    return
                subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(0.25)

    def on_pkt(pkt):
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            return
        bssid = (pkt[Dot11].addr3 or "").upper()
        layer = pkt[Dot11Beacon] if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp]
        privacy = bool(int(layer.cap) & 0x10)
        elements, elt = [], pkt.getlayer(Dot11Elt)
        while isinstance(elt, Dot11Elt):
            elements.append((elt.ID, bytes(elt.info or b"")))
            elt = elt.payload.getlayer(Dot11Elt)
        ie = interpret_ies(elements)
        ssid, channel, rsn, wpa, wps = ie["ssid"], ie["channel"], ie["rsn"], ie["wpa"], ie["wps"]
        try:
            signal = int(pkt.dBm_AntSignal)
        except Exception:
            signal = None
        if not channel:
            try:
                channel = freq_to_channel(int(pkt.ChannelFrequency))
            except Exception:
                pass
        enc, cipher, auth, pmf = classify(rsn, wpa, privacy)
        try:
            freq_mhz = int(pkt.ChannelFrequency)
        except Exception:
            freq_mhz = 0
        key = (bssid, ssid)
        net = Network(bssid=bssid, ssid=ssid, channel=channel, signal=signal,
                      encryption=enc, cipher=cipher, auth=auth, pmf=pmf, band=band_for_freq(freq_mhz),
                      wps=bool(wps), wps_locked=(wps or {}).get("locked") if wps else None)
        old = found.get(key)
        if old and old.signal is not None and (signal is None or old.signal > signal):
            net.signal = old.signal
        found[key] = net

    t = threading.Thread(target=hopper, daemon=True)
    if hop and shutil.which("iw"):
        t.start()
    try:
        sniff(iface=iface, prn=on_pkt, store=False, timeout=duration)
    except (PermissionError, OSError) as e:
        raise ScanError(f"Could not capture on {iface}: {e}. Is it in monitor mode?") from e
    finally:
        stop.set()
    return list(found.values())


# --------------------------------------------------------------------------- #
# Backend: airodump-ng (+ wash)
# --------------------------------------------------------------------------- #
def _map_privacy(priv, cipher, auth):
    toks = set((priv or "").upper().split())
    if not toks or "OPN" in toks:
        return "OPEN"
    if "WEP" in toks:
        return "WEP"
    if "OWE" in toks:
        return "OWE"
    mgt = "MGT" in (auth or "").upper()
    if "WPA3" in toks and "WPA2" in toks:
        return "WPA2/WPA3"
    if "WPA3" in toks:
        return "WPA3"
    if "WPA2" in toks and "WPA" in toks:
        return "WPA/WPA2"
    if "WPA2" in toks:
        return "WPA2-Enterprise" if mgt else "WPA2"
    if "WPA" in toks:
        return "WPA"
    return "WPA2"


def parse_airodump_csv(text):
    text = text.replace("\r", "").lstrip("\n")
    block = text.split("\n\n")[0]
    nets = []
    for i, row in enumerate(csv.reader(block.splitlines())):
        if i == 0 or len(row) < 14:
            continue
        row = [c.strip() for c in row]
        try:
            channel = int(row[3])
        except ValueError:
            channel = 0
        try:
            power = int(row[8])
        except ValueError:
            power = None
        if power is not None and (power >= 0):      # -1 means "unknown"
            power = None
        nets.append(Network(
            bssid=row[0], ssid=row[13], channel=max(channel, 0), signal=power,
            encryption=_map_privacy(row[5], row[6], row[7]),
            cipher=row[6].replace(" ", "/"), auth=row[7].replace(" ", "/")))
    return nets


def run_wash(iface, duration=15):
    """Return {BSSID: locked_bool} for APs with WPS enabled (needs `wash`)."""
    if not shutil.which("wash"):
        return {}
    p = subprocess.Popen(["wash", "-i", iface, "-j"], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True)
    try:
        out, _ = p.communicate(timeout=duration)
    except subprocess.TimeoutExpired:
        p.terminate()
        try:
            out, _ = p.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
    res = {}
    for line in (out or "").splitlines():
        try:
            d = json.loads(line)
            res[d["bssid"].upper()] = bool(d.get("wps_locked"))
        except (ValueError, KeyError, AttributeError):
            continue
    return res


def scan_airodump(iface, duration=20):
    check_iface(iface)
    if not shutil.which("airodump-ng"):
        raise ScanError("airodump-ng not found (install aircrack-ng)")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ScanError("airodump-ng needs root: run with sudo")
    tmp = tempfile.mkdtemp(prefix="wifiaudit_")
    prefix = os.path.join(tmp, "cap")
    proc = subprocess.Popen(["airodump-ng", "--band", "abg", "--write-interval", "1",
                             "--output-format", "csv", "-w", prefix, iface],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(duration)
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
    try:
        files = glob.glob(prefix + "-*.csv")
        if not files:
            raise ScanError("airodump-ng produced no output (monitor mode? root?)")
        with open(files[0], errors="ignore") as f:
            nets = parse_airodump_csv(f.read())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    wps = run_wash(iface)
    for n in nets:
        if n.bssid in wps:
            n.wps, n.wps_locked = True, wps[n.bssid]
        elif wps:
            n.wps = False
    return nets


# --------------------------------------------------------------------------- #
# Backend: OS scan list (nmcli / netsh)
# --------------------------------------------------------------------------- #
def _enc_from_tokens(tokens):
    t = {x.upper() for x in tokens}
    t.discard("")
    if not t or t == {"--"}:
        return "OPEN"
    if "WEP" in t:
        return "WEP"
    if "OWE" in t:
        return "OWE"
    ent = "802.1X" in t
    if "WPA3" in t and "WPA2" in t:
        return "WPA2/WPA3"
    if "WPA3" in t:
        return "WPA3"
    if "WPA2" in t and "WPA1" in t:
        return "WPA/WPA2"
    if "WPA2" in t:
        return "WPA2-Enterprise" if ent else "WPA2"
    if "WPA1" in t or "WPA" in t:
        return "WPA"
    return "WPA2"


def _unescape(s):
    return s.replace("\\:", ":").replace("\\\\", "\\")


def parse_nmcli(text):
    nets, seen = [], set()
    for line in text.splitlines():
        parts = [_unescape(p) for p in re.split(r"(?<!\\):", line)]
        if len(parts) < 5:
            continue
        if len(parts) < 6:
            continue
        inuse, bssid, ssid, chan, sig, sec = parts[:6]
        flags = " ".join(parts[6:]).lower()
        if (bssid, ssid) in seen:
            continue
        seen.add((bssid, ssid))
        cipher = "/".join(c for c, k in (("TKIP", "pair_tkip"), ("CCMP", "pair_ccmp")) if k in flags)
        nets.append(Network(bssid=bssid, ssid=ssid, channel=int(chan or 0),
                            signal=pct_to_dbm(sig or 0), encryption=_enc_from_tokens(sec.split()),
                            cipher=cipher, connected=inuse.strip() == "*"))
    return nets


def _scan_nmcli():
    subprocess.run(["nmcli", "dev", "wifi", "rescan"], capture_output=True, timeout=20)
    time.sleep(3)
    out = subprocess.run(
        ["nmcli", "-t", "--escape", "yes", "-f",
         "IN-USE,BSSID,SSID,CHAN,SIGNAL,SECURITY,WPA-FLAGS,RSN-FLAGS", "dev", "wifi", "list"],
        capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise ScanError("nmcli failed: " + (out.stderr.strip() or "no Wi-Fi adapter?"),
                        "Is Wi-Fi switched on and NetworkManager running?  Try: nmcli radio wifi on")
    return parse_nmcli(out.stdout)


_NETSH_AUTH = {"open": "OPEN", "shared": "WEP", "wpa-personal": "WPA", "wpa-enterprise": "WPA",
               "wpa2-personal": "WPA2", "wpa2-enterprise": "WPA2-Enterprise",
               "wpa3-personal": "WPA3", "wpa3-enterprise": "WPA2-Enterprise", "owe": "OWE"}


def parse_netsh(text):
    nets, ssid, auth, enc, cur = [], "", "", "", None
    for line in text.splitlines():
        m = re.match(r"^\s*SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            ssid, auth, enc, cur = m.group(1).strip(), "", "", None
            continue
        m = re.match(r"^\s*BSSID\s+\d+\s*:\s*(\S+)", line)
        if m:
            e = _NETSH_AUTH.get(auth.lower(), "WPA2")
            if e == "OPEN" and enc.lower() == "wep":
                e = "WEP"
            cur = {"bssid": m.group(1), "ssid": ssid, "encryption": e, "cipher": enc}
            nets.append(cur)
            continue
        m = re.match(r"^\s*(Authentication|Encryption|Signal|Channel)\s*:\s*(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if k == "Authentication":
            auth = v
        elif k == "Encryption":
            enc = v
        elif cur is not None and k == "Signal":
            cur["signal"] = pct_to_dbm(v.strip("% ") or 0)
        elif cur is not None and k == "Channel":
            cur["channel"] = int(v or 0)
    return [Network(**d) for d in nets]


WIN_HINT = ("Windows needs Location services ON for Wi-Fi scans: Settings > Privacy & security > Location "
            "(and 'Let desktop apps access your location'). Also check that Wi-Fi is switched on.")


def windows_connected():
    """(ssid, bssid) of the current Windows Wi-Fi connection, or None."""
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return None
    ssid = bssid = state = ""
    for line in out.splitlines():
        m = re.match(r"^\s*(SSID|BSSID|State)\s*:\s*(.*)$", line)
        if m:
            k, v = m.group(1), m.group(2).strip()
            if k == "SSID":
                ssid = v
            elif k == "BSSID":
                bssid = v.upper()
            else:
                state = v.lower()
    return (ssid, bssid) if bssid and state == "connected" else None


def scan_system():
    sysname = platform.system()
    if sysname == "Linux":
        if not shutil.which("nmcli"):
            raise ScanError("nmcli not found", "Install NetworkManager (sudo apt install network-manager) or use the deep scan")
        return "nmcli", _scan_nmcli()
    if sysname == "Windows":
        out = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, timeout=30)
        text = out.stdout or ""
        if "no wireless interface" in text.lower():
            raise ScanError("No Wi-Fi adapter found on this PC", "Enable the Wi-Fi adapter (or plug in a USB Wi-Fi adapter).")
        nets = parse_netsh(text)
        if out.returncode != 0 or not nets:
            raise ScanError("Windows returned no Wi-Fi networks: " + (text.strip()[:140] or "empty result"), WIN_HINT)
        cur = windows_connected()
        if cur:
            for n in nets:
                n.connected = n.bssid == cur[1]
        return "netsh", nets
    raise ScanError(f"No built-in scan method for {sysname}",
                    "Use a Linux or Windows machine (macOS no longer exposes BSSIDs to apps).")


# --------------------------------------------------------------------------- #
# Backend: DEEP scan - full beacon IEs without monitor mode
# --------------------------------------------------------------------------- #
def _iw_codes(names, table):
    out = []
    for tok in names.replace("IEEE 802.1X", "8021X").replace("/", "|").split():
        if tok.upper() in table:
            out.append(table[tok.upper()])
    return out


_IW_CIPHER = {"CCMP": 4, "TKIP": 2, "GCMP": 8, "GCMP-256": 9, "CCMP-256": 10, "WEP-40": 1, "WEP40": 1, "WEP-104": 5, "WEP104": 5}
_IW_AKM = {"PSK": 2, "8021X": 1, "SAE": 8, "OWE": 18, "FT|PSK": 4, "FT|8021X": 3, "PSK|SHA-256": 6,
           "8021X|SHA-256": 5, "FT|SAE": 9}


def _iw_akm(text):
    t = text.replace("IEEE 802.1X", "8021X")
    out = []
    for tok in t.split():
        k = tok.upper().replace("/", "|")
        if k in _IW_AKM:
            out.append(_IW_AKM[k])
        elif k.startswith("SUITE-B") or k.startswith("FILS"):
            out.append(11)
    return out


def parse_iw_scan(text):
    """Parse `iw dev X scan` / `scan dump` output into Networks (with WPS, PMF, connected flag)."""
    nets, blocks, cur = [], [], None
    for line in text.splitlines():
        m = re.match(r"^BSS\s+([0-9A-Fa-f:]{17})", line)
        if m:
            cur = {"bssid": m.group(1).upper(), "lines": [], "connected": "associated" in line.lower()}
            blocks.append(cur)
        elif cur is not None:
            cur["lines"].append(line)
    for b in blocks:
        ssid, freq, signal, privacy, ds = "", 0, None, False, 0
        sec, sections, age_ms = None, {}, 0
        for raw in b["lines"]:
            line = raw.strip()
            if not line:
                continue
            m = re.match(r"^(RSN|WPA|WPS):\s*(.*)$", line)
            if m and not raw.startswith("\t\t"):
                sec = m.group(1)
                sections[sec] = []
                rest = m.group(2).strip()
                if rest.startswith("*"):
                    sections[sec].append(rest.lstrip("* ").strip())
                continue
            if raw.startswith("\t\t") and sec:
                sections[sec].append(line.lstrip("* ").strip())
                continue
            if not raw.startswith("\t\t"):
                sec = None
            if line.startswith("freq:"):
                try:
                    freq = int(float(line.split(":", 1)[1]))
                except ValueError:
                    pass
            elif line.startswith("signal:"):
                m2 = re.search(r"(-?\d+(?:\.\d+)?)", line)
                signal = int(float(m2.group(1))) if m2 else None
            elif line.startswith("capability:"):
                privacy = "Privacy" in line
            elif line.startswith("SSID:"):
                ssid = line.split(":", 1)[1].strip()
                ssid = re.sub(r"\\x([0-9a-fA-F]{2})", lambda mm: chr(int(mm.group(1), 16)), ssid)
            elif line.startswith("DS Parameter set:"):
                m2 = re.search(r"channel\s+(\d+)", line)
                ds = int(m2.group(1)) if m2 else 0
            elif line.startswith("last seen:"):
                m2 = re.search(r"(\d+)\s*ms", line)
                age_ms = int(m2.group(1)) if m2 else 0
        if age_ms > 120000:                                 # stale cache entry
            continue

        def sec_info(name):
            lines = sections.get(name)
            if lines is None:
                return None
            d = {"pairwise": [], "akm": [], "caps": 0, "group": 0}
            for ln in lines:
                if ln.startswith("Pairwise ciphers:"):
                    d["pairwise"] = _iw_codes(ln.split(":", 1)[1], _IW_CIPHER)
                elif ln.startswith("Authentication suites:"):
                    d["akm"] = _iw_akm(ln.split(":", 1)[1])
                elif ln.startswith("Capabilities:"):
                    m2 = re.search(r"\(0x([0-9a-fA-F]+)\)", ln)
                    d["caps"] = int(m2.group(1), 16) if m2 else 0
                    if "MFP-required" in ln:
                        d["caps"] |= 0x40
                    elif "MFP-capable" in ln:
                        d["caps"] |= 0x80
            return d

        rsn, wpa = sec_info("RSN"), sec_info("WPA")
        enc, cipher, auth, pmf = classify(rsn, wpa, privacy)
        wps = sections.get("WPS")
        locked = None
        if wps is not None:
            locked = any("locked" in ln.lower() and re.search(r"(0x0?1\b|\b1\b|yes|true)", ln.split(":", 1)[-1].lower())
                         for ln in wps)
        n = Network(bssid=b["bssid"], ssid=ssid, channel=ds or freq_to_channel(freq), signal=signal,
                    encryption=enc, cipher=cipher, auth=auth, pmf=pmf, wps=wps is not None, wps_locked=locked,
                    band=band_for_freq(freq), connected=b["connected"])
        nets.append(n)
    return nets


def _linux_managed_iface(iface=None):
    if iface:
        return check_iface(iface)
    for i in list_wifi_interfaces():
        if i["mode"] in ("managed", ""):
            return i["name"]
    raise ScanError("No Wi-Fi adapter found", "Linux VM? A virtual machine cannot see the laptop's built-in Wi-Fi - "
                    "attach a USB Wi-Fi adapter to the VM.")


def scan_iw(iface=None):
    if not shutil.which("iw"):
        raise ScanError("`iw` is not installed", "sudo apt install iw")
    dev = _linux_managed_iface(iface)
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    merged = {}
    for attempt in range(2):
        if root:
            r = subprocess.run(["iw", "dev", dev, "scan"], capture_output=True, text=True, timeout=40)
            if r.returncode != 0 and "busy" in (r.stderr + r.stdout).lower():
                time.sleep(2)
                r = subprocess.run(["iw", "dev", dev, "scan", "dump"], capture_output=True, text=True, timeout=20)
        else:                                               # no root: ask NetworkManager to rescan, then read the cache
            if shutil.which("nmcli"):
                subprocess.run(["nmcli", "dev", "wifi", "rescan", "ifname", dev], capture_output=True, timeout=20)
            time.sleep(3.5 if attempt == 0 else 1.5)
            r = subprocess.run(["iw", "dev", dev, "scan", "dump"], capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            raise ScanError(f"iw scan failed: {(r.stderr or r.stdout).strip()[:160]}",
                            "Make sure Wi-Fi is on and the adapter is not in monitor mode. Root gives the freshest results (sudo).")
        for n in parse_iw_scan(r.stdout):
            old = merged.get((n.bssid, n.ssid))
            if not old or (n.signal or -200) > (old.signal or -200):
                n.connected = n.connected or bool(old and old.connected)
                merged[(n.bssid, n.ssid)] = n
    if not merged:
        raise ScanError("The adapter returned no networks", "Is Wi-Fi switched on? (nmcli radio wifi on / rfkill unblock wifi)")
    return list(merged.values())


# ---- Windows native WLAN API (wlanapi.dll) via ctypes ----------------------------------
def _wlan_structs():
    import ctypes as C

    class GUID(C.Structure):
        _fields_ = [("Data1", C.c_uint32), ("Data2", C.c_uint16), ("Data3", C.c_uint16), ("Data4", C.c_ubyte * 8)]

    class WLAN_INTERFACE_INFO(C.Structure):
        _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", C.c_wchar * 256), ("isState", C.c_uint32)]

    class WLAN_INTERFACE_INFO_LIST(C.Structure):
        _fields_ = [("dwNumberOfItems", C.c_uint32), ("dwIndex", C.c_uint32), ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]

    class DOT11_SSID(C.Structure):
        _fields_ = [("uSSIDLength", C.c_uint32), ("ucSSID", C.c_ubyte * 32)]

    class WLAN_RATE_SET(C.Structure):
        _fields_ = [("uRateSetLength", C.c_uint32), ("usRateSet", C.c_uint16 * 126)]

    class WLAN_BSS_ENTRY(C.Structure):
        _fields_ = [("dot11Ssid", DOT11_SSID), ("uPhyId", C.c_uint32), ("dot11Bssid", C.c_ubyte * 6),
                    ("dot11BssType", C.c_int32), ("dot11BssPhyType", C.c_int32), ("lRssi", C.c_int32),
                    ("uLinkQuality", C.c_uint32), ("bInRegDomain", C.c_ubyte), ("usBeaconPeriod", C.c_uint16),
                    ("ullTimestamp", C.c_uint64), ("ullHostTimestamp", C.c_uint64),
                    ("usCapabilityInformation", C.c_uint16), ("ulChCenterFrequency", C.c_uint32),
                    ("wlanRateSet", WLAN_RATE_SET), ("ulIeOffset", C.c_uint32), ("ulIeSize", C.c_uint32)]

    class WLAN_BSS_LIST(C.Structure):
        _fields_ = [("dwTotalSize", C.c_uint32), ("dwNumberOfItems", C.c_uint32), ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]

    return GUID, WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST, WLAN_BSS_ENTRY, WLAN_BSS_LIST


def scan_wlanapi(wait=4.0):
    """Read raw beacon IEs (RSN/WPA/WPS) from Windows' own WLAN service - no drivers, no admin."""
    import ctypes as C
    from ctypes import wintypes as W
    GUID, IFINFO, IFLIST, BSSENTRY, BSSLIST = _wlan_structs()
    wlan = C.WinDLL("wlanapi.dll")
    wlan.WlanOpenHandle.argtypes = [W.DWORD, C.c_void_p, C.POINTER(W.DWORD), C.POINTER(W.HANDLE)]
    wlan.WlanCloseHandle.argtypes = [W.HANDLE, C.c_void_p]
    wlan.WlanEnumInterfaces.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(C.POINTER(IFLIST))]
    wlan.WlanScan.argtypes = [W.HANDLE, C.POINTER(GUID), C.c_void_p, C.c_void_p, C.c_void_p]
    wlan.WlanGetNetworkBssList.argtypes = [W.HANDLE, C.POINTER(GUID), C.c_void_p, C.c_int32, W.BOOL, C.c_void_p,
                                           C.POINTER(C.POINTER(BSSLIST))]
    wlan.WlanFreeMemory.argtypes = [C.c_void_p]
    for f in (wlan.WlanOpenHandle, wlan.WlanCloseHandle, wlan.WlanEnumInterfaces, wlan.WlanScan,
              wlan.WlanGetNetworkBssList):
        f.restype = W.DWORD

    handle, ver = W.HANDLE(), W.DWORD()
    if wlan.WlanOpenHandle(2, None, C.byref(ver), C.byref(handle)) != 0:
        raise ScanError("Could not open the Windows WLAN service", "Is the 'WLAN AutoConfig' service running?")
    try:
        plist = C.POINTER(IFLIST)()
        if wlan.WlanEnumInterfaces(handle, None, C.byref(plist)) != 0:
            raise ScanError("Could not list Wi-Fi adapters")
        count = plist.contents.dwNumberOfItems
        if count == 0:
            wlan.WlanFreeMemory(plist)
            raise ScanError("No Wi-Fi adapter found on this PC", "Enable Wi-Fi or plug in a USB Wi-Fi adapter.")
        base = C.addressof(plist.contents.InterfaceInfo)
        guids = [GUID.from_buffer_copy(IFINFO.from_address(base + i * C.sizeof(IFINFO)).InterfaceGuid) for i in range(count)]
        wlan.WlanFreeMemory(plist)
        for g in guids:                                     # trigger fresh scans, then give the radio time
            wlan.WlanScan(handle, C.byref(g), None, None, None)
        time.sleep(wait)
        merged = {}
        for g in guids:
            pb = C.POINTER(BSSLIST)()
            if wlan.WlanGetNetworkBssList(handle, C.byref(g), None, 3, False, None, C.byref(pb)) != 0:
                continue
            n_items = pb.contents.dwNumberOfItems
            first = C.addressof(pb.contents.wlanBssEntries)
            for i in range(n_items):
                addr = first + i * C.sizeof(BSSENTRY)
                e = BSSENTRY.from_address(addr)
                bssid = ":".join(f"{b:02X}" for b in e.dot11Bssid)
                ies = C.string_at(addr + e.ulIeOffset, e.ulIeSize) if e.ulIeSize else b""
                net = network_from_ies(bssid, ies, bool(e.usCapabilityInformation & 0x10), int(e.lRssi),
                                       int(e.ulChCenterFrequency // 1000))
                if not net.ssid and e.dot11Ssid.uSSIDLength:        # SSID not carried in IEs
                    net = Network(**{**net.raw(), "ssid": bytes(e.dot11Ssid.ucSSID[:e.dot11Ssid.uSSIDLength]).decode("utf-8", "replace")})
                merged[(net.bssid, net.ssid)] = net
            wlan.WlanFreeMemory(pb)
    finally:
        wlan.WlanCloseHandle(handle, None)
    cur = windows_connected()
    nets = list(merged.values())
    if cur:
        for n in nets:
            n.connected = n.bssid == cur[1]
    if not nets:
        raise ScanError("Windows returned no networks", WIN_HINT)
    return nets


def scan_deep(iface=None):
    """-> (backend_used, networks). Falls back gracefully to the basic OS scan."""
    sysname = platform.system()
    if sysname == "Windows":
        try:
            return "wlanapi", scan_wlanapi()
        except ScanError:
            raise
        except Exception:                                    # ctypes/API surprise: use netsh instead
            return scan_system()
    if sysname == "Linux":
        try:
            return "iw", scan_iw(iface)
        except ScanError as e:
            if shutil.which("nmcli") and "adapter" not in str(e).lower():
                return scan_system()
            raise
    raise ScanError(f"Deep scan is not available on {sysname}", "Use Linux or Windows.")


# --------------------------------------------------------------------------- #
# Backend: demo data (mirrors the sample report in the project brief)
# --------------------------------------------------------------------------- #
def demo_networks():
    N = Network
    return [
        N("00:27:19:AA:01:10", "Home_Network", 6, -55, "WPA2", "CCMP", "PSK", wps=False, pmf="capable"),
        N("5E:12:47:9C:3B:11", "Office_Net", 36, -49, "WPA2", "CCMP", "PSK", wps=False, pmf="capable"),
        N("00:0B:86:10:20:30", "Office_Net", 36, -61, "WPA2", "CCMP", "PSK", wps=False, pmf="required"),
        N("24:A4:3C:11:22:33", "Lab_Secure", 149, -58, "WPA3", "CCMP", "SAE", wps=False, pmf="required"),
        N("00:14:6C:5D:E1:90", "CoffeeShop_WiFi", 11, -67, "WPA", "TKIP", "PSK", wps=True, wps_locked=False),
        N("00:05:5D:72:0A:BC", "Guest_Network", 1, -72, "OPEN", "", "", wps=True, wps_locked=False),
        N("00:E0:FC:34:56:78", "Public_WiFi", 3, -75, "OPEN", "", "", wps=True, wps_locked=False),
        N("00:14:BF:0F:AA:21", "Linksys_Legacy", 9, -70, "WEP", "WEP-40", "", wps=False),
        N("A0:04:60:21:43:65", "NETGEAR47", 11, -64, "WPA2", "CCMP", "PSK", wps=True, wps_locked=False, pmf="none"),
        N("FC:EC:DA:90:80:70", "Neighbor_5G", 44, -66, "WPA/WPA2", "CCMP/TKIP", "PSK", wps=False),
        N("24:0A:C4:BE:EF:01", "ESP_Plug_8F2A", 1, -78, "WPA2", "CCMP", "PSK", wps=True, wps_locked=False, pmf="none"),
        N("02:C0:CA:84:11:7E", "Home_Network", 6, -38, "OPEN", "", "", wps=False, pmf=None),
    ]


def run_backend(backend, iface=None, duration=20):
    """-> (backend_actually_used, [Network])"""
    if backend == "demo":
        return "demo", demo_networks()
    if backend == "system":
        return scan_system()
    if backend == "deep":
        return scan_deep(iface)
    if backend == "scapy":
        return "scapy", scan_scapy(iface, duration)
    if backend == "airodump":
        return "airodump", scan_airodump(iface, duration)
    if backend == "auto":
        first = None
        for b in ("deep", "system"):
            try:
                return run_backend(b, iface, duration)
            except ScanError as e:
                first = first or e
        raise first or ScanError("No scan method available on this machine")
    raise ScanError(f"Unknown backend '{backend}' (choose from {', '.join(BACKENDS)})")


def scan(backend, iface=None, duration=20):
    return run_backend(backend, iface, duration)[1]


# --------------------------------------------------------------------------- #
# Interface helper (netifaces optional)
# --------------------------------------------------------------------------- #
def list_wifi_interfaces():
    out = []
    if platform.system() == "Windows":
        try:
            text = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=15).stdout
        except Exception:
            return out
        cur = None
        for line in text.splitlines():
            m = re.match(r"^\s*(Name|Physical address|State)\s*:\s*(.*)$", line)
            if not m:
                continue
            k, v = m.group(1), m.group(2).strip()
            if k == "Name":
                cur = {"name": v, "mode": "managed", "mac": ""}
                out.append(cur)
            elif cur and k == "Physical address":
                cur["mac"] = v.upper().replace("-", ":")
        return out
    if shutil.which("iw"):
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        cur = None
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                cur = {"name": line.split()[1], "mode": "", "mac": ""}
                out.append(cur)
            elif cur and line.startswith("type "):
                cur["mode"] = line.split()[1]
            elif cur and line.startswith("addr "):
                cur["mac"] = line.split()[1]
    elif os.path.isdir("/sys/class/net"):
        for n in sorted(os.listdir("/sys/class/net")):
            if os.path.isdir(f"/sys/class/net/{n}/wireless"):
                out.append({"name": n, "mode": "", "mac": ""})
    try:
        import netifaces
        for i in out:
            if not i["mac"]:
                links = netifaces.ifaddresses(i["name"]).get(netifaces.AF_LINK, [])
                i["mac"] = links[0]["addr"] if links else ""
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------- #
# What can this machine actually do?  (drives the dashboard's backend picker)
# --------------------------------------------------------------------------- #
def capabilities():
    """What can THIS machine do?  Drives the dashboard's backend picker and setup hints."""
    import importlib.util
    sysname = platform.system()
    root = hasattr(os, "geteuid") and os.geteuid() == 0

    def cap(ok, reason="", hint=""):
        return {"available": bool(ok), "reason": reason, "hint": hint}

    adapters = []
    try:
        adapters = list_wifi_interfaces()
    except Exception:
        pass
    managed = [a for a in adapters if a["mode"] in ("managed", "")]
    no_adapter = ("No Wi-Fi adapter detected",
                  "Using a VM? It cannot see the host's Wi-Fi - attach a USB Wi-Fi adapter to the VM." if sysname == "Linux"
                  else "Enable Wi-Fi, or plug in a USB Wi-Fi adapter.")

    caps = {}
    # deep scan
    if sysname == "Windows":
        ok = bool(managed) and hasattr(__import__("ctypes"), "windll")
        caps["deep"] = cap(ok, "Native WLAN API - full WPS/PMF detail" if ok else no_adapter[0], "" if ok else no_adapter[1])
    elif sysname == "Linux":
        if not shutil.which("iw"):
            caps["deep"] = cap(False, "`iw` not installed", "sudo apt install iw")
        elif not managed:
            caps["deep"] = cap(False, *no_adapter)
        else:
            caps["deep"] = cap(True, "iw scan - full WPS/PMF detail" + ("" if root else " (run with sudo for fresher results)"))
    else:
        caps["deep"] = cap(False, f"Not available on {sysname}", "Use Linux or Windows")
    # basic OS scan
    if sysname == "Linux":
        ok = bool(shutil.which("nmcli")) and bool(managed)
        caps["system"] = cap(ok, "nmcli - basic detail" if ok else ("nmcli not found" if not shutil.which("nmcli") else no_adapter[0]),
                             "" if ok else ("sudo apt install network-manager" if not shutil.which("nmcli") else no_adapter[1]))
    elif sysname == "Windows":
        ok = bool(managed)
        caps["system"] = cap(ok, "netsh - basic detail" if ok else no_adapter[0], "" if ok else no_adapter[1])
    else:
        caps["system"] = cap(False, f"Not supported on {sysname}", "Use Linux or Windows")
    caps["auto"] = cap(caps["deep"]["available"] or caps["system"]["available"],
                       "Best available method" if (caps["deep"]["available"] or caps["system"]["available"]) else
                       (caps["deep"]["reason"] or "No scan method available"), caps["deep"]["hint"] or caps["system"]["hint"])
    # monitor-mode backends
    has_scapy = importlib.util.find_spec("scapy") is not None
    mon = [a for a in adapters if a["mode"] == "monitor"]
    if sysname != "Linux":
        caps["scapy"] = cap(False, "Monitor-mode capture is Linux-only", "Not needed - use Deep scan")
    elif not has_scapy:
        caps["scapy"] = cap(False, "scapy not installed", "pip install scapy")
    elif not root:
        caps["scapy"] = cap(False, "Needs root privileges", "Restart with: sudo python3 run.py")
    elif not mon:
        caps["scapy"] = cap(False, "No monitor-mode interface", "sudo airmon-ng start wlan0   (your own adapter)")
    else:
        caps["scapy"] = cap(True, "Ready on " + mon[0]["name"])
    if sysname != "Linux":
        caps["airodump"] = cap(False, "Linux-only", "Not needed - use Deep scan")
    elif not shutil.which("airodump-ng"):
        caps["airodump"] = cap(False, "airodump-ng not installed", "sudo apt install aircrack-ng")
    elif not root:
        caps["airodump"] = cap(False, "Needs root privileges", "Restart with: sudo python3 run.py")
    elif not mon:
        caps["airodump"] = cap(False, "No monitor-mode interface", "sudo airmon-ng start wlan0   (your own adapter)")
    else:
        caps["airodump"] = cap(True, "Ready on " + mon[0]["name"])
    caps["demo"] = cap(True, "Sample data for testing the UI")
    caps["platform"], caps["root"] = sysname, root
    caps["adapters"] = [{"name": a["name"], "mode": a["mode"], "mac": a["mac"]} for a in adapters]
    caps["monitor_iface"] = mon[0]["name"] if mon else ""
    caps["default"] = "auto"
    return caps

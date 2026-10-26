"""
Vulnerability correlation for banners the port scanner collects.

This ships a small, hand-curated reference of well-known, high-impact CVEs for common
services (the kind that show up on home/small-office networks). It is NOT a live feed -
new CVEs appear daily and a bundled file goes stale. `refresh()` pulls the current NVD
feed for the product names in this file when you have internet access; nothing here
calls out to the network unless you run that explicitly.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

BUNDLED_VERSION = "2026-10-13"   # bump when CURATED below changes

# Each entry: product regex (matched against the banner, case-insensitive) -> list of CVEs.
# version_lt / version_gte use simple dotted-version comparison against a version captured
# from the banner by `version_re` (first capture group). Entries with no version_re apply
# to the product generally (e.g. "still uses Telnet at all").
CURATED = [
    {"id": "openssh", "match": r"OpenSSH", "version_re": r"OpenSSH[_/]?(\d+\.\d+)",
     "cves": [
        {"cve": "CVE-2024-6387", "title": "regreSSHion - signal handler race condition (RCE)",
         "lt": "9.8", "sev": "critical",
         "detail": "A race condition in OpenSSH's signal handler can let a remote attacker execute code as root on glibc-based Linux systems.",
         "fix": "Upgrade OpenSSH to 9.8 or later."},
        {"cve": "CVE-2023-38408", "title": "PKCS#11 provider loading RCE via forwarded agent",
         "lt": "9.3p2", "sev": "high",
         "detail": "A flaw in the ssh-agent PKCS#11 feature can allow remote code execution when agent forwarding is enabled.",
         "fix": "Upgrade to 9.3p2 or later; avoid forwarding your agent to untrusted hosts."}]},
    {"id": "vsftpd", "match": r"vsftpd", "version_re": r"vsftpd (\d+\.\d+\.\d+)",
     "cves": [{"cve": "CVE-2011-2523", "title": "Backdoored vsftpd 2.3.4 (historic)", "lt": "2.3.5", "sev": "critical",
               "detail": "A since-patched, famously backdoored release. A listener on exactly this build should not exist today.",
               "fix": "Upgrade vsftpd immediately."}]},
    {"id": "proftpd", "match": r"ProFTPD", "version_re": r"ProFTPD (\d+\.\d+\.\d+)",
     "cves": [{"cve": "CVE-2019-12815", "title": "mod_copy arbitrary file copy", "lt": "1.3.6", "sev": "high",
               "detail": "Lets an attacker copy files on the server without authentication.", "fix": "Upgrade ProFTPD and disable mod_copy if unused."}]},
    {"id": "samba", "match": r"Samba|SMB", "version_re": r"Samba (\d+\.\d+\.\d+)",
     "cves": [{"cve": "CVE-2017-7494", "title": "SambaCry - remote code execution", "lt": "4.6.4", "sev": "critical",
               "detail": "A malicious shared library can be uploaded and executed remotely (the Samba equivalent of EternalBlue).",
               "fix": "Upgrade Samba; disable SMBv1 entirely."},
              {"cve": "general", "title": "SMB exposed to the network", "sev": "high",
               "detail": "SMB file sharing is the most common ransomware entry point (WannaCry, NotPetya both spread this way).",
               "fix": "Do not expose SMB beyond your LAN; disable SMBv1; require SMB signing."}]},
    {"id": "telnet", "match": r".*", "port": 23,
     "cves": [{"cve": "general", "title": "Telnet in use", "sev": "critical",
               "detail": "Telnet sends everything, including passwords, as plain text and has no modern protection.",
               "fix": "Replace with SSH and disable Telnet entirely."}]},
    {"id": "apache", "match": r"Apache", "version_re": r"Apache/(\d+\.\d+\.\d+)",
     "cves": [{"cve": "CVE-2021-41773", "title": "Path traversal / RCE (Apache 2.4.49)", "lt": "2.4.51", "gte": "2.4.49", "sev": "critical",
               "detail": "A path-traversal bug in a single release allowed reading files and, with CGI enabled, remote code execution.",
               "fix": "Upgrade to 2.4.51 or later."}]},
    {"id": "nginx", "match": r"nginx", "version_re": r"nginx/(\d+\.\d+\.\d+)",
     "cves": [{"cve": "CVE-2021-23017", "title": "DNS resolver off-by-one (RCE)", "lt": "1.20.1", "sev": "high",
               "detail": "A memory-corruption bug in nginx's DNS resolver code.", "fix": "Upgrade to 1.20.1 or later; avoid untrusted resolvers."}]},
    {"id": "iis", "match": r"Microsoft-IIS", "version_re": r"Microsoft-IIS/(\d+\.\d+)",
     "cves": [{"cve": "general", "title": "IIS banner reveals version", "sev": "low",
               "detail": "Version disclosure helps an attacker pick known exploits for that build.", "fix": "Suppress the Server header; keep Windows/IIS patched."}]},
    {"id": "rdp", "match": r".*", "port": 3389,
     "cves": [{"cve": "CVE-2019-0708", "title": "BlueKeep - pre-auth RCE in RDP", "sev": "critical",
               "detail": "A wormable flaw in old Windows RDP implementations; one of the most exploited vulnerabilities in history.",
               "fix": "Keep Windows fully patched, require Network Level Authentication, and never expose RDP directly to the internet - use a VPN."},
              {"cve": "general", "title": "RDP exposed to the network", "sev": "high",
               "detail": "RDP is the top initial-access vector for ransomware gangs.", "fix": "Restrict RDP to a VPN; use strong, unique passwords and MFA where possible."}]},
    {"id": "vnc", "match": r".*", "port": 5900,
     "cves": [{"cve": "general", "title": "VNC exposed to the network", "sev": "high",
               "detail": "Many VNC deployments use weak or no passwords and unencrypted traffic.", "fix": "Password-protect VNC, prefer tunnelling it over SSH/VPN, and don't expose it directly."}]},
    {"id": "redis", "match": r"redis", "port": 6379,
     "cves": [{"cve": "general", "title": "Redis reachable without authentication", "sev": "critical",
               "detail": "Unauthenticated Redis instances are routinely hijacked within minutes of being exposed - a classic cryptomining entry point.",
               "fix": "Set a strong `requirepass`, bind to localhost, and never expose Redis to the network."}]},
    {"id": "mysql", "match": r".*", "port": 3306,
     "cves": [{"cve": "general", "title": "MySQL/MariaDB exposed to the network", "sev": "high",
               "detail": "Databases should rarely be reachable from other machines on the LAN, let alone the internet.",
               "fix": "Bind to localhost or restrict with a firewall; use strong unique credentials."}]},
    {"id": "upnp", "match": r".*", "port": 1900,
     "cves": [{"cve": "general", "title": "UPnP enabled", "sev": "medium",
               "detail": "UPnP lets any device on the network open ports on your router automatically - malware uses this to punch holes outward.",
               "fix": "Disable UPnP on the router unless a specific device needs it."}]},
]
PORT_RULES = [e for e in CURATED if e.get("port")]
PATTERN_RULES = [e for e in CURATED if not e.get("port")]


def _vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")) or (0,)


def _cmp(a, b):
    a, b = _vtuple(a), _vtuple(b)
    ln = max(len(a), len(b))
    a += (0,) * (ln - len(a))
    b += (0,) * (ln - len(b))
    return (a > b) - (a < b)


def _match_version(found, rule):
    if "lt" in rule and _cmp(found, rule["lt"]) >= 0:
        return False
    if "gte" in rule and _cmp(found, rule["gte"]) < 0:
        return False
    return True


def lookup(port, banner):
    """-> list of CVE hits for one open port/banner, using the bundled reference."""
    banner = banner or ""
    hits = []
    for entry in PORT_RULES:
        if entry["port"] == port:
            hits += [dict(c, product=entry["id"]) for c in entry["cves"]]
    for entry in PATTERN_RULES:
        if not re.search(entry["match"], banner, re.I):
            continue
        found = None
        if entry.get("version_re"):
            m = re.search(entry["version_re"], banner)
            found = m.group(1) if m else None
        for c in entry["cves"]:
            if "lt" in c or "gte" in c:
                if found and _match_version(found, c):
                    hits.append(dict(c, product=entry["id"], detected_version=found))
            else:
                hits.append(dict(c, product=entry["id"]))
    seen, out = set(), []
    for h in hits:
        if h["cve"] not in seen:
            seen.add(h["cve"])
            out.append(h)
    return out


def annotate(open_ports):
    """Add a 'cves' list to each open-port dict from port_scan()."""
    for o in open_ports:
        o["cves"] = lookup(o["port"], o.get("banner", ""))
    return open_ports


# --------------------------------------------------------------------------- #
# Optional live refresh (only runs when the user explicitly asks for it and has
# internet access - this sandbox cannot reach NVD, so this path is untested here).
# --------------------------------------------------------------------------- #
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}&resultsPerPage=5"


def refresh(cache_path, products=None, timeout=10):
    """Fetch the newest few CVEs per product from NVD and cache them alongside the bundled
    reference. Requires internet access. Returns a short report of what was updated."""
    products = products or [e["id"] for e in PATTERN_RULES if e["id"] not in ("telnet",)]
    out, errors = {}, []
    for p in products:
        try:
            req = urllib.request.Request(NVD_URL.format(product=p), headers={"User-Agent": "wifi-security-auditor"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.load(r)
            items = []
            for v in data.get("vulnerabilities", []):
                cve = v.get("cve", {})
                desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                items.append({"cve": cve.get("id"), "title": desc[:140], "sev": "unknown", "detail": desc, "fix": "See the NVD entry for remediation guidance."})
            out[p] = items
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as e:
            errors.append(f"{p}: {e}")
    cache = {"fetched": time.strftime("%Y-%m-%d %H:%M"), "products": out}
    os.makedirs(os.path.dirname(os.path.abspath(cache_path)), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)
    return {"updated": list(out.keys()), "errors": errors, "cached_at": cache_path}


def load_cache(cache_path):
    if not os.path.exists(cache_path):
        return None
    try:
        with open(cache_path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

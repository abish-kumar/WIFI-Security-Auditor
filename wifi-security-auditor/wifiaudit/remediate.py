"""
Turns findings (from analyzer.py, nettools port scans, or the vuln database) into
concrete, numbered remediation steps a non-expert could follow in their router's
admin page. This only generates text - it never logs into or changes anything itself.
"""
from __future__ import annotations

import re

# Generic steps, keyed by a short topic the finding title matches against.
STEPS = [
 (r"Open network|no encryption", "Enable WPA2 or WPA3", [
   "Open your router's admin page (usually http://192.168.1.1 or http://192.168.0.1 - check the Network info tool).",
   "Find the Wireless / Wi-Fi Security section.",
   "Set Security Mode to WPA3-Personal if offered, otherwise WPA2-Personal (AES/CCMP).",
   "Set a passphrase of 14+ random characters or 4+ random words.",
   "Save and reconnect your devices with the new password."]),
 (r"WEP", "Replace WEP with WPA2/WPA3", [
   "Open the Wireless Security section of your router's admin page.",
   "Change Security Mode from WEP to WPA2-Personal (or WPA3 if available).",
   "Set a strong passphrase and save.",
   "If the router only supports WEP, it is over 15 years old - plan to replace it."]),
 (r"WPA \(v", "Upgrade from WPA to WPA2/WPA3", [
   "Open the Wireless Security section.",
   "Change Security Mode to WPA2-Personal (AES) or WPA2/WPA3-Transition.",
   "Save and reconnect devices - very old devices (pre-2006) may need a firmware update."]),
 (r"TKIP", "Switch the cipher from TKIP to AES", [
   "Open the Wireless Security section.",
   "Change Encryption/Cipher from TKIP (or Auto) to AES-only.",
   "Save - this can briefly disconnect clients while they rejoin."]),
 (r"WPS enabled and unlocked|WPS.*unlocked", "Turn off WPS", [
   "Open the Wireless or WPS section of your router's admin page.",
   "Switch WPS (Wi-Fi Protected Setup) to Off, including the push-button mode.",
   "Save. Devices still join normally by typing the Wi-Fi password."]),
 (r"WPS enabled \(setup locked\)|WPS.*locked", "Turn off WPS entirely", [
   "WPS is temporarily locked after failed attempts, but it will unlock again - turn it off instead of relying on the lock.",
   "Open the Wireless/WPS section and switch WPS to Off."]),
 (r"management-frame protection|PMF|802\.11w", "Enable Protected Management Frames (PMF)", [
   "Open the Wireless Security section.",
   "Find 802.11w / PMF / Management Frame Protection.",
   "Set it to Required if all your devices are from 2018 or later, otherwise Capable/Optional.",
   "Save."]),
 (r"Hidden SSID", "Stop hiding the network name", [
   "Open the Wireless section.",
   "Turn Hide SSID / Broadcast SSID back on (set to broadcast).",
   "Rely on WPA2/WPA3 encryption for protection instead - hiding the name adds no real security."]),
 (r"Default|vendor-style SSID", "Rename the network and change admin credentials", [
   "Open the Wireless section and set a unique Network Name (SSID) that does not reveal the router brand.",
   "Open the Administration/System section and change the default admin username and password.",
   "Check for and install any available firmware update."]),
 (r"rogue access point|evil twin|impostor", "Investigate and remove the suspected impostor", [
   "Note its BSSID (hardware address), signal strength and which SSID it is copying.",
   "Walk around with the Networks page open to see where its signal gets stronger - that is roughly its direction.",
   "If you find a device that should not be there, disconnect and physically remove it.",
   "If it is actually yours (a mesh node, a repeater), mark it as trusted from its detail panel."]),
 (r"HTTPS certificates failed", "Treat this network as actively hostile", [
   "Disconnect from this Wi-Fi network now.",
   "Do not enter any password or sensitive information while connected.",
   "If you must use it, connect through a VPN first.",
   "Report it to the venue (hotel/cafe) if it is meant to be their official network."]),
 (r"DNS answers look tampered", "Change your DNS server", [
   "Open your router's WAN/Internet or DNS settings.",
   "Set DNS servers to 1.1.1.1 / 1.0.0.1 (Cloudflare) or 9.9.9.9 (Quad9).",
   "Save and reboot the router.",
   "If the problem persists after changing DNS, contact your ISP - the tampering may be happening upstream."]),
 (r"Captive portal", "Be cautious on this network", [
   "Only enter credentials on the login page you were expecting - never your main email or banking password.",
   "Prefer connecting through a VPN once past the portal.",
   "Avoid signing in to important accounts until you are on a trusted network."]),
 (r"Telnet", "Disable Telnet", [
   "Open the device's admin page or management settings.",
   "Turn off the Telnet service.",
   "Use SSH instead if remote access is needed."]),
 (r"SMB exposed|SMB.*network", "Restrict SMB file sharing", [
   "Open the device's network/sharing settings.",
   "Disable SMBv1 if it is still enabled.",
   "Restrict SMB access to the local network only (never forward port 445 on your router).",
   "Require SMB signing if the device supports it."]),
 (r"RDP exposed|Remote Desktop", "Stop exposing Remote Desktop directly", [
   "Do not forward port 3389 on your router.",
   "Require Network Level Authentication in Windows' Remote Desktop settings.",
   "Use a VPN to reach RDP from outside your network instead of exposing it directly."]),
 (r"database exposed|MySQL|PostgreSQL|Redis|MSSQL", "Stop exposing the database to the network", [
   "Bind the database to localhost (127.0.0.1) unless another machine genuinely needs it.",
   "If network access is required, restrict it with a firewall to specific IP addresses.",
   "Set or rotate a strong, unique password for the database."]),
 (r"UPnP", "Turn off UPnP", [
   "Open the router's Advanced or NAT settings.",
   "Disable UPnP (Universal Plug and Play).",
   "Forward specific ports manually only if a device genuinely needs it."]),
]


def steps_for(title, detail=""):
    """-> (heading, [step, step, ...]) for a finding/CVE title, or None if nothing matches."""
    text = title + " " + detail
    for pat, heading, steps in STEPS:
        if re.search(pat, text, re.I):
            return heading, steps
    return None


def plan(findings):
    """Build a de-duplicated remediation plan from a list of {title, detail, fix, sev} dicts
    (analyzer findings, vuln-db hits, or router-fingerprint notes all use this shape)."""
    seen, out = set(), []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: order.get(x.get("sev", "info"), 4)):
        got = steps_for(f.get("title", ""), f.get("detail", ""))
        if got:
            heading, steps = got
        else:
            if not f.get("fix"):
                continue
            heading, steps = f["title"], [f["fix"]]
        key = heading
        if key in seen:
            continue
        seen.add(key)
        out.append({"sev": f.get("sev", "info"), "heading": heading, "steps": steps, "source": f.get("title", "")})
    return out


def plan_to_text(items, title="Remediation plan"):
    lines = [title, "=" * len(title), ""]
    for i, it in enumerate(items, 1):
        lines.append(f"{i}. [{it['sev'].upper()}] {it['heading']}")
        for s in it["steps"]:
            lines.append(f"     - {s}")
        lines.append("")
    return "\n".join(lines)

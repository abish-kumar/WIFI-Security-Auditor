"""
Network toolbox - everything here is for auditing YOUR OWN network.

Safety rules baked in: host discovery and port scanning only accept private / local addresses
(10.x, 172.16-31.x, 192.168.x, 169.254.x, 100.64.x, 127.x). Nothing here attacks, brute-forces
or intercepts anything: it reads, probes with ordinary TCP connections, and measures.
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import time as _time
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import string
import subprocess
import time
import urllib.error
import urllib.request

from . import vulndb
from .oui import is_locally_administered, lookup

IS_WIN = platform.system() == "Windows"
PRIVATE = [ipaddress.ip_network(n) for n in
           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "100.64.0.0/10")]
MAC_RE = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")


class ToolError(Exception):
    def __init__(self, msg, hint=""):
        super().__init__(msg)
        self.hint = hint


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6:
        return a.is_private or a.is_loopback or a.is_link_local
    return any(a in n for n in PRIVATE)


def _run(cmd, timeout=12):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return r.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def norm_mac(m):
    return (m or "").upper().replace("-", ":")


# =========================================================================== #
# 1. Local network info
# =========================================================================== #
def parse_ip_route(text):
    """`ip route show default` -> (gateway, dev)"""
    m = re.search(r"default via (\S+) dev (\S+)", text)
    return (m.group(1), m.group(2)) if m else (None, None)


def parse_ip_addr(text, dev=None):
    """`ip -o -4 addr show` -> [(dev, ip, prefix)]"""
    out = []
    for line in text.splitlines():
        m = re.match(r"^\d+:\s+(\S+)\s+inet\s+([\d.]+)/(\d+)", line)
        if m and (dev is None or m.group(1) == dev):
            out.append((m.group(1), m.group(2), int(m.group(3))))
    return out


def parse_route_print(text, local_ip=None):
    """Windows `route print -4` -> (gateway, local_ip, prefix); language independent."""
    gw = ip = None
    best = 0
    rows = []
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 5 and re.match(r"^\d+\.\d+\.\d+\.\d+$", p[0]) and re.match(r"^\d+\.\d+\.\d+\.\d+$", p[1]):
            rows.append(p)
    for p in rows:                                       # default route with the lowest metric
        if p[0] == "0.0.0.0" and p[1] == "0.0.0.0" and re.match(r"^\d+\.", p[2]):
            try:
                metric = int(p[4])
            except ValueError:
                metric = 9999
            if gw is None or metric < best:
                gw, ip, best = p[2], p[3], metric
    ip = local_ip or ip
    prefix = None
    for p in rows:
        if p[3] == ip and p[0] != "0.0.0.0" and p[1] not in ("255.255.255.255", "0.0.0.0") and not p[0].startswith(("127.", "224.")):
            try:
                prefix = ipaddress.ip_network(f"{p[0]}/{p[1]}").prefixlen
                break
            except ValueError:
                pass
    return gw, ip, prefix


def parse_dns_ipconfig(text):
    dns, grab = [], False
    for line in text.splitlines():
        if re.search(r"DNS Servers", line):
            grab = True
            dns += re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", line)
        elif grab and re.match(r"^\s+\d+\.\d+\.\d+\.\d+\s*$", line):
            dns.append(line.strip())
        else:
            grab = False
    return list(dict.fromkeys(dns))


def _udp_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))                       # UDP connect sends no packet; it just picks a route
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def parse_ip_addr6(text, dev=None):
    """`ip -o -6 addr show` -> [(dev, ip, prefix, scope)]"""
    out = []
    for line in text.splitlines():
        m = re.match(r"^\d+:\s+(\S+)\s+inet6\s+([0-9a-fA-F:]+)/(\d+)\s+scope\s+(\S+)", line)
        if m and (dev is None or m.group(1) == dev):
            out.append((m.group(1), m.group(2), int(m.group(3)), m.group(4)))
    return out


def ipv6_addresses(dev=None):
    """Best-effort list of this machine's IPv6 addresses (global + link-local)."""
    out = []
    if IS_WIN:
        text = _run(["netsh", "interface", "ipv6", "show", "address"])
        cur = ""
        for line in text.splitlines():
            m = re.match(r"^Interface\s+\d+:\s*(.+)$", line.strip())
            if m:
                cur = m.group(1)
                continue
            m = re.match(r"^(Address|Temporary|Public|DHCP)?\s*([0-9a-fA-F:]+(?:/\d+)?)\s*$", line.strip())
            m2 = re.search(r"\b([0-9a-fA-F:]{4,}::?[0-9a-fA-F:]*)\b", line)
            if m2 and ":" in m2.group(1) and (dev is None or dev == cur):
                addr = m2.group(1)
                out.append((cur, addr, "link-local" if addr.lower().startswith("fe80") else "global"))
    elif shutil.which("ip"):
        for d, a, p, scope in parse_ip_addr6(_run(["ip", "-o", "-6", "addr", "show"]), dev):
            out.append((d, a, "link-local" if scope == "link" else "global"))
    return out


def has_ipv6_internet():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.connect(("2606:4700:4700::1111", 80))      # Cloudflare - UDP connect sends nothing
        return True
    except OSError:
        return False
    finally:
        s.close()


def local_info():
    ip = _udp_local_ip()
    gw = dev = prefix = None
    dns = []
    if IS_WIN:
        gw, rip, prefix = parse_route_print(_run(["route", "print", "-4"]), ip)
        ip = ip or rip
        dns = parse_dns_ipconfig(_run(["ipconfig", "/all"]))
        if not dns:
            out = _run(["powershell", "-NoProfile", "-Command",
                        "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses -join ' '"], 15)
            dns = re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", out)
    else:
        gw, dev = parse_ip_route(_run(["ip", "route", "show", "default"]))
        addrs = parse_ip_addr(_run(["ip", "-o", "-4", "addr", "show"]))
        for d, a, p in addrs:
            if a == ip or (ip is None and d == dev):
                ip, dev, prefix = a, d, p
                break
        try:
            with open("/etc/resolv.conf") as f:
                dns = re.findall(r"^nameserver\s+(\S+)", f.read(), re.M)
        except OSError:
            pass
        if dns and dns[0].startswith("127.") and shutil.which("resolvectl"):
            out = _run(["resolvectl", "dns"])
            real = [x for x in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", out) if not x.startswith("127.")]
            dns = real or dns
    if not ip:
        raise ToolError("No active network connection found", "Connect to Wi-Fi or Ethernet first.")
    prefix = prefix or 24
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    mac = ""
    if dev and os.path.exists(f"/sys/class/net/{dev}/address"):
        with open(f"/sys/class/net/{dev}/address") as f:
            mac = norm_mac(f.read().strip())
    v6 = ipv6_addresses(dev)
    v6_global = [a for _, a, scope in v6 if scope == "global"]
    return {"ip": ip, "prefix": prefix, "cidr": str(net), "netmask": str(net.netmask), "gateway": gw, "iface": dev or "",
            "dns": dns, "mac": mac, "hostname": socket.gethostname(),
            "gateway_is_private": bool(gw and is_private(gw)),
            "ipv6": [{"iface": d, "address": a, "scope": scope} for d, a, scope in v6],
            "ipv6_global": v6_global, "ipv6_internet": bool(v6_global) and has_ipv6_internet()}


# =========================================================================== #
# 2. ARP table + device discovery
# =========================================================================== #
def parse_ip_neigh(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)\s+(\S+)", line)
        if m and m.group(4) not in ("FAILED", "INCOMPLETE"):
            out.append({"ip": m.group(1), "mac": norm_mac(m.group(3)), "iface": m.group(2)})
    return out


def parse_arp_a(text):
    out = []
    for line in text.splitlines():
        ip = re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b", line)
        mac = MAC_RE.search(line)
        if ip and mac:
            out.append({"ip": ip.group(1), "mac": norm_mac(mac.group(0)), "iface": ""})
    return out


def parse_ip_neigh6(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F:]+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)\s+(\S+)", line)
        if m and m.group(4) not in ("FAILED", "INCOMPLETE") and not m.group(1).lower().startswith("fe80") and not m.group(1).lower().startswith("ff"):
            out.append({"ip": m.group(1), "mac": norm_mac(m.group(3)), "iface": m.group(2)})
    return out


def ipv6_neighbors():
    """Devices seen via IPv6 Neighbor Discovery (Linux only; best-effort)."""
    if IS_WIN or not shutil.which("ip"):
        return []
    return parse_ip_neigh6(_run(["ip", "-6", "neigh", "show"]))


def arp_table():
    rows = []
    if not IS_WIN and shutil.which("ip"):
        rows = parse_ip_neigh(_run(["ip", "neigh", "show"]))
    if not rows and not IS_WIN and os.path.exists("/proc/net/arp"):
        with open("/proc/net/arp") as f:
            for line in f.read().splitlines()[1:]:
                p = line.split()
                if len(p) >= 6 and p[2] == "0x2" and p[3] != "00:00:00:00:00:00":
                    rows.append({"ip": p[0], "mac": norm_mac(p[3]), "iface": p[5]})
    if not rows:
        rows = parse_arp_a(_run(["arp", "-a"]))
    clean = []
    for r in rows:
        first = int(r["ip"].split(".")[0])
        if r["mac"] in ("FF:FF:FF:FF:FF:FF", "") or r["mac"].startswith("01:00:5E") or first >= 224:
            continue
        clean.append(r)
    return clean


PROBE_PORTS = (80, 443, 445, 22, 139, 53, 8080, 62078)


def _probe(ip, timeout=0.25):
    for p in PROBE_PORTS:
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((ip, p))
            return ip, True, p
        except ConnectionRefusedError:
            return ip, True, None                        # a refusal means a host answered
        except OSError:
            pass
        finally:
            s.close()
    return ip, False, None


def _hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def discover(cidr=None, known=None):
    info = None
    try:
        info = local_info()
    except ToolError:
        if not cidr:
            raise
    cidr = cidr or info["cidr"]
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise ToolError("That is not a valid network (example: 192.168.1.0/24)")
    if net.version != 4 or not is_private(str(net.network_address)):
        raise ToolError("For safety, device discovery only works on private networks",
                        "Allowed: 10.x.x.x, 172.16-31.x.x, 192.168.x.x")
    if net.num_addresses > 1024:
        raise ToolError("That network is too large (max /22 = 1024 addresses)", "Try a /24 such as 192.168.1.0/24")
    t0 = time.time()
    hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    alive = {}
    with cf.ThreadPoolExecutor(max_workers=128) as ex:
        for ip, ok, port in ex.map(_probe, hosts):
            if ok:
                alive[ip] = port
    time.sleep(0.4)                                      # let ARP entries settle
    arp = {r["ip"]: r["mac"] for r in arp_table() if r["ip"] in set(hosts)}
    ips = sorted(set(alive) | set(arp), key=lambda x: tuple(int(o) for o in x.split(".")))
    names = {}
    ex = cf.ThreadPoolExecutor(max_workers=32)
    futs = {ex.submit(_hostname, ip): ip for ip in ips}
    done, _ = cf.wait(futs, timeout=3)
    for f in done:
        names[futs[f]] = f.result()
    ex.shutdown(wait=False)
    me = info["ip"] if info else None
    gw = info["gateway"] if info else None
    known = known or {}
    devices = []
    for ip in ips:
        mac = arp.get(ip) or (info["mac"] if ip == me else "")
        devices.append({"ip": ip, "mac": mac, "vendor": lookup(mac) if mac else "", "hostname": names.get(ip, ""),
                        "is_gateway": ip == gw, "is_self": ip == me, "randomized": bool(mac) and is_locally_administered(mac),
                        "label": known.get(mac, "") if mac else "", "known": bool(mac) and mac in known})
    return {"cidr": str(net), "devices": devices, "scanned": len(hosts), "seconds": round(time.time() - t0, 1)}


# =========================================================================== #
# 3. Port scanner (own devices only)
# =========================================================================== #
SERVICES = {  # port: (name, level, plain-English note)
    21: ("FTP", "high", "File transfer in clear text - passwords can be sniffed. Replace with SFTP."),
    22: ("SSH", "low", "Remote login. Safe if you use strong passwords or keys; disable if unused."),
    23: ("Telnet", "critical", "Remote login in clear text with famously weak defaults. Turn it off."),
    25: ("SMTP", "low", "Mail server. Unexpected on a home device."),
    53: ("DNS", "info", "Name server - normal on a router."),
    80: ("HTTP", "info", "Web page without encryption. Router admin pages here are visible to anyone on the network."),
    110: ("POP3", "medium", "Old clear-text mail protocol."),
    135: ("MS-RPC", "medium", "Windows internals; should not be reachable from other devices."),
    139: ("NetBIOS", "medium", "Legacy Windows file sharing."),
    143: ("IMAP", "medium", "Mail access, often unencrypted."),
    443: ("HTTPS", "info", "Encrypted web page - normal."),
    445: ("SMB", "high", "Windows file sharing - the path ransomware and worms (WannaCry) use. Keep it off untrusted networks."),
    515: ("LPD", "low", "Printer service."),
    554: ("RTSP", "medium", "Video stream - typical of IP cameras. Check it needs a password."),
    631: ("IPP", "low", "Network printing."),
    1433: ("MSSQL", "high", "Database exposed to the network."),
    1723: ("PPTP", "medium", "Old VPN protocol with known weaknesses."),
    1900: ("UPnP", "medium", "Lets devices open router ports automatically; often abused."),
    3306: ("MySQL", "high", "Database exposed to the network."),
    3389: ("RDP", "high", "Windows Remote Desktop - a top ransomware entry point. Use a VPN instead."),
    5000: ("UPnP/Flask", "low", "Development or media service."),
    5432: ("PostgreSQL", "high", "Database exposed to the network."),
    5900: ("VNC", "high", "Remote screen control, often with weak passwords."),
    5985: ("WinRM", "medium", "Windows remote management."),
    8000: ("HTTP-alt", "low", "Alternative web service."),
    8080: ("HTTP-alt", "low", "Alternative web service / admin panel."),
    8443: ("HTTPS-alt", "info", "Alternative encrypted web service."),
    9100: ("JetDirect", "low", "Network printer raw port."),
    62078: ("iPhone sync", "info", "Apple device sync service - normal for iPhones/iPads."),
}
PRESETS = {
    "quick": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5900, 8080],
    "common": sorted(SERVICES),
    "web": [80, 443, 8000, 8080, 8443, 5000],
    "full": list(range(1, 1025)),
}


def parse_ports(spec):
    ports = set()
    for part in str(spec).replace(" ", "").split(","):
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            else:
                ports.add(int(part))
        except ValueError:
            raise ToolError(f"Cannot read port list '{spec}'", "Example: 22,80,443 or 8000-8100")
    ports = {p for p in ports if 1 <= p <= 65535}
    if not ports:
        raise ToolError("No valid ports given")
    if len(ports) > 1100:
        raise ToolError("Too many ports (max 1100 per scan)")
    return sorted(ports)


def _clean(b):
    return re.sub(r"[^\x20-\x7e]", " ", b.decode("latin-1")).strip()[:100]


def _check_port(host, port, timeout):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except OSError:
        s.close()
        return None
    banner = ""
    try:
        s.settimeout(0.7)
        if port in (80, 8000, 8080, 5000):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            data = s.recv(400).decode("latin-1", "replace")
            m = re.search(r"(?im)^server:\s*(.+)$", data)
            banner = _clean((m.group(1) if m else data.split("\r\n")[0]).encode("latin-1", "replace"))
        elif port in (21, 22, 25, 110, 143):
            banner = _clean(s.recv(120))
    except OSError:
        pass
    finally:
        s.close()
    return banner


def port_scan(host, ports="quick", timeout=0.6):
    host = (host or "").strip()
    if not host:
        raise ToolError("Enter an IP address to scan")
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        raise ToolError(f"Cannot resolve '{host}'")
    if not is_private(ip):
        raise ToolError("For safety this scanner only works on private/local addresses",
                        "Scan devices on your own network (e.g. 192.168.1.1).")
    plist = PRESETS[ports] if ports in PRESETS else parse_ports(ports)
    t0 = time.time()
    found = []
    with cf.ThreadPoolExecutor(max_workers=200) as ex:
        for port, banner in zip(plist, ex.map(lambda p: _check_port(ip, p, timeout), plist)):
            if banner is None:
                continue
            name, level, note = SERVICES.get(port, (_svc(port), "info", "Open port with no special risk note."))
            cves = vulndb.lookup(port, banner)
            if cves:
                worst_sev = max(cves, key=lambda c: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(c["sev"], 0))["sev"]
                if {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(worst_sev, 0) > {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(level, 0):
                    level = worst_sev
            found.append({"port": port, "service": name, "level": level, "note": note, "banner": banner, "cves": cves})
    risk = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max((risk[f["level"]] for f in found), default=-1)
    verdict = ("No open ports found in the scanned range - the device is quiet." if not found else
               "Some open ports are risky - see the notes below." if worst >= 3 else
               "Open ports found, none alarming." if worst <= 1 else "A few ports deserve a look.")
    return {"host": host, "ip": ip, "scanned": len(plist), "open": found, "verdict": verdict,
            "worst": worst, "seconds": round(time.time() - t0, 1)}


def _svc(port):
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "unknown"


# =========================================================================== #
# 4. Connection quality (latency / jitter / loss)
# =========================================================================== #
def parse_ping(text):
    times = [float(x) for x in re.findall(r"time=\s*([\d.]+)\s*ms", text)]
    times += [0.5 for _ in re.findall(r"time<1ms", text)]
    return times


def tcp_rtt(host, count=5, ports=(443, 80, 53)):
    for port in ports:
        times = []
        for _ in range(count):
            s = socket.socket()
            s.settimeout(1.5)
            t = time.perf_counter()
            try:
                s.connect((host, port))
                times.append((time.perf_counter() - t) * 1000)
            except ConnectionRefusedError:
                times.append((time.perf_counter() - t) * 1000)
            except OSError:
                pass
            finally:
                s.close()
            time.sleep(0.05)
        if times:
            return times, f"TCP:{port}"
    return [], "none"


def measure(name, host, count=5):
    times, method = [], "ping"
    if shutil.which("ping"):
        cmd = (["ping", "-n", str(count), "-w", "1500", host] if IS_WIN else
               ["ping", "-c", str(count), "-W", "1", host])
        times = parse_ping(_run(cmd, timeout=count * 2 + 5))
    if not times:
        times, method = tcp_rtt(host, count)
    jitter = (sum(abs(a - b) for a, b in zip(times, times[1:])) / (len(times) - 1)) if len(times) > 1 else 0
    return {"name": name, "host": host, "method": method, "sent": count, "received": len(times),
            "loss": round(100 * (1 - min(len(times), count) / count)),
            "min": round(min(times), 1) if times else None, "avg": round(sum(times) / len(times), 1) if times else None,
            "max": round(max(times), 1) if times else None, "jitter": round(jitter, 1)}


def connection_quality():
    targets = []
    try:
        gw = local_info().get("gateway")
        if gw:
            targets.append(("Your router", gw))
    except ToolError:
        pass
    targets += [("Cloudflare (1.1.1.1)", "1.1.1.1"), ("Google (8.8.8.8)", "8.8.8.8")]
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        results = list(ex.map(lambda t: measure(*t), targets))
    router = next((r for r in results if r["name"] == "Your router"), None)
    net = [r for r in results if r["name"] != "Your router" and r["avg"] is not None]
    issues, tips = [], []
    if not any(r["received"] for r in results):
        grade, verdict = "F", "No replies from anything - you appear to be offline."
    else:
        pts = 100
        if router and router["avg"] is not None:
            if router["avg"] > 30:
                pts -= 25
                issues.append(f"Your Wi-Fi link to the router is slow ({router['avg']} ms; healthy is under 10 ms).")
                tips.append("Move closer to the router or switch to the 5 GHz band.")
            if router["loss"] >= 5:
                pts -= 25
                issues.append(f"{router['loss']}% of packets to your router are lost - weak or interfered Wi-Fi.")
                tips.append("Change Wi-Fi channel (see Overview > channel chart) and reduce distance/obstacles.")
            if router["jitter"] > 20:
                pts -= 10
                issues.append(f"Latency to the router is unstable (jitter {router['jitter']} ms).")
        if net:
            avg = sum(r["avg"] for r in net) / len(net)
            if avg > 150:
                pts -= 25
                issues.append(f"Internet latency is high ({avg:.0f} ms).")
                tips.append("Restart the router; if it persists, contact your ISP.")
            elif avg > 60:
                pts -= 10
                issues.append(f"Internet latency is moderate ({avg:.0f} ms) - fine for browsing, noticeable in games/calls.")
            if any(r["loss"] >= 5 for r in net):
                pts -= 20
                issues.append("Packet loss to the internet.")
        else:
            pts -= 30
            issues.append("Router answers but the internet does not - check your modem / ISP.")
        grade = "A" if pts >= 90 else "B" if pts >= 75 else "C" if pts >= 60 else "D" if pts >= 40 else "F"
        verdict = {"A": "Excellent - fast and stable.", "B": "Good - suitable for everything.", "C": "Fair - some hiccups likely.",
                   "D": "Poor - expect lag and drops.", "F": "Very poor or offline."}[grade]
    return {"results": results, "grade": grade, "verdict": verdict, "issues": issues, "tips": list(dict.fromkeys(tips))}


# =========================================================================== #
# 5. Internet / DNS / HTTPS-interception health
# =========================================================================== #
def _resolve_ms(name):
    t = time.perf_counter()
    try:
        socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
        return round((time.perf_counter() - t) * 1000, 1), True
    except OSError:
        return round((time.perf_counter() - t) * 1000, 1), False


def _ips(name):
    try:
        return {a[4][0] for a in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)}
    except OSError:
        return set()


def tls_check(host="example.com"):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        return {"host": host, "ok": True, "issuer": issuer.get("organizationName") or issuer.get("commonName", "unknown")}
    except ssl.SSLCertVerificationError as e:
        return {"host": host, "ok": False, "tampered": True, "error": str(e.verify_message or e)[:140]}
    except OSError as e:
        return {"host": host, "ok": False, "tampered": False, "error": str(e)[:100]}


def internet_health():
    findings, out = [], {}
    # captive portal
    def fetch(url):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        op = urllib.request.build_opener(NoRedirect)
        try:
            r = op.open(urllib.request.Request(url, headers={"User-Agent": "wifi-auditor"}), timeout=6)
            return r.status, r.read(200).decode("latin-1", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except (OSError, ValueError):
            return None, ""
    s1, _ = fetch("http://connectivitycheck.gstatic.com/generate_204")
    s2, b2 = fetch("http://detectportal.firefox.com/success.txt")
    online = s1 == 204 or (s2 == 200 and b2.strip() == "success")
    captive = (s1 is not None and s1 != 204) and not (s2 == 200 and b2.strip() == "success")
    out["internet"] = {"online": online, "captive_portal": captive and s1 is not None}
    if s1 is None and s2 is None:
        findings.append({"sev": "high", "title": "No internet access", "detail": "Neither test site could be reached.",
                         "fix": "Check Wi-Fi connection, router and ISP."})
    elif captive:
        findings.append({"sev": "medium", "title": "Captive portal detected",
                         "detail": "This network intercepts web traffic to show a login/terms page (typical of hotels and cafes).",
                         "fix": "Only log in on pages you expect. Avoid sensitive accounts until connected through a VPN."})
    # DNS
    dns = {"servers": []}
    try:
        dns["servers"] = local_info()["dns"]
    except ToolError:
        pass
    timings = []
    for name in ("example.com", "wikipedia.org", "cloudflare.com"):
        ms, ok = _resolve_ms(name)
        timings.append({"name": name, "ms": ms, "ok": ok})
    dns["timings"] = timings
    ok_t = [t["ms"] for t in timings if t["ok"]]
    dns["avg_ms"] = round(sum(ok_t) / len(ok_t), 1) if ok_t else None
    rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(26)) + ".com"
    hijack = bool(_ips(rnd)) and bool(ok_t)
    dns["nxdomain_hijack"] = hijack
    if hijack:
        findings.append({"sev": "medium", "title": "DNS answers for domains that do not exist",
                         "detail": "A made-up domain name resolved. Your DNS server (or ISP/router) rewrites failed lookups, "
                                   "usually to show ads - and the same mechanism can redirect real sites.",
                         "fix": "Switch to a trustworthy DNS resolver (1.1.1.1, 9.9.9.9, 8.8.8.8) in your router."})
    exp = {"one.one.one.one": {"1.1.1.1", "1.0.0.1"}, "dns.google": {"8.8.8.8", "8.8.4.4"}}
    spoof = []
    for host, want in exp.items():
        got = _ips(host)
        if got and not (got & want):
            spoof.append({"host": host, "got": sorted(got), "expected": sorted(want)})
    dns["spoof_checks"] = spoof
    if spoof:
        findings.append({"sev": "critical", "title": "DNS answers look tampered with",
                         "detail": "Well-known names returned unexpected addresses: " +
                                   "; ".join(f"{s['host']} -> {', '.join(s['got'])}" for s in spoof),
                         "fix": "Do not log in to anything. Change DNS servers and check the router for DNS hijacking."})
    if dns["avg_ms"] and dns["avg_ms"] > 200:
        findings.append({"sev": "low", "title": "Slow DNS", "detail": f"Lookups take {dns['avg_ms']} ms on average.",
                         "fix": "Try a faster DNS resolver such as 1.1.1.1."})
    out["dns"] = dns
    # HTTPS interception
    tls = [tls_check(h) for h in ("example.com", "www.wikipedia.org")]
    out["tls"] = tls
    if any(t.get("tampered") for t in tls):
        findings.append({"sev": "critical", "title": "HTTPS certificates failed verification",
                         "detail": "A secure site presented a certificate your computer does not trust. On public Wi-Fi this is the signature of "
                                   "a man-in-the-middle attack (or a corporate proxy).",
                         "fix": "Disconnect, avoid entering passwords, and use mobile data or a VPN."})
    out["findings"] = findings
    out["verdict"] = ("Everything looks healthy." if not findings else
                      "Serious problem found." if any(f["sev"] == "critical" for f in findings) else "Some issues found.")
    return out


# =========================================================================== #
# 6. ARP spoofing health
# =========================================================================== #
def arp_health(baseline_path=None):
    rows = arp_table()
    gw = None
    try:
        gw = local_info().get("gateway")
    except ToolError:
        pass
    by_mac = {}
    for r in rows:
        by_mac.setdefault(r["mac"], []).append(r["ip"])
    findings = []
    for mac, ips in by_mac.items():
        if len(ips) > 1:
            findings.append({"sev": "medium", "title": f"One device claims {len(ips)} addresses",
                             "detail": f"{mac} answers for {', '.join(ips)}. A router doing proxy-ARP does this innocently, "
                                       "but so does an ARP-spoofing attacker.",
                             "fix": "If the MAC is not your router, investigate that device."})
    gw_mac = next((r["mac"] for r in rows if r["ip"] == gw), None)
    base = None
    if baseline_path and os.path.exists(baseline_path):
        try:
            with open(baseline_path) as f:
                base = json.load(f).get(gw or "")
        except (OSError, ValueError):
            base = None
    if gw_mac and base and base != gw_mac:
        findings.append({"sev": "critical", "title": "Your router's hardware address CHANGED",
                         "detail": f"Router {gw} was {base} when you saved the baseline and is {gw_mac} now. "
                                   "That is exactly what ARP spoofing / a man-in-the-middle looks like "
                                   "(unless you replaced the router).",
                         "fix": "Disconnect from this network. If you did swap the router, save a new baseline."})
    elif gw_mac and not base:
        findings.append({"sev": "info", "title": "No baseline saved yet",
                         "detail": "Save the router's current hardware address while you trust the network; later checks will compare against it.",
                         "fix": "Press 'Save baseline'."})
    if not gw_mac:
        findings.append({"sev": "low", "title": "Router not in ARP table",
                         "detail": "Open a web page or ping the router first, then re-run.", "fix": ""})
    return {"gateway": gw, "gateway_mac": gw_mac, "baseline": base,
            "entries": [{**r, "vendor": lookup(r["mac"]), "is_gateway": r["ip"] == gw} for r in rows],
            "findings": findings,
            "verdict": "Possible ARP spoofing!" if any(f["sev"] == "critical" for f in findings) else
                       "No sign of ARP spoofing." if not [f for f in findings if f["sev"] in ("medium", "high")] else "Worth a look."}


def save_baseline(path):
    info = local_info()
    gw = info.get("gateway")
    mac = next((r["mac"] for r in arp_table() if r["ip"] == gw), None)
    if not gw or not mac:
        raise ToolError("Router's hardware address not known yet", "Ping or open the router page first, then try again.")
    data = {}
    if os.path.exists(path):
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
    data[gw] = mac
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f)
    return {"gateway": gw, "mac": mac}


# =========================================================================== #
# 7. Current Wi-Fi link (live signal)
# =========================================================================== #
def signal_quality(dbm):
    if dbm is None:
        return {"label": "Unknown", "pct": 0, "advice": ""}
    pct = max(0, min(100, int(2 * (dbm + 100))))
    for lim, label, adv in ((-50, "Excellent", "Signal is superb."), (-60, "Good", "Reliable for streaming and calls."),
                            (-70, "Fair", "Fine for browsing; video calls may stutter."),
                            (-80, "Weak", "Expect slow speeds and drops. Move closer or add an access point."),
                            (-999, "Very poor", "Connection will be unreliable.")):
        if dbm >= lim:
            return {"label": label, "pct": pct, "advice": adv}


def parse_netsh_link(text):
    d = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z][A-Za-z ()/.-]*?)\s*:\s*(.*)$", line)
        if m:
            d.setdefault(m.group(1).strip().lower(), m.group(2).strip())
    if d.get("state", "").lower() != "connected":
        return {"connected": False}
    pct = int(re.sub(r"\D", "", d.get("signal", "0")) or 0)
    ch = int(re.sub(r"\D", "", d.get("channel", "0")) or 0)
    return {"connected": True, "ssid": d.get("ssid", ""), "bssid": norm_mac(d.get("bssid") or d.get("ap bssid", "")), "channel": ch,
            "signal_dbm": int(pct / 2 - 100), "signal_pct": pct, "rx_rate": d.get("receive rate (mbps)", ""),
            "tx_rate": d.get("transmit rate (mbps)", ""), "auth": d.get("authentication", ""), "cipher": d.get("cipher", ""),
            "radio": d.get("radio type", ""), "iface": d.get("name", "")}


def parse_iw_link(text, iface=""):
    if "Not connected" in text or "Connected to" not in text:
        return {"connected": False}
    g = lambda pat: (re.search(pat, text) or [None, ""])[1]
    freq = int(g(r"freq:\s*(\d+)") or 0)
    from .models import freq_to_channel
    sig = g(r"signal:\s*(-?\d+)")
    return {"connected": True, "ssid": g(r"SSID:\s*(.*)").strip(), "bssid": norm_mac(g(r"Connected to\s+([0-9a-fA-F:]{17})")),
            "channel": freq_to_channel(freq), "signal_dbm": int(sig) if sig else None,
            "rx_rate": g(r"rx bitrate:\s*([\d.]+)"), "tx_rate": g(r"tx bitrate:\s*([\d.]+)"), "iface": iface}


def current_link():
    if IS_WIN:
        d = parse_netsh_link(_run(["netsh", "wlan", "show", "interfaces"]))
    elif shutil.which("iw"):
        d = {"connected": False}
        from .scanner import list_wifi_interfaces
        for i in list_wifi_interfaces():
            if i["mode"] in ("managed", ""):
                r = parse_iw_link(_run(["iw", "dev", i["name"], "link"]), i["name"])
                if r["connected"]:
                    d = r
                    break
    else:
        d = {"connected": False}
    if d.get("connected"):
        d["band"] = "2.4 GHz" if 0 < d["channel"] <= 14 else "5 GHz" if d["channel"] else ""
        d["quality"] = signal_quality(d.get("signal_dbm"))
    d["t"] = time.time()
    return d


# =========================================================================== #
# 8. Saved Wi-Fi profiles audit  (never reads passwords)
# =========================================================================== #
def _profile_risk(auth, cipher, auto):
    a = (auth or "").upper()
    openish = a in ("OPEN", "") or "OPEN" in a or "NONE" in (cipher or "").upper() and "WPA" not in a
    wep = "WEP" in a or "WEP" in (cipher or "").upper() or a == "SHARED"
    wpa1 = a in ("WPA", "WPA-PERSONAL", "WPA-PSK", "WPA-ENTERPRISE") or (a.startswith("WPA-") and "WPA2" not in a and "WPA3" not in a)
    if openish or wep:
        kind = "open" if openish else "WEP"
        return ("high" if auto else "medium",
                f"Saved as {kind}." + (" Your device auto-connects, so an attacker can clone this network name and your device will join silently." if auto
                                       else " If you ever join it again, its traffic is unprotected."),
                "Forget this network (Settings > Wi-Fi > Manage known networks) or turn off auto-connect.")
    if wpa1:
        return ("medium", "Old WPA (v1) security.", "Forget it, or upgrade that router to WPA2/WPA3.")
    return ("ok", "Uses modern security.", "")


def parse_netsh_profile(text):
    d = {}
    for line in text.splitlines():
        m = re.match(r"^\s*(Authentication|Cipher|Connection mode)\s*:\s*(.*)$", line)
        if m:
            d.setdefault(m.group(1), m.group(2).strip())
    return d


def saved_profiles():
    out = []
    if IS_WIN:
        names = re.findall(r"(?:All User Profile|User Profile)\s*:\s*(.+)", _run(["netsh", "wlan", "show", "profiles"]))
        for name in [n.strip() for n in names][:60]:
            d = parse_netsh_profile(_run(["netsh", "wlan", "show", "profile", f"name={name}"]))
            auth, cipher = d.get("Authentication", ""), d.get("Cipher", "")
            auto = "automatically" in d.get("Connection mode", "").lower()
            lvl, note, fix = _profile_risk(auth, cipher, auto)
            out.append({"name": name, "security": auth or "unknown", "cipher": cipher, "autoconnect": auto, "risk": lvl, "note": note, "fix": fix})
    elif shutil.which("nmcli"):
        for line in _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"]).splitlines()[:200]:
            name, _, typ = line.rpartition(":")
            if "wireless" not in typ:
                continue
            vals = _run(["nmcli", "-g", "802-11-wireless-security.key-mgmt,connection.autoconnect", "connection", "show", name]).splitlines()
            km = vals[0].strip() if vals else ""
            auto = len(vals) > 1 and vals[1].strip().lower() == "yes"
            auth = {"": "Open", "none": "WEP", "wpa-psk": "WPA/WPA2-Personal", "sae": "WPA3-Personal", "wpa-eap": "Enterprise"}.get(km, km)
            lvl, note, fix = _profile_risk(auth, "", auto)
            out.append({"name": name, "security": auth, "cipher": "", "autoconnect": auto, "risk": lvl, "note": note, "fix": fix})
    else:
        raise ToolError("Saved-network audit needs Windows (netsh) or Linux (nmcli)")
    order = {"high": 0, "medium": 1, "ok": 2}
    out.sort(key=lambda x: (order.get(x["risk"], 3), x["name"].lower()))
    return {"profiles": out, "risky": sum(1 for p in out if p["risk"] != "ok")}


# =========================================================================== #
# 9. Router / gateway fingerprinting
# =========================================================================== #
ROUTER_SIGNATURES = [
    (r"RomPager", "An embedded web server (RomPager) found on many older routers - several versions have known remote-code-execution bugs (Misfortune Cookie)."),
    (r"GoAhead", "GoAhead embedded web server - common on IP cameras and cheap routers; several CVEs exist for old versions."),
    (r"lighttpd", "lighttpd web server - common on consumer routers."),
    (r"mini_httpd|boa/", "A minimal embedded web server typical of budget routers."),
    (r"DD-WRT", "DD-WRT third-party firmware."),
    (r"OpenWrt", "OpenWrt third-party firmware - generally well-maintained if kept updated."),
    (r"Tomato", "Tomato third-party firmware."),
]
ROUTER_VENDOR_HINTS = [
    (r"TP-?LINK", "TP-Link"), (r"NETGEAR", "Netgear"), (r"D-?Link", "D-Link"), (r"ASUS", "ASUS"),
    (r"Linksys", "Linksys"), (r"Huawei", "Huawei"), (r"ZTE", "ZTE"), (r"MikroTik", "MikroTik"),
    (r"Ubiquiti|UniFi", "Ubiquiti"), (r"Belkin", "Belkin"), (r"Tenda", "Tenda"), (r"Xiaomi", "Xiaomi"),
]


def _http_probe(ip, port, use_tls=False, timeout=3):
    import http.client
    conn_cls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
    ctx = ssl._create_unverified_context() if use_tls else None
    try:
        conn = conn_cls(ip, port, timeout=timeout, context=ctx) if use_tls else conn_cls(ip, port, timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": "wifi-security-auditor"})
        r = conn.getresponse()
        body = r.read(4000).decode("utf-8", "replace")
        headers = {k: v for k, v in r.getheaders()}
        conn.close()
        return r.status, headers, body
    except Exception:
        return None, {}, ""


def fingerprint_router(ip=None):
    """Identify the admin web UI of a router/gateway by its HTTP banner and page title - read-only GET, no login attempted."""
    ip = ip or (local_info() or {}).get("gateway")
    if not ip:
        raise ToolError("No router address known", "Connect to a network first.")
    if not is_private(ip):
        raise ToolError("For safety this only works on private/local addresses")
    tried = []
    for port, tls in ((80, False), (443, True), (8080, False)):
        status, headers, body = _http_probe(ip, port, tls)
        tried.append(port)
        if status is None:
            continue
        server = headers.get("Server", "") or headers.get("server", "")
        title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:80] if title_m else ""
        vendor = next((v for pat, v in ROUTER_VENDOR_HINTS if re.search(pat, server + " " + title + " " + body[:2000], re.I)), "")
        notes = [note for pat, note in ROUTER_SIGNATURES if re.search(pat, server, re.I)]
        auth = "WWW-Authenticate" in headers or status == 401
        return {"ip": ip, "reachable": True, "port": port, "https": tls, "server": server or "(not announced)",
                "page_title": title, "vendor": vendor, "notes": notes, "requires_login": auth,
                "status": status, "admin_url": ("https://" if tls else "http://") + ip + (f":{port}" if port not in (80, 443) else "")}
    return {"ip": ip, "reachable": False, "tried_ports": tried,
            "note": "No web admin page answered. Some routers only allow admin access from a specific LAN port, or use a non-standard port."}


# =========================================================================== #
# 9c. Download speed test
# =========================================================================== #
# Cloudflare publishes this endpoint specifically for speed measurement - no API key, no
# auth, widely used by open-source speed-test tools. We fall back to a couple of other
# well-known large static files if it is unreachable. This network call cannot be
# exercised in an offline sandbox; the byte/time -> Mbps math is covered by unit tests.
SPEED_TEST_URLS = [
    ("Cloudflare", "https://speed.cloudflare.com/__down?bytes=25000000"),
    ("Wikimedia (fallback)", "https://upload.wikimedia.org/wikipedia/commons/e/e8/Big_Buck_Bunny_Trailer_1080p.ogv"),
]


def _mbps(num_bytes, seconds):
    if seconds <= 0:
        return 0.0
    return round((num_bytes * 8) / seconds / 1_000_000, 1)


def speed_test(max_seconds=8, max_bytes=30_000_000):
    """Download as much as we can in max_seconds (or until max_bytes), report Mbps."""
    import urllib.request
    last_err = None
    for name, url in SPEED_TEST_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "wifi-security-auditor"})
            t0 = _time.perf_counter()
            got = 0
            with urllib.request.urlopen(req, timeout=6) as r:
                deadline = t0 + max_seconds
                while _time.perf_counter() < deadline and got < max_bytes:
                    chunk = r.read(262144)
                    if not chunk:
                        break
                    got += len(chunk)
            elapsed = _time.perf_counter() - t0
            if got < 50_000:                                 # suspiciously small - probably not a real transfer
                raise ToolError(f"Only received {got} bytes from {name}")
            mbps = _mbps(got, elapsed)
            rating = ("Excellent" if mbps >= 100 else "Good" if mbps >= 25 else "Fair" if mbps >= 5 else "Slow")
            return {"server": name, "mbps": mbps, "mb_transferred": round(got / 1_000_000, 1),
                    "seconds": round(elapsed, 1), "rating": rating,
                    "note": "Download speed only - a reliable public upload-test endpoint isn't available without an account, "
                            "so upload speed isn't measured here. Your real speed can vary with server load and network conditions."}
        except Exception as e:                               # noqa: BLE001 - any of several network errors, all handled the same way
            last_err = e
            continue
    raise ToolError("Could not reach a speed-test server", f"Check your internet connection. ({last_err})")


# =========================================================================== #
# 9d. Guest-network isolation heuristic
# =========================================================================== #
GUEST_PATTERNS = (r"guest", r"visitor", r"public")


def guest_network_check(cidr=None):
    """Heuristic only: a real guarantee requires inspecting the router's own firewall rules,
    which this tool cannot do from outside. We infer isolation from what is reachable."""
    import re as _re
    link = current_link() if "current_link" in globals() else {}
    ssid = link.get("ssid", "") if isinstance(link, dict) else ""
    looks_guest = bool(ssid) and any(_re.search(p, ssid, _re.I) for p in GUEST_PATTERNS)
    d = discover(cidr)
    others = [x for x in d["devices"] if not x["is_self"] and not x["is_gateway"]]
    if not others:
        verdict = "Looks isolated - only the router answered besides this device."
        risk = "ok"
    elif len(others) <= 2:
        verdict = f"{len(others)} other device(s) are reachable - worth checking your router's guest-isolation setting."
        risk = "medium"
    else:
        verdict = f"{len(others)} other devices are reachable from here - guest isolation may not be enabled."
        risk = "high"
    return {"ssid": ssid, "looks_like_guest_name": looks_guest, "reachable_other_devices": len(others),
            "devices": others, "verdict": verdict, "risk": risk,
            "note": "This is an inference from what answered on the network, not a reading of the router's actual firewall "
                    "rules - treat a clean result as reassuring, not as proof."}


# =========================================================================== #
# 9e. My network activity (THIS device's own connections - not packet capture)
# =========================================================================== #
ACTIVITY_CATEGORIES = [
    (r"^(80|8080|8000)$", "Web (unencrypted)"), (r"^(443|8443)$", "Web (encrypted)"),
    (r"^(25|465|587|110|143|993|995)$", "Email"), (r"^(53)$", "DNS"),
    (r"^(21|22|989|990)$", "File transfer"), (r"^(3389|5900|22)$", "Remote access"),
    (r"^(1935|554|8554)$", "Streaming/media"), (r"^(3306|5432|6379|27017|1433)$", "Database"),
    (r"^(6881|6882|6883|6884|6885|6886|6887|6888|6889)$", "Peer-to-peer"),
]


def _categorize(port):
    import re as _re
    for pat, cat in ACTIVITY_CATEGORIES:
        if _re.match(pat, str(port)):
            return cat
    return "Other"


def parse_ss(text):
    """`ss -tunp` columns: Netid State Recv-Q Send-Q Local:Port Peer:Port [process]."""
    out = []
    for line in text.splitlines()[1:]:
        p = line.split()
        if len(p) < 6:
            continue
        local, remote = p[4], p[5]
        m_l = re.search(r":(\d+)$", local)
        m_r = re.match(r"^(.+):(\d+)$", remote)
        if m_r and m_r.group(1) not in ("0.0.0.0", "*", "::"):
            out.append({"local_port": int(m_l.group(1)) if m_l else 0, "remote": m_r.group(1),
                        "remote_port": int(m_r.group(2)), "state": p[1]})
    return out


def parse_netstat(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*(TCP|UDP)\s+\S+:(\d+)\s+([\d.]+):(\d+)\s+(\S*)", line)
        if m and m.group(3) not in ("0.0.0.0", "*"):
            out.append({"local_port": int(m.group(2)), "remote": m.group(3), "remote_port": int(m.group(4)), "state": m.group(5)})
    return out


def network_activity():
    rows = []
    if IS_WIN:
        rows = parse_netstat(_run(["netstat", "-ano"]))
    elif shutil.which("ss"):
        rows = parse_ss(_run(["ss", "-tunp"]))
    elif shutil.which("netstat"):
        rows = parse_netstat(_run(["netstat", "-an"]))
    else:
        raise ToolError("No connection-listing tool found", "Needs `ss` or `netstat`.")
    seen, out = set(), []
    for r in rows:
        if not is_private(r["remote"]) and r["remote"] not in ("127.0.0.1", "::1"):
            key = (r["remote"], r["remote_port"])
            if key in seen:
                continue
            seen.add(key)
            out.append({**r, "category": _categorize(r["remote_port"]), "hostname": ""})
    by_cat = {}
    for r in out:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    return {"connections": sorted(out, key=lambda x: x["category"]), "total": len(out), "by_category": by_cat,
            "note": "Only this device's own active connections to the internet are listed - never other devices' traffic, "
                    "and never the content of anything, only who it's talking to."}


# =========================================================================== #
# 9b. MAC / vendor lookup
# =========================================================================== #
def mac_info(mac):
    m = norm_mac((mac or "").strip())
    if not MAC_RE.fullmatch(m):
        raise ToolError("Enter a MAC address like 00:14:6C:5D:E1:90")
    first = int(m.split(":")[0], 16)
    return {"mac": m, "vendor": lookup(m) or "Unknown (built-in list is small - add data/oui.csv for full coverage)",
            "locally_administered": bool(first & 2), "multicast": bool(first & 1),
            "note": ("Locally administered = randomised/virtual address (phones use these for privacy; attackers use them to spoof)."
                     if first & 2 else "Globally unique address assigned by the manufacturer.")}

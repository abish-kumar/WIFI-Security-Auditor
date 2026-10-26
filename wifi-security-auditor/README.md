# 📡 Wi-Fi Security Auditor

A **passive** Wi-Fi auditing toolkit: discover nearby networks, grade their security, detect WPS exposure and
rogue access points / evil twins, track changes over time, and export professional reports.

**Stack:** Python · Scapy · Airodump-ng (CLI) · Netifaces · SQLite · ReportLab · Flask

> ⚠️ **Authorised use only.** This tool only *listens* (beacon / probe-response frames, OS scan lists).
> It never deauthenticates, injects, or cracks anything. Still, only assess networks you own or have written permission to test.

## ⚡ Quick start (one command)
| Your system | Do this |
|---|---|
| **Windows** | double-click **`start.bat`** (or `py run.py`) |
| **Linux / macOS** | `./start.sh` (or `python3 run.py`) |
| **Linux, full monitor-mode scans** | `sudo ./start.sh` |

The first run installs what is missing automatically (Flask, ReportLab, Scapy) into a private `.venv`, starts the
dashboard on a free port, opens your browser and **immediately scans your real Wi-Fi environment**.
Every CLI command also works through the launcher: `python run.py scan -f pdf`.

**Troubleshooting**
* *"Python not found"* → install Python 3.8+ from python.org (tick "Add to PATH" on Windows).
* *Scapy / airodump greyed out in "New scan"* → hover/read the card: it tells you exactly what is missing (root, tool, Linux).
* *"Scan failed: no Wi-Fi adapter"* (desktop PC / VM) → plug in a USB Wi-Fi adapter. ("Use sample data" in Scan options only exists for testing the interface.)
* *Port busy* → the launcher automatically picks the next free port.

## 🧭 Understand it in 60 seconds
* **Overview** - a dial grades the wireless world around you from A to F, followed by *"What to do first"* in plain English.
* **Networks / Threats** - click any network for a plain-English report: *what we found, why it matters, how to fix it*. Dotted-underlined words explain themselves on hover; click one to open its glossary entry.
* **Toolbox** - ten tools for the network you are on (below). Every tool explains what it does, why you'd use it and what to expect *before* you run it.
* **Learn** - how scores work, a searchable glossary of 36 terms, and responsible-use notes. A short tour appears on first launch (press `?` to reopen it).

## 🧰 The Toolbox
| Tool | What it tells you |
|---|---|
| My connection | live signal meter + graph, speed, channel, security of the Wi-Fi you're using |
| Who is on my network? | every device (name, maker, address), highlights unknown ones; label devices once, new ones stand out afterwards |
| Port scanner | which ports a device leaves open, with plain-English risk notes, service banners, and known-CVE matches |
| Connection quality | latency / jitter / packet loss to router and internet, graded A-F, tells you if it's the Wi-Fi or the ISP |
| Internet & DNS health | captive portals, DNS tampering/hijacking, HTTPS interception (certificate checks) |
| ARP spoof check | duplicate addresses and router-address changes vs. a saved baseline |
| Router fingerprint | identifies your router's make/admin software from its web page; flags known-weak embedded web servers |
| Saved networks audit | remembered Wi-Fi profiles that are open/WEP/WPA1 and auto-connect (passwords are never read) |
| Network info | IP, router, subnet, DNS, and IPv6 - each explained |
| Passphrase tester | crack-time estimate for a Wi-Fi password, computed locally in the browser |
| Address & vendor lookup | MAC → manufacturer (172 built-in vendors), randomised-address detection |
| My locations | remembers Home/Office/Cafe routers so your own gear isn't re-flagged every visit |
| Alert delivery | send Live Monitor alerts to email or a Slack/Discord webhook |

Every network report also has a **Get a fix plan** button that turns every finding into a numbered, de-duplicated,
severity-sorted set of router-settings instructions - the same engine as `auditor.py remediate`.

Terminal equivalents: `python run.py net info | discover [CIDR] | ports HOST [--ports common] | quality | internet | arp [save] | saved | link | mac MAC`.
**Safety:** discovery, port scanning and router fingerprinting refuse anything outside private ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, 127.x). Nothing in the toolbox attacks, brute-forces or intercepts anything.

## 🩹 Vulnerability matching & remediation
The port scanner checks each open port's service banner against a bundled, hand-curated reference of well-known
CVEs (`wifiaudit/vulndb.py`, version shown in-app) - e.g. an old OpenSSH build is flagged with the exact CVE,
severity and fix. This is a snapshot, not a live feed: run `python run.py vulndb refresh` when you have internet
access to pull the newest entries for the same products from NVD.

Every finding - from Wi-Fi scans, the port scanner, or the vulnerability matcher - feeds the same remediation
engine (`wifiaudit/remediate.py`), which turns it into plain, numbered router-settings steps, de-duplicated and
sorted by severity. Use the dashboard's **Get a fix plan** button or `python run.py remediate`.

## 🌐 IPv6 and Wi-Fi 6E
Network info, device discovery's ARP table and the ARP spoof check now also read IPv6 addresses and the IPv6
neighbor table (Linux). 6 GHz (Wi-Fi 6E) networks are correctly labelled by reading the radio frequency directly,
since channel numbers alone are ambiguous between 5 GHz and 6 GHz.

## 📍 Multi-location trust & alerts
Save a network as "Home", "Office" or "Cafe" (**My locations** in the Toolbox, or `python run.py location save
<name>`) so your own router stops looking unfamiliar every time you reconnect. Configure email (SMTP) or a
Slack/Discord webhook under **Alert delivery** (or `python run.py alert-config`) so Live Monitor / `watch` can
reach you even when the dashboard isn't open.

## 📶 Signal, coverage & speed
- **Estimated distance** - shown next to your live signal in My connection: a rough metres figure from the standard log-distance path-loss model, always labelled as an estimate (walls/floors change the real answer).
- **Coverage map** - a Toolbox tool: click where you're standing on a simple grid (no floor plan needed) and it logs your current signal there, building a green-to-red map of weak spots per saved location.
- **Signal history** - every live-signal reading is quietly logged to a small time-series table (auto-pruned/rolled-up so it never grows unbounded), for the future "is this router getting worse" view.
- **Speed test** - real download throughput (Mbps) via a standard public test endpoint, separate from the latency/jitter numbers in Connection quality.

## 🧩 More Toolbox additions
- **Guest network check** - a heuristic (not a guarantee) that looks at what else answers on a guest-named network to flag missing client isolation.
- **My network activity** - lists only *this device's* own active connections (the same info `netstat`/`ss` show you) grouped by category. This is not packet capture and never reads other devices' traffic.
- **Compare two scans** (History page) - a direct side-by-side diff of any two stored scans, not just consecutive ones.
- **Scheduled reports** - recurring scan+report while the app is running (History page, or `auditor.py schedule enable --frequency daily --time 09:00`), plus a documented cron/Task Scheduler recipe for when you'd rather not keep it running.
- **Remediation as PDF** - the fix-plan is now downloadable, not just copy/paste.

## What it really does
It talks to your actual Wi-Fi adapter, collects each access point's beacon data and audits it:

| Check | How |
|---|---|
| Nearby networks | **Deep scan** reads raw beacon elements from the OS (no monitor mode, no special hardware): Windows → native WLAN API, Linux → `iw scan` |
| Weak encryption | Open · WEP · WPA1 · WPA/WPA2 mixed · WPA2+TKIP · WPA2 · WPA2/WPA3 · WPA3 · Enterprise · OWE, plus PMF (802.11w) |
| WPS vulnerabilities | WPS element present + "AP setup locked" flag → unlocked WPS = high risk |
| Rogue APs / evil twins | trusted SSID with unknown BSSID, same SSID with weaker security, vendor mismatch, spoofed (locally-administered) BSSID, abnormally strong clone, Karma-style multi-SSID BSSID, lure SSIDs |
| *Your* connection | detects the AP you are connected to and screams if it matches rogue indicators |
| Reports | HTML · PDF · JSON · CSV, with a fix for every finding |
| Monitoring | **Live monitor** (dashboard) and `watch` (CLI): rescans on a timer, alerts on new rogue APs, new open networks, encryption downgrades; stores history and diffs scans |

## Platform support (honest matrix)
| | Deep scan (WPS/PMF) | Basic scan | Monitor mode (Scapy / airodump) |
|---|---|---|---|
| **Windows 10/11** | ✅ native WLAN API (falls back to `netsh` automatically) | ✅ `netsh` | n/a (not needed) |
| **Linux** | ✅ `iw` (root = freshest results; non-root reads NetworkManager's cache) | ✅ `nmcli` | ✅ needs root + monitor-mode adapter |
| **macOS** | ❌ Apple hides BSSIDs/SSIDs from apps | ❌ | ❌ |

* **Windows:** turn on *Settings → Privacy & security → Location* (Windows blocks Wi-Fi scanning otherwise). The WLAN-API reader is written to the documented API and verified with structure-layout and beacon-parsing tests; if anything unexpected happens it falls back to `netsh` and tells you which method was used ("via netsh" badge). Please report any Windows-specific problem.
* **Linux VM (Kali/Ubuntu in VirtualBox/VMware):** the VM cannot see your laptop's Wi-Fi card. Attach a USB Wi-Fi adapter to the VM, or run the tool directly on the host OS.
* Checks run with `python run.py doctor` (or the **Scan options** dialog) show exactly what is missing on your machine.

## Manual install (optional)
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo apt install aircrack-ng iw network-manager     # Linux, optional tools
python auditor.py doctor                             # check dependencies / privileges
```

## Usage
```bash
python auditor.py scan -f html pdf                         # real scan, best method auto-selected
python auditor.py scan -b deep -f pdf                      # force the deep scan (WPS/PMF detail)

# Full-fidelity scan (your own adapter, monitor mode, root):
sudo airmon-ng start wlan0
sudo python3 auditor.py scan -b scapy -i wlan0mon -d 30 -f pdf html -l "HQ floor 2"
sudo python3 auditor.py scan -b airodump -i wlan0mon -d 30       # uses wash too if installed

python auditor.py history                  # stored scans
python auditor.py diff                     # what changed since the previous scan
python auditor.py show 3 -f pdf            # regenerate a report for scan #3
python auditor.py trust "Office_Net" 00:0B:86:10:20:30   # whitelist your own AP
sudo python3 auditor.py watch -b scapy -i wlan0mon --interval 120   # continuous alerts
python run.py                              # dashboard (auto-opens browser)
```
`scan` exits with code **2** when a rogue AP is found (handy for cron / CI alerting).

## Scoring (0-100)
Open −60 · WEP −70 · WPA1 −40 · WPA/WPA2 mixed −25 · WPA2+TKIP −20 · WPS unlocked −25 (locked −10) · no PMF −5 · default-style SSID −5.
`≥80 SECURE` · `≥30 VULNERABLE` · `<30 HIGH RISK` (Open/WEP are always HIGH RISK; unlocked WPS caps the level at VULNERABLE).
Rogue APs are reported as their own category: **Secure + Vulnerable + Rogue = Networks found**.

## Project layout
```
auditor.py            CLI entry point
wifiaudit/scanner.py  backends + 802.11 IE parsers
wifiaudit/analyzer.py scoring, rogue detection, statistics
wifiaudit/database.py SQLite storage + diffing   (analysis is recomputed on read, so trusting a BSSID updates old scans)
wifiaudit/report.py   HTML / PDF / JSON / CSV
wifiaudit/web.py      Flask dashboard + REST API
wifiaudit/nettools.py network toolbox engine (discovery, ports, quality, DNS/TLS, ARP, link, profiles)
wifiaudit/static/     dashboard UI (index.html, style.css, glossary.js, core.js, views.js, tools.js, main.js)
config.json           trusted SSID → BSSID allow-list, thresholds
tests/                python -m unittest discover -s tests
```

## Security notes (built in)
* SSIDs are attacker-controlled → always escaped (HTML/PDF) or rendered with `textContent`; CSV cells are protected against formula injection.
* Interface names are validated; no shell is ever invoked (argument lists only).
* Dashboard binds to `127.0.0.1` and POST endpoints require an `X-Requested-With` header (blocks cross-site requests).

## Platform notes
`wash` JSON field names can vary between Reaver versions; if WPS shows "-" with airodump, run `wash -i wlan0mon -j` and check the output.
Add the IEEE `oui.csv` to `data/` for complete vendor names.

## Ideas to extend
GPS tagging for war-driving surveys · MQTT/Slack/email alerts in `watch` · 6 GHz support · 802.1X certificate checks · Docker image.

import json
import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wifiaudit import nettools as nt


class TestParsers(unittest.TestCase):
    def test_linux_route_and_addr(self):
        self.assertEqual(nt.parse_ip_route("default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.23 metric 600"),
                         ("192.168.1.1", "wlan0"))
        out = "3: wlan0    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic wlan0\\       valid_lft 86000sec"
        self.assertEqual(nt.parse_ip_addr(out), [("wlan0", "192.168.1.23", 24)])

    def test_windows_route_print_is_language_independent(self):
        text = """IPv4 Route Table
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.23     50
          0.0.0.0          0.0.0.0      10.0.0.1        10.0.0.7        900
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link      192.168.1.23    306
     192.168.1.23  255.255.255.255         On-link      192.168.1.23    306
"""
        self.assertEqual(nt.parse_route_print(text), ("192.168.1.1", "192.168.1.23", 24))

    def test_dns_parse(self):
        t = "   DNS Servers . . . . . . . . . . . : 192.168.1.1\n                                       8.8.8.8\n   NetBIOS over Tcpip. . . : Enabled\n"
        self.assertEqual(nt.parse_dns_ipconfig(t), ["192.168.1.1", "8.8.8.8"])

    def test_arp_parsers(self):
        neigh = ("192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n192.168.1.50 dev wlan0  FAILED\n"
                 "192.168.1.9 dev wlan0 lladdr aa:bb:cc:dd:ee:09 STALE\n")
        self.assertEqual([r["ip"] for r in nt.parse_ip_neigh(neigh)], ["192.168.1.1", "192.168.1.9"])
        win = ("Interface: 192.168.1.23 --- 0x5\n  Internet Address      Physical Address      Type\n"
               "  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic\n  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n")
        rows = nt.parse_arp_a(win)
        self.assertEqual(rows[0]["mac"], "AA:BB:CC:DD:EE:01")
        mac = nt.parse_arp_a("? (192.168.1.7) at 1a:2b:3c:4d:5e:6f on en0 ifscope [ethernet]")
        self.assertEqual(mac[0]["ip"], "192.168.1.7")

    def test_ping_parser(self):
        self.assertEqual(nt.parse_ping("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms\n64 bytes: time=9.8 ms"), [12.3, 9.8])
        self.assertEqual(nt.parse_ping("Reply from 1.1.1.1: bytes=32 time=14ms TTL=57\nReply from 1.1.1.1: bytes=32 time<1ms TTL=57"), [14.0, 0.5])

    def test_netsh_link(self):
        t = """    Name                   : Wi-Fi
    Physical address       : aa:bb:cc:dd:ee:ff
    State                  : connected
    SSID                   : HomeNet
    BSSID                  : 00:27:19:aa:01:10
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Channel                : 36
    Receive rate (Mbps)    : 433.3
    Transmit rate (Mbps)   : 390
    Signal                 : 88%
"""
        d = nt.parse_netsh_link(t)
        self.assertEqual((d["ssid"], d["bssid"], d["channel"], d["signal_dbm"], d["rx_rate"]), ("HomeNet", "00:27:19:AA:01:10", 36, -56, "433.3"))
        self.assertFalse(nt.parse_netsh_link("    State : disconnected")["connected"])

    def test_iw_link(self):
        t = "Connected to 00:27:19:aa:01:10 (on wlan0)\n\tSSID: HomeNet\n\tfreq: 5180\n\tsignal: -52 dBm\n\trx bitrate: 433.3 MBit/s VHT-MCS 9\n\ttx bitrate: 390.0 MBit/s\n"
        d = nt.parse_iw_link(t, "wlan0")
        self.assertEqual((d["ssid"], d["channel"], d["signal_dbm"], d["rx_rate"]), ("HomeNet", 36, -52, "433.3"))
        self.assertFalse(nt.parse_iw_link("Not connected.")["connected"])

    def test_signal_quality(self):
        self.assertEqual(nt.signal_quality(-45)["label"], "Excellent")
        self.assertEqual(nt.signal_quality(-75)["label"], "Weak")
        self.assertEqual(nt.signal_quality(-90)["label"], "Very poor")

    def test_profile_risk(self):
        self.assertEqual(nt._profile_risk("Open", "None", True)[0], "high")
        self.assertEqual(nt._profile_risk("Open", "None", False)[0], "medium")
        self.assertEqual(nt._profile_risk("WPA-Personal", "TKIP", True)[0], "medium")
        self.assertEqual(nt._profile_risk("WPA2-Personal", "CCMP", True)[0], "ok")
        self.assertEqual(nt._profile_risk("WPA3-Personal", "CCMP", True)[0], "ok")

    def test_ports_parse(self):
        self.assertEqual(nt.parse_ports("22, 80,8000-8002"), [22, 80, 8000, 8001, 8002])
        with self.assertRaises(nt.ToolError):
            nt.parse_ports("abc")
        with self.assertRaises(nt.ToolError):
            nt.parse_ports("1-5000")

    def test_mac_info(self):
        self.assertEqual(nt.mac_info("00-14-6c-5d-e1-90")["vendor"], "Netgear")
        self.assertTrue(nt.mac_info("02:11:22:33:44:55")["locally_administered"])
        with self.assertRaises(nt.ToolError):
            nt.mac_info("nope")


class TestSafetyAndLive(unittest.TestCase):
    def test_private_only(self):
        for ip in ("192.168.1.1", "10.1.2.3", "172.20.0.5", "127.0.0.1", "169.254.1.1"):
            self.assertTrue(nt.is_private(ip), ip)
        for ip in ("8.8.8.8", "1.1.1.1", "172.32.0.1", "93.184.216.34", "garbage"):
            self.assertFalse(nt.is_private(ip), ip)

    def test_portscan_refuses_public(self):
        with self.assertRaises(nt.ToolError):
            nt.port_scan("8.8.8.8", "quick")
        with self.assertRaises(nt.ToolError):
            nt.discover("8.8.8.0/24")
        with self.assertRaises(nt.ToolError):
            nt.discover("10.0.0.0/8")

    def test_portscan_finds_real_listener_and_banner(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]

        def serve():
            for _ in range(2):
                try:
                    c, _ = srv.accept()
                    c.sendall(b"SSH-2.0-TestServer\r\n")
                    c.close()
                except OSError:
                    return
        threading.Thread(target=serve, daemon=True).start()
        res = nt.port_scan("127.0.0.1", str(port))
        srv.close()
        self.assertEqual([o["port"] for o in res["open"]], [port])
        self.assertEqual(res["scanned"], 1)

    def test_risky_service_flagged(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(2)
        port = srv.getsockname()[1]
        nt.SERVICES[port] = ("Telnet", "critical", "test")
        try:
            res = nt.port_scan("127.0.0.1", str(port))
        finally:
            del nt.SERVICES[port]
            srv.close()
        self.assertEqual(res["open"][0]["level"], "critical")
        self.assertEqual(res["worst"], 4)
        self.assertIn("risky", res["verdict"])

    def test_discover_loopback(self):
        res = nt.discover("127.0.0.0/30")
        self.assertIn("127.0.0.1", [d["ip"] for d in res["devices"]])

    def test_baseline_roundtrip_and_spoof_detection(self):
        p = os.path.join(tempfile.mkdtemp(), "b.json")
        orig_ll, orig_arp = nt.local_info, nt.arp_table
        try:
            nt.local_info = lambda: {"gateway": "192.168.1.1", "ip": "192.168.1.5", "cidr": "192.168.1.0/24", "dns": [], "mac": ""}
            nt.arp_table = lambda: [{"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01", "iface": ""}]
            self.assertEqual(nt.save_baseline(p)["mac"], "AA:BB:CC:DD:EE:01")
            self.assertEqual(nt.arp_health(p)["verdict"], "No sign of ARP spoofing.")
            nt.arp_table = lambda: [{"ip": "192.168.1.1", "mac": "66:66:66:66:66:66", "iface": ""},
                                    {"ip": "192.168.1.77", "mac": "66:66:66:66:66:66", "iface": ""}]
            h = nt.arp_health(p)
            self.assertEqual(h["verdict"], "Possible ARP spoofing!")
            titles = " ".join(f["title"] for f in h["findings"])
            self.assertIn("CHANGED", titles)
            self.assertIn("claims 2 addresses", titles)
        finally:
            nt.local_info, nt.arp_table = orig_ll, orig_arp

    def test_measure_loopback(self):
        r = nt.measure("loop", "127.0.0.1", 3)
        self.assertIn(r["method"], ("ping", "none") + tuple(f"TCP:{p}" for p in (443, 80, 53)))


if __name__ == "__main__":
    unittest.main()

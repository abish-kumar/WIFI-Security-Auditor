"""Tiny MAC-vendor lookup. Drop the IEEE oui.csv into data/ for full coverage."""
import csv
import os

_BUILTIN = {
    # Networking / routers / APs
    "00:27:19": "TP-Link", "F4:F2:6D": "TP-Link", "50:C7:BF": "TP-Link", "A4:2B:B0": "TP-Link", "D8:0D:17": "TP-Link",
    "EC:08:6B": "TP-Link", "C0:4A:00": "TP-Link",
    "00:14:6C": "Netgear", "A0:04:60": "Netgear", "20:E5:2A": "Netgear", "9C:3D:CF": "Netgear", "30:46:9A": "Netgear",
    "C0:3F:0E": "Netgear", "E0:46:9A": "Netgear",
    "00:05:5D": "D-Link", "00:1C:F0": "D-Link", "1C:7E:E5": "D-Link", "C8:D3:A3": "D-Link", "B8:A3:86": "D-Link",
    "00:14:BF": "Linksys", "00:1A:70": "Linksys", "58:6D:8F": "Linksys", "C0:56:27": "Linksys", "48:F8:B3": "Linksys",
    "00:18:0A": "Cisco Meraki", "88:15:44": "Cisco Meraki", "0C:8D:DB": "Cisco Meraki", "AC:17:C8": "Cisco",
    "00:0B:86": "Aruba Networks", "20:4C:03": "Aruba Networks", "6C:F3:7F": "Aruba Networks",
    "24:A4:3C": "Ubiquiti", "FC:EC:DA": "Ubiquiti", "DC:9F:DB": "Ubiquiti", "74:83:C2": "Ubiquiti", "80:2A:A8": "Ubiquiti",
    "00:12:17": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
    "B4:FB:E4": "ASUS", "1C:B7:2C": "ASUS", "2C:FD:A1": "ASUS", "AC:9E:17": "ASUS", "04:D4:C4": "ASUS",
    "94:10:3E": "Belkin", "08:86:3B": "Belkin", "C0:56:E3": "Belkin",
    "C8:3A:35": "Tenda", "D8:38:0D": "Tenda", "00:B0:0C": "Tenda",
    "00:E0:FC": "Huawei", "48:46:FB": "Huawei", "F4:9F:F3": "Huawei", "00:25:9E": "Huawei",
    "34:29:12": "ZTE", "F8:7A:EF": "ZTE",
    "78:11:DC": "MikroTik", "4C:5E:0C": "MikroTik", "D4:CA:6D": "MikroTik", "E4:8D:8C": "MikroTik",
    "50:8A:06": "Xiaomi", "78:11:DC": "Xiaomi", "28:6C:07": "Xiaomi", "64:09:80": "Xiaomi", "34:CE:00": "Xiaomi",
    "EC:17:2F": "Fritz!Box (AVM)", "08:96:D7": "Fritz!Box (AVM)", "C8:0E:14": "Fritz!Box (AVM)",
    "00:1D:D0": "Sagemcom", "CC:03:FA": "Sagemcom",
    "00:1E:74": "ZyXEL", "B0:B2:DC": "ZyXEL",
    "00:0C:F6": "Cisco", "00:1B:D4": "Cisco", "00:21:D8": "Cisco",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "24:0A:C4": "Espressif (ESP32/ESP8266)", "30:AE:A4": "Espressif (ESP32/ESP8266)", "AC:67:B2": "Espressif",
    "84:F3:EB": "Espressif", "A0:20:A6": "Espressif", "EC:62:60": "Espressif",
    "00:C0:CA": "ALFA Network",
    # Phones / tablets / laptops
    "F0:18:98": "Apple", "A4:C3:61": "Apple", "3C:15:C2": "Apple", "88:66:5A": "Apple", "D0:23:DB": "Apple",
    "F4:5C:89": "Apple", "9C:35:EB": "Apple", "A8:5C:2C": "Apple", "BC:52:B7": "Apple", "DC:A9:04": "Apple",
    "00:12:47": "Samsung", "5C:0A:5B": "Samsung", "8C:71:F8": "Samsung", "A0:21:95": "Samsung", "CC:07:AB": "Samsung",
    "E8:50:8B": "Samsung", "F4:7B:5E": "Samsung",
    "3C:A9:F4": "Google", "F4:F5:D8": "Google", "54:60:09": "Google", "A4:77:33": "Google",
    "DC:71:44": "LG Electronics", "00:1C:62": "LG Electronics", "A8:16:B2": "LG Electronics",
    "00:1F:16": "OnePlus", "AC:C1:EE": "OnePlus",
    "00:1A:11": "Google (legacy)", "3C:5A:B4": "Google",
    "28:C6:8E": "Lenovo/Motorola", "00:23:76": "Motorola", "40:88:E0": "Motorola",
    "00:21:6A": "Intel", "00:24:D7": "Intel", "3C:A9:F4": "Intel", "A4:34:D9": "Intel", "AC:72:89": "Intel",
    "00:1B:21": "Intel", "F8:34:41": "Intel", "4C:34:88": "Intel",
    "00:16:6F": "Dell", "18:03:73": "Dell", "B8:CA:3A": "Dell", "F8:B1:56": "Dell",
    "00:14:22": "Dell", "D4:BE:D9": "Dell",
    "00:1F:29": "Hewlett Packard", "3C:D9:2B": "HP", "98:4B:E1": "HP", "A0:48:1C": "HP",
    "00:50:56": "VMware (virtual)", "00:0C:29": "VMware (virtual)", "00:05:69": "VMware (virtual)",
    "08:00:27": "VirtualBox (virtual)", "0A:00:27": "VirtualBox (virtual)",
    "00:15:5D": "Hyper-V (virtual)", "00:1C:42": "Parallels (virtual)",
    "52:54:00": "QEMU/KVM (virtual)",
    # IoT / cameras / smart home
    "68:C6:3A": "Espressif (IoT)", "CC:50:E3": "Espressif (IoT)",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips",
    "44:65:0D": "Amazon (Echo/Fire)", "68:37:E9": "Amazon", "74:C2:46": "Amazon", "F0:27:2D": "Amazon",
    "B0:7F:B9": "Amazon", "FC:65:DE": "Amazon",
    "A4:08:01": "Nest/Google Home", "64:16:66": "Nest",
    "EC:71:DB": "Sonos", "5C:AA:FD": "Sonos", "00:0E:58": "Sonos",
    "00:40:8C": "AXIS Communications (IP camera)", "AC:CC:8E": "Hikvision (IP camera)", "4C:11:BF": "Hikvision",
    "BC:AD:28": "Dahua (IP camera)", "9C:8E:CD": "Dahua",
    "00:17:C8": "TCL/Roku", "DC:3A:5E": "Roku", "B0:A7:37": "Roku",
    "A8:66:7F": "Apple (HomePod/TV)",
    "7C:A1:AE": "Sonoff/Itead (smart plugs)",
    # Printers
    "00:1B:A9": "HP Printer", "3C:D9:2B": "HP Printer", "00:0F:B0": "Brother", "30:05:5C": "Brother",
    "00:80:92": "Epson", "64:EB:8C": "Epson", "00:26:AB": "Canon",
    "00:21:5A": "Canon",
}
# A hand-curated starter set; the full IEEE registry has 50,000+ entries. For complete
# coverage, download the public OUI CSV (see README) and place it at data/oui.csv - it
# loads automatically and overlays this list (data/oui.csv entries win on conflicts).
_TABLE = {k.replace(":", ""): v for k, v in _BUILTIN.items()}
BUILTIN_COUNT = len(_BUILTIN)


def load_oui_csv(path):
    """Load IEEE-format CSV (Registry,Assignment,Organization Name,...)."""
    n = 0
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if len(row) >= 3 and len(row[1]) == 6:
                _TABLE[row[1].upper()] = row[2].strip()
                n += 1
    return n


def is_locally_administered(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def lookup(mac):
    if not mac or is_locally_administered(mac):
        return ""
    return _TABLE.get(mac.upper().replace(":", "")[:6], "")


_extra = os.path.join(os.path.dirname(__file__), "..", "data", "oui.csv")
if os.path.exists(_extra):
    try:
        load_oui_csv(_extra)
    except OSError:
        pass

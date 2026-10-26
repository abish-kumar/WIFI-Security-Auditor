from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .oui import lookup

RAW_FIELDS = ("bssid", "ssid", "channel", "signal", "encryption", "cipher", "auth",
              "wps", "wps_locked", "pmf", "hidden", "vendor", "band", "connected")


def freq_to_channel(freq):
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5170 <= freq <= 5895:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


def band_for_freq(freq):
    """Unlike channel numbers (which overlap between 5 GHz and 6 GHz), raw frequency is unambiguous."""
    if not freq:
        return ""
    if freq == 2484 or 2412 <= freq <= 2472:
        return "2.4 GHz"
    if 5955 <= freq <= 7115:
        return "6 GHz"
    if 5170 <= freq <= 5895:
        return "5 GHz"
    return ""


@dataclass
class Network:
    bssid: str
    ssid: str = ""
    channel: int = 0
    signal: int | None = None          # dBm
    encryption: str = "OPEN"           # OPEN WEP WPA WPA/WPA2 WPA2 WPA2/WPA3 WPA3 WPA2-Enterprise OWE
    cipher: str = ""
    auth: str = ""
    wps: bool | None = None            # None = unknown for this backend
    wps_locked: bool | None = None
    pmf: str | None = None             # required / capable / none
    hidden: bool = False
    vendor: str = ""
    band: str = ""
    connected: bool = False           # the adapter is currently associated with this AP
    # --- filled in by analyzer ---
    score: int = 100
    level: str = "UNKNOWN"
    findings: list = field(default_factory=list)
    rogue: bool = False
    rogue_score: int = 0
    rogue_reasons: list = field(default_factory=list)

    def __post_init__(self):
        self.bssid = (self.bssid or "").upper()
        self.ssid = self.ssid or ""
        if not self.ssid.strip("\x00"):
            self.ssid, self.hidden = "", True
        self.channel = int(self.channel or 0)
        self.encryption = self.encryption or "OPEN"
        self.cipher, self.auth = self.cipher or "", self.auth or ""
        self.connected = bool(self.connected)
        if not self.band and self.channel:
            # Channel numbers alone are ambiguous between 5 GHz and 6 GHz (Wi-Fi 6E); callers that
            # know the raw frequency should pass band= explicitly (see band_for_freq). This is a
            # reasonable default when only a channel number is available.
            self.band = "2.4 GHz" if self.channel <= 14 else "5 GHz"
        if not self.vendor:
            self.vendor = lookup(self.bssid)

    @property
    def display_level(self):
        return "ROGUE AP" if self.rogue else self.level

    @property
    def name(self):
        return self.ssid or "<hidden>"

    def raw(self):
        return {k: getattr(self, k) for k in RAW_FIELDS}

    def to_dict(self):
        d = asdict(self)
        d["display_level"] = self.display_level
        d["name"] = self.name
        return d

    @classmethod
    def from_raw(cls, d):
        return cls(**{k: d[k] for k in RAW_FIELDS if k in d})

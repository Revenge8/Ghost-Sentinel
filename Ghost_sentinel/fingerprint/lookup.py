# core/fingerprint/lookup.py — Ghost Sentinel Signature Matcher
# ==============================================================
# Correlates observed network artefacts against known device signatures.
# Adapted from reference SignatureMatcher (doc 9) — no external deps,
# uses your local OUI database and pattern tables.
from __future__ import annotations

import re
import logging
from typing import Any, Optional

from .evidence import FingerprintMatch
from .mac import detect_randomised_mac

_log = logging.getLogger(__name__)

def _parse_opt55(opt55: Any) -> list[int]:
    """
    Best-effort parse DHCP option 55 (parameter request list).
    Accepts list/tuple of ints, bytes, or stringified lists like "[1, 3, 6]".
    """
    if opt55 is None:
        return []
    if isinstance(opt55, (bytes, bytearray)):
        return [int(b) for b in opt55]
    if isinstance(opt55, (list, tuple)):
        out: list[int] = []
        for x in opt55:
            try:
                out.append(int(x))
            except Exception:
                continue
        return out
    s = str(opt55).strip()
    if not s:
        return []
    nums = re.findall(r"\d+", s)
    return [int(n) for n in nums] if nums else []


_OPT55_BUILT_IN: list[tuple[frozenset[int], Optional[str], str, Optional[str], float]] = [
    (frozenset({1,3,6,15,31,33,43,44,46,47,119,121,249,252}),
     "Microsoft", "workstation", "Windows 10/11", 0.75),
    (frozenset({1,3,6,15,31,33,43,44,46,47,121,249}),
     "Microsoft", "workstation", "Windows 7",     0.70),
    (frozenset({1,3,6,15,95,119,121,252}),
     "Apple",     "mobile",      "iOS/macOS",     0.72),
    (frozenset({1,3,6,15,26,28,51,58,59}),
     "Google",    "mobile",      "Android",       0.70),
    (frozenset({1,3,6,12,15,26,28,40,41,42,119}),
     None,        "workstation", "Linux",         0.68),
    (frozenset({1,2,3,6,12,15,28}),
     None,        "iot",         "Linux",         0.65),
]
_OPT55_THRESHOLD = 0.75


def _match_opt55(option_codes: list[int]) -> Optional[tuple[Optional[str], str, Optional[str], float]]:
    if not option_codes:
        return None
    probe = frozenset(option_codes)
    best_score = 0.0
    best: Optional[tuple[Optional[str], str, Optional[str], float]] = None
    for pset, vendor, dtype, os_fam, conf in _OPT55_BUILT_IN:
        overlap = len(probe & pset) / max(len(pset), 1)
        if overlap >= _OPT55_THRESHOLD and overlap > best_score:
            best_score = overlap
            best = (vendor, dtype, os_fam, conf * overlap)
    return best



# ─────────────────────────────────────────────────────────────────────────────
# Device category map
# ─────────────────────────────────────────────────────────────────────────────

DEVICE_CATEGORIES: dict[str, str] = {
    "router": "Network Device", "switch": "Network Device",
    "firewall": "Network Device", "access_point": "Network Device",
    "gateway": "Network Device", "wireless_controller": "Network Device",
    "mesh_router": "Network Device", "vpn_gateway": "Network Device",
    "workstation": "Computing", "laptop": "Computing", "server": "Computing",
    "desktop": "Computing", "computer": "Computing", "thin_client": "Computing",
    "mobile": "Mobile Device", "phone": "Mobile Device",
    "smartphone": "Mobile Device", "tablet": "Mobile Device",
    "printer": "Peripheral", "scanner": "Peripheral", "multifunction": "Peripheral",
    "smart_tv": "Media Device", "tv": "Media Device",
    "smart_speaker": "Media Device", "game_console": "Media Device",
    "media_player": "Media Device", "streaming_device": "Media Device",
    "set_top_box": "Media Device", "soundbar": "Media Device",
    "iot": "IoT Device", "camera": "IoT Device", "ip_camera": "IoT Device",
    "thermostat": "IoT Device", "doorbell": "IoT Device",
    "smart_plug": "IoT Device", "smart_lighting": "IoT Device",
    "wearable": "IoT Device", "smartwatch": "IoT Device",
    "sensor": "IoT Device", "robot_vacuum": "IoT Device",
    "smart_home": "IoT Device", "home_hub": "IoT Device",
    "nas": "Storage", "san": "Storage", "storage_array": "Storage",
    "voip_phone": "Communication", "pbx": "Communication",
    "video_conferencing": "Communication",
    "plc": "SCADA/ICS", "hmi": "SCADA/ICS", "rtu": "SCADA/ICS",
    "scada_server": "SCADA/ICS", "industrial_switch": "SCADA/ICS",
    "industrial_router": "SCADA/ICS", "power_meter": "SCADA/ICS",
    "building_automation": "SCADA/ICS",
    "hypervisor": "Virtualization", "virtual_machine": "Virtualization",
    "container": "Container", "container_host": "Container",
    "embedded": "Embedded", "kiosk": "Embedded", "pos_terminal": "Embedded",
}


# ─────────────────────────────────────────────────────────────────────────────
# Built-in DHCP Option 60 patterns
# (mirrors your _OPT60_PATTERNS from core_fingerprint but as dicts)
# ─────────────────────────────────────────────────────────────────────────────

_OPT60_BUILT_IN: list[tuple[re.Pattern, str, Optional[str], Optional[str], float]] = [
    (re.compile(r"MSFT\s*5\.0",      re.I), "Microsoft",   "workstation", "Windows",  0.80),
    (re.compile(r"MSFT",             re.I), "Microsoft",   "workstation", "Windows",  0.75),
    (re.compile(r"dhcpcd",           re.I), "Apple",       "workstation", "macOS",    0.70),
    (re.compile(r"AirPort",          re.I), "Apple",       "network",     "macOS",    0.82),
    (re.compile(r"android-dhcp-\d+", re.I), "Google",     "mobile",      "Android",  0.85),
    (re.compile(r"android",          re.I), "Google",      "mobile",      "Android",  0.80),
    (re.compile(r"udhcp\s*\d",       re.I), None,          "iot",         "Linux",    0.70),
    (re.compile(r"linux",            re.I), None,          "workstation", "Linux",    0.65),
    (re.compile(r"Ubiquiti",         re.I), "Ubiquiti",    "network",     "Linux",    0.85),
    (re.compile(r"UniFi",            re.I), "Ubiquiti",    "network",     "Linux",    0.85),
    (re.compile(r"Cisco\s*Systems",  re.I), "Cisco",       "network",     None,       0.85),
    (re.compile(r"Polycom",          re.I), "Polycom",     "voip_phone",  None,       0.85),
    (re.compile(r"Yealink",          re.I), "Yealink",     "voip_phone",  None,       0.85),
    (re.compile(r"Grandstream",      re.I), "Grandstream", "voip_phone",  None,       0.85),
    (re.compile(r"HP LaserJet",      re.I), "HP",          "printer",     None,       0.87),
    (re.compile(r"Hewlett.Packard",  re.I), "HP",          "printer",     None,       0.82),
    (re.compile(r"Canon.*print",     re.I), "Canon",       "printer",     None,       0.82),
    (re.compile(r"Roku",             re.I), "Roku",        "streaming_device","Roku OS", 0.88),
    (re.compile(r"Amazon.*Fire",     re.I), "Amazon",      "media_player","Fire OS",  0.88),
    (re.compile(r"Chromecast",       re.I), "Google",      "media_player","Cast OS",  0.88),
    (re.compile(r"ESP",              re.I), "Espressif",   "iot",         "FreeRTOS", 0.75),
]

# ─────────────────────────────────────────────────────────────────────────────
# Built-in hostname patterns
# ─────────────────────────────────────────────────────────────────────────────

_HOSTNAME_BUILT_IN: list[tuple[re.Pattern, Optional[str], str, Optional[str], float]] = [
    (re.compile(r"\biPhone\b",              re.I), "Apple",        "phone",       "iOS",      0.90),
    (re.compile(r"\biPad\b",               re.I), "Apple",        "tablet",      "iOS",      0.90),
    (re.compile(r"\biMac\b",               re.I), "Apple",        "computer",    "macOS",    0.88),
    (re.compile(r"\bMacBook\b",            re.I), "Apple",        "laptop",      "macOS",    0.88),
    (re.compile(r"\bAppleTV\b",            re.I), "Apple",        "media_player","tvOS",     0.88),
    (re.compile(r"\bPixel[-\s]?\d",        re.I), "Google",       "phone",       "Android",  0.85),
    (re.compile(r"\bGalaxy[-\s]",          re.I), "Samsung",      "phone",       "Android",  0.82),
    (re.compile(r"\bRedmi\b",              re.I), "Xiaomi",       "phone",       "Android",  0.82),
    (re.compile(r"\bAndroid\b",            re.I), None,           "phone",       "Android",  0.72),
    (re.compile(r"\bDESKTOP-[A-Z0-9]{7}\b",re.I),"Microsoft",    "workstation", "Windows",  0.88),
    (re.compile(r"\bLAPTOP-[A-Z0-9]{7}\b", re.I),"Microsoft",    "laptop",      "Windows",  0.88),
    (re.compile(r"^WIN-[A-Z0-9]+$",        re.I), "Microsoft",    "workstation", "Windows",  0.82),
    (re.compile(r"\bubuntu\b",             re.I), None,           "workstation", "Linux",    0.75),
    (re.compile(r"\bdebian\b",             re.I), None,           "workstation", "Linux",    0.75),
    (re.compile(r"\bfedora\b",             re.I), None,           "workstation", "Linux",    0.75),
    (re.compile(r"\bkali\b",               re.I), None,           "workstation", "Linux",    0.72),
    (re.compile(r"raspberrypi",            re.I), "Raspberry Pi", "embedded",    "Linux",    0.82),
    (re.compile(r"\bpi\b",                 re.I), "Raspberry Pi", "embedded",    "Linux",    0.60),
    (re.compile(r"\brouter\b",             re.I), None,           "router",      None,       0.65),
    (re.compile(r"\bswitch\b",             re.I), None,           "switch",      None,       0.65),
    (re.compile(r"\bunifi\b",              re.I), "Ubiquiti",     "access_point","Linux",    0.82),
    (re.compile(r"\besp\d{2}\b",           re.I), "Espressif",    "iot",         "FreeRTOS", 0.80),
    (re.compile(r"\bshelly\b",             re.I), None,           "iot",         "Linux",    0.78),
    (re.compile(r"\bsonoff\b",             re.I), None,           "iot",         None,       0.75),
    (re.compile(r"\btuya\b",               re.I), None,           "iot",         None,       0.75),
    (re.compile(r"\bRoku\b",               re.I), "Roku",         "streaming_device","Roku OS", 0.85),
    (re.compile(r"\bChromecast\b",         re.I), "Google",       "media_player","Cast OS",  0.88),
    (re.compile(r"\bFireTV\b",             re.I), "Amazon",       "media_player","Fire OS",  0.85),
    (re.compile(r"\bBravia\b",             re.I), "Sony",         "smart_tv",    None,       0.85),
    (re.compile(r"\bSmart[ -]?TV\b",       re.I), None,           "smart_tv",    None,       0.68),
    (re.compile(r"HP[-_]?[A-Z]+[-_]?\d",  re.I), "HP",           "printer",     None,       0.72),
    (re.compile(r"\bprinter\b",            re.I), None,           "printer",     None,       0.68),
]

# ─────────────────────────────────────────────────────────────────────────────
# Built-in mDNS service patterns
# ─────────────────────────────────────────────────────────────────────────────

_MDNS_BUILT_IN: list[tuple[str, Optional[str], str, Optional[str], float]] = [
    ("_airplay._tcp",    "Apple",     "media_player",  "tvOS/macOS",  0.88),
    ("_raop._tcp",       "Apple",     "media_player",  "tvOS/macOS",  0.88),
    ("_homekit._tcp",    "Apple",     "iot",           "iOS/macOS",   0.85),
    ("_companion-link",  "Apple",     "phone",         "iOS",         0.90),
    ("_sleep-proxy",     "Apple",     "workstation",   "macOS",       0.82),
    ("_smb._tcp",        None,        "workstation",   "Windows",     0.72),
    ("_rdp._tcp",        "Microsoft", "workstation",   "Windows",     0.80),
    ("_ipp._tcp",        None,        "printer",       None,          0.72),
    ("_ipps._tcp",       None,        "printer",       None,          0.72),
    ("_pdl-datastream",  None,        "printer",       None,          0.75),
    ("_ssh._tcp",        None,        "server",        "Linux",       0.62),
    ("_googlecast._tcp", "Google",    "media_player",  "Cast OS",     0.90),
    ("_roku._tcp",       "Roku",      "streaming_device","Roku OS",   0.90),
    ("_spotify-connect", None,        "media_player",  None,          0.70),
    ("_sonos._tcp",      "Sonos",     "smart_speaker", None,          0.90),
    ("_hue._tcp",        "Philips",   "smart_lighting",None,          0.88),
    ("_matter._tcp",     None,        "iot",           None,          0.75),
    ("_tuya._tcp",       None,        "iot",           None,          0.78),
]

# ─────────────────────────────────────────────────────────────────────────────
# Apple model code → human-readable name
# ─────────────────────────────────────────────────────────────────────────────

APPLE_MODEL_MAP: dict[str, str] = {
    "AudioAccessory5,1": "HomePod mini",
    "AudioAccessory6,1": "HomePod 2nd gen",
    "AppleTV5,3": "Apple TV 4th gen",
    "AppleTV6,2": "Apple TV 4K",
    "AppleTV11,1": "Apple TV 4K 2nd gen",
    "AppleTV14,1": "Apple TV 4K 3rd gen",
    "iPhone14,5": "iPhone 13",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone16,1": "iPhone 15 Pro",
    "iPad14,1": "iPad mini 6th gen",
    "MacBookAir10,1": "MacBook Air M1",
    "MacBookPro18,1": "MacBook Pro M1 Pro",
    "iMac21,1": "iMac 24-inch M1",
}


# ─────────────────────────────────────────────────────────────────────────────
# SignatureMatcher — main class
# ─────────────────────────────────────────────────────────────────────────────

class SignatureMatcher:
    """
    Correlate observed network artefacts with known device signatures.

    All matching is synchronous and in-memory, backed by your local
    OUI database (utils.extract) and built-in pattern tables.
    """

    def __init__(self) -> None:
        # OUI lookup delegate (lazy import to avoid circular deps)
        self._get_vendor = self._load_vendor_fn()

    @staticmethod
    def _load_vendor_fn():
        try:
            from utils.extract import get_vendor
            return get_vendor
        except ImportError:
            return lambda mac: None

    # ── MAC / OUI ─────────────────────────────────────────────────────────

    def match_mac(self, mac: str) -> list[FingerprintMatch]:
        """Identify a device by its MAC address via OUI lookup."""
        hits: list[FingerprintMatch] = []
        if not mac or detect_randomised_mac(mac):
            return hits

        vendor = self._get_vendor(mac)
        if vendor and vendor not in ("Unknown Vendor", "Generic / Not in DB", "Unknown"):
            hits.append(FingerprintMatch(
                source="oui",
                match_type="exact",
                confidence=0.95,
                manufacturer=vendor,
                raw_data={"mac": mac, "source_db": "IEEE OUI"},
            ))
        return hits

    lookup_mac = match_mac   # backward-compat

    # ── DHCP ──────────────────────────────────────────────────────────────

    def match_dhcp(
        self,
        opt55: Optional[str] = None,
        opt60: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> list[FingerprintMatch]:
        """Collect evidence from DHCP Option 55, Option 60, and hostname."""
        hits: list[FingerprintMatch] = []

        # Option 60
        if opt60:
            for rx, mfr, dtype, os_fam, conf in _OPT60_BUILT_IN:
                if rx.search(opt60):
                    hits.append(FingerprintMatch(
                        source="dhcp_opt60", match_type="pattern",
                        confidence=conf, manufacturer=mfr,
                        device_type=dtype, os_family=os_fam,
                        raw_data={"opt60": opt60},
                    ))
                    break

        # Hostname
        if hostname:
            hn_match = self.match_hostname(hostname)
            if hn_match:
                hits.append(hn_match)

        # Option 55
        codes = _parse_opt55(opt55)
        if codes:
            m = _match_opt55(codes)
            if m:
                mfr, dtype, os_fam, conf = m
                hits.append(FingerprintMatch(
                    source="dhcp_opt55", match_type="pattern",
                    confidence=conf, manufacturer=mfr,
                    device_type=dtype, os_family=os_fam,
                    raw_data={"opt55": codes},
                ))

        return hits

    lookup_dhcp = match_dhcp

    # ── Hostname ──────────────────────────────────────────────────────────

    def match_hostname(self, hostname: str) -> Optional[FingerprintMatch]:
        """Identify a device from its advertised hostname."""
        if not hostname:
            return None
        for rx, mfr, dtype, os_fam, conf in _HOSTNAME_BUILT_IN:
            if rx.search(hostname):
                return FingerprintMatch(
                    source="hostname", match_type="pattern",
                    confidence=conf, manufacturer=mfr,
                    device_type=dtype, os_family=os_fam,
                    raw_data={"hostname": hostname},
                )
        return None

    lookup_hostname = match_hostname

    # ── mDNS ──────────────────────────────────────────────────────────────

    def match_mdns(
        self,
        service_type: str,
        name: Optional[str] = None,
        packet_data: Optional[dict] = None,
    ) -> list[FingerprintMatch]:
        """Correlate mDNS advertisements to a device profile."""
        hits: list[FingerprintMatch] = []
        if packet_data is None:
            packet_data = {}

        svc_lower = service_type.lower()

        # Pattern matching
        for svc_pat, mfr, dtype, os_fam, conf in _MDNS_BUILT_IN:
            if svc_pat in svc_lower:
                hits.append(FingerprintMatch(
                    source="mdns", match_type="pattern",
                    confidence=conf, manufacturer=mfr,
                    device_type=dtype, os_family=os_fam,
                    raw_data={"service_type": service_type, "name": name},
                ))
                break

        # Google Cast model (md field from TXT)
        if "model" in packet_data:
            hits.append(FingerprintMatch(
                source="mdns_txt", match_type="exact", confidence=0.92,
                model=packet_data["model"],
                device_type=packet_data.get("device_type", "media_player"),
                manufacturer=packet_data.get("txt_manufacturer"),
                raw_data={"txt_model": packet_data["model"],
                          "friendly_name": packet_data.get("friendly_name")},
            ))

        # Apple model code (am field from TXT)
        if "apple_model" in packet_data:
            a_code = packet_data["apple_model"]
            a_name = APPLE_MODEL_MAP.get(a_code, a_code)
            dtype  = ("phone"        if a_code.startswith("iPhone")
                      else "tablet"  if a_code.startswith("iPad")
                      else "laptop"  if a_code.startswith("MacBook")
                      else "computer" if a_code.startswith("iMac")
                      else "smart_speaker" if a_code.startswith("AudioAccessory")
                      else "media_player")
            os_fam = "iOS" if a_code.startswith("iPhone") else None
            hits.append(FingerprintMatch(
                source="mdns_txt", match_type="exact", confidence=0.95,
                model=a_name, device_type=dtype, manufacturer="Apple",
                os_family=os_fam,
                raw_data={"apple_model_code": a_code},
            ))

        return hits

    lookup_mdns = match_mdns

    # ── TTL ───────────────────────────────────────────────────────────────

    def match_ttl(self, ttl_value: int) -> Optional[FingerprintMatch]:
        """
        Record the observed TTL as weak evidence.

        TTL is NOT a reliable platform indicator by itself:
          ≤ 64  → Linux / Android / macOS / iOS / embedded
          ≤ 128 → Windows (also UniFi OS and many routers)
          ≤ 255 → Cisco / Juniper / network devices

        Confidence is kept at 0.10 so that DHCP / mDNS / OUI dominate.
        Only TTL > 200 (likely network device) gets a modest boost.
        """
        if ttl_value <= 0:
            return None
        if ttl_value > 200:
            return FingerprintMatch(
                source="ttl", match_type="heuristic", confidence=0.25,
                device_type="network_device",
                raw_data={"ttl": ttl_value, "initial_ttl": 255},
            )
        initial = 64 if ttl_value <= 64 else 128
        return FingerprintMatch(
            source="ttl", match_type="heuristic", confidence=0.10,
            raw_data={"ttl": ttl_value, "initial_ttl": initial},
        )

    lookup_ttl = match_ttl

    # ── TCP signature ─────────────────────────────────────────────────────

    def match_tcp(self, sig: str) -> Optional[FingerprintMatch]:
        """Match a p0f-style TCP/IP stack signature (stub — extend with DB)."""
        # No built-in DB shipped; returns None until a tcp_sigs.json is added.
        return None

    lookup_tcp = match_tcp

    # ── Banner ────────────────────────────────────────────────────────────

    def match_banner(
        self, protocol: str, banner_text: str
    ) -> Optional[FingerprintMatch]:
        """Identify a device from a service banner string."""
        if not banner_text:
            return None

        bl = banner_text.lower()
        _BANNER_HINTS: list[tuple[str, str, Optional[str], Optional[str], float]] = [
            ("ssh-2.0-openssh",    "ssh",    None,        "Linux",   0.70),
            ("ssh-2.0-cisco",      "ssh",    "Cisco",     "IOS",     0.85),
            ("jetdirect",          "http",   "HP",        None,      0.80),
            ("synology",           "http",   "Synology",  "DSM",     0.82),
            ("unifi",              "http",   "Ubiquiti",  "Linux",   0.80),
            ("mikrotik",           "http",   "MikroTik",  "RouterOS",0.85),
            ("windows server",     "smb",    "Microsoft", "Windows", 0.88),
            ("samba",              "smb",    None,        "Linux",   0.72),
        ]
        for pattern, proto_filter, mfr, os_fam, conf in _BANNER_HINTS:
            if protocol.lower() == proto_filter and pattern in bl:
                return FingerprintMatch(
                    source="banner", match_type="pattern",
                    confidence=conf, manufacturer=mfr, os_family=os_fam,
                    raw_data={"protocol": protocol, "banner": banner_text[:200]},
                )
        return None

    lookup_banner = match_banner

    # ── SSDP ──────────────────────────────────────────────────────────────

    def match_ssdp(
        self,
        server: Optional[str] = None,
        st: Optional[str] = None,
    ) -> Optional[FingerprintMatch]:
        """Identify from SSDP SERVER header or search target."""
        if server:
            sl = server.lower()
            _SSDP_HINTS: list[tuple[str, Optional[str], Optional[str], Optional[str], float]] = [
                ("windows",  "Microsoft", None,        "Windows",   0.78),
                ("linux",    None,        None,        "Linux",     0.65),
                ("roku",     "Roku",      "streaming_device","Roku OS",0.88),
                ("synology", "Synology",  "nas",       "DSM",       0.85),
                ("unifi",    "Ubiquiti",  "access_point","Linux",   0.85),
                ("samsung",  "Samsung",   None,        None,        0.70),
                ("tplink",   "TP-Link",   None,        None,        0.75),
            ]
            for pattern, mfr, dtype, os_fam, conf in _SSDP_HINTS:
                if pattern in sl:
                    return FingerprintMatch(
                        source="ssdp", match_type="pattern",
                        confidence=conf, manufacturer=mfr,
                        device_type=dtype, os_family=os_fam,
                        raw_data={"server": server},
                    )
        if st:
            st_l = st.lower()
            dtype = (
                "router" if "internetgateway" in st_l else
                "media_player" if "mediarenderer" in st_l else
                "server" if "mediaserver" in st_l else
                "printer" if "printer" in st_l else None
            )
            if dtype:
                return FingerprintMatch(
                    source="ssdp_upnp", match_type="exact", confidence=0.75,
                    device_type=dtype, raw_data={"st": st},
                )
        return None

    lookup_ssdp = match_ssdp

    # ── HTTP User-Agent ───────────────────────────────────────────────────

    def match_useragent(self, ua: str) -> Optional[FingerprintMatch]:
        """Parse HTTP User-Agent to infer OS and device type."""
        if not ua:
            return None

        _QUICK: list[tuple[str, Optional[str], str, Optional[str], float]] = [
            ("Roku/",      "Roku",      "streaming_device", "RokuOS",   0.88),
            ("Silk/",      "Amazon",    "tablet",           "Fire OS",  0.85),
            ("Tizen/",     "Samsung",   "smart_tv",         "Tizen",    0.88),
            ("Web0S",      "LG",        "smart_tv",         "webOS",    0.88),
            ("webOS",      "LG",        "smart_tv",         "webOS",    0.88),
            ("PlayStation","Sony",      "game_console",     "PlayStation",0.88),
            ("Xbox",       "Microsoft", "game_console",     "Xbox",     0.88),
            ("Nintendo",   "Nintendo",  "game_console",     None,       0.88),
            ("CrKey",      "Google",    "media_player",     "Cast OS",  0.88),
            ("AppleTV",    "Apple",     "media_player",     "tvOS",     0.88),
            ("Sonos/",     "Sonos",     "smart_speaker",    None,       0.88),
        ]
        for token, mfr, dtype, os_fam, conf in _QUICK:
            if token in ua:
                return FingerprintMatch(
                    source="http_useragent", match_type="pattern",
                    confidence=conf, manufacturer=mfr, device_type=dtype,
                    os_family=os_fam, raw_data={"user_agent": ua[:200]},
                )

        # Generic OS detection
        detected_os: Optional[str] = None
        detected_dtype = "workstation"
        m = re.search(r"Android\s+([\d.]+)", ua)
        if m:
            detected_os = "Android"
            detected_dtype = "phone"
        elif "iPhone" in ua:
            detected_os = "iOS"
            detected_dtype = "phone"
        elif "iPad" in ua:
            detected_os = "iPadOS"
            detected_dtype = "tablet"
        elif "Mac OS X" in ua or "Macintosh" in ua:
            detected_os = "macOS"
        elif "Windows NT" in ua:
            detected_os = "Windows"
        elif "Linux" in ua:
            detected_os = "Linux"

        if not detected_os:
            return None
        return FingerprintMatch(
            source="http_useragent", match_type="pattern", confidence=0.78,
            device_type=detected_dtype, os_family=detected_os,
            raw_data={"user_agent": ua[:200]},
        )

    lookup_useragent = match_useragent

    # ── TLS SNI / JA3 (passive observation) ───────────────────────────────

    def match_tls_sni(self, sni: str) -> Optional[FingerprintMatch]:
        """
        Infer vendor/OS hints from TLS Server Name Indication.
        Conservative: returns moderate confidence only.
        """
        if not sni:
            return None
        host = sni.strip().lower().rstrip(".")
        if not host:
            return None

        _HINTS: list[tuple[str, Optional[str], Optional[str], Optional[str], float]] = [
            ("apple.com",        "Apple",     None,      "iOS/macOS", 0.70),
            ("icloud.com",       "Apple",     None,      "iOS/macOS", 0.70),
            ("mzstatic.com",     "Apple",     None,      "iOS/macOS", 0.65),
            ("windowsupdate.com","Microsoft", None,      "Windows",   0.75),
            ("microsoft.com",    "Microsoft", None,      "Windows",   0.65),
            ("office.com",       "Microsoft", None,      "Windows",   0.60),
            ("android.com",      "Google",    None,      "Android",   0.65),
            ("googleapis.com",   "Google",    None,      None,        0.55),
            ("roku.com",         "Roku",      "streaming_device", "Roku OS", 0.70),
            ("sonos.com",        "Sonos",     "smart_speaker", None,  0.70),
            ("samsung.com",      "Samsung",   None,      None,        0.55),
        ]
        for suffix, mfr, dtype, os_fam, conf in _HINTS:
            if host == suffix or host.endswith("." + suffix):
                return FingerprintMatch(
                    source="tls_sni",
                    match_type="heuristic",
                    confidence=conf,
                    manufacturer=mfr,
                    device_type=dtype,
                    os_family=os_fam,
                    raw_data={"sni": host},
                )
        return FingerprintMatch(
            source="tls_sni",
            match_type="heuristic",
            confidence=0.40,
            raw_data={"sni": host},
        )

    lookup_tls_sni = match_tls_sni

    def match_ja3(self, ja3_hash: str, ja3_str: str = "") -> Optional[FingerprintMatch]:
        """
        Record JA3 as an identity signal. Matching a JA3 DB is optional.
        """
        if not ja3_hash:
            return None
        return FingerprintMatch(
            source="ja3",
            match_type="exact",
            confidence=0.50,
            raw_data={"ja3": ja3_hash, "ja3_str": ja3_str[:300] if ja3_str else ""},
        )

    lookup_ja3 = match_ja3

    # ── Generic category helper ───────────────────────────────────────────

    def get_device_category(self, device_type: str) -> Optional[str]:
        if not device_type:
            return None
        return DEVICE_CATEGORIES.get(device_type.lower())


# Backward-compat alias (reference code uses FingerprintLookup)
FingerprintLookup = SignatureMatcher


__all__ = [
    "SignatureMatcher",
    "FingerprintLookup",
    "DEVICE_CATEGORIES",
]
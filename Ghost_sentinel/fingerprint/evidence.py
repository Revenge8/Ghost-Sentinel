# core/fingerprint/evidence.py — Ghost Sentinel
# =================================================
# All data containers and signal-fusion logic.
#
# Contains:
#   FingerprintMatch  — single identification signal from one source
#   Evidence          — your original evidence dataclass (kept for ScapyAdapter)
#   FingerprintResult — aggregated device profile (your original + new fields)
#   SOURCE_WEIGHTS    — trust tier per source (from lookup logic)
#   aggregate_evidence() — weighted ballot consensus fusion (from doc 11)
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Source trust weights  (higher = stronger signal)
# ─────────────────────────────────────────────────────────────────────────────

SOURCE_WEIGHTS: Dict[str, float] = {
    # Protocol-level evidence — most reliable
    "lldp":               1.00,
    "cdp":                1.00,
    "snmp":               0.95,
    "mdns":               0.92,
    "mdns_txt":           0.95,
    "mdns_service_map":   0.70,
    "dhcp_opt60":         0.90,
    "dhcp_hostname":      0.88,
    "dhcp_hostname_pattern": 0.85,
    "dhcp_opt55":         0.82,
    "dhcp_client_id":     0.60,
    "dhcpv6":             0.80,
    "huginn_device":      0.90,
    "huginn_dhcp":        0.82,
    "huginn_dhcp_vendor": 0.75,
    "huginn_dhcpv6":      0.70,
    "huginn_dhcpv6_enterprise": 0.70,
    "iana_enterprise":    0.60,
    "satori_dhcp":        0.85,
    "satori_ssh":         0.82,
    "satori_smb":         0.82,
    "satori_web":         0.78,
    "satori_useragent":   0.80,
    "tcp":                0.78,
    "banner":             0.80,
    "banner_cache":       0.70,
    "passive_banner":     0.85,
    "http_useragent":     0.80,
    "tls_sni":            0.55,
    "ja3":                0.72,
    "ja4":                0.75,
    "ssdp":               0.70,
    "ssdp_upnp":          0.75,
    "hostname":           0.80,
    "netbios":            0.65,
    "dns":                0.55,
    "icmpv6":             0.60,
    "ws_discovery":       0.85,
    "ntp":                0.55,
    "stp":                0.60,
    "iot_scada":          0.60,
    # MAC / OUI
    "oui":                0.95,
    "huginn_mac":         0.80,
    "mac_oui":            0.30,   # your static hint table
    "mac_oui_db":         0.30,   # IEEE DB via utils.extract
    # Weaker signals
    "arp":                0.30,
    "igmp":               0.40,
    "ttl":                0.10,
    "http_host":          0.55,
}

FALLBACK_TRUST: float = 0.50


# ─────────────────────────────────────────────────────────────────────────────
# FingerprintMatch  (from reference lookup/engine architecture)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FingerprintMatch:
    """Single identification signal produced by one fingerprint source."""

    source:      str
    match_type:  str
    confidence:  float

    device_type:  Optional[str] = None
    category:     Optional[str] = None
    manufacturer: Optional[str] = None
    model:        Optional[str] = None
    os_family:    Optional[str] = None
    os_version:   Optional[str] = None
    vendor:       Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def effective_weight(self) -> float:
        """Ballot weight = source trust × signal confidence."""
        return SOURCE_WEIGHTS.get(self.source, FALLBACK_TRUST) * self.confidence

    def __repr__(self) -> str:
        parts = [f"src={self.source!r}", f"conf={self.confidence:.2f}"]
        if self.manufacturer:
            parts.append(f"mfr={self.manufacturer!r}")
        if self.os_family:
            parts.append(f"os={self.os_family!r}")
        if self.device_type:
            parts.append(f"dev={self.device_type!r}")
        return f"FingerprintMatch({', '.join(parts)})"


# ─────────────────────────────────────────────────────────────────────────────
# Evidence  (your original dataclass — kept for ScapyAdapter compatibility)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Evidence:
    """A single piece of heuristic fingerprinting evidence (Scapy pipeline)."""
    source:    str
    method:    str           # "exact" | "pattern" | "heuristic"
    certainty: float         # 0.0 – 1.0
    vendor:    Optional[str] = None
    category:  Optional[str] = None
    os_family: Optional[str] = None
    model:     Optional[str] = None
    hostname:  Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_match(self) -> FingerprintMatch:
        """Convert to a FingerprintMatch for use in the fusion pipeline."""
        return FingerprintMatch(
            source=self.source,
            match_type=self.method,
            confidence=self.certainty,
            manufacturer=self.vendor,
            device_type=self.category,
            os_family=self.os_family,
            model=self.model,
            raw_data=self.raw,
        )


# ─────────────────────────────────────────────────────────────────────────────
# FingerprintResult  (your original + os_intel + fusion fields)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FingerprintResult:
    """Fully resolved device profile for one observation."""
    mac: str = ""
    ip:  str = ""

    # Core identity (merged from Evidence objects)
    vendor:    Optional[str] = None
    category:  Optional[str] = None
    os_family: Optional[str] = None
    model:     Optional[str] = None
    hostname:  Optional[str] = None

    # Composite certainty (0.0 – 1.0)
    certainty: float = 0.0

    # os_intel enrichment
    firmware:             Optional[Dict[str, Any]] = None
    os_validated:         bool  = True
    os_plausibility:      float = 0.5
    os_plausibility_note: str   = ""
    inferred_os:          Optional[str] = None
    confidence_tier:      Optional[str] = None  # VALIDATED/PLAUSIBLE/SUSPECT/UNKNOWN

    # Fusion output (from aggregate_evidence)
    device_type:   Optional[str] = None
    manufacturer:  Optional[str] = None
    os_version:    Optional[str] = None
    os_confirmed:  bool = False
    fused_confidence: float = 0.0

    # Confidence scoring (points-based, packet-evidence driven)
    score_points:    int = 0
    score_threshold: int = 80
    verdict_ready:   bool = False
    score_breakdown: List[Dict[str, Any]] = field(default_factory=list)

    # Raw evidence list (Scapy pipeline)
    evidence: List[Evidence] = field(default_factory=list)
    # All FingerprintMatch signals (lookup/engine pipeline)
    matches:  List[FingerprintMatch] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "mac":                 self.mac,
            "ip":                  self.ip,
            "vendor":              self.vendor,
            "category":            self.category,
            "os_family":           self.os_family,
            "model":               self.model,
            "hostname":            self.hostname,
            "certainty":           round(self.certainty, 3),
            "device_type":         self.device_type,
            "manufacturer":        self.manufacturer,
            "os_version":          self.os_version,
            "os_confirmed":        self.os_confirmed,
            "fused_confidence":    round(self.fused_confidence, 3),
            "score_points":        self.score_points,
            "score_threshold":     self.score_threshold,
            "verdict_ready":       self.verdict_ready,
            "score_breakdown":     self.score_breakdown,
            "firmware":            self.firmware,
            "os_validated":        self.os_validated,
            "os_plausibility":     round(self.os_plausibility, 3),
            "os_plausibility_note": self.os_plausibility_note,
            "inferred_os":         self.inferred_os,
            "confidence_tier":     self.confidence_tier,
            "evidence_count":      len(self.evidence),
            "match_count":         len(self.matches),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Scoring helpers  (your original)
# ─────────────────────────────────────────────────────────────────────────────

def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def combine_scores(*scores: float) -> float:
    """Additive combination with 0.70 diminishing-returns discount."""
    total    = 0.0
    discount = 1.0
    for s in sorted(scores, reverse=True):
        total   += s * discount
        discount *= 0.70
    return clamp(total)


# ─────────────────────────────────────────────────────────────────────────────
# Fusion helpers  (from reference evidence.py / doc 11)
# ─────────────────────────────────────────────────────────────────────────────

# OS families that are single-purpose appliance OSes — NOT fullstack
_FULLSTACK_OS_NAMES = frozenset({
    "Linux", "Windows", "macOS", "FreeBSD", "OpenBSD", "NetBSD",
    "Solaris", "Unix", "AIX", "ESXi", "VMkernel",
    "Proxmox VE", "Proxmox", "Hyper-V", "XenServer", "AHV",
})
_FULLSTACK_OS_PREFIXES = (
    "linux", "windows", "freebsd", "openbsd", "netbsd", "unix", "kali",
)


def _is_fullstack_os(name: str) -> bool:
    if name in _FULLSTACK_OS_NAMES:
        return True
    return name.lower().startswith(_FULLSTACK_OS_PREFIXES)


# OUI device-type labels that are speculative (product-line assumptions)
_SPECULATIVE_LABELS = frozenset({
    "smart_speaker", "media_player", "smart_tv", "phone", "smart_display",
    "iot", "thermostat", "ip_camera", "doorbell", "smart_plug",
    "smart_lighting", "smart_lock", "home_hub", "game_console",
    "streaming_device", "set_top_box", "wearable", "sensor",
    "router", "switch", "access_point", "wireless_bridge",
})

# Multi-product vendors: OUI can't tell which product line
_MULTI_PRODUCT_VENDORS = frozenset({
    "Samsung", "Samsung Electronics", "LG", "LG Electronics", "Sony",
    "Microsoft", "Google", "Amazon", "Xiaomi", "Huawei",
    "Dell", "HP", "Hewlett Packard", "Hewlett-Packard",
    "Lenovo", "ASUS", "ASUSTek", "Apple", "Roku", "Philips", "Panasonic", "TCL",
})

# Vendors where OUI attribution requires confirmation
_HARDWARE_LOCKED_VENDORS = frozenset({"Apple"})

# OS families whose possible manufacturers are restricted
_OS_EXCLUSIVE_MANUFACTURERS: Dict[str, frozenset] = {
    "macos":       frozenset({"Apple"}),
    "mac os x":    frozenset({"Apple"}),
    "ios":         frozenset({"Apple", "Cisco"}),
    "ios/macos":   frozenset({"Apple"}),
    "ipados":      frozenset({"Apple"}),
    "tvos":        frozenset({"Apple"}),
    "tvos/macos":  frozenset({"Apple"}),
    "cisco ios":   frozenset({"Cisco"}),
    "nx-os":       frozenset({"Cisco"}),
    "routeros":    frozenset({"MikroTik", "Mikrotikls"}),
    "junos":       frozenset({"Juniper"}),
    "fortios":     frozenset({"Fortinet"}),
    "arubaos":     frozenset({"Aruba", "HPE"}),
    "edgeos":      frozenset({"Ubiquiti"}),
    "dsm":         frozenset({"Synology"}),
    "qts":         frozenset({"QNAP"}),
    "fire os":     frozenset({"Amazon"}),
    "cast os":     frozenset({"Google"}),
    "webos":       frozenset({"LG"}),
    "tizen":       frozenset({"Samsung"}),
    "roku":        frozenset({"Roku"}),
    "xbox":        frozenset({"Microsoft"}),
    "playstation": frozenset({"Sony"}),
    "android":     frozenset({
        "Google", "Samsung", "Xiaomi", "Huawei", "OnePlus", "Oppo",
        "Vivo", "Realme", "Honor", "Sony Mobile", "LG Mobile",
        "HTC", "Motorola", "Nokia", "Lenovo", "ASUS",
        "Meta", "Amazon", "TCL", "Hisense",
    }),
}

_VIRTUALISATION_VENDORS = frozenset({
    "VMware", "QEMU/KVM", "QEMU", "KVM", "Xen", "XCP-ng",
    "Citrix", "Docker", "Parallels", "VirtualBox", "Nutanix", "Microsoft",
})

_SERVER_OS_KEYWORDS = (
    "windows server", "esxi", "vmkernel", "vsphere", "vcenter",
    "proxmox", "hyper-v", "xenserver", "ahv",
)


def _derive_role_from_os(os_name: str) -> str:
    lc = os_name.lower()
    for kw in _SERVER_OS_KEYWORDS:
        if kw in lc:
            return "server"
    if "bsd" in lc or "solaris" in lc:
        return "server"
    if lc in ("ios", "ipados", "android", "watchos"):
        return "phone"
    if lc == "tvos":
        return "media_player"
    if lc in ("fire os", "cast os", "roku os", "tizen", "webos"):
        return "media_player"
    return "computer"


def _os_compatible(os_family: str, manufacturer: Optional[str]) -> bool:
    if not manufacturer or not os_family:
        return True
    mfr_lc = manufacturer.lower()
    if any(v.lower() in mfr_lc for v in _VIRTUALISATION_VENDORS):
        return True
    permitted = _OS_EXCLUSIVE_MANUFACTURERS.get(os_family.lower())
    if permitted is None:
        return True
    return any(p.lower() in mfr_lc for p in permitted)


def _downweight_locked_vendors(signals: List[FingerprintMatch]) -> None:
    for locked in _HARDWARE_LOCKED_VENDORS:
        locked_lc = locked.lower()
        corroborating = [
            s for s in signals
            if s.source != "oui" and s.manufacturer
            and locked_lc in s.manufacturer.lower()
        ]
        if not corroborating:
            continue
        distinct = {s.source for s in corroborating}
        n = len(distinct)
        if n >= 3:
            continue
        reduction = 0.35 if n <= 1 else 0.10
        for sig in corroborating:
            sig.confidence *= reduction
            if n <= 1:
                sig.manufacturer = None
            if sig.os_family and sig.os_family.lower() in _OS_EXCLUSIVE_MANUFACTURERS:
                permitted = _OS_EXCLUSIVE_MANUFACTURERS[sig.os_family.lower()]
                if any(locked_lc in p.lower() for p in permitted):
                    sig.os_family = None
                    sig.os_version = None


def _invalidate_incompatible_os(
    signals: List[FingerprintMatch], oui_vendor: Optional[str]
) -> None:
    if not oui_vendor:
        return
    for sig in signals:
        if sig.source == "oui" or not sig.os_family:
            continue
        if _is_fullstack_os(sig.os_family):
            continue
        if _os_compatible(sig.os_family, oui_vendor):
            continue
        sig.os_family = None
        sig.os_version = None
        sig.confidence *= 0.30


def _suppress_android_without_oui(signals: List[FingerprintMatch]) -> None:
    android_sigs = [s for s in signals if s.os_family and "android" in s.os_family.lower()]
    if not android_sigs:
        return
    linux_sigs = [
        s for s in signals
        if s.os_family and _is_fullstack_os(s.os_family)
        and "android" not in s.os_family.lower()
    ]
    all_partial = all(
        s.raw_data.get("match_source", "").endswith("_partial")
        for s in android_sigs
    )
    if not linux_sigs and not all_partial:
        return
    for sig in android_sigs:
        sig.confidence *= 0.20


def _tally(
    signals: List[FingerprintMatch],
    verified_os: Optional[str],
    verified_os_src: Optional[str],
    verified_os_role: Optional[str],
) -> Dict[str, Dict[str, float]]:
    dims = ("device_type", "manufacturer", "os_family")
    ballots: Dict[str, Dict[str, float]] = {d: {} for d in dims}
    for sig in signals:
        w = sig.effective_weight()
        for dim in dims:
            candidate = getattr(sig, dim, None)
            if candidate is None:
                continue
            aw = w
            # Discount speculative OUI labels when real OS is confirmed
            if dim == "device_type" and verified_os and sig.source == "oui":
                if candidate in _SPECULATIVE_LABELS:
                    aw *= 0.15
            # Discount OUI non-server type when server OS confirmed
            if dim == "device_type" and verified_os_role == "server" and sig.source == "oui":
                if candidate != "server" and candidate not in _SPECULATIVE_LABELS:
                    aw *= 0.25
            # Drop OUI device_type for multi-product vendors
            if dim == "device_type" and sig.source in ("oui", "huginn_mac", "huginn_device"):
                mfr = sig.manufacturer or ""
                if any(v.lower() in mfr.lower() for v in _MULTI_PRODUCT_VENDORS):
                    continue
            ballots[dim][candidate] = ballots[dim].get(candidate, 0.0) + aw
    return ballots


def _prune_contradictory(
    ballots: Dict[str, Dict[str, float]], verified_os: str
) -> None:
    verified_lc = verified_os.lower()
    for mfr in list(ballots.get("manufacturer", {})):
        if not mfr:
            continue
        bound: set = set()
        for os_key, permitted in _OS_EXCLUSIVE_MANUFACTURERS.items():
            if any(p.lower() in mfr.lower() for p in permitted):
                bound.add(os_key)
        if bound and not any(
            verified_lc == b or verified_lc.startswith(b) for b in bound
        ):
            del ballots["manufacturer"][mfr]

    for os_c in list(ballots.get("os_family", {})):
        if not os_c or os_c == verified_os or _is_fullstack_os(os_c):
            continue
        if os_c.lower() in _OS_EXCLUSIVE_MANUFACTURERS:
            del ballots["os_family"][os_c]


def _vendor_default_device_type(vendor: str) -> Optional[str]:
    _MAP = {
        "sonos": "smart_speaker", "roku": "streaming_device",
        "synology": "nas", "qnap": "nas", "hikvision": "ip_camera",
        "dahua": "ip_camera", "reolink": "ip_camera", "wyze": "camera",
        "ring": "doorbell", "nest": "smart_home",
    }
    vl = vendor.lower()
    for k, v in _MAP.items():
        if k in vl:
            return v
    return None


def _guess_os_from_vendor(vendor: str, role: Optional[str]) -> Optional[str]:
    _MAP: Dict[str, Any] = {
        "cisco": {"router": "IOS", "switch": "IOS", "firewall": "ASA", "_default": "IOS"},
        "juniper": "Junos", "mikrotik": "RouterOS", "fortinet": "FortiOS",
        "ubiquiti": "UniFi OS", "aruba": "ArubaOS",
        "synology": "DSM", "qnap": "QTS",
        "apple": {"phone": "iOS", "tablet": "iPadOS", "computer": "macOS",
                  "smart_speaker": "HomePod OS", "_default": "macOS"},
        "samsung": {"smart_tv": "Tizen", "phone": "Android", "_default": None},
        "google": {"smart_speaker": "Cast OS", "phone": "Android", "_default": None},
        "amazon": {"smart_speaker": "Fire OS", "tablet": "Fire OS", "_default": None},
        "roku": "RokuOS", "sonos": "Sonos OS",
        "sony": {"game_console": "PlayStation", "_default": None},
        "microsoft": {"game_console": "Xbox", "_default": None},
    }
    vl = vendor.lower()
    for k, mapping in _MAP.items():
        if k not in vl:
            continue
        if isinstance(mapping, str):
            return mapping
        if role and role in mapping:
            return mapping[role]
        return mapping.get("_default")
    return None


def _compute_confidence(signals: List[FingerprintMatch]) -> float:
    num = denom = 0.0
    for sig in signals:
        trust = SOURCE_WEIGHTS.get(sig.source, FALLBACK_TRUST)
        num   += trust * sig.confidence
        denom += trust
    return num / denom if denom > 0.0 else 0.0


def _best_field(signals: List[FingerprintMatch], attr: str) -> Any:
    relevant = [s for s in signals if getattr(s, attr, None) is not None]
    if not relevant:
        return None
    return getattr(max(relevant, key=lambda s: s.confidence), attr)


def _evidence_trail(signals: List[FingerprintMatch]) -> List[Dict[str, Any]]:
    out = []
    for sig in signals:
        e: Dict[str, Any] = {
            "source": sig.source,
            "match_type": sig.match_type,
            "confidence": sig.confidence,
        }
        for f in ("manufacturer", "device_type", "os_family", "os_version", "model"):
            v = getattr(sig, f, None)
            if v is not None:
                e[f] = v
        out.append(e)
    return out


def aggregate_evidence(matches: List[FingerprintMatch]) -> Dict[str, Any]:
    """
    Fuse a list of FingerprintMatch signals into a unified device profile.

    Uses weighted ballot consensus with cross-validation guards:
      1. Locate OUI vendor
      2. Invalidate OS detections incompatible with OUI
      3. Penalise hardware-locked vendors without OUI backing
      4. Penalise ambiguous Android signals
      5. Verify fullstack OS
      6. Tally weighted ballots
      7. Cross-validate ballots vs verified OS
      8. Pick winners + fallback inference

    Returns dict with: device_type, manufacturer, model, os_family,
    os_version, confidence, evidence, os_confirmed.
    """
    if not matches:
        return {
            "device_type": "Unknown", "manufacturer": None, "model": None,
            "os_family": None, "os_version": None, "confidence": 0.0,
            "evidence": [], "os_confirmed": False,
        }

    # 1. OUI vendor
    oui_vendor: Optional[str] = None
    for sig in matches:
        if sig.source == "oui" and sig.manufacturer:
            oui_vendor = sig.manufacturer
            break

    # 2–4. Pre-processing
    _invalidate_incompatible_os(matches, oui_vendor)
    if oui_vendor is None:
        _downweight_locked_vendors(matches)
        _suppress_android_without_oui(matches)

    # 5. Verify fullstack OS
    verified_os: Optional[str] = None
    verified_os_src: Optional[str] = None
    for sig in sorted(matches, key=lambda m: m.effective_weight(), reverse=True):
        if sig.source == "oui" or not sig.os_family:
            continue
        if not _is_fullstack_os(sig.os_family):
            continue
        if _os_compatible(sig.os_family, oui_vendor):
            verified_os = sig.os_family
            verified_os_src = sig.source
            break
        sig.os_family = None
        sig.os_version = None
        sig.confidence *= 0.15

    verified_os_role = _derive_role_from_os(verified_os) if verified_os else None

    # 6. Tally
    ballots = _tally(matches, verified_os, verified_os_src, verified_os_role)

    # 7. Cross-validate
    if verified_os and not oui_vendor:
        _prune_contradictory(ballots, verified_os)

    # Inject device-role vote from verified OS
    if verified_os:
        role = _derive_role_from_os(verified_os)
        boost = SOURCE_WEIGHTS.get(verified_os_src or "tcp", 0.80) * 0.85
        ballots["device_type"][role] = ballots["device_type"].get(role, 0.0) + boost

    # OUI manufacturer dominance
    if oui_vendor:
        ballots["manufacturer"][oui_vendor] = (
            ballots["manufacturer"].get(oui_vendor, 0.0) + 2.0
        )

    # 8. Pick winners
    def _top(ballot: Dict[str, float]) -> Optional[str]:
        return max(ballot, key=ballot.__getitem__) if ballot else None

    chosen_type  = _top(ballots["device_type"])
    chosen_mfr   = _top(ballots["manufacturer"])
    chosen_os    = _top(ballots["os_family"])

    if (not chosen_type or chosen_type == "Unknown") and chosen_mfr:
        chosen_type = _vendor_default_device_type(chosen_mfr) or chosen_type

    if chosen_os is None and chosen_mfr:
        chosen_os = _guess_os_from_vendor(chosen_mfr, chosen_type)

    return {
        "device_type":  chosen_type or "Unknown",
        "manufacturer": chosen_mfr,
        "model":        _best_field(matches, "model"),
        "os_family":    chosen_os,
        "os_version":   _best_field(matches, "os_version"),
        "confidence":   _compute_confidence(matches),
        "evidence":     _evidence_trail(matches),
        "os_confirmed": verified_os is not None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Points-based scoring (UI gating)
# ─────────────────────────────────────────────────────────────────────────────

_POINTS_BY_SOURCE: Dict[str, int] = {
    # L2
    "oui": 20,
    "mac_oui": 10,
    "mac_oui_db": 10,
    # L3/L4 (weak alone)
    "ttl": 15,
    "tcp": 25,
    # L7 (strong)
    "mdns_txt": 60,
    "mdns": 50,
    "ssdp": 45,
    "ssdp_upnp": 30,
    "http_useragent": 40,
    "tls_sni": 30,
    "ja3": 20,
    # DHCP (often strong)
    "dhcp_opt60": 40,
    "dhcp_opt55": 25,
    "dhcp_hostname": 15,
    "dhcp_hostname_pattern": 25,
    "hostname": 10,
    # Other weak signals
    "arp": 5,
    "igmp": 10,
}


def score_matches(
    matches: List[FingerprintMatch],
    threshold: int = 80,
    cap: int = 100,
) -> Dict[str, Any]:
    """
    Compute a points score from per-packet signals.

    - Uses at-most-once per source to avoid inflated certainty from spammy traffic.
    - Weights are intentionally conservative; mDNS TXT/model is treated as strong.
    """
    if not matches:
        return {
            "points": 0,
            "threshold": threshold,
            "verdict_ready": False,
            "breakdown": [],
        }

    best_by_source: Dict[str, FingerprintMatch] = {}
    for m in matches:
        src = (m.source or "").strip()
        if not src:
            continue
        prev = best_by_source.get(src)
        if prev is None or m.effective_weight() > prev.effective_weight():
            best_by_source[src] = m

    breakdown: List[Dict[str, Any]] = []
    total = 0
    for src, m in best_by_source.items():
        pts = _POINTS_BY_SOURCE.get(src, 0)
        if pts <= 0:
            continue
        total += pts
        breakdown.append({
            "source": src,
            "points": pts,
            "confidence": round(float(m.confidence), 3),
            "manufacturer": m.manufacturer,
            "device_type": m.device_type,
            "os_family": m.os_family,
        })

    total = min(int(total), int(cap))
    breakdown.sort(key=lambda x: x["points"], reverse=True)
    return {
        "points": total,
        "threshold": threshold,
        "verdict_ready": total >= threshold,
        "breakdown": breakdown,
    }


__all__ = [
    "FingerprintMatch",
    "Evidence",
    "FingerprintResult",
    "SOURCE_WEIGHTS",
    "FALLBACK_TRUST",
    "combine_scores",
    "clamp",
    "aggregate_evidence",
    "score_matches",
]
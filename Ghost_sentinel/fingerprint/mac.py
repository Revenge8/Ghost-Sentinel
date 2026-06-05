# core/fingerprint/mac.py — Ghost Sentinel MAC Address Analysis
# ==============================================================
# Detects locally-administered (randomised) MAC addresses and provides
# multi-signal correlation to link randomised MACs back to real identities.
#
# Logic from: reference mac_intel.py (doc 8)
# Kept:       your is_randomized_mac / extract_correlation_signals signatures
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

_log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Known hypervisor / container MAC prefixes
# These carry the locally-administered bit but are NOT randomised.
# ─────────────────────────────────────────────────────────────────────────────

_HYPERVISOR_PREFIXES = (
    "02:42",        # Docker containers
    "02:50:56",     # VMware NSX
    "52:54:00",     # QEMU / KVM
)

# ─────────────────────────────────────────────────────────────────────────────
# Signal weights for multi-factor identity correlation
# Higher weight = rarer signal = stronger identity indicator
# ─────────────────────────────────────────────────────────────────────────────

SIGNAL_WEIGHTS: dict[str, float] = {
    "hostname":   0.35,
    "dhcp_opt60": 0.25,
    "dhcp_opt55": 0.15,
    "tcp_sig":    0.15,
    "mdns_name":  0.10,
}

# Minimum score to consider two devices the same identity
CORRELATION_THRESHOLD: float = 0.40


# ─────────────────────────────────────────────────────────────────────────────
# Core MAC analysis
# ─────────────────────────────────────────────────────────────────────────────

def detect_randomised_mac(addr: Optional[str]) -> bool:
    """
    Return True when *addr* is a locally-administered (randomised) MAC.

    The locally-administered bit is bit 1 of the first octet.
    Addresses assigned by Docker, QEMU/KVM and VMware NSX also carry
    this bit but are NOT randomised and are therefore excluded.

    Accepts colon- or dash-separated hex notation.
    Returns False for None or empty strings.
    """
    if not addr:
        return False

    upper = addr.replace("-", ":").upper()

    # Exempt known hypervisor/container prefixes
    for pfx in _HYPERVISOR_PREFIXES:
        if upper.startswith(pfx.upper()):
            return False

    first_hex = addr.replace("-", ":").split(":")[0]
    if not first_hex:
        return False

    try:
        octet = int(first_hex, 16)
    except ValueError:
        return False

    return (octet & 0x02) != 0


# Backward-compat alias — your existing code uses this name
is_randomized_mac = detect_randomised_mac


# ─────────────────────────────────────────────────────────────────────────────
# Correlation fingerprint construction
# ─────────────────────────────────────────────────────────────────────────────

def extract_correlation_signals(pkt: dict, proto: str = "dhcpv4") -> dict:
    """
    Pull identity-relevant signals from parsed packet data.

    Returns a dict mapping signal names to normalised string values.
    Only signals actually present in *pkt* appear in the output.

    Supported protocols: dhcpv4, tcp_syn, mdns
    """
    signals: dict[str, str] = {}

    # Hostname from DHCP / DHCPv6 / mDNS
    hn = pkt.get("hostname") or pkt.get("fqdn")
    if hn and hn not in ("Unknown", "Hidden/Unknown", ""):
        signals["hostname"] = hn.lower()

    # DHCPv4 signals
    if proto == "dhcpv4":
        v60 = pkt.get("opt60")
        if v60:
            signals["dhcp_opt60"] = v60
        v55 = pkt.get("opt55")
        if v55:
            signals["dhcp_opt55"] = str(v55)

    # TCP stack fingerprint
    if proto == "tcp_syn":
        ttl_val  = pkt.get("ttl")
        win_val  = pkt.get("window_size")
        mss_val  = pkt.get("mss")
        opts_val = pkt.get("tcp_options", "")
        if ttl_val is not None and win_val is not None:
            mss_str = str(mss_val) if mss_val else "*"
            signals["tcp_sig"] = f"{ttl_val}:{win_val}:{mss_str}:{opts_val}"

    # mDNS instance name
    if proto == "mdns":
        svc = pkt.get("mdns_services") or pkt.get("mdns_name")
        if svc:
            signals["mdns_name"] = (
                svc[0].lower() if isinstance(svc, list) else str(svc).lower()
            )

    return signals


# Backward-compat alias
build_correlation_fingerprint = extract_correlation_signals


# ─────────────────────────────────────────────────────────────────────────────
# Correlation scoring
# ─────────────────────────────────────────────────────────────────────────────

def compute_correlation_score(probe_fp: dict, known_fp: dict) -> float:
    """
    Score how closely two signal-fingerprints overlap.

    Each shared signal contributes its weight from SIGNAL_WEIGHTS.
    Result is a float in [0.0, 1.0].
    """
    total = 0.0
    for sig, wt in SIGNAL_WEIGHTS.items():
        a = probe_fp.get(sig)
        b = known_fp.get(sig)
        if a and b and a == b:
            total += wt
    return total


# Backward-compat alias
score_correlation = compute_correlation_score


# ─────────────────────────────────────────────────────────────────────────────
# Identity candidates
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IdentityCandidate:
    """A device that may share real-world identity with a randomised MAC."""
    real_mac:   str
    confidence: float
    reason:     str
    hostname:   Optional[str] = None


# Backward-compat alias
CorrelationCandidate = IdentityCandidate


def find_identity_candidates(
    mac: str,
    hostname: Optional[str],
    known_devices: list[dict],
) -> list[IdentityCandidate]:
    """
    Search known devices for those likely sharing identity with *mac*.

    *known_devices* is the list of device dicts from core_storage —
    each dict has at minimum "mac" and optionally "hostname".

    When *hostname* is provided the list is scanned for other devices
    advertising the same hostname (case-insensitive). Devices with a
    globally-unique OUI MAC receive higher confidence than
    locally-administered ones.

    Returns a list sorted by confidence (descending).
    """
    if not hostname:
        return []

    results: list[IdentityCandidate] = []
    hn_lower = hostname.lower()

    for dev in known_devices:
        if dev.get("mac") == mac:
            continue
        dev_hn = dev.get("hostname", "")
        if dev_hn and dev_hn.lower() == hn_lower:
            other_mac = dev.get("mac", "")
            if not detect_randomised_mac(other_mac):
                conf = 0.92
                why  = "Matching hostname with real OUI MAC"
            else:
                conf = 0.85
                why  = "Matching hostname with locally-administered MAC"
            results.append(IdentityCandidate(
                real_mac=other_mac,
                confidence=conf,
                reason=why,
                hostname=dev_hn,
            ))

    results.sort(key=lambda c: c.confidence, reverse=True)
    return results


# Backward-compat alias (original async version required a DB object;
# this sync version works with your existing storage list)
discover_identity_candidates = find_identity_candidates
find_correlation_candidates  = find_identity_candidates


__all__ = [
    # Core detection
    "detect_randomised_mac",
    "is_randomized_mac",          # compat alias
    # Correlation
    "extract_correlation_signals",
    "build_correlation_fingerprint",  # compat alias
    "compute_correlation_score",
    "score_correlation",          # compat alias
    # Constants
    "SIGNAL_WEIGHTS",
    "CORRELATION_THRESHOLD",
    # Identity matching
    "IdentityCandidate",
    "CorrelationCandidate",       # compat alias
    "find_identity_candidates",
    "discover_identity_candidates",  # compat alias
    "find_correlation_candidates",   # compat alias
]
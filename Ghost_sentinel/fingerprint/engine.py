# core/fingerprint/engine.py — Ghost Sentinel Fingerprint Engine
# ==============================================================
# Orchestrates the full fingerprinting pipeline:
#   1. Scapy packet → normalised dict (ScapyAdapter)
#   2. Protocol-specific analysers → Evidence list (your original pipeline)
#   3. Evidence → FingerprintMatch list via SignatureMatcher
#   4. FingerprintMatch list → FingerprintResult via aggregate_evidence()
#   5. os_intel enrichment (firmware, plausibility, confidence tier)
#
# Adapted from reference FingerprintEngine (doc 10).
from __future__ import annotations

import re
import logging
import hashlib
from typing import Any, Dict, List, Optional

from .evidence import (
    Evidence, FingerprintMatch, FingerprintResult,
    combine_scores, aggregate_evidence, score_matches,
)
from .lookup import SignatureMatcher
from .mac import detect_randomised_mac

_log = logging.getLogger(__name__)

# os_intel — optional enrichment layer
try:
    from .os_intel import (  # local module (no network I/O)
        resolve_vendor_name, guess_firmware,
        assess_os_plausibility, distros_for_kernel,
        format_inferred_os, ConfidenceTier,
    )
    _OS_INTEL = True
except Exception:
    _OS_INTEL = False
    ConfidenceTier = None  # type: ignore[assignment,misc]


# ─────────────────────────────────────────────────────────────────────────────
# Pattern databases (your original — kept here for ScapyAdapter pipeline)
# ─────────────────────────────────────────────────────────────────────────────

_OPT55_PATTERNS: List[tuple] = [
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

_IGMP_PATTERNS: List[tuple] = [
    ("239.255.255.250", None, "iot",   0.45),
    ("224.0.0.251",     None, "any",   0.35),
    ("239.255.0.",      None, "media_player", 0.40),
    ("239.2.",          None, "media_player", 0.35),
]

_OUI_HINTS: Dict[str, tuple] = {
    "3C:22:FB": ("Apple",        "workstation"),
    "A4:B1:97": ("Apple",        "phone"),
    "DC:A9:04": ("Apple",        "phone"),
    "54:60:09": ("Google",       "network"),
    "F4:F5:D8": ("Google",       "media_player"),
    "FC:65:DE": ("Amazon",       "media_player"),
    "B8:27:EB": ("Raspberry Pi", "embedded"),
    "DC:A6:32": ("Raspberry Pi", "embedded"),
    "E4:5F:01": ("Raspberry Pi", "embedded"),
    "84:F3:EB": ("Espressif",    "iot"),
    "A4:CF:12": ("Espressif",    "iot"),
    "24:A4:3C": ("Ubiquiti",     "access_point"),
    "78:45:58": ("Ubiquiti",     "access_point"),
    "00:0E:58": ("Sonos",        "smart_speaker"),
    "A0:0B:BA": ("Samsung",      "phone"),
    "D4:61:DA": ("Samsung",      "phone"),
}


def _match_opt55(option_codes: List[int]) -> Optional[tuple]:
    if not option_codes:
        return None
    probe = frozenset(option_codes)
    best_score, best = 0.0, None
    for pset, vendor, category, os_fam, cert in _OPT55_PATTERNS:
        overlap = len(probe & pset) / max(len(pset), 1)
        if overlap >= _OPT55_THRESHOLD and overlap > best_score:
            best_score = overlap
            best = (vendor, category, os_fam, cert * overlap)
    return best


_HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9\-]{1,63}(?<!-)$")


def _is_valid_hostname(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", name):
        return False
    return all(_HOSTNAME_RE.match(p) for p in name.rstrip(".").split("."))


# ─────────────────────────────────────────────────────────────────────────────
# ScapyAdapter  (your original — unchanged)
# ─────────────────────────────────────────────────────────────────────────────

class ScapyAdapter:
    """Converts raw Scapy packets into normalised dicts for the engine."""

    @staticmethod
    def from_packet(pkt) -> dict:
        data: dict = {
            "protocol": None, "src_mac": None, "src_ip": None, "dst_ip": None,
            "hostname": None, "opt55": [], "opt60": None,
            "client_id": None, "mdns_services": [], "igmp_group": None,
            "ttl": None,
            "tcp_window": None,
            "tcp_options": "",
            "mss": None,
            "tls_sni": None,
            "ja3": None,
            "ja3_str": None,
        }
        try:
            from scapy.layers.l2   import Ether, ARP
            from scapy.layers.inet import IP, UDP, TCP
            from scapy.layers.dhcp import DHCP, BOOTP

            if pkt.haslayer(Ether):
                data["src_mac"] = pkt[Ether].src.upper()
            if pkt.haslayer(IP):
                data["src_ip"] = pkt[IP].src
                data["dst_ip"] = pkt[IP].dst
                data["ttl"]    = int(getattr(pkt[IP], "ttl", 0) or 0) or None

            if pkt.haslayer(ARP):
                data.update(protocol="arp",
                            src_mac=pkt[ARP].hwsrc.upper(),
                            src_ip=pkt[ARP].psrc)
                return data

            if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
                data["protocol"] = "dhcpv4"
                for opt in pkt[DHCP].options:
                    if not isinstance(opt, tuple):
                        continue
                    tag, val = opt[0], opt[1] if len(opt) > 1 else None
                    if tag == "hostname" and val:
                        data["hostname"] = (
                            val.decode("utf-8", errors="ignore")
                            if isinstance(val, (bytes, bytearray)) else str(val))
                    elif tag == "vendor_class_id" and val:
                        data["opt60"] = (
                            val.decode("utf-8", errors="ignore")
                            if isinstance(val, (bytes, bytearray)) else str(val))
                    elif tag == "param_req_list" and val:
                        data["opt55"] = list(val) if hasattr(val, "__iter__") else []
                    elif tag == "client_id" and val:
                        data["client_id"] = (
                            val.hex() if isinstance(val, (bytes, bytearray)) else str(val))
                return data

            # TCP SYN stack signature (p0f-style passive)
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                try:
                    syn = bool(int(tcp.flags) & 0x02)
                    ack = bool(int(tcp.flags) & 0x10)
                except Exception:
                    syn, ack = False, False

                if syn and not ack:
                    data["protocol"]    = "tcp_syn"
                    data["tcp_window"]  = int(getattr(tcp, "window", 0) or 0) or None
                    opts = getattr(tcp, "options", None) or []
                    # Options as stable string (order preserved)
                    opt_names: list[str] = []
                    mss_val: Optional[int] = None
                    for o in opts:
                        if not isinstance(o, tuple) or not o:
                            continue
                        name = str(o[0])
                        opt_names.append(name)
                        if name.lower() == "mss":
                            try:
                                mss_val = int(o[1])
                            except Exception:
                                pass
                    data["mss"] = mss_val
                    data["tcp_options"] = ",".join(opt_names)

                    # Best-effort TLS ClientHello parsing when SYN carries data (rare)
                    # or later packets are fed into analyze_packet().
                    try:
                        # Only attempt TLS parse for 443 traffic
                        if int(getattr(tcp, "dport", 0) or 0) == 443:
                            _extract_tls_signals(pkt, data)
                    except Exception:
                        pass
                    return data

                # TLS ClientHello in established flow (not SYN) — still extract signals
                try:
                    if int(getattr(tcp, "dport", 0) or 0) == 443:
                        _extract_tls_signals(pkt, data)
                        if data.get("tls_sni") or data.get("ja3"):
                            data["protocol"] = "tls"
                            return data
                except Exception:
                    pass

            if pkt.haslayer(UDP) and pkt[UDP].dport == 5353:
                data["protocol"] = "mdns"
                try:
                    from scapy.layers.dns import DNS
                    if pkt.haslayer(DNS):
                        dns = pkt[DNS]
                        svcs: List[str] = []
                        an = dns.an
                        while an and hasattr(an, "rrname"):
                            name = (an.rrname.decode("utf-8", errors="ignore")
                                    if isinstance(an.rrname, (bytes, bytearray))
                                    else str(an.rrname))
                            svcs.append(name.rstrip(".").lower())
                            an = an.payload if hasattr(an, "payload") else None
                        qd = dns.qd
                        while qd and hasattr(qd, "qname"):
                            name = (qd.qname.decode("utf-8", errors="ignore")
                                    if isinstance(qd.qname, (bytes, bytearray))
                                    else str(qd.qname))
                            svcs.append(name.rstrip(".").lower())
                            qd = qd.payload if hasattr(qd, "payload") else None
                        data["mdns_services"] = svcs
                except Exception:
                    pass
                return data

            try:
                from scapy.contrib.igmp import IGMP
                if pkt.haslayer(IGMP):
                    data.update(protocol="igmp", igmp_group=pkt[IGMP].gaddr)
                    return data
            except ImportError:
                pass

        except Exception as exc:
            _log.debug("ScapyAdapter error: %s", exc)
        return data


# ─────────────────────────────────────────────────────────────────────────────
# TLS helpers (best-effort, no hard dependency)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_tls_signals(pkt, data: dict) -> None:
    """
    Populate data['tls_sni'], data['ja3'], data['ja3_str'] when possible.
    Safe no-op if Scapy TLS layers aren't available.
    """
    try:
        from scapy.layers.tls.handshake import TLSClientHello  # type: ignore
        from scapy.layers.tls.extensions import (  # type: ignore
            TLS_Ext_ServerName, TLS_Ext_SupportedGroups, TLS_Ext_ECPointFormats
        )
    except Exception:
        return

    if not pkt.haslayer(TLSClientHello):
        return

    ch = pkt[TLSClientHello]

    # SNI
    try:
        for ext in getattr(ch, "ext", []) or []:
            if isinstance(ext, TLS_Ext_ServerName):
                sn_list = getattr(ext, "servernames", None) or []
                for sn in sn_list:
                    name = getattr(sn, "servername", None)
                    if isinstance(name, (bytes, bytearray)):
                        name = name.decode("utf-8", errors="ignore")
                    if name:
                        data["tls_sni"] = str(name)
                        raise StopIteration
    except StopIteration:
        pass
    except Exception:
        pass

    # JA3 (client hello fingerprint) — https://github.com/salesforce/ja3
    try:
        ver = int(getattr(ch, "version", 0) or 0)
        ciphers = [int(x) for x in (getattr(ch, "ciphers", []) or [])]
        exts: list[int] = []
        groups: list[int] = []
        ec_pf: list[int] = []

        for ext in getattr(ch, "ext", []) or []:
            et = getattr(ext, "type", None)
            if et is not None:
                try:
                    exts.append(int(et))
                except Exception:
                    pass
            if isinstance(ext, TLS_Ext_SupportedGroups):
                for g in getattr(ext, "groups", []) or []:
                    try:
                        groups.append(int(g))
                    except Exception:
                        pass
            if isinstance(ext, TLS_Ext_ECPointFormats):
                for pf in getattr(ext, "ecpl", []) or []:
                    try:
                        ec_pf.append(int(pf))
                    except Exception:
                        pass

        ja3_str = (
            f"{ver},"
            f"{'-'.join(str(x) for x in ciphers)},"
            f"{'-'.join(str(x) for x in exts)},"
            f"{'-'.join(str(x) for x in groups)},"
            f"{'-'.join(str(x) for x in ec_pf)}"
        )
        data["ja3_str"] = ja3_str
        data["ja3"] = hashlib.md5(ja3_str.encode("utf-8", errors="ignore")).hexdigest()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# FingerprintEngine
# ─────────────────────────────────────────────────────────────────────────────

class FingerprintEngine:
    """
    Core fingerprint engine — two complementary pipelines in one class:

    Pipeline A (Scapy / passive sniffing):
        analyze_packet(pkt) → FingerprintResult
        Runs protocol-specific Evidence analysers, then fuses via
        aggregate_evidence().

    Pipeline B (active lookup / per-packet delegation):
        process_dhcpv4(), process_mdns(), process_arp(), process_tcp_syn(),
        process_ssdp(), process_http_useragent() …
        Each delegates to SignatureMatcher and returns a list of
        FingerprintMatch objects ready for aggregation.

    Both pipelines apply os_intel enrichment automatically when available.
    """

    def __init__(self) -> None:
        self.lookup = SignatureMatcher()
        self._oui_seen: set[str] = set()

    def reload(self) -> None:
        """Re-initialise the lookup engine (call after updating OUI DB)."""
        self.lookup = SignatureMatcher()
        self._oui_seen.clear()

    # ── OUI deduplication ────────────────────────────────────────────────

    def _lookup_oui_once(self, mac: str) -> list[FingerprintMatch]:
        """OUI lookup — fires only on first observation per MAC."""
        if not mac or mac in self._oui_seen:
            return []
        self._oui_seen.add(mac)
        if len(self._oui_seen) > 50_000:
            self._oui_seen.clear()
        return self.lookup.match_mac(mac)

    # ── Pipeline A — Scapy packet analysis ───────────────────────────────

    def analyze_packet(self, pkt) -> FingerprintResult:
        """Analyse a raw Scapy packet → FingerprintResult."""
        return self.analyze_dict(ScapyAdapter.from_packet(pkt))

    def analyze_dict(self, data: dict) -> FingerprintResult:
        """Analyse a normalised field dict → FingerprintResult."""
        result = FingerprintResult(
            mac=data.get("src_mac") or "",
            ip=data.get("src_ip")  or "",
        )
        proto = data.get("protocol")
        extra_matches: list[FingerprintMatch] = []

        if proto == "dhcpv4":
            self._proc_dhcpv4(data, result)
        elif proto == "mdns":
            self._proc_mdns(data, result)
        elif proto == "igmp":
            self._proc_igmp(data, result)
        elif proto == "arp":
            self._proc_arp(data, result)

        self._proc_mac_oui(result)
        self._merge_evidence(result)

        # L3: TTL (weak evidence)
        ttl_val = data.get("ttl")
        if isinstance(ttl_val, int) and ttl_val > 0:
            try:
                ttl_m = self.lookup.match_ttl(ttl_val)
                if ttl_m:
                    extra_matches.append(ttl_m)
            except Exception:
                pass

        # L4: TCP SYN signature (window + options)
        if proto == "tcp_syn":
            try:
                win = data.get("tcp_window")
                opts = data.get("tcp_options") or ""
                mss = data.get("mss")
                if isinstance(win, int) and win > 0:
                    extra_matches.extend(self.process_tcp_syn(
                        src_mac=result.mac,
                        src_ip=result.ip,
                        ttl=int(ttl_val or 0) if ttl_val else 0,
                        window_size=win,
                        mss=int(mss) if isinstance(mss, int) else None,
                        tcp_options=str(opts),
                    ))
            except Exception:
                pass

        # L7: TLS passive observation
        sni = data.get("tls_sni")
        if sni:
            try:
                m = self.lookup.match_tls_sni(str(sni))
                if m:
                    extra_matches.append(m)
            except Exception:
                pass
        ja3_hash = data.get("ja3")
        if ja3_hash:
            try:
                m = self.lookup.match_ja3(str(ja3_hash), ja3_str=str(data.get("ja3_str") or ""))
                if m:
                    extra_matches.append(m)
            except Exception:
                pass

        # De-randomization: DHCP option 61 may leak real MAC even when L2 is randomised
        try:
            if proto == "dhcpv4" and detect_randomised_mac(result.mac):
                cid = data.get("client_id")
                extracted: Optional[str] = None
                try:
                    cid_s = str(cid or "").strip().lower()
                    if re.fullmatch(r"[0-9a-f]+", cid_s) and len(cid_s) in (14, 16) and cid_s.startswith("01"):
                        mac_hex = cid_s[2:14]
                        extracted = ":".join(mac_hex[i:i+2] for i in range(0, 12, 2)).upper()
                except Exception:
                    extracted = None
                candidate = extracted or cid
                if candidate and not detect_randomised_mac(str(candidate)) and str(candidate) != result.mac:
                    oui_hits = self.lookup.match_mac(str(candidate))
                    for h in oui_hits:
                        h.raw_data["via_option61"] = True
                        h.raw_data["option61_mac"] = str(candidate)
                    extra_matches.extend(oui_hits)
        except Exception:
            pass

        # Convert Evidence → FingerprintMatch and fuse
        matches = [ev.to_match() for ev in result.evidence] + extra_matches
        fused = aggregate_evidence(matches)
        result.device_type      = fused["device_type"]
        result.manufacturer     = fused["manufacturer"]
        result.os_family        = fused.get("os_family")  # type: ignore[assignment]
        result.os_version       = fused["os_version"]
        result.os_confirmed     = fused["os_confirmed"]
        result.fused_confidence = fused["confidence"]
        result.matches          = matches

        # Points-based score + gating for UI (avoid overconfident single-packet claims)
        try:
            scored = score_matches(matches, threshold=result.score_threshold)
            result.score_points    = int(scored["points"])
            result.verdict_ready   = bool(scored["verdict_ready"])
            result.score_breakdown = list(scored["breakdown"])
        except Exception:
            pass
        if not result.verdict_ready:
            # Per requirement: only show device_type once evidence is strong.
            result.device_type = "Unknown"

        if _OS_INTEL:
            self._enrich_os_intel(result, data)

        return result

    # ── Protocol analysers (your original Evidence-based pipeline) ────────

    def _proc_dhcpv4(self, data: dict, result: FingerprintResult) -> None:
        from .lookup import _OPT60_BUILT_IN

        opt60: Optional[str] = data.get("opt60")
        if opt60:
            for rx, mfr, dtype, os_fam, cert in _OPT60_BUILT_IN:
                if rx.search(opt60):
                    result.evidence.append(Evidence(
                        source="dhcp_opt60", method="pattern", certainty=cert,
                        vendor=mfr, category=dtype, os_family=os_fam,
                        raw={"opt60": opt60},
                    ))
                    break

        hostname: Optional[str] = data.get("hostname")
        if hostname and _is_valid_hostname(hostname):
            result.evidence.append(Evidence(
                source="dhcp_hostname", method="exact", certainty=0.75,
                hostname=hostname, raw={"hostname": hostname},
            ))
            hn_match = self.lookup.match_hostname(hostname)
            if hn_match:
                result.evidence.append(Evidence(
                    source="dhcp_hostname_pattern", method="pattern",
                    certainty=hn_match.confidence,
                    vendor=hn_match.manufacturer,
                    category=hn_match.device_type,
                    os_family=hn_match.os_family,
                    hostname=hostname,
                    raw={"hostname": hostname},
                ))

        opt55: List[int] = data.get("opt55") or []
        if opt55:
            match = _match_opt55(opt55)
            if match:
                vendor, category, os_fam, cert = match
                result.evidence.append(Evidence(
                    source="dhcp_opt55", method="pattern", certainty=cert,
                    vendor=vendor, category=category, os_family=os_fam,
                    raw={"opt55": opt55},
                ))

        client_id: Optional[str] = data.get("client_id")
        if client_id:
            result.evidence.append(Evidence(
                source="dhcp_client_id", method="exact", certainty=0.50,
                raw={"client_id": client_id},
            ))

    def _proc_mdns(self, data: dict, result: FingerprintResult) -> None:
        for svc in (data.get("mdns_services") or []):
            hits = self.lookup.match_mdns(svc)
            for h in hits:
                result.evidence.append(Evidence(
                    source=h.source, method=h.match_type,
                    certainty=h.confidence, vendor=h.manufacturer,
                    category=h.device_type, os_family=h.os_family,
                    model=h.model, raw=h.raw_data,
                ))

    def _proc_igmp(self, data: dict, result: FingerprintResult) -> None:
        group: Optional[str] = data.get("igmp_group")
        if not group:
            return
        for prefix, mfr, dtype, cert in _IGMP_PATTERNS:
            if str(group).startswith(prefix):
                result.evidence.append(Evidence(
                    source="igmp", method="heuristic", certainty=cert,
                    vendor=mfr, category=dtype, raw={"group": group},
                ))
                break

    def _proc_arp(self, data: dict, result: FingerprintResult) -> None:
        result.evidence.append(Evidence(
            source="arp", method="heuristic", certainty=0.30,
            raw={"ip": data.get("src_ip")},
        ))

    def _proc_mac_oui(self, result: FingerprintResult) -> None:
        mac = result.mac
        if not mac:
            return
        norm   = mac.replace("-", ":").upper()
        prefix = ":".join(norm.split(":")[:3])

        # Static hint table
        hint = _OUI_HINTS.get(prefix)
        if hint:
            vendor, category = hint
            result.evidence.append(Evidence(
                source="mac_oui", method="heuristic", certainty=0.30,
                vendor=vendor, category=category, raw={"oui": prefix},
            ))
            return

        # Full IEEE DB via SignatureMatcher
        oui_hits = self.lookup.match_mac(mac)
        for h in oui_hits:
            result.evidence.append(Evidence(
                source="mac_oui_db", method="heuristic", certainty=0.30,
                vendor=h.manufacturer, raw={"oui": prefix},
            ))

    def _merge_evidence(self, result: FingerprintResult) -> None:
        if not result.evidence:
            return
        for fname in ("vendor", "category", "os_family", "model", "hostname"):
            best = max(
                (e for e in result.evidence if getattr(e, fname, None)),
                key=lambda e: e.certainty, default=None,
            )
            if best:
                setattr(result, fname, getattr(best, fname))
        result.certainty = combine_scores(*(e.certainty for e in result.evidence))

    # ── os_intel enrichment ───────────────────────────────────────────────

    def _enrich_os_intel(self, result: FingerprintResult, data: dict) -> None:
        vendor   = result.manufacturer or result.vendor
        category = result.device_type or result.category or "general purpose"
        os_fam   = result.os_family

        if vendor:
            try:
                fw = guess_firmware(manufacturer=vendor,
                                     device_type=category, os_family=os_fam)
                result.firmware = fw
            except Exception:
                pass

        if os_fam:
            try:
                ok, note, score = assess_os_plausibility(
                    detected_os=os_fam, device_type=category, manufacturer=vendor)
                result.os_validated        = ok
                result.os_plausibility     = score
                result.os_plausibility_note = note
            except Exception:
                pass

        kver: Optional[str] = data.get("kernel_version")
        if kver and os_fam and "linux" in os_fam.lower():
            try:
                distros = distros_for_kernel(kver)
                result.inferred_os = format_inferred_os(distros, result.firmware)
            except Exception:
                pass
        elif result.firmware:
            try:
                result.inferred_os = format_inferred_os(None, result.firmware)
            except Exception:
                pass

        if not result.evidence and not result.matches:
            result.confidence_tier = ConfidenceTier.UNKNOWN.value if ConfidenceTier else "UNKNOWN"
        elif not result.os_validated:
            result.confidence_tier = ConfidenceTier.SUSPECT.value if ConfidenceTier else "SUSPECT"
        elif result.certainty >= 0.70 or result.fused_confidence >= 0.70:
            result.confidence_tier = ConfidenceTier.VALIDATED.value if ConfidenceTier else "VALIDATED"
        else:
            result.confidence_tier = ConfidenceTier.PLAUSIBLE.value if ConfidenceTier else "PLAUSIBLE"

    # ── Pipeline B — active per-packet delegation ─────────────────────────

    def process_arp(self, src_mac: str, src_ip: str) -> list[FingerprintMatch]:
        return self._lookup_oui_once(src_mac)

    def process_dhcpv4(
        self,
        client_mac: str,
        opt55: Optional[str]  = None,
        opt60: Optional[str]  = None,
        hostname: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> list[FingerprintMatch]:
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(client_mac))

        # If randomised MAC but Option 61 has a real MAC, use it for OUI
        if not matches and client_id and detect_randomised_mac(client_mac):
            extracted: Optional[str] = None
            try:
                cid = str(client_id).strip().lower()
                # Common BOOTP client_id encoding: 0x01 + 6-byte MAC
                # ScapyAdapter stores option 61 as hex string via val.hex()
                if re.fullmatch(r"[0-9a-f]+", cid) and len(cid) in (14, 16) and cid.startswith("01"):
                    mac_hex = cid[2:14]
                    extracted = ":".join(mac_hex[i:i+2] for i in range(0, 12, 2)).upper()
            except Exception:
                extracted = None

            candidate = extracted or client_id
            if not detect_randomised_mac(candidate) and candidate != client_mac:
                oui_hits = self._lookup_oui_once(candidate)
                for m in oui_hits:
                    m.raw_data["via_option61"]  = True
                    m.raw_data["option61_mac"]  = candidate
                matches.extend(oui_hits)

        matches.extend(self.lookup.match_dhcp(opt55=opt55, opt60=opt60,
                                               hostname=hostname))
        return matches

    def process_mdns(
        self,
        src_mac: str,
        src_ip: str,
        service_type: str,
        name: Optional[str]   = None,
        packet_data: Optional[dict] = None,
    ) -> list[FingerprintMatch]:
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        matches.extend(self.lookup.match_mdns(service_type, name, packet_data))
        return matches

    def process_ssdp(
        self,
        src_mac: str,
        src_ip: str,
        server: Optional[str] = None,
        st:     Optional[str] = None,
    ) -> list[FingerprintMatch]:
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        ssdp = self.lookup.match_ssdp(server=server, st=st)
        if ssdp:
            matches.append(ssdp)
        return matches

    def process_tcp_syn(
        self,
        src_mac: str,
        src_ip:  str,
        ttl:     int,
        window_size: int,
        mss:     Optional[int] = None,
        tcp_options: str       = "",
    ) -> list[FingerprintMatch]:
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        sig  = f"{ttl}:{window_size}:{mss or '*'}:{tcp_options}"
        tcp  = self.lookup.match_tcp(sig)
        if tcp:
            matches.append(tcp)
        ttl_m = self.lookup.match_ttl(ttl)
        if ttl_m:
            matches.append(ttl_m)
        return matches

    def process_http_useragent(
        self,
        src_mac: str,
        user_agent: str,
        host: Optional[str] = None,
    ) -> list[FingerprintMatch]:
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        ua = self.lookup.match_useragent(user_agent)
        if ua:
            matches.append(ua)
        return matches

    def process_banner(
        self,
        src_mac: str,
        protocol: str,
        banner: str,
    ) -> list[FingerprintMatch]:
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        b = self.lookup.match_banner(protocol, banner)
        if b:
            matches.append(b)
        return matches

    def process_ip_observed(
        self, src_mac: str, src_ip: str, ttl: int, ttl_os_hint: str = ""
    ) -> list[FingerprintMatch]:
        matches: list[FingerprintMatch] = []
        matches.extend(self._lookup_oui_once(src_mac))
        ttl_m = self.lookup.match_ttl(ttl)
        if ttl_m:
            matches.append(ttl_m)
        return matches


# ─────────────────────────────────────────────────────────────────────────────
# Sniffer callback helper  (your original)
# ─────────────────────────────────────────────────────────────────────────────

def make_callback(engine: FingerprintEngine, on_result):
    """
    Return a Scapy-compatible packet handler.

    Usage:
        handler = make_callback(engine, lambda r: print(r.as_dict()))
        sniff(filter="udp port 67 or udp port 68 or udp port 5353",
              prn=handler, store=False)
    """
    def _handler(pkt):
        try:
            result = engine.analyze_packet(pkt)
            if result.evidence or result.matches:
                on_result(result)
        except Exception as exc:
            _log.debug("fingerprint callback error: %s", exc)
    return _handler


__all__ = [
    "FingerprintEngine",
    "ScapyAdapter",
    "make_callback",
]
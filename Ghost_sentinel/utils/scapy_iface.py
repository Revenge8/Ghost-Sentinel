# utils/scapy_iface.py — Ghost Sentinel
from __future__ import annotations

import sys
import os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import logging
import subprocess
import re
from typing import Any

_log = logging.getLogger(__name__)
_IS_WINDOWS = sys.platform.startswith("win")


# ─────────────────────────────────────────────────────────────────────────────
# Get the real active adapters from ipconfig — the ground truth on Windows.
# This gives us the friendly name + IP together, so we can match them to
# Scapy's IFACES without guessing key names across Scapy versions.
# ─────────────────────────────────────────────────────────────────────────────

def _ipconfig_adapters() -> list[dict[str, Any]]:
    """
    Parse ipconfig /all and return only adapters that have a routable IPv4.
    Each entry: {friendly_name, ips, gateway, mac}
    """
    try:
        out = subprocess.run(
            ["ipconfig", "/all"], capture_output=True,
            text=True, timeout=5, encoding="utf-8", errors="ignore",
        ).stdout
    except Exception:
        return []

    adapters = []
    current: dict[str, Any] = {}

    for line in out.splitlines():
        # New adapter section
        m = re.match(r"^[A-Za-z].*adapter (.+?):", line)
        if m:
            if current.get("ips"):
                adapters.append(current)
            current = {"friendly_name": m.group(1).strip(), "ips": [],
                       "gateway": "", "mac": ""}
            continue

        if not current:
            continue

        # IPv4 address
        m = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", line)
        if m:
            ip = m.group(1).strip().rstrip("(Preferred)").strip()
            if not ip.startswith("169.254") and not ip.startswith("127."):
                current["ips"].append(ip)
            continue

        # Default gateway
        m = re.search(r"Default Gateway[^:]*:\s*([\d.]+)", line)
        if m:
            current["gateway"] = m.group(1).strip()
            continue

        # MAC / Physical address
        m = re.search(r"Physical Address[^:]*:\s*([0-9A-Fa-f\-]{17})", line)
        if m:
            current["mac"] = m.group(1).replace("-", ":").upper()

    if current.get("ips"):
        adapters.append(current)

    return adapters


def _scapy_ifaces_map() -> dict[str, str]:
    """
    Build a map: description.lower() -> GUID (Scapy internal name).
    Uses IFACES which always has real NPF GUIDs as keys on Windows.
    """
    result: dict[str, str] = {}
    try:
        from scapy.interfaces import IFACES
        for guid, obj in IFACES.items():
            desc = (
                getattr(obj, "description", None)
                or getattr(obj, "name", None)
                or ""
            )
            if desc:
                result[str(desc).lower()] = guid
    except Exception:
        pass
    return result


def _get_guid_for_adapter(friendly_name: str, desc_map: dict[str, str]) -> str:
    """
    Match an ipconfig friendly name to a Scapy GUID.

    Strategy:
    1. Exact match (case-insensitive)
    2. Friendly name is substring of IFACES description
    3. IFACES description is substring of friendly name
    4. Fall back to get_windows_if_list() if available
    """
    fn_lc = friendly_name.lower()

    # 1 — exact
    if fn_lc in desc_map:
        return desc_map[fn_lc]

    # 2 — friendly name contained in ifaces desc
    for desc_lc, guid in desc_map.items():
        if fn_lc in desc_lc:
            return guid

    # 3 — ifaces desc contained in friendly name
    for desc_lc, guid in desc_map.items():
        if desc_lc and desc_lc in fn_lc:
            return guid

    # 4 — get_windows_if_list() fallback
    try:
        from scapy.arch.windows import get_windows_if_list
        for entry in get_windows_if_list():
            desc = str(
                entry.get("description") or entry.get("friendlyname") or ""
            ).lower()
            name = str(entry.get("name") or entry.get("guid") or "")
            if fn_lc in desc or desc in fn_lc:
                if "NPF_" not in name and name:
                    name = r"\Device\NPF_" + (
                        name if name.startswith("{") else "{" + name + "}"
                    )
                return name
    except Exception:
        pass

    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def list_scapy_ifaces() -> list[dict[str, Any]]:
    """
    Return ONLY active adapters that have a routable IPv4 address.

    On Windows this uses ipconfig /all as the source of truth for which
    adapters are real and active, then looks up the NPF GUID from IFACES.
    This avoids showing the 100+ virtual Npcap adapters that IFACES alone
    contains.

    Each dict: name (GUID), description, ips, mac, index.
    """
    if not _IS_WINDOWS:
        return _list_posix()

    adapters  = _ipconfig_adapters()
    desc_map  = _scapy_ifaces_map()
    results   = []

    for adapter in adapters:
        fn   = adapter["friendly_name"]
        guid = _get_guid_for_adapter(fn, desc_map)

        if not guid:
            _log.warning("No GUID found for adapter %r — skipping", fn)
            continue

        results.append({
            "name":        guid,
            "description": fn,
            "ips":         adapter["ips"],
            "mac":         adapter["mac"],
            "index":       0,
        })
        _log.info("[iface] %-20s  %s  ips=%s", fn, guid, adapter["ips"])

    # Last resort: if we still got nothing, fall back to IFACES
    if not results:
        _log.warning("ipconfig parsing yielded nothing — falling back to IFACES")
        return _list_via_ifaces()

    return results


def _list_via_ifaces() -> list[dict[str, Any]]:
    try:
        from scapy.interfaces import IFACES
        from scapy.all import get_if_addr
    except ImportError:
        return []

    results = []
    for iface_name, iface_obj in IFACES.items():
        ips: list[str] = []
        try:
            ip = get_if_addr(iface_name)
            if ip and ip not in ("0.0.0.0", "127.0.0.1"):
                ips.append(ip)
        except Exception:
            pass

        if not ips:
            continue  # skip adapters with no routable IP

        desc = (
            getattr(iface_obj, "description", None)
            or getattr(iface_obj, "name", None)
            or iface_name
        )
        results.append({
            "name":        iface_name,
            "description": str(desc),
            "ips":         ips,
            "mac":         str(getattr(iface_obj, "mac", "") or ""),
            "index":       int(getattr(iface_obj, "index", 0) or 0),
        })
    return results


def _list_posix() -> list[dict[str, Any]]:
    from scapy.arch import get_if_list
    from scapy.interfaces import IFACES
    from scapy.all import get_if_addr

    results = []
    for iface_name in get_if_list():
        iface_obj = IFACES.get(iface_name)
        ips: list[str] = []
        try:
            ip = get_if_addr(iface_name)
            if ip and ip not in ("0.0.0.0", "127.0.0.1"):
                ips.append(ip)
        except Exception:
            pass

        desc = (
            getattr(iface_obj, "description", None)
            or getattr(iface_obj, "name", None)
            or iface_name
        ) if iface_obj else iface_name

        results.append({
            "name": iface_name, "description": str(desc),
            "ips": ips, "mac": str(getattr(iface_obj, "mac", "") or "") if iface_obj else "",
            "index": int(getattr(iface_obj, "index", 0) or 0) if iface_obj else 0,
        })
    return results


def resolve_iface(hint: str = "") -> str:
    try:
        from scapy.all import conf
        default = str(conf.iface)
    except Exception:
        default = ""

    if not hint:
        return default

    ifaces = list_scapy_ifaces()

    for it in ifaces:
        if it["name"] == hint:
            return hint

    hint_lc = hint.lower()

    for it in ifaces:
        if hint_lc in it["description"].lower():
            return it["name"]

    for it in ifaces:
        if hint in it["ips"]:
            return it["name"]

    _log.warning("resolve_iface: no match for %r", hint)
    return default


__all__ = ["list_scapy_ifaces", "resolve_iface"]
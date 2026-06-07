# utils/extract.py — MAC vendor lookup utility
from __future__ import annotations

import sys, os
import logging

_log = logging.getLogger(__name__)
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Supports both filename variants
_CANDIDATES = [
    os.path.join(_ROOT, "data", "mac-vendors"),        
    os.path.join(_ROOT, "data", "mac-vendors.txt"),
    os.path.join(_ROOT, "data", "oui_lookup.txt"),
]
_VENDORS_FILE = next((p for p in _CANDIDATES if os.path.exists(p)), None)

_oui_cache: dict[str, str] = {}
_loaded = False


def _load():
    global _loaded
    if _loaded:
        return
    if not _VENDORS_FILE:
        _log.warning("No vendor file found in data/")
        _loaded = True
        return
    try:
        with open(_VENDORS_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    # Normalize to XX:XX:XX format
                    raw = parts[0].upper()
                    if len(raw) == 6:  # AABBCC format (oui_lookup.txt)
                        key = f"{raw[0:2]}:{raw[2:4]}:{raw[4:6]}"
                    else:              # already XX:XX:XX format
                        key = raw
                    _oui_cache[key] = parts[1].strip()
        _loaded = True
        _log.info("Loaded %d OUI entries.", len(_oui_cache))
    except Exception as e:
        _log.error("Failed to load vendor file.")
        _log.debug("Vendor load error: %s", e)
        _loaded = True


def get_vendor(mac: str) -> str:
    """Return vendor name for a MAC address, or 'Unknown Vendor'."""
    _load()
    if not mac:
        return "Unknown Vendor"
    norm   = mac.replace("-", ":").upper()
    prefix = ":".join(norm.split(":")[:3])
    return _oui_cache.get(prefix, "Unknown Vendor")
import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import json
import logging
import threading
import tempfile

DB_FILE = os.path.join(_ROOT, "data", "devices.json")

# Keys that must never be persisted to device storage
_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "credential", "credentials", "auth", "authorization",
})

# Single lock protecting all file I/O — prevents concurrent write corruption
_lock = threading.RLock()

log = logging.getLogger(__name__)

# ── Internal helpers ───────────────────────────────────────────────────────


def _atomic_write(path: str, data: list):
    """
    Write data to path atomically using a temp file + rename.
    If the process crashes mid-write, the original file is untouched.
    """
    dir_name = os.path.dirname(path)
    os.makedirs(dir_name, exist_ok=True)

    # Write to a temp file in the same directory so rename is atomic
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_path, path)   # atomic on Linux, Windows, macOS
    except Exception:
        # Clean up the temp file if anything goes wrong
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _sanitize_device(dev: dict) -> dict:
    """Strip sensitive fields before persisting device records."""
    if not isinstance(dev, dict):
        return {}
    return {k: v for k, v in dev.items() if str(k).lower() not in _SENSITIVE_KEYS}


def _merge_device(existing: dict, new_data: dict) -> dict:
    """
    Requirement 3: merge new_data into existing, keeping the better value.

    Rules:
    - Keep existing value if new_data value is empty/None/Unknown.
    - Overwrite with new_data value if it is more informative.
    - Always merge 'signals' dicts if both have them (union).
    """
    _EMPTY = {None, "", "Unknown", "Hidden/Unknown", "Unknown Vendor"}

    merged = existing.copy()
    for key, new_val in new_data.items():
        if key == "signals" and isinstance(new_val, dict):
            # Union-merge signal dicts — never lose a signal
            existing_signals = merged.get("signals", {})
            merged["signals"] = {**existing_signals, **new_val}
            continue

        old_val = merged.get(key)
        new_is_empty = (new_val in _EMPTY) or (
            isinstance(new_val, str) and not new_val.strip())
        old_is_empty = (old_val in _EMPTY) or (
            isinstance(old_val, str) and not str(old_val).strip())

        if new_is_empty and not old_is_empty:
            # New data is worse — keep existing
            continue

        merged[key] = new_val

    return merged


# ── Public API ─────────────────────────────────────────────────────────────

def save_devices(devices_list: list):
    """
    Serialize the full device list to JSON atomically.
    Thread-safe — safe to call from multiple threads.
    """
    if not isinstance(devices_list, list):
        log.error("save_devices: expected a list, got %s", type(devices_list))
        return

    try:
        sanitized = [_sanitize_device(d) for d in devices_list if isinstance(d, dict)]
        with _lock:
            _atomic_write(DB_FILE, sanitized)
    except Exception as e:
        log.error("Failed to save devices: %s", e)


def load_devices() -> list:
    """
    Load device history from JSON storage.
    Returns an empty list if the file is missing or corrupted.
    Thread-safe.
    """
    with _lock:
        if not os.path.exists(DB_FILE):
            return []
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                log.warning("Device DB is not a list — resetting.")
                return []
            return data
        except Exception as e:
            log.error("Error loading device database: %s", e)
            return []


def update_device_info(mac: str, new_data: dict):
    """
    Requirement 3: look up device by MAC and merge new evidence.
    - If MAC exists: merge using _merge_device (keeps better values).
    - If MAC is new: append as a fresh entry.
    Thread-safe — loads, merges, and saves under a single lock acquisition
    so no other thread can interleave a write between the load and save.
    """
    if not mac or not isinstance(mac, str):
        log.warning("update_device_info: invalid MAC '%s' — skipping.", mac)
        return
    if not isinstance(new_data, dict):
        log.warning("update_device_info: new_data must be a dict — skipping.")
        return

    try:
        with _lock:
            # Load, merge, save — all under one lock so it's atomic
            if not os.path.exists(DB_FILE):
                devices = []
            else:
                try:
                    with open(DB_FILE, "r", encoding="utf-8") as f:
                        devices = json.load(f)
                    if not isinstance(devices, list):
                        devices = []
                except Exception:
                    devices = []

            found = False
            for i, dev in enumerate(devices):
                if dev.get("mac") == mac:
                    devices[i] = _sanitize_device(_merge_device(dev, new_data))
                    found = True
                    break

            if not found:
                devices.append(_sanitize_device({"mac": mac, **new_data}))

            _atomic_write(DB_FILE, devices)

    except Exception as e:
        log.error("update_device_info failed for MAC %s: %s", mac, e)


def get_device(mac: str) -> dict | None:
    """
    Requirement 2: retrieve a single device by MAC for the UI to
    distinguish 'Known Device' vs 'New Anomaly'.
    Returns None if not found.
    """
    if not mac:
        return None
    devices = load_devices()
    for dev in devices:
        if dev.get("mac") == mac:
            return dev
    return None


def is_known_device(mac: str) -> bool:
    """
    Requirement 2: returns True if this MAC has been seen before.
    Used by the UI to flag new anomalies vs known devices.
    """
    return get_device(mac) is not None


class Storage:
    """Thin class wrapper so main.py can do: from core.core_storage import Storage"""

    def __init__(self):
        pass

    def save_devices(self, devices: list) -> None:
        save_devices(devices)

    def load_devices(self) -> list:
        return load_devices()                 # calls the module-level function

    def get_device(self, mac: str) -> dict | None:
        return get_device(mac)

    def is_known_device(self, mac: str) -> bool:
        return is_known_device(mac)
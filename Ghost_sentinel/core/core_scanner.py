# core/core_scanner.py — Ghost Sentinel Discovery Engine
from __future__ import annotations

import sys
import os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import socket
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError
import time
import logging

from scapy.all import ARP, Ether, IP, ICMP, srp, srp1, conf
conf.verb = 0

_log = logging.getLogger(__name__)
from utils.scapy_iface import resolve_iface

_active_iface: str = ""

_VENDORS_FILE = next((
    p for p in [
        os.path.join(_ROOT, "data", "mac-vendors.txt"),
        os.path.join(_ROOT, "data", "mac-vendors"),
        os.path.join(_ROOT, "data", "oui.txt"),
        os.path.join(_ROOT, "data", "oui_lookup.txt"),
    ] if os.path.exists(p)
), None)

_oui_cache:  dict[str, str] = {}
_oui_loaded: bool            = False
_oui_lock:   threading.Lock  = threading.Lock()


# ═════════════════════════════════════════════════════════════════════════════
# 1. MAC VENDOR RESOLUTION
# ═════════════════════════════════════════════════════════════════════════════

def _load_oui_db() -> None:
    global _oui_loaded
    with _oui_lock:
        if _oui_loaded:
            return
        if not _VENDORS_FILE:
            print("[scanner] WARNING: no vendor file found in data/")
            _oui_loaded = True
            return
        try:
            loaded = 0
            with open(_VENDORS_FILE, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if "(hex)" not in line or "(base 16)" in line:
                        continue
                    left, right = line.split("(hex)", 1)
                    key    = left.strip().upper().replace("-", "").replace(":", "")
                    vendor = right.strip()
                    if len(key) != 6 or not vendor:
                        continue
                    _oui_cache[key] = vendor
                    loaded += 1
            _oui_loaded = True
            print(f"[scanner] OUI database loaded — {loaded:,} entries")
        except Exception as exc:
            print(f"[scanner] ERROR loading OUI database: {exc}")
            _oui_loaded = True


def get_vendor(mac: str) -> str:
    _load_oui_db()
    if not mac:
        return "Generic / Not in DB"
    try:
        key = mac.upper().replace(":", "").replace("-", "")[:6]
        if len(key) < 6:
            return "Generic / Not in DB"
        if int(key[:2], 16) & 0x02:
            return "Randomized MAC (Mobile)"
        return _oui_cache.get(key, "Generic / Not in DB")
    except Exception:
        return "Generic / Not in DB"


# ═════════════════════════════════════════════════════════════════════════════
# 2. MAC RESOLUTION
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_mac(ip: str, iface: str, timeout: float = 1.0) -> str:
    try:
        ans = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface, timeout=timeout, verbose=0,
        )
        if ans and ans.haslayer(ARP):
            return ans[ARP].hwsrc
    except Exception:
        pass
    return ""


# ═════════════════════════════════════════════════════════════════════════════
# 3. HOSTNAME DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_dns(ip: str, timeout: float = 0.8) -> str:
    result: list[str] = []
    def _work():
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            result.append(name)
        except Exception:
            pass
    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout=timeout)
    return result[0] if result else ""


def _resolve_nbns(ip: str, timeout: float = 1.0) -> str:
    nbns_query = (
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    )
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(nbns_query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        if len(data) < 57:
            return ""
        num_names = data[56]
        offset = 57
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            name  = data[offset:offset+15].decode("ascii", errors="ignore").strip()
            flags = data[offset+16]
            if flags == 0x04 and name:
                return name
            offset += 18
    except Exception:
        pass
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
    return ""


def get_hostname(ip: str) -> str:
    return _resolve_dns(ip) or _resolve_nbns(ip) or "Unknown"


# ═════════════════════════════════════════════════════════════════════════════
# 4. OS FINGERPRINTING
# ═════════════════════════════════════════════════════════════════════════════

def _os_from_ttl(ttl: int) -> str:
    if ttl <= 64:   return f"Linux / Android  (TTL {ttl})"
    if ttl <= 128:  return f"Windows  (TTL {ttl})"
    if ttl <= 255:  return f"Network Device / Cisco  (TTL {ttl})"
    return f"Unknown  (TTL {ttl})"


_HEURISTICS: list[tuple[list[str], str, int]] = [
    (["iphone", "ipad"],                                        "iOS",                  90),
    (["macbook", "imac"],                                       "macOS",                88),
    (["apple"],                                                 "Apple Device",         75),
    (["android", "samsung", "pixel", "oneplus", "xiaomi"],     "Android",              85),
    (["windows", "msft", "microsoft"],                         "Windows",              80),
    (["linux", "ubuntu", "debian", "fedora", "centos"],        "Linux",                80),
    (["router", "cisco", "netgear", "asus", "dlink",
      "tp-link", "tplink", "mikrotik", "ubiquiti"],            "Network Device",       80),
    (["printer", "hp", "canon", "epson", "brother", "lexmark"],"Printer",              75),
    (["raspberry", "raspberrypi"],                              "Linux (Raspberry Pi)", 85),
    (["synology", "qnap", "nas"],                              "NAS",                  80),
    (["smart-tv", "smarttv", "roku", "firetv", "appletv",
      "chromecast", "shield"],                                  "Smart TV / Streamer",  80),
    (["ring", "nest", "wyze", "arlo", "eufy", "blink"],        "Security Camera / IoT",75),
    (["amazon", "alexa", "echo"],                               "Amazon Device",        78),
    (["google", "home"],                                        "Google Device",        75),
]

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _heuristic_os(vendor: str, hostname: str) -> tuple[str, int]:
    corpus = (vendor + " " + hostname).lower()
    for keywords, label, confidence in _HEURISTICS:
        if any(kw in corpus for kw in keywords):
            return label, confidence
    return "", 0


def probe_os(ip: str, mac: str = "", vendor: str = "",
             hostname: str = "", iface: str = "") -> tuple[str, int]:
    label, conf_val = _heuristic_os(vendor, hostname)
    if conf_val >= 80:
        return label, conf_val
    try:
        eth_dst = mac if mac else "ff:ff:ff:ff:ff:ff"
        ans = srp1(
            Ether(dst=eth_dst) / IP(dst=ip) / ICMP(),
            iface=iface or str(conf.iface), timeout=0.8, verbose=0,
        )
        if ans and ans.haslayer(IP):
            ttl_label = _os_from_ttl(ans[IP].ttl)
            return (label, max(conf_val, 60)) if label else (ttl_label, 60)
    except Exception:
        pass
    return (label, conf_val) if label else ("Unknown", 0)


# ═════════════════════════════════════════════════════════════════════════════
# 5. RANGE VALIDATION
# ═════════════════════════════════════════════════════════════════════════════

_MAX_ARP_HOSTS = 4096


def _validate_range(network_str: str) -> tuple[bool, str]:
    try:
        net = ipaddress.ip_network(network_str, strict=False)
    except ValueError as exc:
        return False, f"Invalid CIDR: {exc}"
    if net.version != 4:
        return False, "Only IPv4 is supported."
    if any(net.network_address in p for p in _PRIVATE_NETS):
        if int(net.num_addresses) > _MAX_ARP_HOSTS:
            return False, f"Range too large — use a CIDR with ≤ {_MAX_ARP_HOSTS} hosts."
        return True, ""
    return False, "Only private network ranges are permitted."


# ═════════════════════════════════════════════════════════════════════════════
# 6. PER-DEVICE ENRICHMENT
# ═════════════════════════════════════════════════════════════════════════════

def _enrich(ip: str, mac: str, iface: str) -> dict:
    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        resolved = _resolve_mac(ip, iface)
        if resolved:
            mac = resolved
        else:
            return {
                "ip": ip, "mac": "Unknown", "vendor": "Generic / Not in DB",
                "hostname": "Unknown", "os": "Unknown",
                "os_confidence": 0, "status": "Online",
            }
    try:
        vendor = get_vendor(mac)
    except Exception:
        vendor = "Generic / Not in DB"
    try:
        hostname = get_hostname(ip)
    except Exception:
        hostname = "Unknown"
    try:
        os_label, os_conf = probe_os(ip, mac=mac, vendor=vendor,
                                     hostname=hostname, iface=iface)
    except Exception:
        os_label, os_conf = "Unknown", 0
    return {
        "ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
        "os": os_label, "os_confidence": os_conf, "status": "Online",
    }


# ═════════════════════════════════════════════════════════════════════════════
# 7. ARP SWEEP
#
# Windows + Npcap: srp() in list mode (pdst=list) silently sends nothing.
# Fix: use srp1() per IP, parallelised with ThreadPoolExecutor so a /24
# still completes in ~10-15s instead of 254 * timeout seconds serially.
# Progress is reported on every single host so the bar always moves.
# ═════════════════════════════════════════════════════════════════════════════

def _arp_one(ip: str, iface: str, timeout: float) -> tuple[str, str] | None:
    """Probe a single IP with ARP. Returns (ip, mac) or None."""
    try:
        ans = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface, timeout=timeout, verbose=0,
        )
        if ans and ans.haslayer(ARP):
            return (ip, ans[ARP].hwsrc)
    except Exception:
        pass
    return None


def _arp_sweep(
    targets: list[str],
    iface: str,
    timeout: float,
    progress_cb,
    workers: int = 50,
    stop_event=None,
) -> list[tuple[str, str]]:
    """
    Parallel ARP sweep using srp1() per IP.

    50 workers on a /24 = ~5 concurrent probes per second at timeout=0.5s.
    Progress is reported atomically so the TUI bar moves smoothly.
    """
    results:  list[tuple[str, str]] = []
    total   = len(targets)
    done_count = 0
    lock    = threading.Lock()

    # Report real total immediately so TUI shows X/254 not X/1
    if callable(progress_cb):
        try:
            progress_cb(0, total, "arp_sweep")
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=workers,
                            thread_name_prefix="gs-arp") as pool:
        futures = {pool.submit(_arp_one, ip, iface, timeout): ip
                   for ip in targets}

        for future in as_completed(futures):
            if stop_event is not None and stop_event.is_set():
                for f in futures:
                    f.cancel()
                break

            result = None
            try:
                result = future.result(timeout=timeout + 0.5)
            except Exception:
                pass

            with lock:
                done_count += 1
                current_done = done_count
                if result:
                    results.append(result)
                    _log.info("ARP reply: %s → %s", result[0], result[1])

            if callable(progress_cb):
                try:
                    progress_cb(current_done, total, "arp_sweep")
                except Exception:
                    pass

    return results


# ═════════════════════════════════════════════════════════════════════════════
# 8. PUBLIC SCAN ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def scan_network_logic(
    network_range: str,
    interface:     str   = "",
    timeout:       float = 0.5,
    max_workers:   int   = 30,
    progress_cb           = None,
    batch_size:    int   = 96,    # kept for API compat
    batch_sleep:   float = 0.03,  # kept for API compat
    stop_event            = None,
) -> tuple[list[dict], str | None]:
    global _active_iface

    ok, err = _validate_range(network_range)
    if not ok:
        return [], err

    # Honour the GUID pinned by the TUI — never overwrite it
    if interface.strip():
        resolved_iface = interface.strip()
    elif str(conf.iface):
        resolved_iface = str(conf.iface)
    else:
        resolved_iface = resolve_iface("")

    _active_iface = resolved_iface
    conf.iface    = resolved_iface
    _log.info("Scan using interface: %s", resolved_iface)

    try:
        net     = ipaddress.ip_network(network_range, strict=False)
        targets = [str(ip) for ip in net.hosts()]
        if not targets:
            return [], None
    except Exception as exc:
        return [], f"Range parse error: {exc}"

    try:
        raw = _arp_sweep(
            targets, resolved_iface, timeout, progress_cb,
            workers=50, stop_event=stop_event,
        )
    except PermissionError:
        return [], "Permission denied — run Ghost Sentinel as Administrator."
    except Exception as exc:
        return [], f"ARP sweep error: {exc}"

    if not raw:
        _log.info("ARP sweep complete — no hosts replied.")
        return [], None

    _log.info("ARP found %d host(s) — enriching…", len(raw))

    devices: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(raw)),
                            thread_name_prefix="gs-enrich") as pool:
        futures = {
            pool.submit(_enrich, ip, mac, resolved_iface): (ip, mac)
            for ip, mac in raw
        }
        try:
            for future in as_completed(futures, timeout=25):
                if stop_event is not None and stop_event.is_set():
                    break
                ip, mac = futures[future]
                try:
                    devices.append(future.result(timeout=1))
                except Exception:
                    devices.append({
                        "ip": ip, "mac": mac, "vendor": get_vendor(mac),
                        "hostname": "Unknown", "os": "Unknown",
                        "os_confidence": 0, "status": "Online",
                    })
        except FuturesTimeoutError:
            for future, (ip, mac) in futures.items():
                if future.done():
                    continue
                future.cancel()
                devices.append({
                    "ip": ip, "mac": mac, "vendor": get_vendor(mac),
                    "hostname": "Unknown", "os": "Unknown",
                    "os_confidence": 0, "status": "Online",
                })

    devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".") if x.isdigit()])
    return devices, None
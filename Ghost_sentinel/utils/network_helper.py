"""
Ghost Sentinel Network Environment Helper — Windows, zero extra dependencies.
Uses only stdlib: socket, subprocess, re, ipaddress.

FIX: get_interface() now returns ONLY the short adapter name after the
     "adapter " prefix (e.g. "Ethernet", "Wi-Fi") so resolve_iface() can
     match it cleanly against get_windows_if_list() description fields.
"""
import re
import socket
import subprocess
import ipaddress


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str]) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=5, encoding="utf-8", errors="ignore",
        )
        return result.stdout
    except Exception:
        return ""


def _ipconfig() -> str:
    return _run(["ipconfig", "/all"])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_my_ip() -> str:
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        try:
            if s is not None:
                s.close()
        except Exception:
            pass


def get_gateway() -> str:
    out = _run(["route", "print", "-4"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            ip = parts[2]
            try:
                socket.inet_aton(ip)
                return ip
            except OSError:
                continue

    out = _ipconfig()
    match = re.search(
        r"Default Gateway[^:]*:\s*([\d]{1,3}(?:\.[\d]{1,3}){3})", out)
    return match.group(1) if match else "Unknown"


def get_interface() -> str:
    """
    Return the SHORT adapter name (e.g. "Ethernet", "Wi-Fi") by finding
    which adapter section in ipconfig /all contains the local IP.

    FIX: previously returned the full "Ethernet adapter Ethernet" heading,
    which confused resolve_iface(). Now strips everything up to and
    including "adapter " so only the short name remains.

    This short name matches the 'description' field returned by
    get_windows_if_list(), enabling an exact GUID lookup.
    """
    my_ip = get_my_ip()
    if my_ip == "127.0.0.1":
        return ""

    out = _ipconfig()
    current_adapter = ""

    for line in out.splitlines():
        # Match headings like:
        #   "Ethernet adapter Ethernet:"
        #   "Wireless LAN adapter Wi-Fi:"
        #   "Ethernet adapter vEthernet (WSL):"
        adapter_match = re.match(r"^\S.*adapter (.+?):", line)
        if adapter_match:
            current_adapter = adapter_match.group(1).strip()

        if my_ip in line and current_adapter:
            return current_adapter

    return ""


def get_subnet_mask() -> str:
    my_ip = get_my_ip()
    out   = _ipconfig()
    lines = out.splitlines()

    for i, line in enumerate(lines):
        if my_ip in line:
            for j in range(i + 1, min(i + 4, len(lines))):
                mask_match = re.search(
                    r"Subnet Mask[^:]*:\s*([\d]{1,3}(?:\.[\d]{1,3}){3})",
                    lines[j],
                )
                if mask_match:
                    return mask_match.group(1)
    return ""


def get_network_range() -> str | None:
    my_ip = get_my_ip()
    if my_ip == "127.0.0.1":
        return None

    mask = get_subnet_mask()
    if mask:
        try:
            network = ipaddress.IPv4Network(f"{my_ip}/{mask}", strict=False)
            return str(network)
        except ValueError:
            pass

    prefix = ".".join(my_ip.split(".")[:3])
    return f"{prefix}.0/24"


def get_network_info() -> dict:
    return {
        "ip":        get_my_ip(),
        "gateway":   get_gateway(),
        "interface": get_interface(),   # now returns "Ethernet", not "Ethernet adapter Ethernet"
        "range":     get_network_range(),
    }


# ---------------------------------------------------------------------------
# CLI self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    info = get_network_info()
    print("--- Ghost Sentinel Network Report ---")
    print(f"Your IP    :  {info['ip']}")
    print(f"Gateway    :  {info['gateway']}")
    print(f"Interface  :  {info['interface']}")
    print(f"Scan Range :  {info['range']}")
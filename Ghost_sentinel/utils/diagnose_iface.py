"""
diagnose_iface.py — Ghost Sentinel Windows Interface Diagnostic
===============================================================
Run this FIRST as Administrator to see exactly what Scapy finds.
It prints every key from every API so we know which one has the GUID.

Usage:
    python diagnose_iface.py
"""
import sys
import os

print("=" * 70)
print("Ghost Sentinel — Windows Interface Diagnostic")
print("=" * 70)

# ── 1. Python + Scapy versions ────────────────────────────────────────────────
print(f"\n[1] Python  : {sys.version}")
try:
    import scapy
    print(f"    Scapy   : {scapy.__version__}")
except Exception as e:
    print(f"    Scapy   : IMPORT FAILED — {e}")
    sys.exit(1)

# ── 2. conf.iface (Scapy's auto-detected default) ────────────────────────────
print("\n[2] scapy conf.iface (auto-detected default):")
try:
    from scapy.all import conf
    print(f"    → {conf.iface!r}")
    print(f"    type: {type(conf.iface)}")
    # Try to get more attributes
    for attr in ("name", "description", "mac", "index", "guid"):
        val = getattr(conf.iface, attr, "—")
        print(f"    .{attr} = {val!r}")
except Exception as e:
    print(f"    ERROR: {e}")

# ── 3. get_windows_if_list() — raw dump of ALL keys ──────────────────────────
print("\n[3] get_windows_if_list() — ALL entries, ALL keys:")
try:
    from scapy.arch.windows import get_windows_if_list
    entries = get_windows_if_list()
    print(f"    Found {len(entries)} entries\n")
    for i, entry in enumerate(entries):
        print(f"    ── Entry {i} ──────────────────────────────────")
        for k, v in entry.items():
            print(f"       {k!r:20s} = {v!r}")
        print()
except ImportError:
    print("    NOT AVAILABLE on this Scapy version")
except Exception as e:
    print(f"    ERROR: {e}")

# ── 4. IFACES — Scapy's internal interface registry ──────────────────────────
print("\n[4] scapy.interfaces.IFACES — internal registry:")
try:
    from scapy.interfaces import IFACES
    print(f"    Found {len(IFACES)} entries\n")
    for name, obj in list(IFACES.items()):
        print(f"    key = {name!r}")
        for attr in ("name", "description", "mac", "index", "guid", "ip"):
            val = getattr(obj, attr, "—")
            print(f"         .{attr:12s} = {val!r}")
        # Also try get_if_addr
        try:
            from scapy.all import get_if_addr
            ip = get_if_addr(name)
            print(f"         get_if_addr  = {ip!r}")
        except Exception:
            pass
        print()
except Exception as e:
    print(f"    ERROR: {e}")

# ── 5. get_if_list() — legacy list ───────────────────────────────────────────
print("\n[5] scapy.arch.get_if_list():")
try:
    from scapy.arch import get_if_list
    lst = get_if_list()
    print(f"    {lst}")
except Exception as e:
    print(f"    ERROR: {e}")

# ── 6. network_helper output ──────────────────────────────────────────────────
print("\n[6] network_helper.get_network_info():")
try:
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _root not in sys.path:
        sys.path.insert(0, _root)
    from utils.network_helper import get_network_info
    info = get_network_info()
    for k, v in info.items():
        print(f"    {k:12s} = {v!r}")
except Exception as e:
    print(f"    ERROR: {e}")

# ── 7. scapy_iface.list_scapy_ifaces() ───────────────────────────────────────
print("\n[7] scapy_iface.list_scapy_ifaces():")
try:
    from utils.scapy_iface import list_scapy_ifaces
    ifaces = list_scapy_ifaces()
    print(f"    Found {len(ifaces)} entries\n")
    for it in ifaces:
        print(f"    name        = {it['name']!r}")
        print(f"    description = {it['description']!r}")
        print(f"    ips         = {it['ips']!r}")
        print(f"    mac         = {it['mac']!r}")
        print()
except Exception as e:
    print(f"    ERROR: {e}")

# ── 8. Quick ARP test on conf.iface ──────────────────────────────────────────
print("\n[8] Quick ARP test (sends 1 packet to gateway):")
try:
    from scapy.all import conf, ARP, Ether, srp
    import socket, subprocess, re

    # Get gateway
    out = subprocess.run(["route", "print", "-4"], capture_output=True,
                         text=True, timeout=5).stdout
    gw = ""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gw = parts[2]
            break

    if not gw:
        print("    Could not detect gateway — skipping ARP test")
    else:
        print(f"    Gateway : {gw}")
        print(f"    iface   : {conf.iface!r}")
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw),
            iface=conf.iface,
            timeout=2,
            verbose=0,
        )
        if ans:
            mac = ans[0][1][ARP].hwsrc
            print(f"    ✔  ARP reply received! Gateway MAC = {mac}")
            print(f"    ✔  The interface is working correctly.")
        else:
            print(f"    ✘  No ARP reply — interface is WRONG or not admin.")
            print(f"       Make sure you ran this as Administrator.")
except Exception as e:
    print(f"    ERROR: {e}")

print("\n" + "=" * 70)
print("Paste the full output above into the chat.")
print("=" * 70)
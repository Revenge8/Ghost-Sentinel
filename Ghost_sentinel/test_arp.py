"""
test_arp.py — tests ARP on ALL interfaces and prints which one works.
Run as Administrator: python test_arp.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import ARP, Ether, srp1, conf
conf.verb = 0

import subprocess, re, socket

# ── Get gateway ───────────────────────────────────────────────────────────────
def get_gw():
    out = subprocess.run(["route","print","-4"], capture_output=True,
                         text=True, timeout=5).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 3 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0":
            try: socket.inet_aton(p[2]); return p[2]
            except: continue
    return ""

gw = get_gw()
print(f"Gateway: {gw}\n")

# ── Test every IFACES entry ───────────────────────────────────────────────────
from scapy.interfaces import IFACES

for guid, obj in IFACES.items():
    desc = getattr(obj, "description", None) or getattr(obj, "name", None) or guid
    try:
        ans = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw),
            iface=guid, timeout=1, verbose=0,
        )
        if ans and ans.haslayer(ARP):
            mac = ans[ARP].hwsrc
            print(f"✔  WORKS  desc={desc}")
            print(f"          guid={guid}")
            print(f"          gw_mac={mac}\n")
        else:
            print(f"✘  no reply  desc={desc}")
            print(f"             guid={guid}\n")
    except Exception as e:
        print(f"✘  error={e}")
        print(f"   desc={desc}")
        print(f"   guid={guid}\n")

print("Paste output here — look for the ✔ WORKS line.")
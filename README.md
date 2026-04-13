# Ghost Sentinel

Passive network monitor for ARP anomaly detection, rogue gateway identification, and traffic interception on local networks.

---

## Features

- ARP sweep with real-time device tracking (IP, MAC, hostname, vendor, uptime)
- OS fingerprinting via ICMP TTL probing and passive DHCP Option 55 analysis
- Rogue gateway detection: MAC conflict tracking, gratuitous ARP monitoring, TTL−1 forwarding analysis
- Bidirectional ARP spoofing with automatic ARP table restoration on exit
- OUI vendor resolution with in-session cache
- Session persistence via local JSON; CSV export
- Auto-elevates to root/Administrator on startup

---

## Architecture & Logic

**ARP Engine**
Runs continuous `arping` sweeps on a configurable CIDR range. New devices are registered immediately; OS probing is dispatched to a short-lived thread to avoid blocking the sweep loop.

**OS Detection (layered)**
1. Hostname keyword matching (Samsung, Xiaomi, etc.)
2. OUI vendor hint — skipped for locally-administered (randomized) MACs
3. ICMP TTL probe: TTL ≤ 64 → Linux/Android, ≤ 128 → Windows, > 128 → network device
4. DHCP fingerprint (Option 55) overrides lower-confidence results when confidence ≥ 70

**DHCP Fingerprinting**
Passively sniffs UDP 67/68. Extracts the parameter-request-list and matches against a signature table covering iOS, macOS, Android, Windows XP–11, and Linux. Unmatched requests fall through to Jaccard-similarity scoring against the full table.

**Bridge / Rogue Gateway Detection**
- Gateway MAC is learned from the first ARP reply for the default-route IP (`.1` heuristic used as fallback)
- Any device claiming the gateway IP with a different MAC is flagged immediately
- Non-gateway ARP conflicts: sender MAC vs. known MAC for that IP
- TTL−1 forwarding: if an observed packet's TTL is exactly one below the OS baseline for that MAC, an intermediate forwarder is suspected
- All tracking is MAC-based to survive DHCP churn
- Confidence: High (ARP hits ≥ 3 or forwarded clients ≥ 3), Medium (TTL drops ≥ 3 or ARP hit ≥ 1), Low (single observation)

**ARP Spoofing & Restoration**
Bidirectional: forged replies sent to both target and gateway at 1.5 s intervals. On stop or window close, corrective ARP is sent to the target, the gateway, and all other tracked devices. Restoration runs on the main thread at exit to guarantee no device is left blocked.

**Threading Model**
Four daemon threads per session: ARP sweep, uptime ticker, DHCP sniffer, bridge/TTL sniffer. All share a single `threading.Event` stop signal. Interface change mid-session triggers a clean stop/restart cycle.

---

## Installation

Requires Python 3.8+. Npcap required on Windows.

```bash
git clone https://github.com/Revenge8/Ghost-Sentinel.git
cd Ghost-Sentinel
```

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

```bash
pip install -r requirements.txt
# Core: scapy, customtkinter, requests
```

```bash
# Linux / macOS
sudo python Ghost_sentinel.py

# Windows — elevated terminal or accept UAC prompt on launch
python Ghost_sentinel.py
```

---

## Development Status

Early development. Network logic is stable; the interface is functional but not a current priority.

Known gaps:
- False positives from legitimate multi-homed devices in the bridge detector
- DHCP signature table coverage is incomplete
- Codebase pending a full Bandit audit pass

Delete `ghost_sentinel_data.json` before running if upgrading from a pre-release build.


## Screenshots
![Main Dashboard](Ghost_sentinel.png)
![Scanning Process](Ghost_sentinel2.png)
![Alerts](Ghost_sentinel3.png)


---

## Legal

For use only on networks you own or have explicit written authorization to test. Unauthorized traffic interception may violate applicable law.

---

## License

MIT License — Copyright (c) 2025 Revenge8

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Ghost Sentinel

**Network Intelligence and LAN Security Platform**

Ghost Sentinel is a Python-based network discovery, monitoring, and defensive analysis tool for local area networks. It combines active ARP reconnaissance, passive packet sniffing, device fingerprinting, persistent host inventory, and optional ARP-based traffic control into a single desktop application built with Tkinter.

The project is designed for authorized network operators, security researchers, and lab environments where raw socket access and ARP visibility are required to understand what is connected to a subnet.

---

## Table of Contents

1. [Project Overview and Logic](#project-overview-and-logic)

2. [Architecture and Directory Structure](#architecture-and-directory-structure)

3. [Detailed Component and Function Breakdown](#detailed-component-and-function-breakdown)

4. [Network Interface Configuration (Critical)](#network-interface-configuration-critical)

5. [Installation and How to Run](#installation-and-how-to-run)

6. [Legal and Ethical Notice](#legal-and-ethical-notice)

---

## Project Overview and Logic

Ghost Sentinel answers a practical question: **who is on my network right now, what are they, and are they behaving normally?**

At runtime, the application follows a layered pipeline:



┌─────────────────────────────────────────────────────────────────────┐ │ main.py (Tkinter GUI) │ │ Interface selection │ Live scan │ Sniffer │ Attack │ History │ └────────────┬──────────────────┬──────────────────┬──────────────────┘ │ │ │ v v v ┌─────────────────┐ ┌───────────────┐ ┌──────────────────┐ │ core_scanner.py │ │core_sniffer.py│ │ core_attacker.py │ │ ARP discovery │ │ Passive DHCP/ │ │ ARP spoof/block │ │ + enrichment │ │ ARP analysis │ │ + ARP restore │ └────────┬────────┘ └───────┬───────┘ └────────┬─────────┘ │ │ │ v v v ┌────────────────────────────────────────────────────────────┐ │ fingerprint/ (OS & device inference) │ │ engine.py │ lookup.py │ evidence.py │ mac.py │ os_intel.py│ └────────────────────────────┬───────────────────────────────┘ │ v ┌────────────────────────────────────────────────────────────┐ │ utils/ (network context, iface resolution, vendor lookup) │ │ network_helper.py │ scapy_iface.py │ extract.py │ └────────────────────────────┬───────────────────────────────┘ │ v ┌────────────────────────────────────────────────────────────┐ │ data/ — devices.json (inventory) + mac-vendors.txt (OUI) │ └────────────────────────────────────────────────────────────┘

### Core operational flow

1. **Bootstrap** — `main.py` loads modules, restores prior device history from `data/devices.json`, detects local IP/gateway/range via `utils/network_helper.py`, and presents an interface picker (Scapy GUID on Windows, interface name on Linux/macOS).

2. **Live scanning** — A background daemon thread repeatedly calls `scan_network_logic()` in `core/core_scanner.py`. The scanner performs a parallel ARP sweep across a private CIDR, enriches each responder with vendor, hostname, and OS hints, then merges results into an in-memory dictionary keyed by **MAC address** (not IP).

3. **Passive monitoring** — A separate sniffer thread runs `start_sniffer()` from `core/core_sniffer.py`, capturing DHCP and ARP traffic. DHCP events update the device table in real time; ARP spoof replies against the known gateway trigger alerts.

4. **Fingerprint refinement** — When available, `FingerprintEngine` (`fingerprint/engine.py`) upgrades weak scanner guesses using protocol-specific signatures (ARP, DHCP option 55/60, mDNS, TTL, TCP SYN, TLS JA3, and more).

5. **Persistence** — After each successful sweep, and on application exit, `core/core_storage.py` atomically writes the full device list to `data/devices.json`.

6. **Optional network control** — The Network Control tab invokes `run_attack()` in `core/core_attacker.py`, which performs bidirectional ARP spoofing to isolate a target host from the gateway until stopped, then restores correct ARP mappings.

All long-running operations execute on **daemon threads**; the GUI updates exclusively through `self.after()` callbacks to preserve Tkinter thread safety.

---

## Architecture and Directory Structure



Ghost_sentinel/ ├── main.py # Tkinter GUI orchestrator and entry point ├── test_arp.py # Interface diagnostic — ARP probe per adapter ├── core/ │ ├── init.py # Public re-exports of core modules │ ├── core_scanner.py # Active discovery engine (ARP + enrichment) │ ├── core_sniffer.py # Passive packet capture and event extraction │ ├── core_attacker.py # ARP spoof / restore for device isolation │ └── core_storage.py # Thread-safe JSON persistence layer ├── fingerprint/ │ ├── engine.py # Fingerprint orchestration and Scapy adapter │ ├── lookup.py # Signature matching against protocol patterns │ ├── evidence.py # Evidence fusion, scoring, and result objects │ ├── mac.py # Randomized MAC detection and correlation │ └── os_intel.py # OS plausibility, firmware, and confidence tiers ├── utils/ │ ├── network_helper.py # Local IP, gateway, subnet, and range detection │ ├── scapy_iface.py # Scapy interface enumeration and GUID resolution │ ├── extract.py # Standalone OUI vendor lookup utility │ └── diagnose_iface.py # Deep Scapy/Npcap interface diagnostic script └── data/ ├── devices.json # Persistent discovered-device inventory └── mac-vendors.txt # IEEE OUI vendor database (~235k entries)

### Directory reference

| Path | Responsibility |

|------|----------------|

| `main.py` | Application shell: themed Tkinter UI, thread orchestration, live scan loop, CSV export, privilege warning |

| `core/` | Security and network primitives: scanning, sniffing, attacking, storage |

| `fingerprint/` | Passive and active device/OS identification pipeline |

| `utils/` | OS-level network context, Scapy interface bridging, vendor extraction |

| `data/` | Local databases: JSON device history and IEEE MAC vendor file |

---

### `core/` — Network security engine

| Module | Purpose |

|--------|---------|

| `core_scanner.py` | Active LAN discovery. Validates private CIDR ranges, parallelizes per-host ARP probes (`srp1`), resolves hostnames (DNS + NetBIOS), probes OS via TTL/heuristics, and returns structured device records. |

| `core_sniffer.py` | Passive intelligence. Sniffs DHCP (ports 67/68) and ARP with `store=False` and 2-second timeout bursts. Extracts DHCP hostname, vendor class (opt60), parameter list (opt55). Detects gateway ARP impersonation. |

| `core_attacker.py` | Controlled ARP manipulation. Resolves target/gateway MACs, validates inputs, sends spoofed ARP replies to both parties every 2 seconds, and always restores correct mappings on stop or exit. |

| `core_storage.py` | Durable inventory. Atomic JSON writes (temp file + rename), MAC-keyed merge logic that preserves the best-known field values, and thread-safe read/write under a global lock. |

### `fingerprint/` — Device and OS identification

| Module | Purpose |

|--------|---------|

| `engine.py` | Central fingerprint orchestrator. Converts Scapy packets to normalized dicts (`ScapyAdapter`), runs protocol analysers, fuses evidence via `aggregate_evidence()`, and optionally enriches with `os_intel`. |

| `lookup.py` | `SignatureMatcher` correlates observed artefacts (OUI, DHCP opt55/opt60, mDNS, TTL, JA3, SSDP, HTTP UA, etc.) against built-in pattern tables and returns weighted `FingerprintMatch` objects. |

| `evidence.py` | Data model and fusion math: `Evidence`, `FingerprintMatch`, `FingerprintResult`, source trust weights, contradiction pruning, and confidence aggregation. |

| `mac.py` | Privacy-aware MAC analysis. Detects locally administered (randomized) MACs, extracts multi-signal correlation fingerprints, scores identity overlap, and suggests candidate real identities from known devices. |

| `os_intel.py` | Offline OS intelligence layer. Vendor normalization, firmware guessing, kernel-to-distro mapping, OS plausibility assessment, and formatted inferred OS strings with confidence tiers. |

### `utils/` — Low-level network utilities

| Module | Purpose |

|--------|---------|

| `network_helper.py` | Windows-centric environment detection using `ipconfig`, `route print`, and UDP socket trick for local IP. Derives subnet mask, CIDR scan range, gateway, and friendly adapter name. |

| `scapy_iface.py` | Bridges OS adapter names to Scapy internal identifiers. On Windows, parses `ipconfig /all`, maps friendly names to NPF GUIDs via `IFACES` and `get_windows_if_list()`. On POSIX, enumerates `get_if_list()` with routable IPs only. |

| `extract.py` | Lightweight OUI resolver supporting multiple vendor file formats (`mac-vendors.txt`, `oui_lookup.txt`). Used independently of the scanner's embedded OUI loader. |

| `diagnose_iface.py` | Standalone diagnostic that dumps Scapy version, `conf.iface`, `IFACES`, `get_windows_if_list()`, and performs a single ARP test to the gateway. |

### `data/` — Local data layer

| Asset | Logic |

|-------|-------|

| `devices.json` | Append/update inventory keyed by MAC. Each record may include IP, vendor, hostname, OS, confidence, status (`Online`/`Offline`/`Blocked`), `first_seen`, and `last_seen` Unix timestamps. Written atomically to prevent corruption on crash. |

| `mac-vendors.txt` | IEEE Registration Authority OUI database in Wireshark `(hex)` format. Parsed at runtime into a 6-hex-digit prefix cache for manufacturer identification. Also detects randomized MACs via the locally administered bit. |

---

## Detailed Component and Function Breakdown

### `main.py`

| Symbol | Technical behavior |

|--------|-------------------|

| `_die()` | Graceful fatal import handler; shows Tkinter error dialog or stderr message and exits. |

| `_os_interfaces()` | Cross-platform interface discovery via `ipconfig`/`netsh` (Windows), `networksetup`/`ifconfig` (macOS), or `ip addr`/`ifconfig -a` (Linux). Returns `{name, description, ips}` dicts; loopback adapters excluded. |

| `_iface_candidates()` | Merges Scapy `list_scapy_ifaces()` results with `_os_interfaces()` IP enrichment. Falls back to OS-only list if Scapy returns nothing. |

| `_configure_ttk_styles()` | Applies Discord-style dark theme to all ttk widgets (notebook, treeview, scrollbar, combobox, buttons). |

| `_Btn` | Themed `ttk.Button` wrapper with `primary`, `danger`, and `neutral` variants. |

| `_NeonEntry` | Styled `tk.Entry` for dark-theme text fields. |

| `_is_admin()` | Privilege check via `ctypes.windll.shell32.IsUserAnAdmin()` (Windows) or `os.geteuid() == 0` (Unix). Triggers startup warning if not elevated. |

| `GhostSentinel` | Main `tk.Tk` subclass managing all application state, UI tabs, and background workers. |

| `_build_header()` | Centered title block with live clock. |

| `_build_network_bar()` | Live dashboard: interface, Scapy iface, local IP, gateway, range, status, host count, scan progress, sniffer/attack indicators. |

| `_build_scanner_tab()` | Range field, hybrid interface combobox (dropdown + manual entry), live scan controls, device treeview, CSV export. |

| `_build_sniffer_tab()` | Sniffer start/stop, color-tagged live traffic log (DHCP, ARP spoof, randomized MAC). |

| `_build_attack_tab()` | Target/gateway IP inputs, block/restore controls, activity log. Legal-use warning displayed. |

| `_build_storage_tab()` | Historical device treeview with reload and clear actions. |

| `_reload_iface_combo()` | Repopulates interface dropdown from `_iface_candidates()`. |

| `_on_iface_combo()` | Dropdown selection maps friendly name to internal Scapy iface name/GUID. |

| `_on_iface_manual()` | Manual text entry overrides dropdown; sets `scapy_iface` directly and pins `conf.iface`. |

| `_apply_iface_selection()` | Applies list index selection, resolves gateway MAC via `_resolve_mac()`. |

| `_show_iface_picker()` | Startup modal: listbox selection or manual entry field; never blocks if detection fails. |

| `_pin_iface()` | Writes selected iface to `scapy.all.conf.iface` before any Scapy operation. |

| `_detect_network()` | Background thread calling `get_network_info()`; populates UI fields via `self.after(0, ...)`. |

| `_live_scan_loop()` | Continuous ARP sweep every `SCAN_INTERVAL_SEC` (25s). Honors `stop_event`, merges results, persists to disk. |

| `_merge_scan_results()` | MAC-keyed merge; fingerprint upgrade via `FingerprintEngine.analyze_dict()`; marks unseen hosts offline after 45s. |

| `_progress_cb()` | Thread-safe scan progress state for the network bar. |

| `_sniff_callback()` | Marshals sniffer events to main thread via `self.after(0, ...)`. |

| `_handle_sniff_event()` | Processes DHCP/ARP-spoof/randomized-MAC events; updates `_devices` under lock. |

| `_attack_worker()` | Runs `run_attack()` in background; restores UI state on completion. |

| `_refresh_tree()` | Rebuilds scanner treeview every 1s; applies status color tags and alternating row styling. |

| `_on_close()` | Sets all stop events, saves devices, destroys window. |

| `--export` CLI mode | Exports `devices.json` contents to CSV without launching GUI. |

---

### `core/core_scanner.py`

| Function | Technical behavior |

|----------|-------------------|

| `_load_oui_db()` | Thread-safe lazy load of `data/mac-vendors.txt` into `_oui_cache` (6-hex keys). |

| `get_vendor()` | OUI lookup; returns `Randomized MAC (Mobile)` if locally administered bit set. |

| `_resolve_mac()` | Directed ARP (`srp1`, timeout=1.0) to obtain MAC for a given IP. |

| `_resolve_dns()` | Reverse DNS in a daemon thread with join timeout (0.8s). |

| `_resolve_nbns()` | NetBIOS Name Service UDP query on port 137 with timeout. |

| `get_hostname()` | DNS fallback to NBNS fallback to `"Unknown"`. |

| `_os_from_ttl()` | TTL bucket classifier: <=64 Linux/Android, <=128 Windows, <=255 network gear. |

| `_heuristic_os()` | Keyword corpus match against vendor + hostname for high-confidence OS labels. |

| `probe_os()` | Heuristic first; else ICMP echo probe for TTL-based inference. |

| `_validate_range()` | Rejects non-IPv4, public ranges, and CIDR blocks larger than 4096 hosts. |

| `_enrich()` | Per-host pipeline: MAC resolve, vendor, hostname, OS probe; returns complete device dict. |

| `_arp_one()` | Single-host ARP request via `srp1` with configurable timeout. |

| `_arp_sweep()` | `ThreadPoolExecutor` (50 workers) parallel sweep; supports `stop_event` cancellation; reports progress per host. |

| `scan_network_logic()` | Public API. Validates range, pins interface, sweeps, enriches in parallel (max 30 workers, 25s enrichment timeout), sorts by IP octets. Returns `(devices, error_string)`. |

---

### `core/core_sniffer.py`

| Function | Technical behavior |

|----------|-------------------|

| `process_dhcp_packet()` | Parses DHCP options: hostname, vendor class ID (opt60), parameter request list (opt55). Returns normalized dict or `None`. |

| `detect_arp_spoofing()` | Flags ARP replies where `psrc == gateway_ip` but `hwsrc != gateway_mac`. |

| `start_sniffer()` | Resolves interface, runs `sniff()` in 2s timeout loops with `store=False`, filter `udp port 67 or udp port 68 or arp`. Invokes callback for DHCP, spoof, and randomized MAC events. Handles `KeyboardInterrupt` and backs off on capture errors. |

---

### `core/core_attacker.py`

| Function | Technical behavior |

|----------|-------------------|

| `_valid_mac()` / `_valid_ip()` | Regex and `ipaddress` validation. |

| `_validate()` | Ensures all four MAC/IP values are valid and target != gateway. |

| `_resolve_mac()` | ARP resolution before attack begins. |

| `spoof()` | Sends two ARP reply frames: target believes gateway is at attacker's MAC mapping, gateway believes target IP maps to spoofed entry. |

| `restore()` | Sends five rounds of correct ARP replies to both parties (0.4s apart). |

| `run_attack()` | Supports 4-arg `(target_ip, gateway_ip, iface, stop_event)` and 5-arg MAC-explicit forms. Loops spoof every 2s until `stop_event`; always calls `restore()` in `finally`. |

---

### `core/core_storage.py`

| Function | Technical behavior |

|----------|-------------------|

| `_atomic_write()` | `tempfile.mkstemp` in target directory, JSON dump, `os.replace` for crash-safe writes. |

| `_merge_device()` | Field-level merge preserving better values; unions `signals` dicts; treats `Unknown`/empty as low quality. |

| `save_devices()` | Full-list atomic save under `_lock`. |

| `load_devices()` | Returns `[]` on missing or corrupt file; logs errors. |

| `update_device_info()` | Load-merge-save single MAC entry atomically. |

| `get_device()` / `is_known_device()` | MAC lookup helpers for anomaly detection. |

| `Storage` | Thin class wrapper exposing the above for `main.py`. |

---

### `fingerprint/engine.py`

| Symbol | Technical behavior |

|--------|-------------------|

| `ScapyAdapter.from_packet()` | Normalizes ARP, DHCPv4, TCP SYN, TLS ClientHello, mDNS, and IGMP packets into a unified evidence dict. |

| `_extract_tls_signals()` | Best-effort SNI and JA3 MD5 from TLS ClientHello extensions. |

| `FingerprintEngine` | Dual pipeline: passive `analyze_packet()` and active `analyze_dict()` / `process_*()` methods. |

| `_lookup_oui_once()` | Deduplicated OUI lookup per MAC (cache capped at 50k). |

| `_enrich_os_intel()` | Applies firmware guess, plausibility score, and confidence tier when `os_intel` is available. |

| `make_callback()` | Returns a Scapy `prn` handler that calls `analyze_packet()` and forwards non-empty results. |

---

### `fingerprint/lookup.py`

| Symbol | Technical behavior |

|--------|-------------------|

| `_parse_opt55()` | Normalizes DHCP parameter request lists from bytes, lists, or string forms. |

| `_match_opt55()` | Frozenset overlap scoring against built-in OS/vendor signatures (Windows, Apple, Android, Linux). |

| `DEVICE_CATEGORIES` | Maps internal device roles to human-readable categories. |

| `SignatureMatcher` | Core matcher with methods for MAC OUI, DHCP opt60/55, mDNS services, TTL, TCP window/MSS, JA3, SSDP, HTTP User-Agent, and more. Each returns `FingerprintMatch` with calibrated confidence. |

---

### `fingerprint/evidence.py`

| Symbol | Technical behavior |

|--------|-------------------|

| `SOURCE_WEIGHTS` | Trust table weighting protocol sources (LLDP=1.0 down to TTL=0.1). |

| `FingerprintMatch` | Single-signal identification record with `effective_weight() = trust × confidence`. |

| `Evidence` | Legacy Scapy-pipeline evidence object with `to_match()` converter. |

| `FingerprintResult` | Aggregated profile: vendor, OS, model, certainty, os_intel fields, evidence trail. |

| `aggregate_evidence()` | Weighted ballot consensus across matches; prunes contradictions, downweights locked vendors, suppresses Android without OUI support. |

| `score_matches()` | Ranks and filters match list before aggregation. |

---

### `fingerprint/mac.py`

| Function | Technical behavior |

|----------|-------------------|

| `detect_randomised_mac()` | Checks locally administered bit (0x02) in first octet; exempts Docker/QEMU/VMware prefixes. |

| `extract_correlation_signals()` | Builds identity fingerprint from hostname, DHCP opt60/55, TCP sig, mDNS name. |

| `compute_correlation_score()` | Weighted overlap score between two signal dicts. |

| `find_identity_candidates()` | Matches randomized MAC hosts to known devices sharing the same DHCP hostname. |

---

### `fingerprint/os_intel.py`

| Symbol | Technical behavior |

|--------|-------------------|

| `ConfidenceTier` | Enum: VALIDATED, PLAUSIBLE, SUSPECT, UNKNOWN. |

| `resolve_vendor_name()` | Normalizes raw vendor strings against alias table. |

| `guess_firmware()` | Maps device type + manufacturer to likely firmware family. |

| `assess_os_plausibility()` | Scores whether inferred OS is consistent with vendor and device role. |

| `distros_for_kernel()` | Maps kernel version strings to likely Linux distributions. |

| `format_inferred_os()` | Produces human-readable OS string with tier annotation. |

---

### `utils/network_helper.py`

| Function | Technical behavior |

|----------|-------------------|

| `_run()` | Safe `subprocess.run()` wrapper: list args, no shell, 5s timeout. |

| `get_my_ip()` | UDP connect to 8.8.8.8:80 to determine outbound interface IP without sending data. |

| `get_gateway()` | Parses `route print -4` default route; falls back to `ipconfig` gateway line. |

| `get_interface()` | Matches local IP to `ipconfig /all` adapter section; returns short name (e.g., `Ethernet`, `Wi-Fi`). |

| `get_subnet_mask()` | Reads mask from adapter section following local IP line. |

| `get_network_range()` | Computes CIDR from IP+mask; defaults to `/24` guess on failure. |

| `get_network_info()` | Aggregates all above into `{ip, gateway, interface, range}`. |

---

### `utils/scapy_iface.py`

| Function | Technical behavior |

|----------|-------------------|

| `_ipconfig_adapters()` | Parses active Windows adapters with routable IPv4, gateway, and MAC from `ipconfig /all`. |

| `_scapy_ifaces_map()` | Builds `description.lower() -> NPF GUID` map from `scapy.interfaces.IFACES`. |

| `_get_guid_for_adapter()` | Four-strategy friendly-name to GUID match (exact, substring, reverse substring, `get_windows_if_list`). |

| `list_scapy_ifaces()` | Windows: ipconfig-grounded list with GUID resolution. POSIX: `get_if_list()` with routable IP filter. |

| `resolve_iface(hint)` | Resolves hint by exact name, description substring, or IP match; falls back to `conf.iface`. |

---

### `utils/extract.py`

| Function | Technical behavior |

|----------|-------------------|

| `_load()` | Parses vendor file into `XX:XX:XX` keyed cache. |

| `get_vendor()` | Returns manufacturer string or `Unknown Vendor`. |

---

### `utils/diagnose_iface.py`

Standalone diagnostic script. Sequentially prints Python/Scapy versions, `conf.iface` attributes, full `get_windows_if_list()` dump, `IFACES` registry, `get_if_list()`, `network_helper` output, `list_scapy_ifaces()` results, and a single ARP probe to the default gateway.

---

### `test_arp.py`

Interface validation utility. Discovers the default gateway via `route print -4`, then iterates every entry in `scapy.interfaces.IFACES` and sends a single ARP request (`srp1`, timeout=1s) to the gateway through each adapter. Prints `WORKS` for interfaces that receive a reply, enabling the operator to identify the correct Scapy interface name or GUID.

---

### `core/__init__.py`

Re-exports `scan_network_logic`, `start_sniffer`, `run_attack`, `Storage`, and optionally `FingerprintEngine` / `make_callback` for programmatic use.

---

## Network Interface Configuration (Critical)

> [!IMPORTANT]

> Ghost Sentinel requires the **correct network interface** to send and receive raw ARP/DHCP frames. An incorrect interface produces zero scan results, silent packet drops, or misleading empty host tables — especially on Windows where Scapy uses Npcap NPF GUIDs (`\Device\NPF_{GUID}`) internally while the OS displays friendly names like `Ethernet` or `Wi-Fi`.

### Why this matters

| Platform | What you see in the OS | What Scapy needs |

|----------|------------------------|------------------|

| Windows | `Ethernet`, `Wi-Fi` | NPF GUID (e.g., `\Device\NPF_{XXXXXXXX-...}`) |

| Linux | `eth0`, `wlan0`, `enp3s0` | Same interface name |

| macOS | `en0`, `en1` | Same interface name |

Ghost Sentinel resolves this automatically via `utils/scapy_iface.py` and the hybrid interface selector in the Scanner tab (dropdown + manual text field). However, when auto-detection fails or multiple virtual adapters exist, manual verification is required.

### How to find your working interface

**Step 1 — Run the ARP interface test (required if unsure):**

```powershell

# Windows — run PowerShell or CMD as Administrator

cd Ghost_sentinel

python test_arp.py



# Linux / macOS — run as root

sudo python test_arp.py

Step 2 — Read the output. Look for a line marked WORKS:

WORKS  desc=Realtek PCIe GbE Family Controller

       guid=\Device\NPF_{A1B2C3D4-...}

       gw_mac=aa:bb:cc:dd:ee:ff

Step 3 — Copy the working identifier into Ghost Sentinel:

Paste the GUID (guid=...) or friendly description into the Interface field in the Scanner tab, or

Select the matching entry from the dropdown after clicking Refresh Ifaces.

Step 4 — Verify in the network bar. After selection, confirm:

Scapy iface shows a non-empty GUID or interface name

Local IP and Gateway match your actual network

Range reflects your subnet (e.g., 192.168.1.0/24)

Additional diagnostics

python utils/diagnose_iface.py

This produces a full dump of Scapy's interface registry, useful when Npcap is installed but GUID mapping fails.

Platform prerequisites

PlatformRequirementWindows

Npcap installed (WinPcap-compatible mode recommended) + Run as Administrator

Linux

libpcap + root (sudo) or CAP_NET_RAW capability

macOS

root (sudo) for raw socket access

Installation and How to Run

Prerequisites

Python 3.10 or newer (3.11+ recommended)

pip package manager

Npcap (Windows) or libpcap (Linux)

Elevated privileges (Administrator / root) for scanning and sniffing

1. Clone the repository

git clone https://github.com/<your-org>/Ghost_sentinel.git

cd Ghost_sentinel



2. Create a virtual environment (recommended)

python -m venv .venv

# Windows

.venv\Scripts\activate

# Linux / macOS

source .venv/bin/activate

3. Install dependencies

The project has no committed requirements.txt at present. Install the required third-party package directly:

pip install scapy

Optional but recommended on Windows:

pip install scapy[complete]

Tkinter is part of the Python standard library on most distributions. On minimal Linux installs:

# Debian/Ubuntu

sudo apt install python3-tk

4. Verify interface (before first scan)

# Windows (Administrator)

python test_arp.py

# Linux/macOS

sudo python test_arp.py

5. Launch the application

# Windows — run terminal as Administrator

python main.py

# Linux / macOS

sudo python main.py

6. Optional — export device history without GUI

python main.py --export devices_export.csv

Application tabs

TabFunctionScanner

Configure range and interface; start/stop live ARP scan; view discovered hosts; export CSV

Sniffer

Passive DHCP and ARP monitoring; ARP spoof detection; randomized MAC alerts

Network Control

ARP-based device isolation (authorized testing only); restore on stop

History

Reload or clear persisted records from data/devices.json

Legal and Ethical Notice

Ghost Sentinel performs active network reconnaissance and can manipulate ARP tables. These capabilities are lawful only on networks you own or have explicit written authorization to test.

Unauthorized scanning, interception, or traffic manipulation may violate computer misuse laws in your jurisdiction. The ARP spoofing feature in core_attacker.py is provided for controlled lab and defensive testing scenarios only. Always obtain permission before deployment.

License

Specify your license here (e.g., MIT, GPL-3.0) before public distribution.

Contributing

Pull requests should preserve the modular core/ / fingerprint/ / utils/ separation, maintain MAC-keyed device identity, and keep all Scapy operations behind interface validation and private-range checks.

Ghost Sentinel v2.0 — Network Intelligence Platform
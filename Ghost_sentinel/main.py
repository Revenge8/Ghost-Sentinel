"""
Ghost Sentinel — main.py
========================
Tkinter GUI orchestrator. Scanning and sniffing run on daemon threads;
the UI refreshes via self.after() without blocking the main loop.

Project layout:
  main.py
  core/   → scanner, sniffer, storage, attacker
  utils/  → network_helper, scapy_iface
  fingerprint/ → FingerprintEngine
"""
from __future__ import annotations

import os
import re
import sys
import csv
import time
import subprocess
import threading
import logging
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Any

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _die(module: str, extra: str = "") -> None:
    if extra:
        _log.error("Import failed for %s: %s", module, extra)
    msg = (f"Required module '{module}' could not be imported.\n"
           f"Make sure the project structure is intact.")
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Ghost Sentinel — Import Error", msg)
        root.destroy()
    except Exception:
        print(f"[FATAL] {msg}")
    sys.exit(1)


try:
    from utils.network_helper import get_network_info
except ImportError as e:
    _die("utils.network_helper", str(e))

try:
    from utils.scapy_iface import list_scapy_ifaces, resolve_iface, sanitize_iface_hint
except ImportError as e:
    _die("utils.scapy_iface", str(e))

try:
    from core.core_scanner import scan_network_logic
except ImportError as e:
    _die("core.core_scanner", str(e))

try:
    from core.core_sniffer import start_sniffer
except ImportError as e:
    _die("core.core_sniffer", str(e))

try:
    from core.core_storage import Storage
except ImportError as e:
    _die("core.core_storage", str(e))

try:
    from core.core_attacker import run_attack, _resolve_mac
    _ATTACKER_AVAILABLE = True
except ImportError:
    _ATTACKER_AVAILABLE = False
    _resolve_mac = None  # type: ignore[assignment]
    def run_attack(*a, **kw) -> str:  # type: ignore[misc]
        return "core_attacker module not found."

try:
    from fingerprint.engine import FingerprintEngine
    _FP_ENGINE = FingerprintEngine()
    _FINGERPRINT_AVAILABLE = True
except ImportError:
    _FINGERPRINT_AVAILABLE = False
    _FP_ENGINE = None

_log = logging.getLogger("ghost_sentinel")


def _validate_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address((ip or "").strip())
        return True
    except ValueError:
        return False


def _safe_cli_export_path(path: str) -> str:
    """Reject path traversal in CLI --export mode."""
    path = (path or "").strip()
    if not path:
        return "ghost_sentinel_export.csv"
    norm = path.replace("\\", "/")
    if ".." in norm.split("/"):
        return "ghost_sentinel_export.csv"
    if "\x00" in path:
        return "ghost_sentinel_export.csv"
    return path

SCAN_INTERVAL_SEC = 25
UI_REFRESH_MS     = 1000
OFFLINE_AFTER_SEC = 45

# ── Discord / Claude-style dark palette ───────────────────────────────────────
_C = {
    "void":              "#1e1f22",
    "panel":             "#2b2d31",
    "card":              "#313338",
    "input":             "#1e1f22",
    "border":            "#3f4147",
    "accent":            "#5865f2",
    "accent_hover":      "#4752c4",
    "text":              "#dbdee1",
    "text_dim":          "#949ba4",
    "success":           "#57f287",
    "danger":            "#ed4245",
    "warn":              "#fee75c",
    "btn_primary_fg":    "#ffffff",
    "btn_neutral":       "#4e5058",
    "btn_neutral_hover": "#5d6069",
    "tree_bg":           "#313338",
    "tree_header":       "#2b2d31",
    "row_alt":           "#2b2d31",
    "row_sel":           "#404249",
    "row_new":           "#36373f",
    "row_blocked":       "#3a2b2b",
}

_UI_FONT   = "Segoe UI" if sys.platform.startswith("win") else "Arial"
FONT_UI     = (_UI_FONT, 11)
FONT_UI_B   = (_UI_FONT, 11, "bold")
FONT_TITLE  = (_UI_FONT, 16, "bold")
FONT_LABEL  = (_UI_FONT, 11)
FONT_TABLE  = (_UI_FONT, 11)
FONT_HEADING = (_UI_FONT, 10, "bold")


# ── OS-aware interface discovery via system commands ──────────────────────────

def _os_interfaces() -> list[dict[str, Any]]:
    """
    Query the OS directly for network interfaces.
    Works on Windows, Linux, and macOS without any extra libraries.
    Returns a list of dicts with keys: name, description, ips.
    """
    ifaces: list[dict[str, Any]] = []

    if sys.platform.startswith("win"):
        # Strategy 1: ipconfig (always available on Windows)
        try:
            out = subprocess.check_output(
                ["ipconfig", "/all"], stderr=subprocess.DEVNULL,
                timeout=8, text=True, errors="replace",
            )
            current: dict[str, Any] = {}
            for line in out.splitlines():
                # New adapter block
                m = re.match(r"^(\S.*):$", line)
                if m:
                    if current.get("name"):
                        ifaces.append(current)
                    current = {"name": m.group(1).strip(), "description": m.group(1).strip(), "ips": []}
                # IPv4 address line
                ip_m = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", line, re.IGNORECASE)
                if ip_m and current:
                    current.setdefault("ips", []).append(ip_m.group(1).strip().rstrip("(Preferred)").strip())
            if current.get("name"):
                ifaces.append(current)
        except Exception:
            pass

        # Strategy 2: netsh (gives Scapy-friendly names on newer Windows)
        if not ifaces:
            try:
                out = subprocess.check_output(
                    ["netsh", "interface", "show", "interface"],
                    stderr=subprocess.DEVNULL, timeout=8,
                    text=True, errors="replace",
                )
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] in ("Enabled", "Disabled"):
                        name = " ".join(parts[3:])
                        ifaces.append({"name": name, "description": name, "ips": []})
            except Exception:
                pass

    elif sys.platform == "darwin":
        # macOS: networksetup + ifconfig
        try:
            out = subprocess.check_output(
                ["networksetup", "-listallhardwareports"],
                stderr=subprocess.DEVNULL, timeout=8,
                text=True, errors="replace",
            )
            current = {}
            for line in out.splitlines():
                if line.startswith("Hardware Port:"):
                    current = {"description": line.split(":", 1)[1].strip(), "ips": []}
                elif line.startswith("Device:") and current:
                    current["name"] = line.split(":", 1)[1].strip()
                    ifaces.append(current)
                    current = {}
        except Exception:
            pass

        # Fallback: ifconfig
        if not ifaces:
            try:
                out = subprocess.check_output(
                    ["ifconfig"], stderr=subprocess.DEVNULL,
                    timeout=8, text=True, errors="replace",
                )
                for line in out.splitlines():
                    m = re.match(r"^(\w+):", line)
                    if m:
                        ifaces.append({"name": m.group(1), "description": m.group(1), "ips": []})
                    ip_m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_m and ifaces:
                        ifaces[-1].setdefault("ips", []).append(ip_m.group(1))
            except Exception:
                pass

    else:
        # Linux: ip addr (modern), fallback to ifconfig
        try:
            out = subprocess.check_output(
                ["ip", "addr"], stderr=subprocess.DEVNULL,
                timeout=8, text=True, errors="replace",
            )
            current = {}
            for line in out.splitlines():
                m = re.match(r"^\d+:\s+(\S+):", line)
                if m:
                    if current.get("name"):
                        ifaces.append(current)
                    name = m.group(1).rstrip("@")
                    current = {"name": name, "description": name, "ips": []}
                ip_m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                if ip_m and current:
                    current.setdefault("ips", []).append(ip_m.group(1))
            if current.get("name"):
                ifaces.append(current)
        except Exception:
            pass

        if not ifaces:
            try:
                out = subprocess.check_output(
                    ["ifconfig", "-a"], stderr=subprocess.DEVNULL,
                    timeout=8, text=True, errors="replace",
                )
                for line in out.splitlines():
                    m = re.match(r"^(\w[\w:.-]+)\s", line)
                    if m:
                        ifaces.append({"name": m.group(1).rstrip(":"), "description": m.group(1).rstrip(":"), "ips": []})
                    ip_m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_m and ifaces:
                        ifaces[-1].setdefault("ips", []).append(ip_m.group(1))
            except Exception:
                pass

    # Remove loopback
    ifaces = [
        i for i in ifaces
        if i.get("name") and "loopback" not in i["name"].lower()
        and i["name"].lower() not in ("lo", "lo0")
        and i.get("name") != ""
    ]
    return ifaces


def _configure_ttk_styles(root: tk.Misc) -> ttk.Style:
    """Apply Discord-like theme to all ttk widgets."""
    s = ttk.Style(root)
    s.theme_use("clam")

    s.configure(".", background=_C["void"], foreground=_C["text"], font=FONT_UI)
    s.configure("TFrame", background=_C["void"])
    s.configure("TPanedwindow", background=_C["void"])

    s.configure(
        "Ghost.TNotebook", background=_C["panel"], borderwidth=0,
        tabmargins=[8, 4, 8, 0],
    )
    s.configure(
        "Ghost.TNotebook.Tab",
        background=_C["panel"], foreground=_C["text_dim"],
        font=FONT_UI_B, padding=[16, 8], borderwidth=0,
    )
    s.map(
        "Ghost.TNotebook.Tab",
        background=[("selected", _C["void"]), ("active", _C["card"])],
        foreground=[("selected", _C["text"]), ("active", _C["text"])],
    )

    s.configure(
        "Ghost.Treeview",
        background=_C["tree_bg"], foreground=_C["text"],
        fieldbackground=_C["tree_bg"], borderwidth=0,
        rowheight=25, font=FONT_TABLE,
    )
    s.configure(
        "Ghost.Treeview.Heading",
        background=_C["tree_header"], foreground=_C["text_dim"],
        font=FONT_HEADING, relief="flat", borderwidth=0, padding=[8, 6],
    )
    s.map(
        "Ghost.Treeview",
        background=[("selected", _C["row_sel"])],
        foreground=[("selected", _C["text"])],
    )
    s.map("Ghost.Treeview.Heading", background=[("active", _C["card"])])

    s.configure(
        "Ghost.Vertical.TScrollbar",
        background=_C["btn_neutral"], troughcolor=_C["panel"],
        borderwidth=0, arrowcolor=_C["text_dim"], relief="flat",
    )
    s.map(
        "Ghost.Vertical.TScrollbar",
        background=[("active", _C["accent"]), ("pressed", _C["accent_hover"])],
    )

    s.configure(
        "Ghost.TCombobox",
        fieldbackground=_C["input"], background=_C["input"],
        foreground=_C["text"], arrowcolor=_C["text_dim"],
        bordercolor=_C["border"], lightcolor=_C["border"],
        darkcolor=_C["border"], insertcolor=_C["text"],
        padding=[8, 6],
    )
    s.map(
        "Ghost.TCombobox",
        fieldbackground=[("readonly", _C["input"])],
        selectbackground=[("readonly", _C["row_sel"])],
        selectforeground=[("readonly", _C["text"])],
    )

    for name, bg, fg, hover in (
        ("Ghost.Primary.TButton", _C["accent"],      _C["btn_primary_fg"], _C["accent_hover"]),
        ("Ghost.Danger.TButton",  _C["danger"],      _C["btn_primary_fg"], "#c03537"),
        ("Ghost.Neutral.TButton", _C["btn_neutral"], _C["text"],           _C["btn_neutral_hover"]),
    ):
        s.configure(
            name, background=bg, foreground=fg, borderwidth=0,
            focusthickness=0, font=FONT_UI_B, padding=[12, 6],
        )
        s.map(
            name,
            background=[("active", hover), ("pressed", hover), ("disabled", _C["panel"])],
            foreground=[("disabled", _C["text_dim"])],
        )

    return s


class _Btn(ttk.Button):
    """Themed ttk button — variant: primary | danger | neutral."""

    _STYLES = {
        "primary": "Ghost.Primary.TButton",
        "danger":  "Ghost.Danger.TButton",
        "neutral": "Ghost.Neutral.TButton",
    }

    def __init__(self, parent, text: str, cmd, variant: str = "neutral", **kw):
        style = self._STYLES.get(variant, "Ghost.Neutral.TButton")
        super().__init__(parent, text=text, command=cmd, style=style, cursor="hand2", **kw)


class _NeonEntry(tk.Entry):
    """Styled text field matching the dark theme."""

    def __init__(self, parent, **kw):
        super().__init__(
            parent,
            bg=_C["input"], fg=_C["text"],
            insertbackground=_C["text"],
            selectbackground=_C["row_sel"],
            selectforeground=_C["text"],
            relief="flat", bd=0, font=FONT_UI,
            highlightbackground=_C["border"],
            highlightcolor=_C["accent"],
            highlightthickness=1,
            **kw,
        )


def _is_admin() -> bool:
    if sys.platform.startswith("win"):
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _iface_candidates() -> list[dict[str, Any]]:
    """
    Merge Scapy interfaces with OS-detected interfaces.
    OS detection runs first as a reliable fallback.
    """
    # 1. Try Scapy
    scapy_ifaces: list[dict[str, Any]] = []
    try:
        scapy_ifaces = [
            it for it in list_scapy_ifaces()
            if "loopback" not in str(it.get("name", "")).lower()
            and "loopback" not in str(it.get("description", "")).lower()
        ]
    except Exception:
        pass

    # 2. OS-level detection
    os_ifaces = _os_interfaces()

    # 3. Merge: prefer Scapy list, enrich with OS ips if missing
    if scapy_ifaces:
        # Build a map of OS ifaces by description for IP enrichment
        os_map: dict[str, list[str]] = {}
        for oi in os_ifaces:
            key = (oi.get("description") or oi.get("name") or "").lower()
            os_map[key] = oi.get("ips", [])

        for si in scapy_ifaces:
            if not si.get("ips"):
                key = (si.get("description") or si.get("name") or "").lower()
                si["ips"] = os_map.get(key, [])
        return scapy_ifaces

    # 4. Scapy gave nothing — use OS results directly
    return os_ifaces


# ─────────────────────────────────────────────────────────────────────────────
# Main window
# ─────────────────────────────────────────────────────────────────────────────

class GhostSentinel(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("GHOST SENTINEL // Network Intelligence v2.0")
        self.geometry("1200x700")
        self.minsize(900, 550)
        self.configure(bg=_C["void"])
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._lock         = threading.RLock()
        self._stop         = threading.Event()
        self._stop_scan    = threading.Event()
        self._stop_sniff   = threading.Event()
        self._stop_attack  = threading.Event()
        self._live_scan_on = False
        self._sniffing     = False
        self._attacking    = False
        self._devices: dict[str, dict]    = {}
        self._net_info: dict              = {}
        self._scan_state: dict[str, Any]  = {
            "active": False, "done": 0, "total": 1, "phase": "",
        }
        self._status_text = "Ready"
        self.scapy_iface  = ""
        self.gateway_mac  = ""
        self._iface_list: list[dict[str, Any]] = []
        self._new_macs: set[str] = set()

        _configure_ttk_styles(self)
        self.option_add("*TCombobox*Listbox.background",       _C["card"])
        self.option_add("*TCombobox*Listbox.foreground",       _C["text"])
        self.option_add("*TCombobox*Listbox.selectBackground", _C["row_sel"])
        self.option_add("*TCombobox*Listbox.selectForeground", _C["text"])

        self._storage = Storage()
        for dev in self._storage.load_devices():
            mac = dev.get("mac", "")
            if mac:
                dev.setdefault("status", "Offline")
                self._devices[mac] = dev

        self._build_header()
        self._build_network_bar()
        self._build_notebook()
        self._build_statusbar()
        self._style_tree_tags()

        if not _is_admin():
            messagebox.showwarning(
                "Privileges",
                "Ghost Sentinel works best when run as Administrator.\n"
                "Scans may find no devices without elevated privileges.",
            )

        threading.Thread(target=self._detect_network, daemon=True).start()
        self.after(200, self._show_iface_picker)
        self._ui_tick()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self, bg=_C["void"])
        hdr.pack(fill="x", padx=12, pady=(10, 0))
        inner = tk.Frame(hdr, bg=_C["void"])
        inner.pack(fill="x", pady=8)

        self._clock_var = tk.StringVar()
        tk.Label(
            inner, textvariable=self._clock_var,
            bg=_C["void"], fg=_C["text_dim"], font=FONT_LABEL,
        ).pack(side="right", padx=4)

        title_block = tk.Frame(inner, bg=_C["void"])
        title_block.pack(expand=True, fill="x")
        tk.Label(
            title_block, text="Ghost Sentinel",
            bg=_C["void"], fg=_C["text"], font=FONT_TITLE,
        ).pack(anchor="center")
        tk.Label(
            title_block, text="Network Intelligence v2.0",
            bg=_C["void"], fg=_C["text_dim"], font=FONT_LABEL,
        ).pack(anchor="center", pady=(2, 0))

        tk.Frame(self, bg=_C["border"], height=1).pack(fill="x", padx=12)

    def _build_network_bar(self):
        bar = tk.Frame(self, bg=_C["panel"], padx=12, pady=10)
        bar.pack(fill="x")

        def _kv(label: str, var: tk.StringVar, width: int = 14):
            f = tk.Frame(bar, bg=_C["panel"])
            f.pack(side="left", padx=10)
            tk.Label(
                f, text=label + ":", bg=_C["panel"],
                fg=_C["text_dim"], font=FONT_LABEL,
            ).pack(side="left")
            tk.Label(
                f, textvariable=var, bg=_C["panel"], fg=_C["text"],
                font=FONT_UI_B, width=width, anchor="w",
            ).pack(side="left", padx=(6, 0))

        self._var_iface     = tk.StringVar(value="—")
        self._var_scapy     = tk.StringVar(value="—")
        self._var_ip        = tk.StringVar(value="—")
        self._var_gw        = tk.StringVar(value="—")
        self._var_range     = tk.StringVar(value="—")
        self._var_status    = tk.StringVar(value="Ready")
        self._var_progress  = tk.StringVar(value="")
        self._var_count     = tk.StringVar(value="0")
        self._var_sniff_ind = tk.StringVar(value="SNIFFER OFF")
        self._var_atk_ind   = tk.StringVar(value="ATTACK OFF")

        _kv("Interface",   self._var_iface,  12)
        _kv("Scapy iface", self._var_scapy,  28)
        _kv("Local IP",    self._var_ip,     14)
        _kv("Gateway",     self._var_gw,     14)
        _kv("Range",       self._var_range,  16)
        _kv("Status",      self._var_status, 22)

        tk.Frame(bar, bg=_C["border"], width=1).pack(side="left", fill="y", padx=6)
        _kv("Hosts", self._var_count, 4)

        tk.Label(
            bar, textvariable=self._var_progress,
            bg=_C["panel"], fg=_C["accent"], font=FONT_LABEL,
        ).pack(side="right", padx=8)
        tk.Label(
            bar, textvariable=self._var_sniff_ind,
            bg=_C["panel"], fg=_C["text_dim"], font=FONT_LABEL,
        ).pack(side="right", padx=6)
        tk.Label(
            bar, textvariable=self._var_atk_ind,
            bg=_C["panel"], fg=_C["text_dim"], font=FONT_LABEL,
        ).pack(side="right", padx=4)
        tk.Frame(self, bg=_C["border"], height=1).pack(fill="x", padx=12)

    def _build_notebook(self):
        self._nb = ttk.Notebook(self, style="Ghost.TNotebook")
        self._nb.pack(fill="both", expand=True)

        self._tab_scanner = tk.Frame(self._nb, bg=_C["void"])
        self._tab_sniffer = tk.Frame(self._nb, bg=_C["void"])
        self._tab_attack  = tk.Frame(self._nb, bg=_C["void"])
        self._tab_storage = tk.Frame(self._nb, bg=_C["void"])

        self._nb.add(self._tab_scanner, text="  SCANNER  ")
        self._nb.add(self._tab_sniffer, text="  SNIFFER  ")
        self._nb.add(self._tab_attack,  text="  NETWORK CONTROL  ")
        self._nb.add(self._tab_storage, text="  HISTORY  ")

        self._build_scanner_tab()
        self._build_sniffer_tab()
        self._build_attack_tab()
        self._build_storage_tab()

    def _build_scanner_tab(self):
        p = self._tab_scanner
        ctrl = tk.Frame(p, bg=_C["panel"], padx=12, pady=10)
        ctrl.pack(fill="x")

        tk.Label(ctrl, text="Range", bg=_C["panel"],
                 fg=_C["text_dim"], font=FONT_LABEL).pack(side="left", padx=(4, 4))
        self._range_entry = _NeonEntry(ctrl, width=20)
        self._range_entry.pack(side="left", padx=4, ipady=4)

        tk.Label(ctrl, text="Interface", bg=_C["panel"],
                 fg=_C["text_dim"], font=FONT_LABEL).pack(side="left", padx=(12, 4))

        # ── Editable combobox: user can type manually if auto-detect fails ──
        self._iface_combo = ttk.Combobox(
            ctrl, width=36, state="normal", style="Ghost.TCombobox",
        )
        self._iface_combo.pack(side="left", padx=4)
        self._iface_combo.bind("<<ComboboxSelected>>", self._on_iface_combo)
        self._iface_combo.bind("<FocusOut>", self._on_iface_manual)
        self._iface_combo.bind("<Return>",   self._on_iface_manual)

        self._btn_live = _Btn(
            ctrl, "Start Live Scan", self._start_live_scan, variant="primary",
        )
        self._btn_live.pack(side="left", padx=8)
        self._btn_stop_live = _Btn(
            ctrl, "Stop Scan", self._stop_live_scan,
            variant="danger", state="disabled",
        )
        self._btn_stop_live.pack(side="left", padx=4)

        _Btn(ctrl, "Export CSV",      self._export_csv,          variant="neutral").pack(side="right", padx=8)
        _Btn(ctrl, "Refresh Ifaces",  self._reload_iface_combo,  variant="neutral").pack(side="right", padx=4)

        tk.Frame(p, bg=_C["border"], height=1).pack(fill="x")

        tree_f = tk.Frame(p, bg=_C["void"])
        tree_f.pack(fill="both", expand=True, padx=10, pady=10)

        cols = ("IP", "MAC", "Vendor", "Hostname", "OS", "Status", "Time")
        self._tree = ttk.Treeview(
            tree_f, columns=cols, show="headings", style="Ghost.Treeview",
        )
        widths = dict(IP=110, MAC=140, Vendor=180, Hostname=140,
                      OS=150, Status=72, Time=80)
        for col in cols:
            self._tree.heading(col, text=col.upper())
            self._tree.column(col, width=widths[col], minwidth=50, anchor="w")

        vsb = ttk.Scrollbar(
            tree_f, orient="vertical", command=self._tree.yview,
            style="Ghost.Vertical.TScrollbar",
        )
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._tree.bind("<Double-1>", self._on_device_select)

    def _build_sniffer_tab(self):
        p = self._tab_sniffer
        ctrl = tk.Frame(p, bg=_C["panel"], padx=12, pady=10)
        ctrl.pack(fill="x")
        self._btn_sniff = _Btn(
            ctrl, "Start Sniffer", self._start_sniffer, variant="primary",
        )
        self._btn_sniff.pack(side="left", padx=8)
        self._btn_stop_sniff = _Btn(
            ctrl, "Stop Sniffer", self._stop_sniffer,
            variant="danger", state="disabled",
        )
        self._btn_stop_sniff.pack(side="left", padx=4)
        _Btn(ctrl, "Clear Log", self._clear_sniff_log, variant="neutral").pack(
            side="right", padx=8)

        tk.Frame(p, bg=_C["border"], height=1).pack(fill="x")
        self._sniff_log = tk.Text(
            p, bg=_C["card"], fg=_C["text"], font=FONT_TABLE,
            relief="flat", bd=0, state="disabled",
            insertbackground=_C["text"],
            highlightbackground=_C["border"], highlightthickness=1,
        )
        sb = ttk.Scrollbar(
            p, orient="vertical", command=self._sniff_log.yview,
            style="Ghost.Vertical.TScrollbar",
        )
        self._sniff_log.configure(yscrollcommand=sb.set)
        self._sniff_log.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        sb.pack(side="right", fill="y", pady=10)
        self._sniff_log.tag_config("dhcp",    foreground=_C["success"])
        self._sniff_log.tag_config("spoof",   foreground=_C["danger"])
        self._sniff_log.tag_config("randmac", foreground=_C["warn"])
        self._sniff_log.tag_config("ts",      foreground=_C["text_dim"])

    def _build_attack_tab(self):
        p = self._tab_attack
        if not _ATTACKER_AVAILABLE:
            tk.Label(
                p, text="core_attacker module not loaded.",
                bg=_C["void"], fg=_C["warn"], font=FONT_UI_B,
            ).pack(pady=30)

        warn_f = tk.Frame(p, bg=_C["panel"], padx=12, pady=8)
        warn_f.pack(fill="x", padx=12, pady=(12, 4))
        tk.Label(
            warn_f,
            text="ARP spoofing — use only on networks you own or are authorised to test.",
            bg=_C["panel"], fg=_C["warn"], font=FONT_LABEL,
        ).pack()

        card = tk.Frame(p, bg=_C["card"],
                        highlightbackground=_C["border"], highlightthickness=1)
        card.pack(padx=12, pady=10, fill="x")

        def _row(label: str, attr: str, placeholder: str):
            f = tk.Frame(card, bg=_C["card"], padx=16, pady=6)
            f.pack(fill="x")
            tk.Label(f, text=label, width=12, anchor="w",
                     bg=_C["card"], fg=_C["text_dim"], font=FONT_LABEL).pack(side="left")
            e = _NeonEntry(f, width=24)
            e.insert(0, placeholder)
            e.pack(side="left", ipady=4, padx=6)
            setattr(self, attr, e)

        _row("Target IP",  "_atk_target_e", "192.168.1.X")
        _row("Gateway IP", "_atk_gw_e",     "192.168.1.1")

        btn_row = tk.Frame(p, bg=_C["void"])
        btn_row.pack(pady=10)
        self._btn_atk_start = _Btn(
            btn_row, "Block Device", self._start_attack, variant="danger",
        )
        self._btn_atk_start.pack(side="left", padx=10)
        self._btn_atk_stop = _Btn(
            btn_row, "Restore", self._stop_attack_cb,
            variant="primary", state="disabled",
        )
        self._btn_atk_stop.pack(side="left", padx=10)

        self._atk_log = tk.Text(
            p, bg=_C["card"], fg=_C["text"], font=FONT_TABLE,
            relief="flat", bd=0, state="disabled", height=10,
            highlightbackground=_C["border"], highlightthickness=1,
        )
        self._atk_log.pack(fill="x", padx=12, pady=10)
        self._atk_log.tag_config("ok",  foreground=_C["success"])
        self._atk_log.tag_config("err", foreground=_C["danger"])
        self._atk_log.tag_config("ts",  foreground=_C["text_dim"])

    def _build_storage_tab(self):
        p = self._tab_storage
        ctrl = tk.Frame(p, bg=_C["panel"], padx=12, pady=10)
        ctrl.pack(fill="x")
        _Btn(ctrl, "Reload", self._reload_history, variant="neutral").pack(side="left", padx=8)
        _Btn(ctrl, "Clear",  self._clear_history,  variant="danger").pack(side="left",  padx=4)
        tk.Frame(p, bg=_C["border"], height=1).pack(fill="x")

        hist_f = tk.Frame(p, bg=_C["void"])
        hist_f.pack(fill="both", expand=True, padx=10, pady=10)
        h_cols = ("MAC", "IP", "Vendor", "Hostname", "OS")
        self._hist_tree = ttk.Treeview(
            hist_f, columns=h_cols, show="headings", style="Ghost.Treeview",
        )
        for col in h_cols:
            self._hist_tree.heading(col, text=col.upper())
            self._hist_tree.column(col, width=170, minwidth=70, anchor="w")
        vsb = ttk.Scrollbar(
            hist_f, orient="vertical", command=self._hist_tree.yview,
            style="Ghost.Vertical.TScrollbar",
        )
        self._hist_tree.configure(yscrollcommand=vsb.set)
        self._hist_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._reload_history()

    def _build_statusbar(self):
        tk.Frame(self, bg=_C["border"], height=1).pack(fill="x", padx=12)
        bar = tk.Frame(self, bg=_C["panel"], pady=8)
        bar.pack(fill="x")
        self._status_var = tk.StringVar(value="Initializing…")
        tk.Label(
            bar, textvariable=self._status_var,
            bg=_C["panel"], fg=_C["text"], font=FONT_LABEL, anchor="w",
        ).pack(side="left", padx=12, fill="x", expand=True)

    def _style_tree_tags(self):
        tag_opts = {
            "online":  {"foreground": _C["success"]},
            "offline": {"foreground": _C["danger"]},
            "unknown": {"foreground": _C["warn"]},
            "blocked": {"foreground": _C["danger"], "background": _C["row_blocked"]},
            "alt":     {"background": _C["row_alt"]},
            "new":     {"background": _C["row_new"]},
        }
        for tree in (self._tree, self._hist_tree):
            for name, opts in tag_opts.items():
                tree.tag_configure(name, **opts)
            tree.tag_configure("base", background=_C["card"], foreground=_C["text"])

    # ── Interface selection ────────────────────────────────────────────────────

    def _reload_iface_combo(self):
        """Re-query interfaces (Scapy + OS fallback) and populate combobox."""
        self._iface_list = _iface_candidates()
        labels = []
        for idx, it in enumerate(self._iface_list, start=1):
            desc = it.get("description", it.get("name", "?"))
            ips  = ", ".join(it.get("ips", [])[:2]) or "no IP"
            labels.append(f"[{idx}] {desc}  ({ips})")
        self._iface_combo["values"] = labels

        if labels and not self._iface_combo.get():
            default = 0
            lip = self._net_info.get("ip", "")
            for i, it in enumerate(self._iface_list):
                if lip and lip in it.get("ips", []):
                    default = i
                    break
            self._iface_combo.current(default)
            self._apply_iface_selection(default)

    def _on_iface_combo(self, _event=None):
        """User picked from the dropdown list."""
        idx = self._iface_combo.current()
        if idx >= 0:
            self._apply_iface_selection(idx)

    def _on_iface_manual(self, _event=None):
        """User typed a name manually and left the field / pressed Enter."""
        idx = self._iface_combo.current()
        if idx >= 0:
            # Selected from list — already handled
            return
        typed = sanitize_iface_hint(self._iface_combo.get())
        if typed:
            self.scapy_iface = typed
            self._var_scapy.set(self._short_guid(typed))
            self._var_iface.set(typed)
            self._pin_iface()
            self._set_status(f"Interface set manually: {typed}")

    def _apply_iface_selection(self, idx: int):
        if idx < 0 or idx >= len(self._iface_list):
            return
        it = self._iface_list[idx]
        self.scapy_iface = str(it["name"])
        self._var_scapy.set(self._short_guid(self.scapy_iface))
        self._var_iface.set(str(it.get("description", "")))
        self._pin_iface()
        gw = self._net_info.get("gateway", "") or ""
        if gw and _resolve_mac:
            try:
                self.gateway_mac = _resolve_mac(gw, self.scapy_iface) or ""
            except Exception:
                self.gateway_mac = ""

    @staticmethod
    def _short_guid(guid: str, max_len: int = 36) -> str:
        g = guid.replace(r"\Device\NPF_", "")
        return g if len(g) <= max_len else g[: max_len - 3] + "…"

    def _show_iface_picker(self):
        """Show interface picker dialog on startup."""
        self._reload_iface_combo()
        if not self._iface_list:
            messagebox.showwarning(
                "Interfaces",
                "No interfaces auto-detected.\n\n"
                "You can type the interface name manually in the Interface field\n"
                "(e.g. 'eth0', 'Ethernet', 'wlan0').\n\n"
                "On Windows: install Npcap and run as Administrator.\n"
                "On Linux/macOS: run as root (sudo).",
            )
            # Try Scapy default as a last resort
            try:
                from scapy.all import conf
                self.scapy_iface = str(conf.iface)
                self._var_scapy.set(self._short_guid(self.scapy_iface))
                self._iface_combo.set(self.scapy_iface)
            except Exception:
                pass
            return

        dlg = tk.Toplevel(self)
        dlg.title("Select Network Interface")
        dlg.configure(bg=_C["card"])
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        tk.Label(
            dlg,
            text="Select an interface below, or close and type one manually.",
            bg=_C["card"], fg=_C["text"], font=FONT_UI_B,
        ).pack(padx=16, pady=(12, 6))

        lb = tk.Listbox(
            dlg, bg=_C["input"], fg=_C["text"],
            selectbackground=_C["row_sel"], selectforeground=_C["text"],
            font=FONT_UI, height=min(8, len(self._iface_list)),
            highlightthickness=1, highlightbackground=_C["accent"],
            relief="flat", bd=0,
        )
        for idx, it in enumerate(self._iface_list, start=1):
            desc = it.get("description", "?")
            ips  = ", ".join(it.get("ips", [])[:2]) or "—"
            lb.insert("end", f"  [{idx}] {desc}  ({ips})")

        default = 0
        lip = self._net_info.get("ip", "")
        for i, it in enumerate(self._iface_list):
            if lip and lip in it.get("ips", []):
                default = i
                break
        lb.selection_set(default)
        lb.pack(padx=16, pady=4, fill="x")

        # Manual entry inside the dialog
        tk.Label(
            dlg, text="Or type interface name:",
            bg=_C["card"], fg=_C["text_dim"], font=FONT_LABEL,
        ).pack(padx=16, pady=(8, 2), anchor="w")
        manual_e = _NeonEntry(dlg, width=40)
        manual_e.pack(padx=16, pady=(0, 6), fill="x")

        def _ok():
            # Manual entry takes priority if filled
            manual = sanitize_iface_hint(manual_e.get())
            if manual:
                self.scapy_iface = manual
                self._var_scapy.set(self._short_guid(manual))
                self._var_iface.set(manual)
                self._iface_combo.set(manual)
                self._pin_iface()
                self._set_status(f"Interface set manually: {manual}")
            else:
                sel = lb.curselection()
                if sel:
                    self._iface_combo.current(sel[0])
                    self._apply_iface_selection(sel[0])
            dlg.destroy()

        _Btn(dlg, "OK", _ok, variant="primary").pack(pady=12)
        dlg.protocol("WM_DELETE_WINDOW", _ok)
        dlg.bind("<Return>", lambda _e: _ok())

    def _pin_iface(self) -> None:
        try:
            from scapy.all import conf
            conf.iface = self.scapy_iface
        except Exception:
            pass

    # ── Network detection ──────────────────────────────────────────────────────

    def _detect_network(self):
        try:
            info = get_network_info()
            self._net_info = info
            self.after(0, lambda: self._var_ip.set(info.get("ip", "—")))
            self.after(0, lambda: self._var_gw.set(info.get("gateway", "—")))
            self.after(0, lambda: self._var_iface.set(info.get("interface", "—")))
            self.after(0, lambda: self._var_range.set(info.get("range", "—")))
            if info.get("range"):
                r = info["range"]
                self.after(0, lambda: (
                    self._range_entry.delete(0, "end"),
                    self._range_entry.insert(0, r),
                ))
            if info.get("gateway"):
                g = info["gateway"]
                self.after(0, lambda: (
                    self._atk_gw_e.delete(0, "end"),
                    self._atk_gw_e.insert(0, g),
                ))
            self.after(0, lambda: self._set_status(
                f"Network detected — {info.get('ip')} on {info.get('interface')}"))
            self.after(0, self._reload_iface_combo)
        except Exception as exc:
            _log.exception("network detection: %s", exc)
            self.after(0, lambda: self._set_status("Network detection failed."))

    # ── Live scan ──────────────────────────────────────────────────────────────

    def _progress_cb(self, done: int, total: int, phase: str) -> None:
        with self._lock:
            self._scan_state.update(
                active=True, done=int(done), total=int(total), phase=str(phase),
            )

    def _merge_scan_results(self, devices: list[dict]) -> None:
        now = time.time()
        seen_macs: set[str] = set()
        with self._lock:
            for d in devices:
                mac = d.get("mac") or ""
                if not mac or mac == "Unknown":
                    continue
                seen_macs.add(mac)
                d.setdefault("first_seen", now)
                d["last_seen"] = now
                d["status"] = "Online"

                if _FINGERPRINT_AVAILABLE and _FP_ENGINE:
                    try:
                        r = _FP_ENGINE.analyze_dict({
                            "protocol": "arp", "src_mac": mac,
                            "src_ip": d.get("ip", ""),
                        })
                        if r.os_family and d.get("os") in (None, "", "Unknown"):
                            d["os"] = r.os_family
                        if r.vendor and d.get("vendor") in (
                            None, "", "Unknown", "Generic / Not in DB",
                        ):
                            d["vendor"] = r.vendor
                    except Exception:
                        pass

                existing = self._devices.get(mac, {})
                if not existing:
                    self._new_macs.add(mac)
                if existing.get("os") and not d.get("os"):
                    d["os"] = existing["os"]
                if existing.get("hostname") and d.get("hostname") == "Unknown":
                    d["hostname"] = existing["hostname"]
                self._devices[mac] = {**existing, **d}

            for mac, rec in self._devices.items():
                if mac not in seen_macs and rec.get("status") == "Online":
                    ls = rec.get("last_seen")
                    if isinstance(ls, (int, float)) and now - ls > OFFLINE_AFTER_SEC:
                        rec["status"] = "Offline"

    def _live_scan_loop(self):
        while not self._stop.is_set() and self._live_scan_on:
            rng = self._range_entry.get().strip() or (self._net_info.get("range") or "")
            if not rng:
                with self._lock:
                    self._status_text = "Enter a network range"
                if self._stop.wait(timeout=3):
                    break
                continue

            if not self.scapy_iface:
                with self._lock:
                    self._status_text = "Select an interface"
                if self._stop.wait(timeout=3):
                    break
                continue

            with self._lock:
                self._status_text = "Scanning…"
            self._stop_scan.clear()
            with self._lock:
                self._scan_state.update(active=True, done=0, total=1, phase="arp_sweep")

            self._pin_iface()
            try:
                devices, err = scan_network_logic(
                    rng, self.scapy_iface,
                    progress_cb=self._progress_cb,
                    stop_event=self._stop_scan,
                )
            except Exception as exc:
                devices, err = [], "Scan failed."
                _log.exception("scan: %s", exc)
            finally:
                with self._lock:
                    self._scan_state["active"] = False

            if self._stop.is_set() or not self._live_scan_on:
                break

            if err:
                with self._lock:
                    self._status_text = f"Error: {err}"
            else:
                self._merge_scan_results(devices or [])
                n = len(devices or [])
                with self._lock:
                    self._status_text = f"Live scan — {n} host(s) found"
                try:
                    with self._lock:
                        self._storage.save_devices(list(self._devices.values()))
                except Exception:
                    pass

            # Wait between sweeps, checking stop every 100 ms
            for _ in range(int(SCAN_INTERVAL_SEC * 10)):
                if self._stop.is_set() or self._stop_scan.is_set() or not self._live_scan_on:
                    break
                time.sleep(0.1)

        self._live_scan_on = False
        with self._lock:
            self._status_text = "Scan stopped"
        self.after(0, lambda: (
            self._btn_live.config(state="normal"),
            self._btn_stop_live.config(state="disabled"),
        ))

    def _start_live_scan(self):
        if self._live_scan_on:
            return
        if not self.scapy_iface:
            messagebox.showwarning("Interface", "Select or type a network interface first.")
            return
        self._stop.clear()
        self._stop_scan.clear()
        self._live_scan_on = True
        self._btn_live.config(state="disabled")
        self._btn_stop_live.config(state="normal")
        self._set_status("Live scan started")
        threading.Thread(
            target=self._live_scan_loop, daemon=True, name="gs-live-scan",
        ).start()
        if not self._sniffing:
            self._start_sniffer()

    def _stop_live_scan(self):
        self._live_scan_on = False
        self._stop_scan.set()
        self._btn_live.config(state="normal")
        self._btn_stop_live.config(state="disabled")
        self._set_status("Stopping scan…")

    # ── Sniffer ────────────────────────────────────────────────────────────────

    def _start_sniffer(self):
        if self._sniffing:
            return
        if not self.scapy_iface:
            messagebox.showwarning("Interface", "Select or type an interface first.")
            return
        self._stop_sniff.clear()
        self._sniffing = True
        self._btn_sniff.config(state="disabled")
        self._btn_stop_sniff.config(state="normal")
        self._var_sniff_ind.set("SNIFFER ON")
        self._pin_iface()
        threading.Thread(
            target=start_sniffer,
            kwargs=dict(
                interface=self.scapy_iface,
                stop_event=self._stop_sniff,
                callback=self._sniff_callback,
                gateway_ip=self._net_info.get("gateway", "") or "",
                gateway_mac=self.gateway_mac,
            ),
            daemon=True, name="gs-sniffer",
        ).start()
        self._sniff_append("Sniffer started.\n", "ts")

    def _stop_sniffer(self):
        self._stop_sniff.set()
        self._sniffing = False
        self._btn_sniff.config(state="normal")
        self._btn_stop_sniff.config(state="disabled")
        self._var_sniff_ind.set("SNIFFER OFF")
        self._sniff_append("Sniffer stopped.\n", "ts")

    def _sniff_callback(self, event_type: str, data: dict):
        self.after(0, self._handle_sniff_event, event_type, data)

    def _handle_sniff_event(self, event_type: str, data: dict):
        ts = time.strftime("%H:%M:%S")
        if event_type == "dhcp":
            ip  = data.get("ip",  "?")
            mac = data.get("mac", "?")
            hn  = data.get("hostname", "?")
            self._sniff_append(f"[{ts}] ", "ts")
            self._sniff_append(f"DHCP  ip={ip}  mac={mac}  host={hn}\n", "dhcp")
            with self._lock:
                if mac and mac != "?":
                    now    = time.time()
                    is_new = mac not in self._devices
                    rec    = self._devices.setdefault(mac, {"mac": mac})
                    if is_new:
                        self._new_macs.add(mac)
                    rec.setdefault("first_seen", now)
                    rec["last_seen"] = now
                    rec.update(ip=ip, hostname=hn, status="Online")
                    if _FINGERPRINT_AVAILABLE and _FP_ENGINE:
                        try:
                            r = _FP_ENGINE.analyze_dict({
                                "protocol": "dhcpv4", "src_mac": mac, "src_ip": ip,
                                "hostname": hn, "opt60": data.get("opt60"),
                                "opt55": data.get("opt55") or [],
                            })
                            if r.os_family and not rec.get("os"):
                                rec["os"] = r.os_family
                            if r.vendor and rec.get("vendor") in (
                                None, "", "Unknown", "Generic / Not in DB",
                            ):
                                rec["vendor"] = r.vendor
                        except Exception:
                            pass
        elif event_type == "arp_spoof":
            self._sniff_append(
                f"[{ts}] ARP SPOOF  attacker={data.get('attacker_mac', '?')}\n", "spoof")
        elif event_type == "randomized_mac":
            self._sniff_append(
                f"[{ts}] Randomized MAC  mac={data.get('mac', '?')}\n", "randmac")

    def _sniff_append(self, text: str, tag: str = ""):
        self._sniff_log.configure(state="normal")
        self._sniff_log.insert("end", text, tag)
        self._sniff_log.see("end")
        self._sniff_log.configure(state="disabled")

    def _clear_sniff_log(self):
        self._sniff_log.configure(state="normal")
        self._sniff_log.delete("1.0", "end")
        self._sniff_log.configure(state="disabled")

    # ── Attack ─────────────────────────────────────────────────────────────────

    def _start_attack(self):
        if not _ATTACKER_AVAILABLE:
            messagebox.showerror("Unavailable", "core_attacker not loaded.")
            return
        if self._attacking:
            return
        target = self._atk_target_e.get().strip()
        gw     = self._atk_gw_e.get().strip()
        iface  = self.scapy_iface or resolve_iface("")
        if not target or not gw:
            messagebox.showwarning("Input", "Enter Target IP and Gateway IP.")
            return
        if not _validate_ipv4(target) or not _validate_ipv4(gw):
            messagebox.showwarning("Input", "Enter valid IPv4 addresses.")
            return
        self._stop_attack.clear()
        self._attacking = True
        self._btn_atk_start.config(state="disabled")
        self._btn_atk_stop.config(state="normal")
        self._var_atk_ind.set("ATTACK ON")
        threading.Thread(
            target=self._attack_worker, args=(target, gw, iface), daemon=True,
        ).start()

    def _attack_worker(self, target: str, gw: str, iface: str):
        err = run_attack(target, gw, iface, self._stop_attack)
        msg = f"Error: {err}\n" if err else "Session ended — network restored.\n"
        tag = "err" if err else "ok"
        self.after(0, lambda: self._atk_log_append(msg, tag))
        self._attacking = False
        self.after(0, lambda: (
            self._btn_atk_start.config(state="normal"),
            self._btn_atk_stop.config(state="disabled"),
            self._var_atk_ind.set("ATTACK OFF"),
        ))

    def _stop_attack_cb(self):
        self._stop_attack.set()
        self._atk_log_append("Stop signal sent…\n", "ok")

    def _atk_log_append(self, text: str, tag: str = ""):
        ts = time.strftime("%H:%M:%S")
        self._atk_log.configure(state="normal")
        self._atk_log.insert("end", f"[{ts}]  ", "ts")
        self._atk_log.insert("end", text, tag)
        self._atk_log.see("end")
        self._atk_log.configure(state="disabled")

    # ── History ────────────────────────────────────────────────────────────────

    def _reload_history(self):
        for item in self._hist_tree.get_children():
            self._hist_tree.delete(item)
        for dev in self._storage.load_devices():
            self._hist_tree.insert("", "end", values=(
                dev.get("mac", ""), dev.get("ip", ""),
                dev.get("vendor", ""), dev.get("hostname", ""),
                dev.get("os", ""),
            ))

    def _clear_history(self):
        if not messagebox.askyesno("Confirm", "Clear ALL stored device history?"):
            return
        self._storage.save_devices([])
        with self._lock:
            self._devices.clear()
        self._reload_history()
        self._refresh_tree()
        self._set_status("History cleared.")

    # ── Tree refresh (called every UI_REFRESH_MS) ──────────────────────────────

    def _refresh_tree(self):
        for item in self._tree.get_children():
            self._tree.delete(item)

        with self._lock:
            snapshot = list(self._devices.values())
            st       = dict(self._scan_state)
            status_text = self._status_text
            new_macs = set(self._new_macs)

        snapshot.sort(key=lambda d: (d.get("status") != "Online", d.get("ip", "")))

        for i, dev in enumerate(snapshot):
            uptime = ""
            if dev.get("first_seen"):
                secs = int(time.time() - dev["first_seen"])
                h, r = divmod(secs, 3600)
                m, s = divmod(r, 60)
                uptime = f"{h:02d}:{m:02d}:{s:02d}"

            vals = (
                dev.get("ip", ""),       dev.get("mac", ""),
                dev.get("vendor", ""),   dev.get("hostname", ""),
                dev.get("os", ""),       dev.get("status", ""),
                uptime,
            )
            status = dev.get("status", "")
            if status == "Online":
                st_tag = "online"
            elif status == "Blocked":
                st_tag = "blocked"
            elif status in ("Unknown", ""):
                st_tag = "unknown"
            else:
                st_tag = "offline"

            tags: list[str] = ["base", st_tag]
            if i % 2 == 1:
                tags.append("alt")
            if dev.get("mac", "") in new_macs:
                tags.append("new")

            self._tree.insert("", "end", values=vals, tags=tuple(tags))

        self._var_count.set(str(len(snapshot)))
        self._var_status.set(status_text)

        if st.get("active"):
            done  = int(st.get("done") or 0)
            total = max(int(st.get("total") or 1), 1)
            pct   = 100.0 * done / total
            self._var_progress.set(
                f"{st.get('phase', 'scan')} {pct:5.1f}% ({done}/{total})")
        else:
            self._var_progress.set("")

        # Mark devices offline if not seen recently
        now = time.time()
        with self._lock:
            for rec in self._devices.values():
                ls = rec.get("last_seen")
                if isinstance(ls, (int, float)) and now - ls > OFFLINE_AFTER_SEC:
                    if rec.get("status") == "Online":
                        rec["status"] = "Offline"

    def _ui_tick(self):
        self._clock_var.set(time.strftime("  %Y-%m-%d  %H:%M:%S"))
        self._refresh_tree()
        self.after(UI_REFRESH_MS, self._ui_tick)

    # ── Device detail popup ────────────────────────────────────────────────────

    def _on_device_select(self, _event):
        sel = self._tree.selection()
        if not sel:
            return
        vals = self._tree.item(sel[0], "values")
        if not vals:
            return
        ip, mac = vals[0], vals[1]
        with self._lock:
            dev = self._devices.get(mac, {})

        popup = tk.Toplevel(self)
        popup.title(f"Device — {ip}")
        popup.configure(bg=_C["card"])
        popup.resizable(False, False)

        tk.Label(popup, text=ip, bg=_C["card"], fg=_C["text"],
                 font=(_UI_FONT, 14, "bold")).pack(pady=(12, 6))

        def _row(lbl: str, val: str):
            f = tk.Frame(popup, bg=_C["card"], padx=14, pady=3)
            f.pack(fill="x")
            tk.Label(f, text=lbl + ":", width=12, anchor="w",
                     bg=_C["card"], fg=_C["text_dim"], font=FONT_LABEL).pack(side="left")
            tk.Label(f, text=val, bg=_C["card"], fg=_C["text"],
                     font=FONT_UI).pack(side="left")

        for lbl, key in (
            ("MAC",      "mac"),      ("Vendor",   "vendor"),
            ("Hostname", "hostname"), ("OS",       "os"),
            ("Status",   "status"),
        ):
            _row(lbl, dev.get(key, ""))

        def _block():
            self._atk_target_e.delete(0, "end")
            self._atk_target_e.insert(0, ip)
            self._nb.select(self._tab_attack)
            popup.destroy()

        _Btn(popup, "Block this device", _block, variant="danger").pack(pady=12)

    # ── Export ─────────────────────────────────────────────────────────────────

    def _export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="ghost_sentinel_export.csv",
        )
        if not path:
            return
        try:
            with self._lock:
                snapshot = list(self._devices.values())
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f, quoting=csv.QUOTE_ALL)
                w.writerow(["IP", "MAC", "Vendor", "Hostname", "OS", "Status", "Time"])
                for dev in snapshot:
                    uptime = ""
                    if dev.get("first_seen"):
                        secs = int(time.time() - dev["first_seen"])
                        h, r = divmod(secs, 3600)
                        m, s = divmod(r, 60)
                        uptime = f"{h:02d}:{m:02d}:{s:02d}"
                    w.writerow([
                        dev.get("ip", ""), dev.get("mac", ""),
                        dev.get("vendor", ""), dev.get("hostname", ""),
                        dev.get("os", ""), dev.get("status", ""), uptime,
                    ])
            self._set_status(f"Exported {len(snapshot)} devices → {path}")
        except Exception as exc:
            _log.exception("export: %s", exc)
            messagebox.showerror("Export Failed", "Could not write export file.")

    def _set_status(self, msg: str):
        self._status_text = msg
        self._status_var.set(msg)

    # ── Cleanup ────────────────────────────────────────────────────────────────

    def _on_close(self):
        self._live_scan_on = False
        self._stop.set()
        self._stop_scan.set()
        self._stop_sniff.set()
        self._stop_attack.set()
        try:
            with self._lock:
                self._storage.save_devices(list(self._devices.values()))
        except Exception:
            pass
        self.destroy()


# ── CLI export mode ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if "--export" in sys.argv:
        raw = sys.argv[-1] if sys.argv[-1].endswith(".csv") else "ghost_sentinel_export.csv"
        path = _safe_cli_export_path(raw)
        st = Storage()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, quoting=csv.QUOTE_ALL)
            w.writerow(["IP", "MAC", "Vendor", "Hostname", "OS", "Status"])
            for d in st.load_devices():
                w.writerow([
                    d.get("ip", ""), d.get("mac", ""), d.get("vendor", ""),
                    d.get("hostname", ""), d.get("os", ""), d.get("status", ""),
                ])
        print(f"Exported to {path}")
        sys.exit(0)

    app = GhostSentinel()
    app.mainloop()
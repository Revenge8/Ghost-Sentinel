# core/os_intel.py — Ghost Sentinel OS Intelligence Knowledge Base
# =================================================================
# Houses reference data and heuristics for:
#   1. Mapping vendors → expected firmware/OS  (IoT & embedded)
#   2. Correlating Linux kernel versions → likely distributions
#   3. Windows build number → friendly name
#   4. Plausibility checks that catch improbable OS detections
#
# This module is pure data + logic — no Scapy, no network I/O.
# Import it anywhere without side effects.
from __future__ import annotations

import sys
import os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import re
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════
# Confidence tier
# ═══════════════════════════════════════════════════════════════════

class ConfidenceTier(Enum):
    """How strongly a fingerprint result has been validated."""
    VALIDATED = "VALIDATED"   # Multiple sources agree + consistent with profile
    PLAUSIBLE = "PLAUSIBLE"   # One source, consistent with manufacturer/device
    SUSPECT   = "SUSPECT"     # Detection contradicts known device characteristics
    UNKNOWN   = "UNKNOWN"     # Not enough data to judge

# Backward-compat alias
ValidationStatus = ConfidenceTier


# ═══════════════════════════════════════════════════════════════════
# Vendor → firmware / OS knowledge base
# ═══════════════════════════════════════════════════════════════════
#
# Each entry carries:
#   os_family          — default OS family
#   firmware_patterns  — list of (regex_str, firmware_name, version_regex|None)
#   expected_kernels   — list of (kernel_prefix, firmware_version_label)
#   device_types       — list of device categories this vendor ships
#   aliases            — alternative vendor name spellings
#   expected_os_families — (optional) broader set of plausible OSes

VENDOR_FIRMWARE_DB: Dict[str, Dict[str, Any]] = {

    # ── Network Equipment ──────────────────────────────────────────
    "Ubiquiti": {
        "os_family": "Linux",
        "aliases": ["Ubiquiti Inc", "Ubiquiti Networks", "UBNT"],
        "firmware_patterns": [
            (r"UniFi[\s-]?OS\s*([\d.]+)?",  "UniFi OS",        r"([\d.]+)"),
            (r"EdgeOS\s*([\d.]+)?",          "EdgeOS",           r"([\d.]+)"),
            (r"EdgeRouter",                  "EdgeOS",           None),
            (r"EdgeSwitch",                  "EdgeSwitch OS",    None),
            (r"AirOS\s*([\d.]+)?",           "AirOS",            r"([\d.]+)"),
            (r"AirMax",                      "AirOS",            None),
            (r"UniFi\s*Protect",             "UniFi OS",         None),
            (r"UniFi\s*Video",               "UniFi Video",      None),
        ],
        "expected_kernels": [
            ("2.6", "Legacy Firmware"),
            ("3.2",  "EdgeOS 1.x / AirOS 5.x"),
            ("3.10", "EdgeOS 1.x / UniFi OS 1.x"),
            ("4.4",  "EdgeOS 2.x / UniFi OS 2.x"),
            ("4.9",  "UniFi OS 3.x"),
            ("4.14", "EdgeOS 2.x"),
            ("5.4",  "UniFi OS 4.x"),
            ("5.10", "UniFi OS 4.x"),
        ],
        "device_types": ["access_point", "router", "switch", "camera", "nvr", "general purpose"],
    },

    "MikroTik": {
        "os_family": "RouterOS",
        "aliases": ["Mikrotikls", "MikroTik Ltd"],
        "firmware_patterns": [
            (r"RouterOS\s*([\d.]+)?", "RouterOS", r"([\d.]+)"),
            (r"SwOS\s*([\d.]+)?",     "SwOS",     r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.3",  "RouterOS 6.x"),
            ("4.14", "RouterOS 7.x"),
            ("5.6",  "RouterOS 7.x"),
        ],
        "device_types": ["router", "switch", "access_point"],
        "expected_os_families": ["RouterOS", "Linux"],
    },

    "Cisco": {
        "os_family": "Cisco IOS",
        "aliases": ["Cisco Systems", "Cisco-Linksys"],
        "firmware_patterns": [
            (r"IOS[\s-]?XE?\s*([\d.]+)?", "Cisco IOS", r"([\d.()]+)"),
            (r"NX-OS\s*([\d.]+)?",         "NX-OS",     r"([\d.]+)"),
            (r"ASA\s*([\d.]+)?",           "Cisco ASA", r"([\d.]+)"),
            (r"Firepower",                 "Firepower",  None),
        ],
        "expected_kernels": [],
        "device_types": ["router", "switch", "firewall", "access_point"],
        "expected_os_families": ["Cisco IOS", "Linux"],
    },

    "Juniper": {
        "os_family": "JunOS",
        "aliases": ["Juniper Networks"],
        "firmware_patterns": [
            (r"JunOS\s*([\d.]+)?", "JunOS", r"([\d.]+)"),
            (r"Junos\s*([\d.]+)?", "JunOS", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("2.6",  "JunOS (FreeBSD-based)"),
            ("3.10", "JunOS Evolved"),
        ],
        "device_types": ["router", "switch", "firewall"],
        "expected_os_families": ["JunOS", "FreeBSD", "Linux"],
    },

    "Fortinet": {
        "os_family": "FortiOS",
        "aliases": ["Fortinet Inc"],
        "firmware_patterns": [
            (r"FortiOS\s*([\d.]+)?", "FortiOS", r"([\d.]+)"),
            (r"FortiGate",           "FortiOS",  None),
            (r"FortiWiFi",           "FortiOS",  None),
        ],
        "expected_kernels": [
            ("2.6",  "FortiOS 5.x"),
            ("3.2",  "FortiOS 6.x"),
            ("4.14", "FortiOS 7.x"),
        ],
        "device_types": ["firewall", "router", "access_point"],
    },

    "Aruba": {
        "os_family": "ArubaOS",
        "aliases": ["Aruba Networks", "HPE Aruba",
                    "Aruba, a Hewlett Packard Enterprise Company"],
        "firmware_patterns": [
            (r"ArubaOS\s*([\d.]+)?",    "ArubaOS",          r"([\d.]+)"),
            (r"Aruba\s*Instant",         "Aruba InstantOS",  None),
        ],
        "expected_kernels": [
            ("3.10", "ArubaOS 6.x"),
            ("4.4",  "ArubaOS 8.x"),
        ],
        "device_types": ["access_point", "switch", "controller"],
    },

    "Ruckus": {
        "os_family": "Linux",
        "aliases": ["Ruckus Wireless", "Ruckus Networks", "CommScope Ruckus"],
        "firmware_patterns": [
            (r"SmartZone\s*([\d.]+)?",  "SmartZone",         r"([\d.]+)"),
            (r"ZoneDirector",           "ZoneDirector",       None),
            (r"Unleashed\s*([\d.]+)?",  "Ruckus Unleashed",  r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.14", "Ruckus Firmware"),
            ("4.4",  "Ruckus Firmware"),
        ],
        "device_types": ["access_point", "controller"],
    },

    "Cisco Meraki": {
        "os_family": "Linux",
        "aliases": ["Meraki", "Cisco Meraki"],
        "firmware_patterns": [
            (r"Meraki\s*MR", "Meraki MR", None),
            (r"Meraki\s*MS", "Meraki MS", None),
            (r"Meraki\s*MX", "Meraki MX", None),
        ],
        "expected_kernels": [
            ("3.10", "Meraki Firmware"),
            ("4.4",  "Meraki Firmware"),
            ("4.9",  "Meraki Firmware"),
        ],
        "device_types": ["access_point", "switch", "firewall", "camera"],
        "expected_os_families": ["Linux"],
    },

    "TP-Link": {
        "os_family": "Linux",
        "aliases": ["TP-LINK", "TP-Link Technologies", "TP-Link Technologies Co.,Ltd."],
        "firmware_patterns": [
            (r"Omada", "Omada Controller", None),
            (r"EAP",   "TP-Link EAP",     None),
        ],
        "expected_kernels": [
            ("2.6",  "Legacy TP-Link"),
            ("3.10", "TP-Link Firmware"),
            ("4.4",  "TP-Link Firmware"),
        ],
        "device_types": ["router", "access_point", "switch"],
    },

    "D-Link": {
        "os_family": "Linux",
        "aliases": ["D-Link Corporation", "D-Link Systems"],
        "firmware_patterns": [
            (r"D-Link", "D-Link Firmware", None),
            (r"DIR-",   "D-Link Router",   None),
        ],
        "expected_kernels": [
            ("2.6",  "D-Link Firmware"),
            ("3.10", "D-Link Firmware"),
            ("4.4",  "D-Link Firmware"),
        ],
        "device_types": ["router", "switch", "access_point", "camera"],
        "expected_os_families": ["Linux"],
    },

    "Linksys": {
        "os_family": "Linux",
        "aliases": ["Linksys LLC", "Belkin Linksys"],
        "firmware_patterns": [
            (r"Linksys", "Linksys Firmware", None),
            (r"OpenWrt",  "OpenWrt",          None),
        ],
        "expected_kernels": [
            ("2.6",  "Linksys Firmware"),
            ("3.10", "Linksys Firmware"),
            ("4.4",  "Linksys Firmware / OpenWrt"),
            ("4.14", "OpenWrt"),
            ("5.4",  "OpenWrt"),
        ],
        "device_types": ["router", "switch", "access_point"],
        "expected_os_families": ["Linux"],
    },

    "ASUS": {
        "os_family": "Linux",
        "aliases": ["ASUSTeK Computer", "ASUS Computer"],
        "firmware_patterns": [
            (r"ASUSWRT",        "ASUSWRT",         None),
            (r"ASUSWRT-Merlin", "ASUSWRT-Merlin",  None),
        ],
        "expected_kernels": [
            ("2.6",  "ASUSWRT"),
            ("3.10", "ASUSWRT"),
            ("4.4",  "ASUSWRT"),
        ],
        "device_types": ["router", "access_point", "workstation", "general purpose"],
        "expected_os_families": ["Linux", "Windows"],
    },

    "Netgear": {
        "os_family": "Linux",
        "aliases": ["NETGEAR"],
        "firmware_patterns": [
            (r"ReadyNAS\s*OS\s*([\d.]+)?", "ReadyNAS OS", r"([\d.]+)"),
            (r"ReadyNAS",                   "ReadyNAS OS",  None),
        ],
        "expected_kernels": [
            ("3.2", "ReadyNAS OS 6.x"),
            ("4.4", "ReadyNAS OS 6.x"),
        ],
        "device_types": ["storage", "nas", "router", "switch", "access_point"],
    },

    "Zyxel": {
        "os_family": "Linux",
        "aliases": ["ZyXEL Communications"],
        "firmware_patterns": [
            (r"ZyXEL", "ZyXEL Firmware", None),
            (r"Zyxel",  "Zyxel Firmware",  None),
        ],
        "expected_kernels": [
            ("2.6",  "ZyXEL Firmware"),
            ("3.10", "ZyXEL Firmware"),
            ("4.4",  "ZyXEL Firmware"),
        ],
        "device_types": ["router", "switch", "access_point", "firewall"],
        "expected_os_families": ["Linux"],
    },

    "Draytek": {
        "os_family": "Linux",
        "aliases": ["DrayTek Corporation"],
        "firmware_patterns": [
            (r"DrayTek", "DrayTek Firmware", None),
            (r"Vigor",    "Vigor Firmware",   None),
        ],
        "expected_kernels": [
            ("2.6",  "DrayTek Firmware"),
            ("3.10", "DrayTek Firmware"),
            ("4.4",  "DrayTek Firmware"),
        ],
        "device_types": ["router", "firewall", "vpn"],
        "expected_os_families": ["Linux"],
    },

    "Sophos": {
        "os_family": "Linux",
        "aliases": ["Sophos Ltd"],
        "firmware_patterns": [
            (r"SFOS\s*([\d.]+)?",  "Sophos Firewall OS", r"([\d.]+)"),
            (r"UTM\s*([\d.]+)?",   "Sophos UTM",         r"([\d.]+)"),
            (r"XG\s*Firewall",     "Sophos XG Firewall",  None),
        ],
        "expected_kernels": [
            ("3.10", "SFOS"),
            ("4.4",  "SFOS"),
            ("4.9",  "SFOS"),
        ],
        "device_types": ["firewall", "router"],
        "expected_os_families": ["Linux"],
    },

    "pfSense": {
        "os_family": "FreeBSD",
        "aliases": ["Netgate", "pfSense"],
        "firmware_patterns": [
            (r"pfSense\s*([\d.]+)?", "pfSense", r"([\d.]+)"),
        ],
        "expected_kernels": [],
        "device_types": ["firewall", "router"],
        "expected_os_families": ["FreeBSD"],
    },

    "OPNsense": {
        "os_family": "FreeBSD",
        "aliases": ["Deciso", "OPNsense"],
        "firmware_patterns": [
            (r"OPNsense\s*([\d.]+)?", "OPNsense", r"([\d.]+)"),
        ],
        "expected_kernels": [],
        "device_types": ["firewall", "router"],
        "expected_os_families": ["FreeBSD"],
    },

    "Cambium": {
        "os_family": "Linux",
        "aliases": ["Cambium Networks"],
        "firmware_patterns": [
            (r"cnPilot", "cnPilot", None),
            (r"ePMP",    "ePMP",    None),
            (r"PMP",     "PMP",     None),
        ],
        "expected_kernels": [
            ("3.10", "Cambium Firmware"),
            ("4.4",  "Cambium Firmware"),
        ],
        "device_types": ["access_point", "router"],
        "expected_os_families": ["Linux"],
    },

    # ── NAS ────────────────────────────────────────────────────────
    "Synology": {
        "os_family": "Linux",
        "aliases": ["Synology Inc"],
        "firmware_patterns": [
            (r"DSM\s*([\d.]+)?",  "DSM",  r"([\d.]+)"),
            (r"DiskStation",       "DSM",   None),
            (r"RackStation",       "DSM",   None),
            (r"SRM\s*([\d.]+)?",  "SRM",  r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("2.6",  "DSM 4.x"),
            ("3.2",  "DSM 5.x"),
            ("3.10", "DSM 5.x/6.x"),
            ("4.4",  "DSM 6.x"),
            ("5.10", "DSM 7.x"),
        ],
        "device_types": ["storage", "nas", "router", "general purpose"],
    },

    "QNAP": {
        "os_family": "Linux",
        "aliases": ["QNAP Systems"],
        "firmware_patterns": [
            (r"QTS\s*([\d.]+)?",           "QTS",       r"([\d.]+)"),
            (r"QuTS\s*hero\s*([\d.]+)?",   "QuTS Hero", r"([\d.]+)"),
            (r"QES\s*([\d.]+)?",           "QES",       r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.4",  "QTS 4.2.x"),
            ("4.2",  "QTS 4.3.x"),
            ("4.14", "QTS 4.4.x/4.5.x"),
            ("5.10", "QTS 5.x"),
        ],
        "device_types": ["storage", "nas", "general purpose"],
    },

    "Western Digital": {
        "os_family": "Linux",
        "aliases": ["WD", "Western Digital Technologies"],
        "firmware_patterns": [
            (r"My\s*Cloud\s*OS\s*([\d.]+)?", "My Cloud OS", r"([\d.]+)"),
            (r"WD\s*My\s*Cloud",              "My Cloud OS",  None),
        ],
        "expected_kernels": [
            ("3.2",  "My Cloud OS 3.x"),
            ("4.14", "My Cloud OS 5.x"),
        ],
        "device_types": ["storage", "nas"],
    },

    "Buffalo": {
        "os_family": "Linux",
        "aliases": ["Buffalo Inc", "Buffalo Technology"],
        "firmware_patterns": [
            (r"LinkStation",  "LinkStation",  None),
            (r"TeraStation",  "TeraStation",  None),
        ],
        "expected_kernels": [
            ("2.6",  "Buffalo Firmware"),
            ("3.10", "Buffalo Firmware"),
            ("4.4",  "Buffalo Firmware"),
        ],
        "device_types": ["storage", "nas", "router"],
        "expected_os_families": ["Linux"],
    },

    "Asustor": {
        "os_family": "Linux",
        "aliases": ["ASUSTOR Inc"],
        "firmware_patterns": [
            (r"ADM\s*([\d.]+)?", "ADM", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.10", "ADM 2.x/3.x"),
            ("4.4",  "ADM 3.x/4.x"),
            ("5.10", "ADM 4.x"),
        ],
        "device_types": ["storage", "nas"],
        "expected_os_families": ["Linux"],
    },

    "TrueNAS": {
        "os_family": "FreeBSD",
        "aliases": ["iXsystems", "FreeNAS"],
        "firmware_patterns": [
            (r"TrueNAS\s*([\d.]+)?", "TrueNAS",  r"([\d.]+)"),
            (r"FreeNAS\s*([\d.]+)?", "FreeNAS",  r"([\d.]+)"),
        ],
        "expected_kernels": [],
        "device_types": ["storage", "nas", "server"],
        "expected_os_families": ["FreeBSD", "Linux"],
    },

    # ── IoT / Smart Home ──────────────────────────────────────────
    "Raspberry Pi": {
        "os_family": "Linux",
        "aliases": ["Raspberry Pi Foundation", "Raspberry Pi Trading Ltd"],
        "firmware_patterns": [
            (r"Raspbian",          "Raspberry Pi OS", None),
            (r"Raspberry\s*Pi\s*OS", "Raspberry Pi OS", None),
        ],
        "expected_kernels": [
            ("4.9",  "Raspberry Pi OS (Stretch)"),
            ("4.19", "Raspberry Pi OS (Buster)"),
            ("5.10", "Raspberry Pi OS (Bullseye)"),
            ("5.15", "Raspberry Pi OS (Bullseye)"),
            ("6.1",  "Raspberry Pi OS (Bookworm)"),
        ],
        "device_types": ["general purpose", "iot", "embedded"],
    },

    "Espressif": {
        "os_family": "RTOS",
        "aliases": ["Espressif Inc", "Espressif Systems"],
        "firmware_patterns": [
            (r"ESP-IDF\s*([\d.]+)?", "ESP-IDF",  r"([\d.]+)"),
            (r"ESP32",               "ESP-IDF",   None),
            (r"ESP8266",             "ESP SDK",   None),
        ],
        "expected_kernels": [],
        "device_types": ["iot", "embedded"],
    },

    "Amazon": {
        "os_family": "Linux",
        "aliases": ["Amazon.com", "Amazon Technologies"],
        "firmware_patterns": [
            (r"Fire\s*OS\s*([\d.]+)?", "Fire OS", r"([\d.]+)"),
            (r"Fire\s*TV",             "Fire TV",  None),
            (r"Echo",                  "Echo (Alexa)", None),
            (r"Kindle",                "Kindle",   None),
        ],
        "expected_kernels": [
            ("3.10", "Fire OS 5.x"),
            ("4.4",  "Fire OS 6.x"),
            ("4.9",  "Fire OS 7.x"),
        ],
        "device_types": ["media_player", "tv", "iot", "tablet", "ereader"],
        "expected_os_families": ["Linux", "Fire OS", "Android"],
    },

    "Google": {
        "os_family": "Linux",
        "aliases": ["Google LLC", "Google Inc"],
        "firmware_patterns": [
            (r"Chromecast",         "Chromecast",    None),
            (r"Google\s*TV",        "Google TV",     None),
            (r"Android\s*TV",       "Android TV",    None),
            (r"Google\s*Home",      "Google Home",   None),
            (r"Nest",               "Nest",          None),
        ],
        "expected_kernels": [
            ("3.10", "Chromecast / Android TV"),
            ("4.4",  "Android TV / Google Home"),
            ("4.9",  "Chromecast / Nest"),
        ],
        "device_types": ["media_player", "tv", "iot", "phone", "tablet", "camera"],
        "expected_os_families": ["Linux", "Android", "Chrome OS", "Fuchsia"],
    },

    "Ring": {
        "os_family": "Linux",
        "aliases": ["Ring LLC", "Ring (Amazon)"],
        "firmware_patterns": [(r"Ring", "Ring Firmware", None)],
        "expected_kernels": [("4.4", "Ring Firmware"), ("4.9", "Ring Firmware")],
        "device_types": ["camera", "iot"],
        "expected_os_families": ["Linux"],
    },

    "Nest": {
        "os_family": "Linux",
        "aliases": ["Nest Labs", "Google Nest"],
        "firmware_patterns": [(r"Nest", "Nest Firmware", None)],
        "expected_kernels": [
            ("3.10", "Nest Firmware"),
            ("4.4",  "Nest Firmware"),
            ("4.9",  "Nest Firmware"),
        ],
        "device_types": ["iot", "camera", "thermostat"],
        "expected_os_families": ["Linux"],
    },

    "Sonos": {
        "os_family": "Linux",
        "aliases": ["Sonos, Inc"],
        "firmware_patterns": [(r"Sonos\s*([\d.]+)?", "Sonos OS", r"([\d.]+)")],
        "expected_kernels": [
            ("3.10", "Sonos OS"),
            ("4.4",  "Sonos OS"),
            ("4.9",  "Sonos OS"),
        ],
        "device_types": ["media_player", "iot"],
        "expected_os_families": ["Linux"],
    },

    # ── Printers ──────────────────────────────────────────────────
    "HP": {
        "os_family": "Linux",
        "aliases": ["Hewlett-Packard", "Hewlett Packard", "HP Inc"],
        "firmware_patterns": [
            (r"JetDirect",              "HP JetDirect",   None),
            (r"FutureSmart\s*([\d.]+)?","HP FutureSmart", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("2.6",  "HP Firmware"),
            ("3.10", "HP FutureSmart"),
            ("4.4",  "HP FutureSmart"),
        ],
        "device_types": ["printer", "general purpose", "server"],
        "expected_os_families": ["Linux", "Windows"],
    },

    "Canon": {
        "os_family": "Embedded",
        "aliases": ["Canon Inc"],
        "firmware_patterns": [],
        "expected_kernels": [("2.6", "Canon Firmware"), ("3.0", "Canon Firmware")],
        "device_types": ["printer", "camera"],
    },

    "Xerox": {
        "os_family": "Linux",
        "aliases": ["Xerox Corporation"],
        "firmware_patterns": [(r"ConnectKey", "Xerox ConnectKey", None)],
        "expected_kernels": [("3.10", "Xerox Firmware"), ("4.4", "Xerox Firmware")],
        "device_types": ["printer"],
        "expected_os_families": ["Linux"],
    },

    "Brother": {
        "os_family": "Linux",
        "aliases": ["Brother Industries"],
        "firmware_patterns": [(r"Brother", "Brother Firmware", None)],
        "expected_kernels": [
            ("2.6",  "Brother Firmware"),
            ("3.10", "Brother Firmware"),
            ("4.4",  "Brother Firmware"),
        ],
        "device_types": ["printer"],
        "expected_os_families": ["Linux", "Embedded"],
    },

    "Epson": {
        "os_family": "Embedded",
        "aliases": ["Seiko Epson", "Epson Corporation"],
        "firmware_patterns": [(r"EPSON", "Epson Firmware", None)],
        "expected_kernels": [("2.6", "Epson Firmware"), ("3.10", "Epson Firmware")],
        "device_types": ["printer"],
        "expected_os_families": ["Linux", "Embedded"],
    },

    # ── Security Cameras ──────────────────────────────────────────
    "Hikvision": {
        "os_family": "Linux",
        "aliases": ["Hangzhou Hikvision", "HIKVISION"],
        "firmware_patterns": [(r"Hikvision", "Hikvision Firmware", None)],
        "expected_kernels": [
            ("3.0", "Hikvision Firmware"),
            ("3.4", "Hikvision Firmware"),
            ("4.9", "Hikvision Firmware"),
        ],
        "device_types": ["camera", "nvr", "dvr"],
    },

    "Dahua": {
        "os_family": "Linux",
        "aliases": ["Dahua Technology", "DAHUA"],
        "firmware_patterns": [(r"Dahua", "Dahua Firmware", None)],
        "expected_kernels": [("3.4", "Dahua Firmware"), ("4.9", "Dahua Firmware")],
        "device_types": ["camera", "nvr", "dvr"],
    },

    "Axis": {
        "os_family": "Linux",
        "aliases": ["Axis Communications"],
        "firmware_patterns": [(r"AXIS\s*OS\s*([\d.]+)?", "AXIS OS", r"([\d.]+)")],
        "expected_kernels": [
            ("3.4",  "AXIS OS"),
            ("4.9",  "AXIS OS"),
            ("4.14", "AXIS OS"),
        ],
        "device_types": ["camera"],
    },

    "Reolink": {
        "os_family": "Linux",
        "aliases": ["Reolink Digital"],
        "firmware_patterns": [(r"Reolink", "Reolink Firmware", None)],
        "expected_kernels": [("3.4", "Reolink Firmware"), ("4.9", "Reolink Firmware")],
        "device_types": ["camera", "nvr"],
        "expected_os_families": ["Linux"],
    },

    "Wyze": {
        "os_family": "Linux",
        "aliases": ["Wyze Labs"],
        "firmware_patterns": [(r"Wyze", "Wyze Firmware", None)],
        "expected_kernels": [("3.4", "Wyze Firmware"), ("4.9", "Wyze Firmware")],
        "device_types": ["camera", "iot"],
        "expected_os_families": ["Linux"],
    },

    # ── Smart TVs ─────────────────────────────────────────────────
    "Samsung": {
        "os_family": "Tizen",
        "aliases": ["Samsung Electronics", "Samsung Electronics Co."],
        "firmware_patterns": [
            (r"Tizen\s*([\d.]+)?", "Tizen",            r"([\d.]+)"),
            (r"SmartTV",           "Samsung Smart TV",  None),
            (r"SMART-TV",          "Samsung Smart TV",  None),
        ],
        "expected_kernels": [
            ("3.0",  "Tizen 2.x"),
            ("3.10", "Tizen 3.x"),
            ("4.4",  "Tizen 4.x/5.x"),
            ("4.9",  "Tizen 5.x/6.x"),
        ],
        "device_types": ["tv", "phone", "tablet", "camera", "storage", "general purpose"],
        "expected_os_families": ["Tizen", "Android", "Linux"],
    },

    "LG": {
        "os_family": "webOS",
        "aliases": ["LG Electronics", "LG Electronics Inc"],
        "firmware_patterns": [
            (r"webOS\s*([\d.]+)?", "webOS",       r"([\d.]+)"),
            (r"Web0S",             "webOS",        None),
            (r"NetCast",           "NetCast",      None),
            (r"SMART-TV",          "LG Smart TV",  None),
        ],
        "expected_kernels": [
            ("3.4",  "webOS 1.x/2.x"),
            ("3.10", "webOS 3.x"),
            ("4.4",  "webOS 4.x"),
            ("4.9",  "webOS 5.x/6.x"),
        ],
        "device_types": ["tv", "phone", "tablet", "general purpose"],
        "expected_os_families": ["webOS", "Android", "Linux"],
    },

    "Sony": {
        "os_family": "Linux",
        "aliases": ["Sony Corporation", "Sony Interactive Entertainment"],
        "firmware_patterns": [
            (r"PlayStation\s*(\d+)", "PlayStation",  r"(\d+)"),
            (r"BRAVIA",              "Sony BRAVIA",   None),
            (r"Android\s*TV",        "Android TV",    None),
        ],
        "expected_kernels": [
            ("3.10", "Android TV / PlayStation 4"),
            ("4.4",  "Android TV"),
            ("4.14", "PlayStation 5"),
        ],
        "device_types": ["tv", "console", "camera", "general purpose"],
        "expected_os_families": ["Linux", "Android", "FreeBSD", "Orbis OS"],
    },

    "Roku": {
        "os_family": "Linux",
        "aliases": ["Roku, Inc"],
        "firmware_patterns": [(r"Roku\s*([\d.]+)?", "Roku OS", r"([\d.]+)")],
        "expected_kernels": [
            ("3.10", "Roku OS"),
            ("4.4",  "Roku OS"),
            ("4.9",  "Roku OS"),
        ],
        "device_types": ["tv", "media_player"],
        "expected_os_families": ["Linux", "Roku OS"],
    },

    # ── Consumer Electronics / Platforms ──────────────────────────
    "Apple": {
        "os_family": "macOS",
        "aliases": ["Apple Inc", "Apple, Inc."],
        "firmware_patterns": [
            (r"macOS\s*([\d.]+)?",      "macOS",          r"([\d.]+)"),
            (r"Mac\s*OS\s*X\s*([\d.]+)?","macOS",         r"([\d.]+)"),
            (r"iOS\s*([\d.]+)?",         "iOS",            r"([\d.]+)"),
            (r"tvOS\s*([\d.]+)?",        "tvOS",           r"([\d.]+)"),
            (r"AirPort",                 "AirPort Firmware", None),
        ],
        "expected_kernels": [],
        "device_types": ["workstation", "phone", "tablet", "media_player", "access_point"],
        "expected_os_families": ["macOS", "iOS", "tvOS", "Darwin"],
    },

    "Microsoft": {
        "os_family": "Windows",
        "aliases": ["Microsoft Corporation"],
        "firmware_patterns": [
            (r"Xbox\s*One",    "Xbox One OS",    None),
            (r"Xbox\s*Series", "Xbox Series OS", None),
            (r"Xbox\s*360",    "Xbox 360 OS",    None),
            (r"Windows\s*([\d.]+)", "Windows",   r"([\d.]+)"),
        ],
        "expected_kernels": [],
        "device_types": ["console", "server", "workstation", "general purpose"],
        "expected_os_families": ["Windows", "Xbox OS"],
    },

    # ── Virtualization ────────────────────────────────────────────
    "VMware": {
        "os_family": "VMkernel",
        "aliases": ["VMware, Inc"],
        "firmware_patterns": [
            (r"ESXi\s*([\d.]+)?", "VMware ESXi",  r"([\d.]+)"),
            (r"vSphere",          "VMware vSphere", None),
        ],
        "expected_kernels": [],
        "device_types": ["hypervisor", "server"],
        "expected_os_families": ["VMkernel", "Linux"],
    },

    "Proxmox": {
        "os_family": "Linux",
        "aliases": ["Proxmox Server Solutions"],
        "firmware_patterns": [
            (r"Proxmox\s*VE\s*([\d.]+)?", "Proxmox VE", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("4.13", "Proxmox VE 5.0-5.1"),
            ("4.15", "Proxmox VE 5.2-5.4"),
            ("5.0",  "Proxmox VE 6.0"),
            ("5.4",  "Proxmox VE 6.2-6.4"),
            ("5.15", "Proxmox VE 7.2-7.4"),
            ("6.2",  "Proxmox VE 8.0"),
            ("6.5",  "Proxmox VE 8.1"),
            ("6.8",  "Proxmox VE 8.2"),
            ("6.11", "Proxmox VE 8.3"),
        ],
        "device_types": ["hypervisor", "server"],
        "expected_os_families": ["Linux"],
    },

    # ── VoIP ──────────────────────────────────────────────────────
    "Polycom": {
        "os_family": "Linux",
        "aliases": ["Poly", "Polycom Inc"],
        "firmware_patterns": [(r"Polycom", "Polycom Firmware", None)],
        "expected_kernels": [
            ("2.6",  "Polycom Firmware"),
            ("3.10", "Polycom Firmware"),
            ("4.4",  "Polycom Firmware"),
        ],
        "device_types": ["phone", "voip", "video_conferencing"],
        "expected_os_families": ["Linux"],
    },

    "Yealink": {
        "os_family": "Linux",
        "aliases": ["Yealink Network Technology"],
        "firmware_patterns": [(r"Yealink", "Yealink Firmware", None)],
        "expected_kernels": [("3.4", "Yealink Firmware"), ("4.4", "Yealink Firmware")],
        "device_types": ["phone", "voip"],
        "expected_os_families": ["Linux"],
    },

    "Grandstream": {
        "os_family": "Linux",
        "aliases": ["Grandstream Networks"],
        "firmware_patterns": [(r"Grandstream", "Grandstream Firmware", None)],
        "expected_kernels": [
            ("2.6",  "Grandstream Firmware"),
            ("3.10", "Grandstream Firmware"),
            ("4.4",  "Grandstream Firmware"),
        ],
        "device_types": ["phone", "voip", "access_point"],
        "expected_os_families": ["Linux"],
    },
}

# Backward-compat aliases
VENDOR_OS_DATABASE = VENDOR_FIRMWARE_DB


# ═══════════════════════════════════════════════════════════════════
# Linux kernel → distribution table
# ═══════════════════════════════════════════════════════════════════

KERNEL_DISTRO_TABLE: Dict[str, List[Tuple[str, str, str]]] = {
    "2.6.32": [("RHEL","6","2010"), ("CentOS","6","2010"), ("Ubuntu","10.04","2010")],
    "3.2":    [("Ubuntu","12.04","2012"), ("Debian","7","2013")],
    "3.10":   [("RHEL","7","2014"), ("CentOS","7","2014")],
    "3.16":   [("Debian","8","2015"), ("Ubuntu","14.10","2014")],
    "4.4":    [("Ubuntu","16.04","2016")],
    "4.9":    [("Debian","9","2017")],
    "4.15":   [("Ubuntu","18.04","2018")],
    "4.18":   [("RHEL","8","2019"), ("CentOS","8","2019")],
    "4.19":   [("Debian","10","2019")],
    "5.4":    [("Ubuntu","20.04","2020")],
    "5.10":   [("Debian","11","2021")],
    "5.15":   [("Ubuntu","22.04","2022")],
    "6.1":    [("Debian","12","2023")],
    "6.2":    [("Ubuntu","23.04","2023")],
    "6.5":    [("Ubuntu","23.10","2023")],
    "6.8":    [("Ubuntu","24.04","2024")],
    "6.11":   [("Ubuntu","24.10","2024")],
}

KERNEL_TO_DISTRO_DATABASE = KERNEL_DISTRO_TABLE


# ═══════════════════════════════════════════════════════════════════
# Windows build → friendly name
# ═══════════════════════════════════════════════════════════════════

WINDOWS_BUILD_NAMES: Dict[str, str] = {
    "5.1":        "Windows XP",
    "6.0":        "Windows Vista / Server 2008",
    "6.1":        "Windows 7 / Server 2008 R2",
    "6.2":        "Windows 8 / Server 2012",
    "6.3":        "Windows 8.1 / Server 2012 R2",
    "10.0":       "Windows 10 / 11 / Server 2016+",
    "10.0.17763": "Windows 10 (1809) / Server 2019",
    "10.0.19041": "Windows 10 (2004)",
    "10.0.19044": "Windows 10 (21H2)",
    "10.0.19045": "Windows 10 (22H2)",
    "10.0.20348": "Windows Server 2022",
    "10.0.22000": "Windows 11 (21H2)",
    "10.0.22621": "Windows 11 (22H2)",
    "10.0.22631": "Windows 11 (23H2)",
    "10.0.26100": "Windows 11 (24H2)",
}

WINDOWS_VERSION_DATABASE = WINDOWS_BUILD_NAMES


# ═══════════════════════════════════════════════════════════════════
# Device type → plausible OS families
# ═══════════════════════════════════════════════════════════════════

DEVICE_OS_PLAUSIBILITY: Dict[str, List[str]] = {
    "router":       ["Linux", "RouterOS", "Cisco IOS", "JunOS", "FortiOS", "BSD", "FreeBSD"],
    "switch":       ["Linux", "Cisco IOS", "JunOS", "RouterOS", "ArubaOS"],
    "firewall":     ["Linux", "FortiOS", "Cisco IOS", "BSD", "FreeBSD"],
    "access_point": ["Linux", "ArubaOS", "Cisco IOS", "RouterOS"],
    "printer":      ["Linux", "Embedded", "Windows"],
    "camera":       ["Linux", "Embedded", "RTOS"],
    "nvr":          ["Linux", "Windows"],
    "dvr":          ["Linux", "Windows"],
    "nas":          ["Linux", "FreeBSD"],
    "storage":      ["Linux", "FreeBSD", "Windows"],
    "server":       ["Linux", "Windows", "FreeBSD", "BSD", "VMkernel"],
    "workstation":  ["Linux", "Windows", "macOS"],
    "phone":        ["iOS", "Android", "Linux"],
    "tablet":       ["iOS", "Android", "Linux", "Windows"],
    "iot":          ["Linux", "RTOS", "Embedded"],
    "embedded":     ["Linux", "RTOS", "Embedded"],
    "general purpose": ["Linux", "Windows", "macOS", "BSD", "FreeBSD"],
    "hypervisor":   ["VMkernel", "Linux"],
}

DEVICE_TYPE_OS_RULES = DEVICE_OS_PLAUSIBILITY


# ═══════════════════════════════════════════════════════════════════
# Utility functions
# ═══════════════════════════════════════════════════════════════════

def resolve_vendor_name(raw_vendor: str) -> Optional[str]:
    """Map a raw vendor string → canonical key in VENDOR_FIRMWARE_DB.

    Tries exact → alias → substring match in that order.
    Returns None when no match found.
    """
    if not raw_vendor:
        return None
    lowered = raw_vendor.lower()
    for canon, meta in VENDOR_FIRMWARE_DB.items():
        if canon.lower() == lowered:
            return canon
        for alias in meta.get("aliases", []):
            if alias.lower() == lowered or alias.lower() in lowered or lowered in alias.lower():
                return canon
    for canon in VENDOR_FIRMWARE_DB:
        if canon.lower() in lowered or lowered in canon.lower():
            return canon
    return None

normalize_vendor_name = resolve_vendor_name


def _major_minor(ver: str) -> Tuple[int, int]:
    """Return (major, minor) ints for a dotted kernel version string."""
    parts = ver.split(".")
    try:
        return int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return 0, 0

get_kernel_major_minor = _major_minor


def version_within_bounds(ver: str, lo: str, hi: Optional[str]) -> bool:
    """True when *ver* lies inside [lo, hi] inclusive."""
    try:
        v    = _major_minor(ver)
        lo_t = _major_minor(lo)
        if not hi:
            return v == lo_t
        return lo_t <= v <= _major_minor(hi)
    except (ValueError, IndexError):
        return False

kernel_version_in_range = version_within_bounds


def split_kernel_range(kver_str: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse a kernel version that may be a range (e.g. "3.2 - 4.14").

    Returns (min_version, max_version); max_version is None for single.
    """
    if not kver_str:
        return None, None
    m = re.match(r"(\d+\.\d+)\s*-\s*(\d+\.\d+)", kver_str)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"(\d+\.\d+)", kver_str)
    return (m.group(1), None) if m else (None, None)

parse_kernel_version = split_kernel_range


def distros_for_kernel(kver: str) -> Optional[List[Dict[str, str]]]:
    """Which Linux distros ship a given kernel version?

    Accepts single versions or ranges. Returns list of dicts (newest first),
    or None.
    """
    if not kver:
        return None
    lo, hi = split_kernel_range(kver)
    if not lo:
        return None

    collected: List[Dict] = []

    if hi:
        for db_kv, distro_list in KERNEL_DISTRO_TABLE.items():
            if version_within_bounds(db_kv, lo, hi):
                for dname, dver, drel in distro_list:
                    collected.append({"distro": dname, "version": dver,
                                       "release": drel, "kernel": db_kv})
    else:
        if lo in KERNEL_DISTRO_TABLE:
            for dname, dver, drel in KERNEL_DISTRO_TABLE[lo]:
                collected.append({"distro": dname, "version": dver,
                                   "release": drel, "kernel": lo})
        else:
            ordered = sorted(KERNEL_DISTRO_TABLE.keys(), key=_major_minor)
            for db_kv in ordered:
                dm, dn = _major_minor(db_kv)
                vm, vn = _major_minor(lo)
                if dm == vm and abs(dn - vn) <= 1:
                    for dname, dver, drel in KERNEL_DISTRO_TABLE[db_kv]:
                        collected.append({"distro": dname, "version": dver,
                                           "release": drel, "kernel": db_kv,
                                           "approximate": True, "distance" : abs(dn - vn)})

    seen: set = set()
    unique: List[Dict] = []
    for entry in collected:
        k = (entry["distro"], entry["version"])
        if k not in seen:
            seen.add(k)
            unique.append(entry)
    unique.sort(key=lambda x: x.get("release", "0"), reverse=True)
    return unique or None

infer_os_from_kernel = distros_for_kernel


def guess_firmware(
    manufacturer: str,
    device_type:    Optional[str]       = None,
    kernel_version: Optional[str]       = None,
    banners:        Optional[List[str]] = None,
    os_family:      Optional[str]       = None,
    banner:         Optional[str]       = None,
) -> Optional[Dict[str, Any]]:
    """Best-effort firmware identification for IoT/embedded devices.

    Examines the vendor knowledge-base, service banners, and kernel version.
    Returns None when vendor is unknown or device clearly runs a desktop OS.
    """
    if banner:
        banners = list(banners or []) + [banner]

    canon = resolve_vendor_name(manufacturer)
    if not canon or canon not in VENDOR_FIRMWARE_DB:
        return None

    _DESKTOP_OS      = {"windows", "macos", "mac os x", "os x"}
    _HYBRID_VENDORS  = {"ASUS", "HP", "Dell", "Lenovo", "Samsung", "LG",
                        "Intel", "Microsoft"}

    if os_family:
        os_lc = os_family.lower()
        if canon in _HYBRID_VENDORS and (os_lc in _DESKTOP_OS or "windows" in os_lc):
            return None
        if os_lc in _DESKTOP_OS or "windows" in os_lc:
            return None

    v_info = VENDOR_FIRMWARE_DB[canon]
    out: Dict[str, Any] = {
        "firmware_name": None,
        "version":       None,
        "confidence":    0.5,
        "manufacturer":  canon,
    }

    # Banner matching first
    if banners:
        combined = " ".join(banners)
        for rx_str, fw_name, ver_rx in v_info.get("firmware_patterns", []):
            m = re.search(rx_str, combined, re.IGNORECASE)
            if m:
                out["firmware_name"] = fw_name
                out["confidence"]    = 0.90
                if ver_rx:
                    vm = re.search(ver_rx, combined)
                    if vm:
                        out["version"] = vm.group(1)
                return out

    # Kernel-version correlation
    if kernel_version:
        lo, hi = split_kernel_range(kernel_version)
        if lo:
            for exp_kv, fw_ver in v_info.get("expected_kernels", []):
                hit = (version_within_bounds(exp_kv, lo, hi)
                       if hi else lo.startswith(exp_kv) or exp_kv.startswith(lo))
                if hit:
                    out["firmware_name"] = f"{canon} Firmware"
                    out["version"]       = fw_ver
                    out["confidence"]    = 0.75
                    return out

    # Generic fallback
    out["firmware_name"] = f"{canon} Firmware"
    out["confidence"]    = 0.50
    return out

infer_firmware_from_manufacturer = guess_firmware


def assess_os_plausibility(
    detected_os:    Optional[str],
    device_type:    str            = "unknown",
    manufacturer:   Optional[str]  = None,
    kernel_version: Optional[str]  = None,
) -> Tuple[bool, str, float]:
    """Is an OS detection consistent with the device profile?

    Returns (is_plausible, explanation, score) where score ∈ [0.0, 1.0].
    """
    if not detected_os:
        return True, "No OS family to validate", 0.5

    os_lc    = detected_os.lower()
    score    = 0.5
    dtype_lc = device_type.lower() if device_type else "unknown"
    acceptable = DEVICE_OS_PLAUSIBILITY.get(dtype_lc, [])

    if acceptable:
        matched = any(a.lower() in os_lc or os_lc in a.lower() for a in acceptable)
        if not matched:
            return False, f"OS '{detected_os}' unusual for device type '{device_type}'", 0.3
        score = 0.7

    if manufacturer:
        canon = resolve_vendor_name(manufacturer)
        if canon and canon in VENDOR_FIRMWARE_DB:
            v_info       = VENDOR_FIRMWARE_DB[canon]
            default_os   = v_info.get("os_family", "").lower()
            known_families = [f.lower()
                              for f in v_info.get("expected_os_families", [default_os]) if f]
            if known_families:
                vendor_ok = any(kf in os_lc or os_lc in kf for kf in known_families)
                if not vendor_ok:
                    return (False,
                            f"OS '{detected_os}' unexpected for {canon} device",
                            0.25)
                score = 0.85

            if kernel_version:
                lo, hi = split_kernel_range(kernel_version)
                if lo:
                    for ek, _ in v_info.get("expected_kernels", []):
                        hit = (version_within_bounds(ek, lo, hi)
                               if hi else lo.startswith(ek) or ek.startswith(lo.split(".")[0]))
                        if hit:
                            score = min(1.0, score + 0.1)
                            break

    # Hard rules
    if "windows" in os_lc and dtype_lc in ("router", "switch", "access_point", "firewall"):
        return False, f"Windows detection highly improbable for {device_type}", 0.1

    if "cisco" in os_lc and manufacturer:
        canon = resolve_vendor_name(manufacturer)
        if canon and canon.lower() != "cisco":
            return False, f"Cisco IOS on non-Cisco device ({manufacturer})", 0.2

    return True, "OS detection is plausible", score

check_os_plausibility = assess_os_plausibility


def format_inferred_os(
    distro_list:   Optional[List[Dict[str, str]]],
    firmware_info: Optional[Dict[str, Any]],
    limit: int = 3,
) -> Optional[str]:
    """Build a human-readable OS summary string.

    Firmware takes precedence (IoT); otherwise up to *limit* distros listed.
    """
    if firmware_info and firmware_info.get("firmware_name"):
        name = firmware_info["firmware_name"]
        ver  = firmware_info.get("version", "")
        return f"{name} ({ver})" if ver else name
    if distro_list:
        parts = [f"{d['distro']} {d['version']}" for d in distro_list[:limit]]
        return " / ".join(parts)
    return None

get_inferred_os_display = format_inferred_os


__all__ = [
    # Enums
    "ConfidenceTier", "ValidationStatus",
    # Databases
    "VENDOR_FIRMWARE_DB", "VENDOR_OS_DATABASE",
    "KERNEL_DISTRO_TABLE", "KERNEL_TO_DISTRO_DATABASE",
    "WINDOWS_BUILD_NAMES", "WINDOWS_VERSION_DATABASE",
    "DEVICE_OS_PLAUSIBILITY", "DEVICE_TYPE_OS_RULES",
    # Functions
    "resolve_vendor_name", "normalize_vendor_name",
    "guess_firmware", "infer_firmware_from_manufacturer",
    "assess_os_plausibility", "check_os_plausibility",
    "distros_for_kernel", "infer_os_from_kernel",
    "split_kernel_range", "parse_kernel_version",
    "version_within_bounds", "kernel_version_in_range",
    "_major_minor", "get_kernel_major_minor",
    "format_inferred_os", "get_inferred_os_display",
]
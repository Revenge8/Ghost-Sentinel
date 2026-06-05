import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from fingerprint.engine import FingerprintEngine, make_callback
from fingerprint.mac import is_randomized_mac, extract_correlation_signals
import time
import logging
from scapy.all import sniff, DHCP, ARP, IP, Ether
from utils.scapy_iface import resolve_iface

_log = logging.getLogger(__name__)


def process_dhcp_packet(packet) -> dict | None:
    """
    Extracts hostname, opt60, opt55 and device info from DHCP packets.
    Returns a dict or None if not a valid DHCP packet.
    """
    if not (packet.haslayer(DHCP)
            and packet.haslayer(IP)
            and packet.haslayer(Ether)):
        return None

    hostname = "Unknown"
    opt60    = None
    opt55    = None

    for opt in packet[DHCP].options:
        if isinstance(opt, tuple):
            if opt[0] == 'hostname':
                hostname = opt[1].decode('utf-8', errors='ignore')
            elif opt[0] == 'vendor_class_id':       # option 60
                opt60 = opt[1].decode('utf-8', errors='ignore')
            elif opt[0] == 'param_req_list':         # option 55
                opt55 = str(list(opt[1]))

    return {
        'ip':       packet[IP].src,
        'mac':      packet[Ether].src,
        'hostname': hostname,
        'opt60':    opt60,
        'opt55':    opt55,
        'type':     'DHCP',
    }


def detect_arp_spoofing(packet, gateway_ip: str, gateway_mac: str) -> dict | None:
    """
    Checks for fake ARP replies claiming to be the gateway.
    Returns a dict with attacker info, or None if clean.
    """
    if not (packet.haslayer(ARP) and packet[ARP].op == 2):
        return None

    sender_ip  = packet[ARP].psrc
    sender_mac = packet[ARP].hwsrc

    if sender_ip == gateway_ip and sender_mac.lower() != gateway_mac.lower():
        return {
            'real_gateway_ip':  gateway_ip,
            'real_gateway_mac': gateway_mac,
            'attacker_mac':     sender_mac,
            'type':             'ARP Spoof Detected',
        }
    return None


def start_sniffer(interface: str, stop_event, callback,
                  gateway_ip: str = "", gateway_mac: str = ""):
    """
    Main sniffing loop. Runs until stop_event is set.

    callback(event_type, data) is called with:
      - ('dhcp', {...})           DHCP packet seen
      - ('arp_spoof', {...})      spoofed ARP reply detected
      - ('randomized_mac', {...}) randomised MAC with correlation signals
    
    gateway_ip and gateway_mac are optional — ARP spoof detection
    is skipped if they are not provided.
    """
    if not interface or not isinstance(interface, str):
        interface = ""
    interface = resolve_iface(interface)

    def packet_handler(pkt):
        try:
            # 1. DHCP — device identification + signal extraction
            dhcp_info = process_dhcp_packet(pkt)
            if dhcp_info:
                callback('dhcp', dhcp_info)

                # If MAC is randomised, extract correlation signals
                # so the UI can attempt identity correlation
                if is_randomized_mac(dhcp_info['mac']):
                    signals = extract_correlation_signals(
                        dhcp_info, proto="dhcpv4")
                    callback('randomized_mac', {
                        'mac':     dhcp_info['mac'],
                        'ip':      dhcp_info['ip'],
                        'signals': signals,
                    })

            # 2. ARP spoofing — only when gateway info is available
            if gateway_ip and gateway_mac:
                spoof_info = detect_arp_spoofing(pkt, gateway_ip, gateway_mac)
                if spoof_info:
                    callback('arp_spoof', spoof_info)

        except Exception as e:
            _log.exception("packet_handler error: %s", e)

    # Short bursts so stop_event is checked every 2 seconds
    while not stop_event.is_set():
        try:
            sniff(
                iface=interface,
                prn=packet_handler,
                store=False,
                timeout=2,
                filter="udp port 67 or udp port 68 or arp",
            )
        except KeyboardInterrupt:
            stop_event.set()
            break
        except Exception as e:
            # Prevent a tight error loop if capture fails (e.g. permissions,
            # interface renamed/disconnected). Back off slightly and retry
            # until stop_event is set.
            _log.error("sniff error: %s", e)
            if stop_event.wait(timeout=0.5):
                break
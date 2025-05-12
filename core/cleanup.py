# core/cleanup.py
from scapy.all import ARP, send
from config import GATEWAY_IP

def restore(target_ip, target_mac, gateway_ip, gateway_mac):
    send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=gateway_mac), count=3, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=target_mac), count=3, verbose=False)

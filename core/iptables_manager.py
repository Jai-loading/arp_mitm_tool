# core/iptables_manager.py
import os

def enable_http_redirect():
    os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")
    print("[+] IPTables rule added to redirect HTTP traffic to port 8080")

def clear_rules():
    os.system("iptables -t nat -F")
    print("[*] Flushed all iptables NAT rules")

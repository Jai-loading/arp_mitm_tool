# core/traffic_sniffer.py
from scapy.all import sniff
from urllib.parse import unquote
import os
import datetime

log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)

def log_packet(packet_data):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    with open(f"{log_dir}/http_log.txt", "a") as f:
        f.write(f"\n=== [{timestamp}] ===\n{packet_data}\n")

def extract_http_data(payload):
    headers = {}
    body = ""
    lines = payload.split("\r\n")
    request_line = lines[0]

    # Extract headers
    for line in lines[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value
        elif line == "":
            # Empty line means headers are done, body starts
            body_index = lines.index(line) + 1
            body = "\n".join(lines[body_index:])
            break

    return request_line, headers, body

def process_packet(packet):
    if packet.haslayer('Raw'):
        try:
            payload = packet['Raw'].load.decode(errors='ignore')
            if "Host:" in payload:
                request_line, headers, body = extract_http_data(payload)

                info = f"[HTTP Request]\n{request_line}\n"
                info += "\n".join([f"{k}: {v}" for k, v in headers.items()])
                if body:
                    info += f"\n\n[POST BODY]\n{body}"

                print(info)
                log_packet(info)
        except Exception as e:
            print(f"[!] Error parsing packet: {e}")

def start_sniffing(interface):
    print("[*] Starting HTTP sniffing...")
    sniff(iface=interface, filter="tcp port 8080", prn=process_packet)

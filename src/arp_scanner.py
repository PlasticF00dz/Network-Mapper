import sys

from src.netmapper import get_local_network

try:
    from scapy.all import ARP, Ether, srp, conf

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available. ARP scanning will be limited.")

import subprocess
import re
import ipaddress


class ARPScanner:

    def __init__(self, network):
        self.network = network
        self.arp_table = {}

    def arp_scan_scapy(self):
        if not SCAPY_AVAILABLE:
            print("❌ Scapy not available for ARP scanning")
            return {}

        print(f"🔍 Starting ARP scan of {self.network}")

        try:

            conf.verb = 0

            arp_request = ARP(pdst=self.network)

            broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

            arp_packet = broadcast_frame / arp_request

            print("📡 Sending ARP broadcast packets...")

            answered_list = srp(arp_packet, timeout=2, verbose=False)[0]
            for element in answered_list:
                ip_address = element[1].psrc  # Source IP
                mac_address = element[1].hwsrc  # Source MAC

                self.arp_table[ip_address] = mac_address
                print(f"📍 {ip_address:15} -> {mac_address}")

            print(f"✅ ARP scan complete. Found {len(self.arp_table)} hosts")
            return self.arp_table

        except Exception as e:
            print(f"❌ ARP scan error: {e}")
            return {}

    def arp_scan_system(self):
        print("🔍 Using system ARP command for MAC discovery")

        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            else:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)

            arp_pattern = r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})'

            matches = re.findall(arp_pattern, result.stdout)

            for ip, mac in matches:
                try:
                    if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(self.network):
                        self.arp_table[ip] = mac.replace('-', ':').lower()
                        print(f"📍 {ip:15} -> {mac}")
                except:
                    continue

            return self.arp_table

        except Exception as e:
            print(f"❌ System ARP scan error: {e}")
            return {}

    def get_mac_address(self, ip_address):
        return self.arp_table.get(ip_address, "Unknown")

if __name__ == "__main__":
    test_network = get_local_network()

    arp_scanner = ARPScanner(test_network)

    if SCAPY_AVAILABLE:
        results = arp_scanner.arp_scan_scapy()

    if not results:
        results = arp_scanner.arp_scan_system()

    print(f"\n📊 ARP Scan Results:")
    for ip, mac in sorted(results.items()):
        print(f"{ip:15} -> {mac}")
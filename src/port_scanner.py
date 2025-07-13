import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import subprocess
import json


class PortScanner:

    def __init__(self, timeout=3):
        self.timeout = timeout
        self.scan_results = {}

    def scan_tcp_port(self, host, port):
        try:
            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Attempt connection
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                print(f"✅ {host}:{port} is open")
                return port
            else:
                return None

        except Exception as e:
            return None

    def scan_udp_port(self, host, port):
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Send empty UDP packet
            sock.sendto(b'', (host, port))

            # Try to receive response
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                print(f"📡 {host}:{port}/udp responded")
                return port
            except socket.timeout:
                sock.close()
                return port  # Assume open

        except Exception as e:
            return None

    def scan_host_ports(self, host, ports, scan_type='tcp'):

        print(f"🔍 Scanning {host} for {scan_type.upper()} ports: {ports}")

        open_ports = []

        if isinstance(ports, str):
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                port_list = list(range(start, end + 1))
            else:
                port_list = [int(ports)]
        elif isinstance(ports, list):
            port_list = ports
        else:
            port_list = [ports]

        scan_func = self.scan_tcp_port if scan_type == 'tcp' else self.scan_udp_port

        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {
                executor.submit(scan_func, host, port): port
                for port in port_list
            }

            for future in future_to_port:
                result = future.result()
                if result is not None:
                    open_ports.append(result)

        self.scan_results[host] = {
            'open_ports': sorted(open_ports),
            'scan_type': scan_type,
            'total_ports_scanned': len(port_list)
        }

        return sorted(open_ports)

    def identify_service(self, host, port):
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL'
        }

        service_info = {
            'port': port,
            'service': common_services.get(port, 'Unknown'),
            'banner': None
        }

        # Attempt banner grabbing
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            # Try to grab banner
            if port in [21, 22, 23, 25]:  # Services that send banner immediately
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info['banner'] = banner
                print(f"🏷️  {host}:{port} banner: {banner[:50]}...")

            sock.close()

        except Exception as e:
            pass

        return service_info



if __name__ == "__main__":
    scanner = PortScanner()
    test_host = "127.0.0.1"
    test_ports = "20-100"  # Small range for testing

    print(f"🧪 Testing port scan on {test_host}")
    open_ports = scanner.scan_host_ports(test_host, test_ports)

    print(f"\n📊 Open ports found: {open_ports}")

    # Test service identification
    if open_ports:
        print(f"\n🔍 Identifying services:")
        for port in open_ports[:3]:  # Test first 3 ports
            service_info = scanner.identify_service(test_host, port)
            print(f"Port {port}: {service_info}")
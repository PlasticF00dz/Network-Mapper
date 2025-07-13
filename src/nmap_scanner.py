import time

try:
    import nmap

    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️  python-nmap not available. Install with: pip install python-nmap")

import subprocess
import json
import xml.etree.ElementTree as ET


class NmapScanner:

    def __init__(self):
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None

    def basic_scan(self, host, port_range="1-1000"):

        if not NMAP_AVAILABLE:
            return self._fallback_scan(host, port_range)

        print(f"🔍 Nmap scanning {host} ports {port_range}")

        try:

            self.nm.scan(host, port_range, arguments='-sS -sV')

            results = {
                'host': host,
                'state': 'unknown',
                'ports': [],
                'hostnames': []
            }

            if host in self.nm.all_hosts():
                host_data = self.nm[host]
                results['state'] = host_data.state()
                results['hostnames'] = host_data.hostnames()

                # Extract port information
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        port_info = {
                            'port': port,
                            'state': port_data['state'],
                            'service': port_data.get('name', 'unknown'),
                            'version': port_data.get('version', ''),
                            'product': port_data.get('product', ''),
                            'extrainfo': port_data.get('extrainfo', '')
                        }
                        results['ports'].append(port_info)

                print(f"✅ Scan complete. Found {len(results['ports'])} ports")
                return results

        except Exception as e:
            print(f"❌ Nmap scan error: {e}")
            return {'host': host, 'state': 'error', 'ports': [], 'hostnames': []}

    def os_detection_scan(self, host):

        if not NMAP_AVAILABLE:
            return {'os_matches': [], 'accuracy': 0}

        print(f"🔍 OS detection scan on {host}")

        try:
            self.nm.scan(host, arguments='-O --osscan-guess')

            os_info = {
                'os_matches': [],
                'accuracy': 0,
                'os_family': 'Unknown'
            }

            if host in self.nm.all_hosts():
                host_data = self.nm[host]

                if 'osmatch' in host_data:
                    for os_match in host_data['osmatch']:
                        os_info['os_matches'].append({
                            'name': os_match['name'],
                            'accuracy': int(os_match['accuracy']),
                            'line': os_match['line']
                        })

                    # Get best match
                    if os_info['os_matches']:
                        best_match = max(os_info['os_matches'], key=lambda x: x['accuracy'])
                        os_info['accuracy'] = best_match['accuracy']

                        # Try to determine OS family
                        os_name = best_match['name'].lower()
                        if 'windows' in os_name:
                            os_info['os_family'] = 'Windows'
                        elif 'linux' in os_name:
                            os_info['os_family'] = 'Linux'
                        elif 'mac' in os_name or 'darwin' in os_name:
                            os_info['os_family'] = 'macOS'
                        elif 'unix' in os_name:
                            os_info['os_family'] = 'Unix'

                print(f"🖥️  OS Detection: {os_info['os_family']} ({os_info['accuracy']}% confidence)")
                return os_info

        except Exception as e:
            print(f"❌ OS detection error: {e}")

        return {'os_matches': [], 'accuracy': 0, 'os_family': 'Unknown'}

    def comprehensive_scan(self, host):

        print(f"🎯 Comprehensive scan of {host}")

        results = {
            'host': host,
            'timestamp': time.time(),
            'basic_scan': {},
            'os_detection': {},
            'script_scan': {}
        }

        results['basic_scan'] = self.basic_scan(host)

        if results['basic_scan']['ports']:
            results['os_detection'] = self.os_detection_scan(host)

        return results

    def _fallback_scan(self, host, port_range):

        print(f"🔄 Using system nmap command for {host}")

        try:
            cmd = ['nmap', '-sS', '-sV', '--host-timeout', '30s', '-p', port_range, host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                lines = result.stdout.split('\n')
                open_ports = []

                for line in lines:
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        port_info = parts[0].split('/')[0]
                        service = parts[2] if len(parts) > 2 else 'unknown'

                        open_ports.append({
                            'port': int(port_info),
                            'state': 'open',
                            'service': service,
                            'version': '',
                            'product': '',
                            'extrainfo': ''
                        })

                return {
                    'host': host,
                    'state': 'up',
                    'ports': open_ports,
                    'hostnames': []
                }

        except Exception as e:
            print(f"❌ Fallback scan error: {e}")

        return {'host': host, 'state': 'error', 'ports': [], 'hostnames': []}


# Test Nmap scanner
if __name__ == "__main__":
    scanner = NmapScanner()

    test_host = "8.8.8.8"

    print("🧪 Testing basic Nmap scan")
    basic_results = scanner.basic_scan(test_host, "80,443,53")

    print(f"\n📊 Basic Scan Results:")
    print(f"Host: {basic_results['host']}")
    print(f"State: {basic_results['state']}")
    print(f"Open Ports: {len(basic_results['ports'])}")

    for port_info in basic_results['ports']:
        print(f"  Port {port_info['port']}: {port_info['service']} ({port_info['state']})")
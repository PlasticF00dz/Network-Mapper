import json
import csv
import os
import sys
import datetime
import subprocess
import sqlite3
import threading
import time
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import webbrowser
import tempfile
import glob
import base64
from io import BytesIO
import numpy as np

# Try to import optional dependencies
try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("⚠️  Matplotlib not available. Visualizations will be disabled.")

try:
    import netifaces

    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    print("⚠️  netifaces not available. Network detection will be limited.")


class IntegratedNetMapperReportGenerator:
    """
    Optimized Network Mapping and Report Generation System
    Only scans hosts that actually respond to discovery methods
    """

    def __init__(self, data_path: str = "scan_data"):
        self.data_path = data_path
        self.db_path = os.path.join(data_path, "netmapper.db")
        self.timeout = 2  # Reduced timeout for faster scanning
        self.max_threads = 100  # Increased threads for efficiency

        # Initialize components
        self.hostname_cache = {}
        self.arp_table = {}
        self.network_graph = {}
        self.host_info = {}

        # Ensure directories exist
        os.makedirs(self.data_path, exist_ok=True)
        os.makedirs(os.path.join(self.data_path, "scans"), exist_ok=True)
        os.makedirs(os.path.join(self.data_path, "reports"), exist_ok=True)
        os.makedirs(os.path.join(self.data_path, "exports"), exist_ok=True)

        # Initialize database
        self._init_database()

        print("🔍 Optimized NetMapper Report Generator initialized")
        print(f"📁 Data directory: {self.data_path}")
        print(f"💾 Database: {self.db_path}")

    def _init_database(self):
        """Initialize SQLite database for scan results"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create scan sessions table
            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS scan_sessions
                           (
                               id
                               TEXT
                               PRIMARY
                               KEY,
                               start_time
                               TEXT,
                               end_time
                               TEXT,
                               target_network
                               TEXT,
                               scan_type
                               TEXT,
                               status
                               TEXT,
                               total_hosts
                               INTEGER
                               DEFAULT
                               0,
                               live_hosts
                               INTEGER
                               DEFAULT
                               0,
                               created_at
                               TEXT
                               DEFAULT
                               CURRENT_TIMESTAMP
                           )
                           ''')

            # Create hosts table
            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS hosts
                           (
                               id
                               INTEGER
                               PRIMARY
                               KEY
                               AUTOINCREMENT,
                               session_id
                               TEXT,
                               ip_address
                               TEXT,
                               hostname
                               TEXT,
                               mac_address
                               TEXT,
                               vendor
                               TEXT,
                               os_name
                               TEXT,
                               os_confidence
                               REAL,
                               status
                               TEXT,
                               response_time
                               REAL,
                               FOREIGN
                               KEY
                           (
                               session_id
                           ) REFERENCES scan_sessions
                           (
                               id
                           )
                               )
                           ''')

            # Create ports table
            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS ports
                           (
                               id
                               INTEGER
                               PRIMARY
                               KEY
                               AUTOINCREMENT,
                               host_id
                               INTEGER,
                               port_number
                               INTEGER,
                               protocol
                               TEXT,
                               state
                               TEXT,
                               service
                               TEXT,
                               version
                               TEXT,
                               banner
                               TEXT,
                               FOREIGN
                               KEY
                           (
                               host_id
                           ) REFERENCES hosts
                           (
                               id
                           )
                               )
                           ''')

            conn.commit()
            conn.close()
            print("✅ Database initialized successfully")
        except Exception as e:
            print(f"❌ Database initialization error: {e}")

    def get_local_network(self):
        """Detect the local network automatically"""
        try:
            if NETIFACES_AVAILABLE:
                # Get default gateway information
                gateways = netifaces.gateways()
                default_gateway = gateways['default'][netifaces.AF_INET]
                interface_name = default_gateway[1]

                # Get interface details
                interface_info = netifaces.ifaddresses(interface_name)
                ipv4_info = interface_info[netifaces.AF_INET][0]
                ip_address = ipv4_info['addr']
                netmask = ipv4_info['netmask']

                # Create network object
                network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                return str(network)
            else:
                # Fallback method
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                return f"{'.'.join(local_ip.split('.')[:-1])}.0/24"
        except Exception as e:
            print(f"❌ Error detecting network: {e}")
            return "192.168.1.0/24"  # Fallback

    def ping_sweep(self, network, max_threads=100):
        """OPTIMIZED ping sweep - faster with progress tracking"""
        print(f"🔍 Starting optimized ping sweep of {network}")

        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
        except ValueError as e:
            print(f"❌ Invalid network format: {e}")
            return []

        live_hosts = []
        lock = threading.Lock()
        total_hosts = len(list(network_obj.hosts()))
        scanned_count = 0

        def ping_host(ip_str):
            nonlocal scanned_count
            try:
                if sys.platform.startswith('win'):
                    cmd = ['ping', '-n', '1', '-w', '1000', ip_str]  # 1 second timeout
                else:
                    cmd = ['ping', '-c', '1', '-W', '1', ip_str]  # 1 second timeout

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=2,  # Overall timeout
                    text=True
                )

                with lock:
                    scanned_count += 1
                    if scanned_count % 50 == 0:  # Progress every 50 hosts
                        print(f"📊 Progress: {scanned_count}/{total_hosts} hosts scanned ({len(live_hosts)} alive)")

                if result.returncode == 0:
                    with lock:
                        live_hosts.append(ip_str)
                    print(f"✅ {ip_str} is alive")
                    return ip_str
                return None
            except subprocess.TimeoutExpired:
                return None
            except Exception as e:
                return None

        # Use ThreadPoolExecutor for concurrent pings
        target_ips = [str(ip) for ip in network_obj.hosts()]
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(ping_host, target_ips)

        print(f"📊 Ping sweep completed: {len(live_hosts)} live hosts out of {total_hosts} scanned")
        return sorted(live_hosts, key=lambda x: ipaddress.IPv4Address(x))

    def arp_scan(self, network):
        """Perform ARP scan to discover MAC addresses"""
        print(f"🔍 Starting ARP scan of {network}")
        return self._arp_scan_system(network)

    def _arp_scan_system(self, network):
        """Fallback ARP scan using system commands"""
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            else:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)

            import re
            arp_pattern = r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})'
            matches = re.findall(arp_pattern, result.stdout)

            arp_results = {}
            network_obj = ipaddress.IPv4Network(network, strict=False)

            for ip, mac in matches:
                try:
                    if ipaddress.IPv4Address(ip) in network_obj:
                        arp_results[ip] = mac.replace('-', ':').lower()
                        print(f"📍 {ip:15} -> {mac}")
                except:
                    continue

            self.arp_table.update(arp_results)
            return arp_results
        except Exception as e:
            print(f"❌ System ARP scan error: {e}")
            return {}

    def resolve_hostnames(self, ip_list):
        """Resolve hostnames for IP addresses - OPTIMIZED"""
        if not ip_list:
            return {}

        print(f"🔍 Resolving hostnames for {len(ip_list)} discovered hosts")

        def resolve_single(ip_address):
            try:
                socket.setdefaulttimeout(self.timeout)
                hostname_info = socket.gethostbyaddr(ip_address)
                hostname = hostname_info[0]
                self.hostname_cache[ip_address] = hostname
                print(f"🏷️  {ip_address:15} -> {hostname}")
                return hostname
            except:
                self.hostname_cache[ip_address] = ""
                return ""

        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(resolve_single, ip_list)

        return self.hostname_cache

    def port_scan(self, host, ports="common"):
        """OPTIMIZED port scanning with smart port selection"""
        print(f"🔍 Scanning ports on {host}")

        # Define port sets
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3389, 5432, 3306]
        extended_ports = list(range(1000, 2000))

        if ports == "common":
            port_list = common_ports
        elif ports == "extended":
            port_list = common_ports + extended_ports
        elif isinstance(ports, str) and '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = list(range(start, end + 1))
        elif isinstance(ports, list):
            port_list = ports
        else:
            port_list = [int(ports)] if isinstance(ports, (str, int)) else common_ports

        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    service = self._get_service_name(port)
                    banner = self._grab_banner(host, port)
                    port_info = {
                        'port_number': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': service,
                        'banner': banner,
                        'version': ''
                    }
                    open_ports.append(port_info)
                    print(f"✅ {host}:{port} ({service}) is open")
                    return port_info
                return None
            except:
                return None

        # Scan ports concurrently
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(scan_port, port_list)

        return sorted(open_ports, key=lambda x: x['port_number'])

    def _get_service_name(self, port):
        """Get service name for a port"""
        service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s', 1723: 'pptp',
            3389: 'rdp', 5432: 'postgresql', 3306: 'mysql',
            135: 'msrpc', 139: 'netbios-ssn', 445: 'microsoft-ds',
            631: 'ipp', 161: 'snmp', 162: 'snmptrap', 389: 'ldap',
            636: 'ldaps', 1433: 'mssql', 1521: 'oracle', 5900: 'vnc'
        }
        return service_map.get(port, 'unknown')

    def _grab_banner(self, host, port):
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Quick banner grab
            sock.connect((host, port))

            # Services that send banner immediately
            if port in [21, 22, 23, 25, 110, 143]:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner[:100]  # Limit banner length

            sock.close()
            return ""
        except:
            return ""

    def detect_os(self, host, port_results=None):
        """Detect operating system"""
        print(f"🔍 Detecting OS for {host}")

        os_info = {
            'os_name': 'Unknown',
            'os_confidence': 0.0,
            'detection_method': 'none'
        }

        # TTL-based detection
        ttl_os = self._detect_os_by_ttl(host)
        if ttl_os:
            os_info.update(ttl_os)

        # Service-based detection
        if port_results:
            service_os = self._detect_os_by_services(port_results)
            if service_os and service_os['os_confidence'] > os_info['os_confidence']:
                os_info.update(service_os)

        return os_info

    def _detect_os_by_ttl(self, host):
        """Detect OS based on TTL values"""
        try:
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '3', host]
            else:
                cmd = ['ping', '-c', '3', host]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                import re
                ttl_pattern = r'ttl=(\d+)|TTL=(\d+)'
                ttl_matches = re.findall(ttl_pattern, result.stdout, re.IGNORECASE)

                if ttl_matches:
                    ttl_values = [int(match[0] or match[1]) for match in ttl_matches]
                    avg_ttl = sum(ttl_values) // len(ttl_values)

                    # Common TTL values and associated OS
                    if 60 <= avg_ttl <= 64:
                        return {'os_name': 'Linux/Unix', 'os_confidence': 0.7, 'detection_method': 'ttl'}
                    elif 120 <= avg_ttl <= 128:
                        return {'os_name': 'Windows', 'os_confidence': 0.7, 'detection_method': 'ttl'}
                    elif avg_ttl >= 250:
                        return {'os_name': 'Network Device', 'os_confidence': 0.6, 'detection_method': 'ttl'}
        except Exception as e:
            pass

        return None

    def _detect_os_by_services(self, port_results):
        """Detect OS based on running services"""
        windows_indicators = ['microsoft', 'iis', 'msrpc', 'microsoft-ds', 'netbios']
        linux_indicators = ['apache', 'nginx', 'openssh', 'postfix', 'bind']

        windows_score = 0
        linux_score = 0

        for port in port_results:
            service = port.get('service', '').lower()
            banner = port.get('banner', '').lower()

            for indicator in windows_indicators:
                if indicator in service or indicator in banner:
                    windows_score += 1

            for indicator in linux_indicators:
                if indicator in service or indicator in banner:
                    linux_score += 1

        if windows_score > linux_score and windows_score > 0:
            return {'os_name': 'Windows', 'os_confidence': min(0.9, windows_score * 0.3),
                    'detection_method': 'services'}
        elif linux_score > 0:
            return {'os_name': 'Linux', 'os_confidence': min(0.9, linux_score * 0.3), 'detection_method': 'services'}

        return None

    def perform_smart_scan(self, target_network, scan_type="smart"):
        """OPTIMIZED smart scan - only scans responsive hosts"""
        session_id = f"smart_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.datetime.now().isoformat()

        print(f"\n🧠 Starting SMART SCAN: {session_id}")
        print(f"🎯 Target: {target_network}")
        print("⚡ Smart scanning only targets responsive hosts for maximum efficiency")
        print("=" * 70)

        # Initialize scan session
        self._save_scan_session(session_id, start_time, target_network, scan_type, 'running')

        scan_results = {
            'session': {
                'id': session_id,
                'start_time': start_time,
                'target_network': target_network,
                'scan_type': scan_type
            },
            'hosts': [],
            'topology': [],
            'summary': {}
        }

        try:
            # Step 1: Quick Host Discovery
            print("🔍 Step 1: Quick Host Discovery")
            live_hosts = self.ping_sweep(target_network, max_threads=self.max_threads)

            # Step 2: ARP Scanning
            print("🔍 Step 2: ARP Scanning")
            arp_results = self.arp_scan(target_network)

            # Combine discoveries - this is the key optimization
            all_discovered = set(live_hosts)
            all_discovered.update(arp_results.keys())

            print(f"\n📊 DISCOVERY SUMMARY:")
            print(f"   • Ping responsive: {len(live_hosts)} hosts")
            print(f"   • ARP responsive: {len(arp_results)} hosts")
            print(f"   • Total unique discovered: {len(all_discovered)} hosts")
            print(
                f"   • Efficiency gain: Scanning {len(all_discovered)} instead of {len(list(ipaddress.IPv4Network(target_network, strict=False).hosts()))} hosts")

            if not all_discovered:
                print("❌ No hosts discovered. Check network connectivity.")
                return ""

            # Step 3: Hostname Resolution (only for discovered hosts)
            print("\n🔍 Step 3: Hostname Resolution")
            self.resolve_hostnames(list(all_discovered))

            # Step 4: Smart Port Scanning (only discovered hosts)
            print("\n🔍 Step 4: Smart Port Scanning and OS Detection")
            print(f"🎯 Scanning only {len(all_discovered)} responsive hosts")

            for i, host_ip in enumerate(sorted(all_discovered, key=lambda x: ipaddress.IPv4Address(x)), 1):
                print(f"\n  🔍 [{i}/{len(all_discovered)}] Scanning {host_ip}")

                # Start with common ports
                port_results = self.port_scan(host_ip, "common")

                # If we found open ports, scan extended range
                if port_results:
                    print(f"    ✅ Found {len(port_results)} open ports, scanning extended range...")
                    extended_results = self.port_scan(host_ip, "extended")
                    port_results.extend(extended_results)

                # OS detection
                os_info = self.detect_os(host_ip, port_results)

                host_data = {
                    'ip_address': host_ip,
                    'hostname': self.hostname_cache.get(host_ip, ''),
                    'mac_address': arp_results.get(host_ip, ''),
                    'vendor': '',
                    'os_name': os_info['os_name'],
                    'os_confidence': os_info['os_confidence'],
                    'status': 'up' if host_ip in live_hosts else 'arp-only',
                    'response_time': 0.0,
                    'ports': port_results
                }

                scan_results['hosts'].append(host_data)

                # Save host to database
                self._save_host_data(session_id, host_data)

                # Show progress
                if port_results:
                    services = [p['service'] for p in port_results if p['service'] != 'unknown']
                    print(f"    📋 Services found: {', '.join(services[:5])}")
                else:
                    print(f"    📋 No open ports found")

            # Generate summary
            scan_results['summary'] = self._generate_summary(scan_results)

            # Finalize scan
            end_time = datetime.datetime.now().isoformat()
            scan_results['session']['end_time'] = end_time

            # Update scan session
            self._update_scan_session(session_id, end_time, 'completed', len(scan_results['hosts']),
                                      len(all_discovered))

            # Save complete results
            self._save_scan_results(session_id, scan_results)

            print("\n" + "=" * 70)
            print(f"✅ SMART SCAN COMPLETED: {session_id}")
            print(f"📊 Successfully scanned {len(scan_results['hosts'])} discovered hosts")
            print(
                f"⚡ Efficiency: {len(all_discovered)} hosts scanned vs {len(list(ipaddress.IPv4Network(target_network, strict=False).hosts()))} possible")
            print(f"⏱️  Duration: {scan_results['summary'].get('scan_duration', 'Unknown')}")

            return session_id

        except Exception as e:
            print(f"❌ Smart scan error: {e}")
            self._update_scan_session(session_id, datetime.datetime.now().isoformat(), 'failed', 0, 0)
            return ""

    def _generate_summary(self, scan_results):
        """Generate scan summary statistics"""
        hosts = scan_results.get('hosts', [])
        total_hosts = len(hosts)
        live_hosts = len([h for h in hosts if h.get('status') == 'up'])
        total_ports = sum(len(h.get('ports', [])) for h in hosts)
        open_ports = sum(len([p for p in h.get('ports', []) if p.get('state') == 'open']) for h in hosts)

        # OS distribution
        os_counts = {}
        for host in hosts:
            os_name = host.get('os_name', 'Unknown')
            os_counts[os_name] = os_counts.get(os_name, 0) + 1

        # Service distribution
        service_counts = {}
        for host in hosts:
            for port in host.get('ports', []):
                service = port.get('service', 'unknown')
                if service and service != 'unknown':
                    service_counts[service] = service_counts.get(service, 0) + 1

        return {
            'total_hosts': total_hosts,
            'live_hosts': live_hosts,
            'total_ports_scanned': total_ports,
            'open_ports': open_ports,
            'os_distribution': os_counts,
            'service_distribution': service_counts,
            'scan_duration': self._calculate_duration(scan_results['session'])
        }

    def _calculate_duration(self, session):
        """Calculate scan duration"""
        try:
            start_time = session.get('start_time', '')
            end_time = session.get('end_time', '')

            if start_time and end_time:
                start_dt = datetime.datetime.fromisoformat(start_time)
                end_dt = datetime.datetime.fromisoformat(end_time)
                duration = end_dt - start_dt
                total_seconds = int(duration.total_seconds())

                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                seconds = total_seconds % 60

                if hours > 0:
                    return f"{hours}h {minutes}m {seconds}s"
                elif minutes > 0:
                    return f"{minutes}m {seconds}s"
                else:
                    return f"{seconds}s"
        except:
            pass

        return "Unknown"

    def generate_report(self, session_id=None, output_format='html', output_file=None):
        """Generate comprehensive report"""
        print(f"📊 Generating {output_format.upper()} report")

        # Get scan data
        scan_data = self._get_scan_data(session_id)
        if not scan_data:
            print("❌ No scan data found")
            return ""

        # Enhance data with analysis
        enhanced_data = self._enhance_scan_data(scan_data)

        # Generate report based on format
        if output_format == 'html':
            return self._generate_html_report(enhanced_data, output_file)
        elif output_format == 'text':
            return self._generate_text_report(enhanced_data, output_file)
        elif output_format == 'json':
            return self._generate_json_report(enhanced_data, output_file)
        elif output_format == 'csv':
            return self._generate_csv_report(enhanced_data, output_file)
        else:
            print(f"❌ Unsupported format: {output_format}")
            return ""

    def _get_scan_data(self, session_id=None):
        """Get scan data from database or latest scan"""
        try:
            if session_id:
                json_file = os.path.join(self.data_path, "scans", f"{session_id}.json")
                if os.path.exists(json_file):
                    with open(json_file, 'r', encoding='utf-8') as f:
                        return json.load(f)
            else:
                # Get latest scan
                scan_files = glob.glob(os.path.join(self.data_path, "scans", "*.json"))
                if scan_files:
                    latest_file = max(scan_files, key=os.path.getmtime)
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        return json.load(f)

            return {}
        except Exception as e:
            print(f"❌ Error retrieving scan data: {e}")
            return {}

    def _enhance_scan_data(self, scan_data):
        """Enhance scan data with analysis"""
        enhanced = scan_data.copy()

        # Add security analysis
        enhanced['security_analysis'] = self._analyze_security_risks(scan_data)

        return enhanced

    def _analyze_security_risks(self, scan_data):
        """Analyze potential security risks"""
        risks = {
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'recommendations': []
        }

        vulnerable_services = {
            'telnet': {'port': 23, 'risk': 'high', 'reason': 'Unencrypted remote access'},
            'ftp': {'port': 21, 'risk': 'medium', 'reason': 'Unencrypted file transfer'},
            'http': {'port': 80, 'risk': 'low', 'reason': 'Unencrypted web traffic'},
            'smtp': {'port': 25, 'risk': 'medium', 'reason': 'Potential mail relay'},
            'snmp': {'port': 161, 'risk': 'high', 'reason': 'Network management protocol'},
            'microsoft-ds': {'port': 445, 'risk': 'high', 'reason': 'SMB file sharing'},
            'rdp': {'port': 3389, 'risk': 'high', 'reason': 'Remote desktop access'},
            'netbios-ssn': {'port': 139, 'risk': 'medium', 'reason': 'NetBIOS session service'},
            'msrpc': {'port': 135, 'risk': 'medium', 'reason': 'Microsoft RPC service'}
        }

        for host in scan_data.get('hosts', []):
            host_ip = host.get('ip_address', '')
            for port in host.get('ports', []):
                if port.get('state') != 'open':
                    continue

                port_num = port.get('port_number')
                service = port.get('service', '').lower()

                for vuln_service, details in vulnerable_services.items():
                    if service == vuln_service or port_num == details['port']:
                        risk_item = {
                            'host': host_ip,
                            'port': port_num,
                            'service': service,
                            'description': f"{vuln_service.upper()} service detected",
                            'reason': details['reason']
                        }

                        if details['risk'] == 'high':
                            risks['high_risk'].append(risk_item)
                        elif details['risk'] == 'medium':
                            risks['medium_risk'].append(risk_item)
                        else:
                            risks['low_risk'].append(risk_item)

        # Generate recommendations
        if risks['high_risk']:
            risks['recommendations'].append("🔴 High Risk: Disable or secure high-risk services immediately")
        if risks['medium_risk']:
            risks['recommendations'].append("🟡 Medium Risk: Consider encrypted alternatives for these services")
        if not risks['high_risk'] and not risks['medium_risk']:
            risks['recommendations'].append("✅ Good: No obvious high-risk services detected")

        return risks

    def _generate_html_report(self, scan_data, output_file=None):
        """Generate HTML report"""
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.data_path, "reports", f"network_report_{timestamp}.html")

        try:
            html_content = self._get_html_template()

            # Replace basic variables
            session = scan_data.get('session', {})
            summary = scan_data.get('summary', {})
            security = scan_data.get('security_analysis', {})

            html_content = html_content.replace('{{SESSION_ID}}', session.get('id', 'Unknown'))
            html_content = html_content.replace('{{TARGET_NETWORK}}', session.get('target_network', 'Unknown'))
            html_content = html_content.replace('{{SCAN_TYPE}}', session.get('scan_type', 'Unknown'))
            html_content = html_content.replace('{{GENERATED_AT}}',
                                                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            html_content = html_content.replace('{{TOTAL_HOSTS}}', str(summary.get('total_hosts', 0)))
            html_content = html_content.replace('{{LIVE_HOSTS}}', str(summary.get('live_hosts', 0)))
            html_content = html_content.replace('{{OPEN_PORTS}}', str(summary.get('open_ports', 0)))
            html_content = html_content.replace('{{SCAN_DURATION}}', str(summary.get('scan_duration', 'Unknown')))

            # Generate hosts table
            hosts_html = ""
            for host in scan_data.get('hosts', []):
                open_ports = [str(p.get('port_number', '')) for p in host.get('ports', []) if p.get('state') == 'open']
                services = [p.get('service', '') for p in host.get('ports', []) if p.get('state') == 'open']
                hosts_html += f"""
                <tr>
                    <td><strong>{host.get('ip_address', '')}</strong></td>
                    <td>{host.get('hostname', 'N/A')}</td>
                    <td>{host.get('os_name', 'Unknown')}</td>
                    <td>{host.get('mac_address', 'N/A')}</td>
                    <td>{', '.join(open_ports)}</td>
                    <td>{', '.join(services)}</td>
                </tr>
                """
            html_content = html_content.replace('{{HOSTS_TABLE}}', hosts_html)

            # Generate security risks
            security_html = ""
            for risk_level in ['high_risk', 'medium_risk', 'low_risk']:
                risks = security.get(risk_level, [])
                if risks:
                    color = {'high_risk': '#dc3545', 'medium_risk': '#fd7e14', 'low_risk': '#28a745'}[risk_level]
                    level_name = risk_level.replace('_', ' ').title()
                    security_html += f"<h4 style='color: {color}'>{level_name} ({len(risks)} issues)</h4><ul>"
                    for risk in risks:
                        security_html += f"<li>{risk['host']}:{risk['port']} - {risk['description']} ({risk['reason']})</li>"
                    security_html += "</ul>"

            if not security_html:
                security_html = "<p style='color: green'>✅ No security risks detected</p>"

            html_content = html_content.replace('{{SECURITY_ANALYSIS}}', security_html)

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            print(f"✅ HTML report generated: {output_file}")

            # Open in browser
            webbrowser.open(f"file://{os.path.abspath(output_file)}")

            return output_file

        except Exception as e:
            print(f"❌ Error generating HTML report: {e}")
            return ""

    def _get_html_template(self):
        """Get HTML report template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetMapper Network Report</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2); 
        }
        .header { 
            text-align: center; 
            margin-bottom: 30px; 
            padding-bottom: 20px; 
            border-bottom: 3px solid #667eea; 
        }
        .header h1 { 
            color: #667eea; 
            margin: 0; 
            font-size: 2.5em; 
            font-weight: 300;
        }
        .header .subtitle {
            color: #666;
            margin-top: 10px;
            font-size: 1.1em;
        }
        .section { 
            margin: 30px 0; 
            padding: 25px; 
            background: #f8f9fa; 
            border-radius: 10px; 
            border-left: 5px solid #667eea; 
        }
        .section h2 { 
            color: #667eea; 
            margin-top: 0; 
            font-size: 1.8em;
        }
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin: 20px 0; 
        }
        .summary-card { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white;
            padding: 25px; 
            border-radius: 10px; 
            text-align: center; 
            box-shadow: 0 5px 15px rgba(0,0,0,0.1); 
            transition: transform 0.3s ease;
        }
        .summary-card:hover {
            transform: translateY(-5px);
        }
        .summary-card .value { 
            font-size: 2.5em; 
            font-weight: bold; 
            margin-bottom: 10px;
        }
        .summary-card .label { 
            opacity: 0.9;
            font-size: 1.1em;
        }
        .host-table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0; 
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .host-table th, .host-table td { 
            padding: 15px; 
            text-align: left; 
            border-bottom: 1px solid #eee;
        }
        .host-table th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            font-weight: 600;
        }
        .host-table tr:hover { 
            background-color: #f8f9fa; 
        }
        .efficiency-badge { 
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
            color: white; 
            padding: 8px 16px; 
            border-radius: 20px; 
            font-size: 0.9em; 
            display: inline-block;
            margin-top: 10px;
        }
        .footer {
            text-align: center; 
            margin-top: 40px; 
            padding-top: 20px; 
            border-top: 2px solid #eee; 
            color: #666;
        }
        .footer p {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 NetMapper Network Report</h1>
            <div class="subtitle">
                Session: {{SESSION_ID}}<br>
                Target: {{TARGET_NETWORK}} | Type: {{SCAN_TYPE}}<br>
                Generated: {{GENERATED_AT}}
            </div>
            <div class="efficiency-badge">⚡ Smart Scanning - Only Responsive Hosts</div>
        </div>

        <div class="section">
            <h2>📊 Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="value">{{TOTAL_HOSTS}}</div>
                    <div class="label">Discovered Hosts</div>
                </div>
                <div class="summary-card">
                    <div class="value">{{LIVE_HOSTS}}</div>
                    <div class="label">Live Hosts</div>
                </div>
                <div class="summary-card">
                    <div class="value">{{OPEN_PORTS}}</div>
                    <div class="label">Open Ports</div>
                </div>
                <div class="summary-card">
                    <div class="value">{{SCAN_DURATION}}</div>
                    <div class="label">Duration</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🔒 Security Analysis</h2>
            {{SECURITY_ANALYSIS}}
        </div>

        <div class="section">
            <h2>🖥️ Discovered Hosts</h2>
            <table class="host-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>MAC Address</th>
                        <th>Open Ports</th>
                        <th>Services</th>
                    </tr>
                </thead>
                <tbody>
                    {{HOSTS_TABLE}}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p><strong>Report generated by NetMapper v2.0 - Optimized Edition</strong></p>
            <p>⚡ Smart scanning technology - Maximum efficiency, minimum time</p>
        </div>
    </div>
</body>
</html>'''

    def _generate_text_report(self, scan_data, output_file=None):
        """Generate text report"""
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.data_path, "reports", f"network_report_{timestamp}.txt")

        try:
            session = scan_data.get('session', {})
            summary = scan_data.get('summary', {})
            security = scan_data.get('security_analysis', {})

            report_lines = []
            report_lines.append("=" * 80)
            report_lines.append("NETMAPPER NETWORK SCAN REPORT")
            report_lines.append("=" * 80)
            report_lines.append(f"Session ID: {session.get('id', 'Unknown')}")
            report_lines.append(f"Target Network: {session.get('target_network', 'Unknown')}")
            report_lines.append(f"Scan Type: {session.get('scan_type', 'Unknown')}")
            report_lines.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report_lines.append("")

            # Summary
            report_lines.append("SCAN SUMMARY")
            report_lines.append("-" * 40)
            report_lines.append(f"Total Hosts Discovered: {summary.get('total_hosts', 0)}")
            report_lines.append(f"Live Hosts: {summary.get('live_hosts', 0)}")
            report_lines.append(f"Open Ports Found: {summary.get('open_ports', 0)}")
            report_lines.append(f"Scan Duration: {summary.get('scan_duration', 'Unknown')}")
            report_lines.append("")

            # Hosts
            report_lines.append("DISCOVERED HOSTS")
            report_lines.append("-" * 40)
            for host in scan_data.get('hosts', []):
                report_lines.append(f"IP: {host.get('ip_address', '')}")
                report_lines.append(f"  Hostname: {host.get('hostname', 'N/A')}")
                report_lines.append(f"  OS: {host.get('os_name', 'Unknown')}")
                report_lines.append(f"  MAC: {host.get('mac_address', 'N/A')}")

                open_ports = [p for p in host.get('ports', []) if p.get('state') == 'open']
                if open_ports:
                    report_lines.append("  Open Ports:")
                    for port in open_ports:
                        report_lines.append(
                            f"    {port.get('port_number')}/{port.get('protocol')} - {port.get('service')}")
                else:
                    report_lines.append("  No open ports found")
                report_lines.append("")

            # Security Analysis
            report_lines.append("SECURITY ANALYSIS")
            report_lines.append("-" * 40)
            for risk_level in ['high_risk', 'medium_risk', 'low_risk']:
                risks = security.get(risk_level, [])
                if risks:
                    level_name = risk_level.replace('_', ' ').title()
                    report_lines.append(f"{level_name} ({len(risks)} issues):")
                    for risk in risks:
                        report_lines.append(f"  - {risk['host']}:{risk['port']} - {risk['description']}")
                    report_lines.append("")

            if not any(security.get(level, []) for level in ['high_risk', 'medium_risk', 'low_risk']):
                report_lines.append("No security risks detected")

            report_lines.append("")
            report_lines.append("=" * 80)
            report_lines.append("Report generated by NetMapper v2.0 - Optimized Edition")
            report_lines.append("Smart scanning technology - Maximum efficiency, minimum time")
            report_lines.append("=" * 80)

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report_lines))

            print(f"✅ Text report generated: {output_file}")
            return output_file

        except Exception as e:
            print(f"❌ Error generating text report: {e}")
            return ""

    def _generate_json_report(self, scan_data, output_file=None):
        """Generate JSON report"""
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.data_path, "reports", f"network_report_{timestamp}.json")

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(scan_data, f, indent=2, default=str)

            print(f"✅ JSON report generated: {output_file}")
            return output_file

        except Exception as e:
            print(f"❌ Error generating JSON report: {e}")
            return ""

    def _generate_csv_report(self, scan_data, output_file=None):
        """Generate CSV report"""
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.data_path, "reports", f"network_report_{timestamp}.csv")

        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Write header
                writer.writerow(['IP Address', 'Hostname', 'OS', 'MAC Address', 'Status', 'Open Ports', 'Services'])

                # Write host data
                for host in scan_data.get('hosts', []):
                    open_ports = [str(p.get('port_number', '')) for p in host.get('ports', []) if
                                  p.get('state') == 'open']
                    services = [p.get('service', '') for p in host.get('ports', []) if p.get('state') == 'open']

                    writer.writerow([
                        host.get('ip_address', ''),
                        host.get('hostname', ''),
                        host.get('os_name', ''),
                        host.get('mac_address', ''),
                        host.get('status', ''),
                        ', '.join(open_ports),
                        ', '.join(services)
                    ])

            print(f"✅ CSV report generated: {output_file}")
            return output_file

        except Exception as e:
            print(f"❌ Error generating CSV report: {e}")
            return ""

    # Database helper methods
    def _save_scan_session(self, session_id, start_time, target_network, scan_type, status):
        """Save scan session to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                           INSERT INTO scan_sessions (id, start_time, target_network, scan_type, status)
                           VALUES (?, ?, ?, ?, ?)
                           ''', (session_id, start_time, target_network, scan_type, status))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ Error saving scan session: {e}")

    def _update_scan_session(self, session_id, end_time, status, total_hosts, live_hosts):
        """Update scan session in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                           UPDATE scan_sessions
                           SET end_time    = ?,
                               status      = ?,
                               total_hosts = ?,
                               live_hosts  = ?
                           WHERE id = ?
                           ''', (end_time, status, total_hosts, live_hosts, session_id))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ Error updating scan session: {e}")

    def _save_host_data(self, session_id, host_data):
        """Save host data to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Insert host
            cursor.execute('''
                           INSERT INTO hosts (session_id, ip_address, hostname, mac_address, vendor,
                                              os_name, os_confidence, status, response_time)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                           ''', (
                               session_id,
                               host_data.get('ip_address', ''),
                               host_data.get('hostname', ''),
                               host_data.get('mac_address', ''),
                               host_data.get('vendor', ''),
                               host_data.get('os_name', ''),
                               host_data.get('os_confidence', 0.0),
                               host_data.get('status', ''),
                               host_data.get('response_time', 0.0)
                           ))

            host_id = cursor.lastrowid

            # Insert ports
            for port_data in host_data.get('ports', []):
                cursor.execute('''
                               INSERT INTO ports (host_id, port_number, protocol, state, service, version, banner)
                               VALUES (?, ?, ?, ?, ?, ?, ?)
                               ''', (
                                   host_id,
                                   port_data.get('port_number', 0),
                                   port_data.get('protocol', 'tcp'),
                                   port_data.get('state', 'unknown'),
                                   port_data.get('service', ''),
                                   port_data.get('version', ''),
                                   port_data.get('banner', '')
                               ))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ Error saving host data: {e}")

    def _save_scan_results(self, session_id, scan_results):
        """Save complete scan results to JSON file"""
        try:
            json_file = os.path.join(self.data_path, "scans", f"{session_id}.json")
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, indent=2, default=str)
            print(f"✅ Scan results saved: {json_file}")
        except Exception as e:
            print(f"❌ Error saving scan results: {e}")

    def list_scan_sessions(self):
        """List all scan sessions"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                           SELECT id, start_time, end_time, target_network, scan_type, status, live_hosts
                           FROM scan_sessions
                           ORDER BY start_time DESC
                           ''')

            sessions = []
            for row in cursor.fetchall():
                sessions.append({
                    'id': row[0],
                    'start_time': row[1],
                    'end_time': row[2],
                    'target_network': row[3],
                    'scan_type': row[4],
                    'status': row[5],
                    'live_hosts': row[6]
                })

            conn.close()
            return sessions
        except Exception as e:
            print(f"❌ Error listing scan sessions: {e}")
            return []

    def run_interactive_mode(self):
        """Run interactive mode"""
        print("\n" + "=" * 60)
        print("🚀 OPTIMIZED NETMAPPER REPORT GENERATOR")
        print("=" * 60)

        while True:
            print("\nAvailable Commands:")
            print("1. 🧠 smart   - Perform SMART scan (recommended)")
            print("2. 📊 report  - Generate report from scan data")
            print("3. 📋 list    - List all scan sessions")
            print("4. 🔍 auto    - Auto-detect and smart scan local network")
            print("5. ❌ exit    - Exit the program")

            choice = input("\nEnter your choice (1-5): ").strip()

            try:
                if choice == '1' or choice.lower() == 'smart':
                    self._interactive_smart_scan()
                elif choice == '2' or choice.lower() == 'report':
                    self._interactive_report()
                elif choice == '3' or choice.lower() == 'list':
                    self._interactive_list()
                elif choice == '4' or choice.lower() == 'auto':
                    self._interactive_auto_smart_scan()
                elif choice == '5' or choice.lower() == 'exit':
                    print("\n👋 Goodbye!")
                    break
                else:
                    print("❌ Invalid choice. Please try again.")
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ Error: {e}")

    def _interactive_smart_scan(self):
        """Interactive smart scan mode"""
        print("\n🧠 SMART SCAN CONFIGURATION")
        print("-" * 40)

        target_network = input("Enter target network (e.g., 192.168.1.0/24): ").strip()
        if not target_network:
            print("❌ Target network is required.")
            return

        print(f"\n🎯 Starting SMART scan of {target_network}...")
        session_id = self.perform_smart_scan(target_network)

        if session_id:
            print(f"\n✅ SMART scan completed successfully!")
            print(f"Session ID: {session_id}")
            if input("\nGenerate report now? (y/n): ").strip().lower() == 'y':
                self._generate_report_for_session(session_id)
        else:
            print("\n❌ SMART scan failed.")

    def _interactive_auto_smart_scan(self):
        """Interactive auto smart scan mode"""
        print("\n🔍 AUTO-DETECTING LOCAL NETWORK")
        print("-" * 40)

        local_network = self.get_local_network()
        print(f"🌐 Detected local network: {local_network}")

        if input(f"\nPerform SMART scan on {local_network}? (y/n): ").strip().lower() == 'y':
            print(f"\n🎯 Starting auto SMART scan of {local_network}...")
            session_id = self.perform_smart_scan(local_network)

            if session_id:
                print(f"\n✅ Auto SMART scan completed successfully!")
                print(f"Session ID: {session_id}")
                if input("\nGenerate report now? (y/n): ").strip().lower() == 'y':
                    self._generate_report_for_session(session_id)
            else:
                print("\n❌ Auto SMART scan failed.")
        else:
            print("❌ Auto SMART scan cancelled.")

    def _interactive_report(self):
        """Interactive report generation mode"""
        print("\n📊 REPORT GENERATION")
        print("-" * 40)

        sessions = self.list_scan_sessions()
        if not sessions:
            print("❌ No scan sessions found. Run a scan first.")
            return

        print("\nAvailable scan sessions:")
        for i, session in enumerate(sessions[:10]):
            print(f"{i + 1}. {session['id']} - {session['target_network']} ({session['status']})")

        session_choice = input("\nEnter session number (or press Enter for latest): ").strip()

        if session_choice.isdigit():
            session_idx = int(session_choice) - 1
            if 0 <= session_idx < len(sessions):
                session_id = sessions[session_idx]['id']
            else:
                print("❌ Invalid session number.")
                return
        else:
            session_id = sessions[0]['id']

        self._generate_report_for_session(session_id)

    def _generate_report_for_session(self, session_id):
        """Generate report for a specific session"""
        print(f"\n📊 Generating report for session: {session_id}")

        print("\nReport Options:")
        print("1. HTML (recommended)")
        print("2. Text")
        print("3. JSON")
        print("4. CSV")

        format_choice = input("Choose report format (1-4, default: 1): ").strip()
        format_map = {'1': 'html', '2': 'text', '3': 'json', '4': 'csv'}
        output_format = format_map.get(format_choice, 'html')

        report_file = self.generate_report(
            session_id=session_id,
            output_format=output_format
        )

        if report_file:
            print(f"\n✅ Report generated: {report_file}")
        else:
            print("\n❌ Report generation failed.")

    def _interactive_list(self):
        """Interactive session listing mode"""
        print("\n📋 SCAN SESSIONS")
        print("-" * 40)

        sessions = self.list_scan_sessions()
        if not sessions:
            print("❌ No scan sessions found.")
            return

        print(f"\nFound {len(sessions)} scan sessions:")
        print("{:<25} {:<20} {:<15} {:<10} {:<10}".format(
            "Session ID", "Start Time", "Target Network", "Status", "Live Hosts"
        ))
        print("-" * 80)

        for session in sessions:
            start_time = session['start_time'][:19] if session['start_time'] else 'N/A'
            target = session['target_network'][:14] if session['target_network'] else 'N/A'
            print("{:<25} {:<20} {:<15} {:<10} {:<10}".format(
                session['id'][:24],
                start_time,
                target,
                session['status'],
                str(session['live_hosts'] or 0)
            ))


def main():
    """Main function to run the Optimized NetMapper Report Generator"""
    print("🚀 NetMapper Optimized Report Generator v2.0")
    print("=" * 60)

    import argparse
    parser = argparse.ArgumentParser(
        description='NetMapper Optimized Report Generator - Smart Network Scanning for Responsive Hosts Only'
    )
    parser.add_argument('--smart', '-s', help='Perform smart scan on target (e.g., 192.168.1.0/24)')
    parser.add_argument('--report', '-r', help='Generate report for session ID')
    parser.add_argument('--format', '-f', choices=['html', 'text', 'json', 'csv'], default='html',
                        help='Report format')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--list', '-l', action='store_true', help='List all scan sessions')
    parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive mode')
    parser.add_argument('--auto', '-a', action='store_true', help='Auto-detect and smart scan local network')
    parser.add_argument('--data-path', '-d', default='scan_data', help='Data directory path')

    args = parser.parse_args()

    # Initialize the generator
    generator = IntegratedNetMapperReportGenerator(data_path=args.data_path)

    try:
        if args.interactive:
            generator.run_interactive_mode()
        elif args.auto:
            # Auto-detect and smart scan local network
            local_network = generator.get_local_network()
            print(f"🌐 Auto-detected network: {local_network}")
            session_id = generator.perform_smart_scan(local_network)
            if session_id:
                print(f"\n✅ Auto SMART scan completed!")
                report_file = generator.generate_report(
                    session_id=session_id,
                    output_format=args.format,
                    output_file=args.output
                )
                if report_file:
                    print(f"✅ Report generated: {report_file}")
        elif args.smart:
            # Perform smart scan
            print(f"🧠 Starting SMART scan of {args.smart}")
            session_id = generator.perform_smart_scan(args.smart)
            if session_id:
                print(f"\n✅ SMART scan completed successfully!")
                print(f"Session ID: {session_id}")
                # Generate report
                report_file = generator.generate_report(
                    session_id=session_id,
                    output_format=args.format,
                    output_file=args.output
                )
                if report_file:
                    print(f"✅ Report generated: {report_file}")
            else:
                print("❌ SMART scan failed.")
        elif args.report:
            # Generate report for specific session
            print(f"📊 Generating {args.format.upper()} report for session: {args.report}")
            report_file = generator.generate_report(
                session_id=args.report,
                output_format=args.format,
                output_file=args.output
            )
            if report_file:
                print(f"✅ Report generated: {report_file}")
            else:
                print("❌ Report generation failed.")
        elif args.list:
            # List all scan sessions
            sessions = generator.list_scan_sessions()
            if sessions:
                print(f"\n📋 Found {len(sessions)} scan sessions:")
                print("{:<25} {:<20} {:<15} {:<10}".format("Session ID", "Start Time", "Target Network", "Status"))
                print("-" * 70)
                for session in sessions:
                    start_time = session['start_time'][:19] if session['start_time'] else 'N/A'
                    target = session['target_network'][:14] if session['target_network'] else 'N/A'
                    print("{:<25} {:<20} {:<15} {:<10}".format(
                        session['id'][:24], start_time, target, session['status']
                    ))
            else:
                print("❌ No scan sessions found.")
        else:
            # Show help and run interactive mode
            print("\n🚀 No specific action provided. Starting interactive mode...")
            print("Use --help for command-line options.")
            generator.run_interactive_mode()

    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("Use --help for usage information.")


if __name__ == "__main__":
    main()

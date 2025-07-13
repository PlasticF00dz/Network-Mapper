#!/usr/bin/env python3
"""
Advanced Network Graph Visualizer
Creates beautiful network topology visualizations from scan data
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import networkx as nx
import numpy as np
import json
import sqlite3
import ipaddress
import os
import sys
from typing import Dict, List, Any, Tuple, Optional
import colorsys
import math
from datetime import datetime


class NetworkVisualizer:
    """
    Advanced Network Visualization System
    Creates interactive and static network topology graphs
    """

    def __init__(self, scan_data_path="scan_data"):
        self.scan_data_path = scan_data_path
        self.db_path = os.path.join(scan_data_path, "netmapper.db")

        # Color schemes for different visualizations
        self.color_schemes = {
            'device_types': {
                'router': '#FF6B6B',  # Red
                'switch': '#4ECDC4',  # Teal
                'server': '#45B7D1',  # Blue
                'workstation': '#96CEB4',  # Green
                'printer': '#FFEAA7',  # Yellow
                'iot': '#DDA0DD',  # Plum
                'mobile': '#98D8C8',  # Mint
                'unknown': '#95A5A6'  # Gray
            },
            'os_types': {
                'windows': '#0078D4',  # Microsoft Blue
                'linux': '#FCC624',  # Linux Yellow
                'macos': '#007AFF',  # Apple Blue
                'android': '#3DDC84',  # Android Green
                'ios': '#007AFF',  # iOS Blue
                'router_os': '#FF6B6B',  # Router Red
                'unknown': '#95A5A6'  # Gray
            },
            'security_levels': {
                'critical': '#E74C3C',  # Red
                'high': '#E67E22',  # Orange
                'medium': '#F39C12',  # Yellow
                'low': '#27AE60',  # Green
                'secure': '#2ECC71'  # Dark Green
            },
            'port_status': {
                'critical_open': '#E74C3C',
                'standard_open': '#3498DB',
                'secure_open': '#27AE60',
                'filtered': '#F39C12',
                'closed': '#95A5A6'
            }
        }

        # Device detection patterns
        self.device_patterns = {
            'router': ['router', 'gateway', 'rt-', 'gw-', 'edge', 'cisco', 'netgear', 'linksys'],
            'switch': ['switch', 'sw-', 'layer2', 'l2-', 'managed'],
            'server': ['server', 'srv-', 'web-', 'mail-', 'db-', 'nas-', 'storage'],
            'workstation': ['pc-', 'ws-', 'desktop-', 'laptop-', 'computer'],
            'printer': ['printer', 'print', 'hp-', 'canon-', 'epson-', 'brother'],
            'iot': ['iot-', 'sensor-', 'cam-', 'camera', 'thermostat', 'alexa', 'nest', 'smart'],
            'mobile': ['android', 'iphone', 'ipad', 'mobile', 'phone', 'tablet']
        }

        # Critical ports for security analysis
        self.critical_ports = {
            21: {'service': 'FTP', 'risk': 'high', 'reason': 'Unencrypted file transfer'},
            22: {'service': 'SSH', 'risk': 'medium', 'reason': 'Remote access (secure if configured)'},
            23: {'service': 'Telnet', 'risk': 'critical', 'reason': 'Unencrypted remote access'},
            25: {'service': 'SMTP', 'risk': 'medium', 'reason': 'Mail server'},
            53: {'service': 'DNS', 'risk': 'low', 'reason': 'Domain name resolution'},
            80: {'service': 'HTTP', 'risk': 'medium', 'reason': 'Unencrypted web traffic'},
            135: {'service': 'RPC', 'risk': 'high', 'reason': 'Windows RPC service'},
            139: {'service': 'NetBIOS', 'risk': 'high', 'reason': 'Windows file sharing'},
            443: {'service': 'HTTPS', 'risk': 'low', 'reason': 'Encrypted web traffic'},
            445: {'service': 'SMB', 'risk': 'critical', 'reason': 'Windows file sharing'},
            993: {'service': 'IMAPS', 'risk': 'low', 'reason': 'Encrypted email'},
            995: {'service': 'POP3S', 'risk': 'low', 'reason': 'Encrypted email'},
            3389: {'service': 'RDP', 'risk': 'critical', 'reason': 'Windows remote desktop'},
            5432: {'service': 'PostgreSQL', 'risk': 'high', 'reason': 'Database server'},
            3306: {'service': 'MySQL', 'risk': 'high', 'reason': 'Database server'}
        }

    def load_scan_data(self, session_id=None):
        """Load scan data from database or latest scan"""
        try:
            if session_id:
                # Load specific session from JSON
                json_file = os.path.join(self.scan_data_path, "scans", f"{session_id}.json")
                if os.path.exists(json_file):
                    with open(json_file, 'r', encoding='utf-8') as f:
                        return json.load(f)

            # Load latest scan from database
            if os.path.exists(self.db_path):
                return self._load_from_database()

            # Fallback to latest JSON file
            scan_files = []
            scans_dir = os.path.join(self.scan_data_path, "scans")
            if os.path.exists(scans_dir):
                scan_files = [f for f in os.listdir(scans_dir) if f.endswith('.json')]

            if scan_files:
                latest_file = max(scan_files, key=lambda f: os.path.getmtime(os.path.join(scans_dir, f)))
                with open(os.path.join(scans_dir, latest_file), 'r', encoding='utf-8') as f:
                    return json.load(f)

            return None

        except Exception as e:
            print(f"❌ Error loading scan data: {e}")
            return None

    def _load_from_database(self):
        """Load scan data from SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get latest session
            cursor.execute('''
                           SELECT id, target_network, start_time, end_time, scan_type
                           FROM scan_sessions
                           ORDER BY start_time DESC LIMIT 1
                           ''')

            session_row = cursor.fetchone()
            if not session_row:
                conn.close()
                return None

            session_id, target_network, start_time, end_time, scan_type = session_row

            # Get hosts and ports
            cursor.execute('''
                           SELECT h.ip_address,
                                  h.hostname,
                                  h.mac_address,
                                  h.os_name,
                                  h.status,
                                  p.port_number,
                                  p.protocol,
                                  p.state,
                                  p.service,
                                  p.banner
                           FROM hosts h
                                    LEFT JOIN ports p ON h.id = p.host_id
                           WHERE h.session_id = ?
                           ORDER BY h.ip_address, p.port_number
                           ''', (session_id,))

            rows = cursor.fetchall()
            conn.close()

            # Convert to scan data format
            return self._convert_db_rows_to_scan_data(session_id, target_network, start_time, end_time, scan_type, rows)

        except Exception as e:
            print(f"❌ Error loading from database: {e}")
            return None

    def _convert_db_rows_to_scan_data(self, session_id, target_network, start_time, end_time, scan_type, rows):
        """Convert database rows to scan data format"""
        hosts_dict = {}

        for row in rows:
            ip, hostname, mac, os_name, status, port_num, protocol, port_state, service, banner = row

            if ip not in hosts_dict:
                hosts_dict[ip] = {
                    'ip_address': ip,
                    'hostname': hostname or '',
                    'mac_address': mac or '',
                    'os_name': os_name or 'Unknown',
                    'status': status or 'unknown',
                    'ports': []
                }

            if port_num:
                hosts_dict[ip]['ports'].append({
                    'port_number': port_num,
                    'protocol': protocol or 'tcp',
                    'state': port_state or 'unknown',
                    'service': service or 'unknown',
                    'banner': banner or ''
                })

        return {
            'session': {
                'id': session_id,
                'target_network': target_network,
                'start_time': start_time,
                'end_time': end_time,
                'scan_type': scan_type
            },
            'hosts': list(hosts_dict.values()),
            'topology': []
        }

    def detect_device_type(self, host_data):
        """Detect device type based on various indicators"""
        hostname = host_data.get('hostname', '').lower()
        os_name = host_data.get('os_name', '').lower()
        ports = host_data.get('ports', [])
        mac = host_data.get('mac_address', '').lower()

        # Check hostname patterns first
        for device_type, patterns in self.device_patterns.items():
            for pattern in patterns:
                if pattern in hostname:
                    return device_type

        # Check MAC address OUI for device type hints
        if mac:
            oui = mac[:8].replace(':', '').upper()
            device_type = self._detect_by_mac_oui(oui)
            if device_type:
                return device_type

        # Check by running services
        open_services = [p.get('service', '').lower() for p in ports if p.get('state') == 'open']

        # Router indicators
        if any(s in ['upnp', 'http'] for s in open_services) and len(open_services) <= 3:
            if any(port.get('port_number') in [80, 8080, 443] for port in ports):
                return 'router'

        # Server indicators
        if any(s in ['http', 'https', 'ssh', 'ftp', 'smtp', 'mysql', 'postgresql'] for s in open_services):
            if len(open_services) >= 3:
                return 'server'

        # Printer indicators
        if any(s in ['ipp', 'printer', 'jetdirect'] for s in open_services):
            return 'printer'

        # Windows workstation
        if any(s in ['microsoft-ds', 'netbios-ssn', 'msrpc'] for s in open_services):
            return 'workstation'

        # IoT device (few services, specific ports)
        if len(open_services) <= 2 and any(port.get('port_number') in [80, 443, 8080] for port in ports):
            return 'iot'

        # Check by OS
        if 'windows' in os_name:
            return 'workstation'
        elif 'linux' in os_name and len(open_services) >= 2:
            return 'server'
        elif any(mobile_os in os_name for mobile_os in ['android', 'ios']):
            return 'mobile'

        return 'unknown'

    def _detect_by_mac_oui(self, oui):
        """Detect device type by MAC OUI (first 6 characters)"""
        # Common OUI patterns (simplified)
        oui_patterns = {
            'apple': 'mobile',
            'samsung': 'mobile',
            'cisco': 'router',
            'netgear': 'router',
            'linksys': 'router',
            'hp': 'printer',
            'canon': 'printer',
            'epson': 'printer'
        }

        # This would need a full OUI database in production
        # For now, return None to use other detection methods
        return None

    def calculate_security_risk(self, host_data):
        """Calculate security risk level for a host"""
        risk_score = 0
        risk_factors = []

        ports = host_data.get('ports', [])

        for port in ports:
            if port.get('state') != 'open':
                continue

            port_num = port.get('port_number', 0)
            service = port.get('service', '').lower()

            if port_num in self.critical_ports:
                port_info = self.critical_ports[port_num]
                if port_info['risk'] == 'critical':
                    risk_score += 10
                    risk_factors.append(f"Critical service: {port_info['service']} ({port_info['reason']})")
                elif port_info['risk'] == 'high':
                    risk_score += 5
                    risk_factors.append(f"High-risk service: {port_info['service']} ({port_info['reason']})")
                elif port_info['risk'] == 'medium':
                    risk_score += 2
                elif port_info['risk'] == 'low':
                    risk_score -= 1  # Secure services reduce risk

        # Determine risk level
        if risk_score >= 10:
            return 'critical', risk_factors
        elif risk_score >= 5:
            return 'high', risk_factors
        elif risk_score >= 2:
            return 'medium', risk_factors
        elif risk_score >= 0:
            return 'low', risk_factors
        else:
            return 'secure', risk_factors

    def create_network_graph(self, scan_data, layout='spring', color_by='device_type',
                             show_labels=True, show_ports=True, node_size_factor=1.0,
                             show_security=False, output_file=None):
        """Create network topology graph"""

        if not scan_data or 'hosts' not in scan_data:
            print("❌ No scan data available for visualization")
            return None

        hosts = scan_data['hosts']
        if not hosts:
            print("❌ No hosts found in scan data")
            return None

        print(f"🎨 Creating network graph with {len(hosts)} hosts")
        print(f"   Layout: {layout}, Color by: {color_by}")

        # Create NetworkX graph
        G = nx.Graph()

        # Process hosts and add nodes
        node_info = {}
        for host in hosts:
            ip = host['ip_address']
            device_type = self.detect_device_type(host)
            risk_level, risk_factors = self.calculate_security_risk(host)

            # Calculate node size based on number of open ports
            open_ports = len([p for p in host.get('ports', []) if p.get('state') == 'open'])
            base_size = 500
            size_multiplier = max(1, open_ports * 0.3)
            node_size = int(base_size * size_multiplier * node_size_factor)

            node_info[ip] = {
                'hostname': host.get('hostname', ''),
                'os_name': host.get('os_name', 'Unknown'),
                'mac_address': host.get('mac_address', ''),
                'device_type': device_type,
                'risk_level': risk_level,
                'risk_factors': risk_factors,
                'open_ports': open_ports,
                'ports': host.get('ports', []),
                'node_size': node_size,
                'status': host.get('status', 'unknown')
            }

            G.add_node(ip, **node_info[ip])

        # Add edges based on network topology
        self._add_network_edges(G, scan_data, node_info)

        # Create visualization
        fig = self._render_network_graph(G, node_info, layout, color_by,
                                         show_labels, show_ports, show_security)

        # Save if output file specified
        if output_file:
            fig.savefig(output_file, dpi=300, bbox_inches='tight',
                        facecolor='white', edgecolor='none')
            print(f"✅ Graph saved to: {output_file}")

        return fig

    def _add_network_edges(self, G, scan_data, node_info):
        """Add edges to represent network connections"""
        hosts = list(node_info.keys())

        if len(hosts) <= 1:
            return

        # Try to identify gateway/router
        gateway_candidates = []
        for host_ip in hosts:
            device_type = node_info[host_ip]['device_type']
            if device_type == 'router':
                gateway_candidates.append(host_ip)

        # If no explicit router, find likely gateway (usually .1 or .254)
        if not gateway_candidates:
            for host_ip in hosts:
                try:
                    ip_obj = ipaddress.IPv4Address(host_ip)
                    ip_str = str(ip_obj)
                    if ip_str.endswith('.1') or ip_str.endswith('.254'):
                        gateway_candidates.append(host_ip)
                        break
                except:
                    continue

        # If still no gateway, use first host
        if not gateway_candidates and hosts:
            gateway_candidates.append(hosts[0])

        # Connect devices in a logical topology
        if gateway_candidates:
            gateway = gateway_candidates[0]

            # Connect all devices to gateway
            for host_ip in hosts:
                if host_ip != gateway:
                    G.add_edge(gateway, host_ip, weight=1)

            # Add some inter-device connections for servers and workstations
            servers = [ip for ip in hosts if node_info[ip]['device_type'] == 'server']
            workstations = [ip for ip in hosts if node_info[ip]['device_type'] == 'workstation']

            # Connect some workstations to servers
            for server in servers[:2]:  # Limit to first 2 servers
                for workstation in workstations[:3]:  # Connect to first 3 workstations
                    if not G.has_edge(server, workstation):
                        G.add_edge(server, workstation, weight=0.5)

    def _render_network_graph(self, G, node_info, layout, color_by,
                              show_labels, show_ports, show_security):
        """Render the network graph with advanced styling"""

        # Create figure
        fig, ax = plt.subplots(1, 1, figsize=(16, 12), dpi=100)
        fig.patch.set_facecolor('white')

        # Choose layout algorithm
        if layout == 'spring':
            pos = nx.spring_layout(G, k=3, iterations=50, seed=42)
        elif layout == 'circular':
            pos = nx.circular_layout(G)
        elif layout == 'kamada_kawai':
            pos = nx.kamada_kawai_layout(G)
        elif layout == 'hierarchical':
            pos = self._create_hierarchical_layout(G, node_info)
        else:
            pos = nx.spring_layout(G, k=3, iterations=50, seed=42)

        # Draw edges
        edge_weights = [G[u][v].get('weight', 1) for u, v in G.edges()]
        nx.draw_networkx_edges(G, pos,
                               width=[w * 2 for w in edge_weights],
                               alpha=0.6,
                               edge_color='#CCCCCC',
                               style='-')

        # Prepare node colors and sizes
        node_colors = []
        node_sizes = []

        for node in G.nodes():
            info = node_info[node]

            # Determine color based on color_by parameter
            if color_by == 'device_type':
                color = self.color_schemes['device_types'].get(info['device_type'], '#95A5A6')
            elif color_by == 'os_type':
                os_name = info['os_name'].lower()
                if 'windows' in os_name:
                    color = self.color_schemes['os_types']['windows']
                elif 'linux' in os_name:
                    color = self.color_schemes['os_types']['linux']
                elif 'mac' in os_name:
                    color = self.color_schemes['os_types']['macos']
                elif 'android' in os_name:
                    color = self.color_schemes['os_types']['android']
                else:
                    color = self.color_schemes['os_types']['unknown']
            elif color_by == 'security':
                color = self.color_schemes['security_levels'].get(info['risk_level'], '#95A5A6')
            else:
                color = '#3498DB'  # Default blue

            node_colors.append(color)
            node_sizes.append(info['node_size'])

        # Draw nodes
        nx.draw_networkx_nodes(G, pos,
                               node_color=node_colors,
                               node_size=node_sizes,
                               alpha=0.8,
                               edgecolors='black',
                               linewidths=2)

        # Add labels
        if show_labels:
            self._add_node_labels(G, pos, node_info, ax)

        # Add port information
        if show_ports:
            self._add_port_indicators(G, pos, node_info, ax)

        # Add security indicators
        if show_security:
            self._add_security_indicators(G, pos, node_info, ax)

        # Add legend
        self._add_legend(ax, color_by, show_security)

        # Set title
        session_info = "Network Topology Visualization"
        if 'session' in G.graph:
            session_info = f"Network Scan: {G.graph['session'].get('target_network', 'Unknown')}"

        plt.title(session_info, fontsize=18, fontweight='bold', pad=20)

        # Remove axes
        ax.set_axis_off()

        # Adjust layout
        plt.tight_layout()

        return fig

    def _create_hierarchical_layout(self, G, node_info):
        """Create hierarchical layout based on device types"""
        pos = {}

        # Group nodes by device type
        device_groups = {}
        for node in G.nodes():
            device_type = node_info[node]['device_type']
            if device_type not in device_groups:
                device_groups[device_type] = []
            device_groups[device_type].append(node)

        # Define hierarchy levels
        hierarchy = {
            'router': 0,
            'switch': 1,
            'server': 2,
            'workstation': 3,
            'printer': 3,
            'iot': 4,
            'mobile': 4,
            'unknown': 5
        }

        # Position nodes
        y_spacing = 2.0
        x_spacing = 1.5

        for device_type, nodes in device_groups.items():
            level = hierarchy.get(device_type, 5)
            y = -level * y_spacing

            # Distribute nodes horizontally at this level
            if len(nodes) == 1:
                x = 0
                pos[nodes[0]] = (x, y)
            else:
                x_positions = np.linspace(-len(nodes) * x_spacing / 2,
                                          len(nodes) * x_spacing / 2,
                                          len(nodes))
                for i, node in enumerate(nodes):
                    pos[node] = (x_positions[i], y)

        return pos

    def _add_node_labels(self, G, pos, node_info, ax):
        """Add custom labels to nodes"""
        for node in G.nodes():
            x, y = pos[node]
            info = node_info[node]

            # Create label text
            hostname = info['hostname'][:12] if info['hostname'] else ''
            ip = node
            device_type = info['device_type'].upper()

            if hostname:
                label = f"{hostname}\n{ip}\n[{device_type}]"
            else:
                label = f"{ip}\n[{device_type}]"

            # Position label below node
            ax.text(x, y - 0.15, label,
                    horizontalalignment='center',
                    verticalalignment='top',
                    fontsize=8,
                    fontweight='bold',
                    bbox=dict(boxstyle="round,pad=0.3",
                              facecolor='white',
                              alpha=0.9,
                              edgecolor='gray'))

    def _add_port_indicators(self, G, pos, node_info, ax):
        """Add port status indicators around nodes"""
        for node in G.nodes():
            x, y = pos[node]
            info = node_info[node]

            open_ports = [p for p in info['ports'] if p.get('state') == 'open']

            if open_ports:
                # Show up to 8 most important ports
                important_ports = []
                for port in open_ports[:8]:
                    port_num = port.get('port_number', 0)
                    if port_num in self.critical_ports:
                        risk = self.critical_ports[port_num]['risk']
                        if risk == 'critical':
                            important_ports.append(('red', port_num))
                        elif risk == 'high':
                            important_ports.append(('orange', port_num))
                        elif risk == 'medium':
                            important_ports.append(('yellow', port_num))
                        else:
                            important_ports.append(('green', port_num))
                    else:
                        important_ports.append(('blue', port_num))

                # Draw port indicators in a circle around the node
                for i, (color, port_num) in enumerate(important_ports):
                    angle = (2 * np.pi * i) / len(important_ports)
                    px = x + 0.08 * np.cos(angle)
                    py = y + 0.08 * np.sin(angle)

                    circle = patches.Circle((px, py), radius=0.015,
                                            facecolor=color,
                                            edgecolor='black',
                                            linewidth=0.5,
                                            alpha=0.8)
                    ax.add_patch(circle)

    def _add_security_indicators(self, G, pos, node_info, ax):
        """Add security risk indicators"""
        for node in G.nodes():
            x, y = pos[node]
            info = node_info[node]

            risk_level = info['risk_level']

            if risk_level in ['critical', 'high']:
                # Add warning symbol for high-risk hosts
                symbol = '⚠️' if risk_level == 'high' else '🚨'
                ax.text(x + 0.1, y + 0.1, symbol,
                        fontsize=12,
                        horizontalalignment='center',
                        verticalalignment='center')

    def _add_legend(self, ax, color_by, show_security):
        """Add comprehensive legend"""
        legend_elements = []

        if color_by == 'device_type':
            for device_type, color in self.color_schemes['device_types'].items():
                legend_elements.append(
                    plt.Line2D([0], [0], marker='o', color='w',
                               markerfacecolor=color, markersize=10,
                               label=device_type.title())
                )
        elif color_by == 'os_type':
            for os_type, color in self.color_schemes['os_types'].items():
                legend_elements.append(
                    plt.Line2D([0], [0], marker='o', color='w',
                               markerfacecolor=color, markersize=10,
                               label=os_type.title())
                )
        elif color_by == 'security':
            for risk_level, color in self.color_schemes['security_levels'].items():
                legend_elements.append(
                    plt.Line2D([0], [0], marker='o', color='w',
                               markerfacecolor=color, markersize=10,
                               label=risk_level.title())
                )

        # Add port indicators legend
        legend_elements.extend([
            plt.Line2D([0], [0], marker='o', color='w',
                       markerfacecolor='red', markersize=6,
                       label='Critical Ports'),
            plt.Line2D([0], [0], marker='o', color='w',
                       markerfacecolor='orange', markersize=6,
                       label='High-Risk Ports'),
            plt.Line2D([0], [0], marker='o', color='w',
                       markerfacecolor='green', markersize=6,
                       label='Secure Ports')
        ])

        # Create legend
        ax.legend(handles=legend_elements,
                  loc='upper left',
                  bbox_to_anchor=(1.02, 1),
                  fontsize=10,
                  title="Legend",
                  title_fontsize=12,
                  frameon=True,
                  fancybox=True,
                  shadow=True)

    def create_interactive_html_graph(self, scan_data, output_file="network_graph.html"):
        """Create interactive HTML network graph"""
        try:
            # Try to use plotly for interactive graphs
            import plotly.graph_objects as go
            import plotly.offline as pyo
            from plotly.subplots import make_subplots

            if not scan_data or 'hosts' not in scan_data:
                print("❌ No scan data available")
                return None

            hosts = scan_data['hosts']

            # Create NetworkX graph for layout
            G = nx.Graph()
            node_info = {}

            for host in hosts:
                ip = host['ip_address']
                device_type = self.detect_device_type(host)
                risk_level, risk_factors = self.calculate_security_risk(host)

                node_info[ip] = {
                    'hostname': host.get('hostname', ''),
                    'os_name': host.get('os_name', 'Unknown'),
                    'mac_address': host.get('mac_address', ''),
                    'device_type': device_type,
                    'risk_level': risk_level,
                    'risk_factors': risk_factors,
                    'ports': host.get('ports', [])
                }

                G.add_node(ip)

            # Add edges
            self._add_network_edges(G, scan_data, node_info)

            # Get layout positions
            pos = nx.spring_layout(G, k=3, iterations=50)

            # Create edge traces
            edge_x = []
            edge_y = []

            for edge in G.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])

            edge_trace = go.Scatter(x=edge_x, y=edge_y,
                                    line=dict(width=2, color='#888'),
                                    hoverinfo='none',
                                    mode='lines')

            # Create node traces
            node_x = []
            node_y = []
            node_text = []
            node_colors = []
            node_sizes = []

            for node in G.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)

                info = node_info[node]

                # Create detailed hover text
                open_ports = [p for p in info['ports'] if p.get('state') == 'open']
                port_list = ', '.join([f"{p['port_number']}/{p['service']}" for p in open_ports[:5]])
                if len(open_ports) > 5:
                    port_list += f" (+{len(open_ports) - 5} more)"

                hover_text = f"<b>{node}</b><br>"
                hover_text += f"Hostname: {info['hostname'] or 'N/A'}<br>"
                hover_text += f"OS: {info['os_name']}<br>"
                hover_text += f"Device Type: {info['device_type'].title()}<br>"
                hover_text += f"MAC: {info['mac_address'] or 'N/A'}<br>"
                hover_text += f"Risk Level: {info['risk_level'].title()}<br>"
                hover_text += f"Open Ports: {port_list or 'None'}<br>"

                if info['risk_factors']:
                    hover_text += f"<br><b>Security Issues:</b><br>"
                    for factor in info['risk_factors'][:3]:
                        hover_text += f"• {factor}<br>"

                node_text.append(hover_text)

                # Color by risk level
                risk_colors = {
                    'critical': '#E74C3C',
                    'high': '#E67E22',
                    'medium': '#F39C12',
                    'low': '#27AE60',
                    'secure': '#2ECC71'
                }
                node_colors.append(risk_colors.get(info['risk_level'], '#95A5A6'))

                # Size by number of open ports
                open_port_count = len(open_ports)
                size = max(20, min(60, 20 + open_port_count * 5))
                node_sizes.append(size)

            node_trace = go.Scatter(x=node_x, y=node_y,
                                    mode='markers+text',
                                    hoverinfo='text',
                                    text=[info['hostname'][:8] if info['hostname'] else node.split('.')[-1]
                                          for node, info in node_info.items()],
                                    textposition="middle center",
                                    hovertext=node_text,
                                    marker=dict(size=node_sizes,
                                                color=node_colors,
                                                line=dict(width=2, color='black')))

            # Create figure
            fig = go.Figure(data=[edge_trace, node_trace],
                            layout=go.Layout(
                                title=dict(
                                    text='Interactive Network Topology',
                                    x=0.5,
                                    font=dict(size=20)
                                ),
                                showlegend=False,
                                hovermode='closest',
                                margin=dict(b=20, l=5, r=5, t=40),
                                annotations=[dict(
                                    text="Hover over nodes for details. Colors indicate security risk levels.",
                                    showarrow=False,
                                    xref="paper", yref="paper",
                                    x=0.005, y=-0.002,
                                    xanchor="left", yanchor="bottom",
                                    font=dict(color="#888", size=12)
                                )],
                                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                plot_bgcolor='white'))

            # Save to HTML
            pyo.plot(fig, filename=output_file, auto_open=False)
            print(f"✅ Interactive graph saved to: {output_file}")
            return output_file

        except ImportError:
            print("⚠️  Plotly not available. Install with: pip install plotly")
            return self._create_simple_html_graph(scan_data, output_file)
        except Exception as e:
            print(f"❌ Error creating interactive graph: {e}")
            return None

    def _create_simple_html_graph(self, scan_data, output_file):
        """Create simple HTML graph without plotly"""
        try:
            html_content = self._generate_html_report(scan_data)

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            print(f"✅ Simple HTML graph saved to: {output_file}")
            return output_file

        except Exception as e:
            print(f"❌ Error creating simple HTML graph: {e}")
            return None

    def _generate_html_report(self, scan_data):
        """Generate HTML report with network information"""
        hosts = scan_data.get('hosts', [])

        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Topology Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
                .host-card { border: 1px solid #ddd; margin: 10px; padding: 15px; border-radius: 8px; background: #f9f9f9; }
                .risk-critical { border-left: 5px solid #E74C3C; }
                .risk-high { border-left: 5px solid #E67E22; }
                .risk-medium { border-left: 5px solid #F39C12; }
                .risk-low { border-left: 5px solid #27AE60; }
                .risk-secure { border-left: 5px solid #2ECC71; }
                .device-type { background: #3498DB; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; }
                .port-list { margin-top: 10px; }
                .port { background: #ecf0f1; padding: 2px 6px; margin: 2px; border-radius: 4px; display: inline-block; font-size: 0.9em; }
                .port-critical { background: #E74C3C; color: white; }
                .port-high { background: #E67E22; color: white; }
                .port-medium { background: #F39C12; color: white; }
                .port-secure { background: #27AE60; color: white; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🌐 Network Topology Report</h1>
                <p>Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
                <p>Total Hosts: """ + str(len(hosts)) + """</p>
        """

        for host in hosts:
            device_type = self.detect_device_type(host)
            risk_level, risk_factors = self.calculate_security_risk(host)

            html += f"""
                <div class="host-card risk-{risk_level}">
                    <h3>{host.get('ip_address', 'Unknown')} 
                        <span class="device-type">{device_type.upper()}</span>
                    </h3>
                    <p><strong>Hostname:</strong> {host.get('hostname', 'N/A')}</p>
                    <p><strong>OS:</strong> {host.get('os_name', 'Unknown')}</p>
                    <p><strong>MAC:</strong> {host.get('mac_address', 'N/A')}</p>
                    <p><strong>Risk Level:</strong> {risk_level.title()}</p>
            """

            if risk_factors:
                html += "<p><strong>Security Issues:</strong></p><ul>"
                for factor in risk_factors:
                    html += f"<li>{factor}</li>"
                html += "</ul>"

            open_ports = [p for p in host.get('ports', []) if p.get('state') == 'open']
            if open_ports:
                html += '<div class="port-list"><strong>Open Ports:</strong><br>'
                for port in open_ports:
                    port_num = port.get('port_number', 0)
                    service = port.get('service', 'unknown')

                    port_class = 'port'
                    if port_num in self.critical_ports:
                        risk = self.critical_ports[port_num]['risk']
                        if risk == 'critical':
                            port_class = 'port-critical'
                        elif risk == 'high':
                            port_class = 'port-high'
                        elif risk == 'medium':
                            port_class = 'port-medium'
                        elif risk == 'low':
                            port_class = 'port-secure'

                    html += f'<span class="{port_class}">{port_num}/{service}</span> '
                html += '</div>'

            html += '</div>'

        html += """
            </div>
        </body>
        </html>
        """

        return html

    def create_embedded_html_report(self, scan_data=None, output_file="embedded_network_report.html"):
        """Create HTML report with embedded network graph visualization"""

        if not scan_data:
            scan_data = self.load_scan_data()

        if not scan_data:
            print("❌ No scan data available")
            return None

        hosts = scan_data.get('hosts', [])
        if not hosts:
            print("❌ No hosts found in scan data")
            return None

        print(f"🎨 Creating embedded HTML report with {len(hosts)} hosts...")

        # Process host data for visualization
        nodes_data = []
        edges_data = []

        for i, host in enumerate(hosts):
            device_type = self.detect_device_type(host)
            risk_level, risk_factors = self.calculate_security_risk(host)
            open_ports = [p for p in host.get('ports', []) if p.get('state') == 'open']

            # Create node data
            node = {
                'id': host['ip_address'],
                'label': host.get('hostname', host['ip_address']),
                'ip': host['ip_address'],
                'hostname': host.get('hostname', ''),
                'os': host.get('os_name', 'Unknown'),
                'mac': host.get('mac_address', ''),
                'device_type': device_type,
                'risk_level': risk_level,
                'risk_factors': risk_factors,
                'open_ports': len(open_ports),
                'ports_detail': [f"{p['port_number']}/{p['service']}" for p in open_ports],
                'x': 300 + 200 * np.cos(2 * np.pi * i / len(hosts)),  # Circular layout
                'y': 300 + 200 * np.sin(2 * np.pi * i / len(hosts))
            }
            nodes_data.append(node)

        # Create edges (simple star topology with first node as center)
        if len(nodes_data) > 1:
            center_node = nodes_data[0]['id']
            for node in nodes_data[1:]:
                edges_data.append({
                    'source': center_node,
                    'target': node['id']
                })

        # Generate the complete HTML with embedded visualization
        html_content = self._generate_embedded_html_template(nodes_data, edges_data, scan_data)

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            print(f"✅ Embedded HTML report created: {output_file}")

            # Open in browser
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(output_file)}")

            return output_file

        except Exception as e:
            print(f"❌ Error creating embedded HTML report: {e}")
            return None

    def _generate_embedded_html_template(self, nodes_data, edges_data, scan_data):
        """Generate HTML template with embedded D3.js visualization"""

        # Convert data to JSON for JavaScript
        import json
        nodes_json = json.dumps(nodes_data)
        edges_json = json.dumps(edges_data)

        # Get session info
        session = scan_data.get('session', {})

        # Calculate statistics
        total_hosts = len(nodes_data)
        device_stats = {}
        risk_stats = {}

        for node in nodes_data:
            device_type = node['device_type']
            risk_level = node['risk_level']
            device_stats[device_type] = device_stats.get(device_type, 0) + 1
            risk_stats[risk_level] = risk_stats.get(risk_level, 0) + 1

        html_template = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive Network Topology Report</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}

        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}

        .header .subtitle {{
            margin-top: 10px;
            opacity: 0.9;
            font-size: 1.1em;
        }}

        .main-content {{
            display: flex;
            min-height: 600px;
        }}

        .graph-container {{
            flex: 2;
            position: relative;
            background: #f8f9fa;
            border-right: 1px solid #dee2e6;
        }}

        .sidebar {{
            flex: 1;
            padding: 20px;
            background: white;
            overflow-y: auto;
            max-height: 600px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}

        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }}

        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .stat-label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}

        .section {{
            margin-bottom: 25px;
        }}

        .section h3 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 5px;
            margin-bottom: 15px;
        }}

        .device-list {{
            max-height: 300px;
            overflow-y: auto;
        }}

        .device-item {{
            background: #f8f9fa;
            margin: 8px 0;
            padding: 12px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
            transition: all 0.3s ease;
        }}

        .device-item:hover {{
            background: #e9ecef;
            transform: translateX(5px);
        }}

        .device-item.risk-critical {{
            border-left-color: #e74c3c;
        }}

        .device-item.risk-high {{
            border-left-color: #e67e22;
        }}

        .device-item.risk-medium {{
            border-left-color: #f39c12;
        }}

        .device-item.risk-low {{
            border-left-color: #27ae60;
        }}

        .device-item.risk-secure {{
            border-left-color: #2ecc71;
        }}

        .device-ip {{
            font-weight: bold;
            color: #2c3e50;
        }}

        .device-type {{
            background: #3498db;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            margin-left: 10px;
        }}

        .risk-badge {{
            float: right;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            color: white;
        }}

        .risk-critical {{ background: #e74c3c; }}
        .risk-high {{ background: #e67e22; }}
        .risk-medium {{ background: #f39c12; }}
        .risk-low {{ background: #27ae60; }}
        .risk-secure {{ background: #2ecc71; }}

        .tooltip {{
            position: absolute;
            background: rgba(0, 0, 0, 0.9);
            color: white;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            pointer-events: none;
            z-index: 1000;
            max-width: 250px;
        }}

        .controls {{
            position: absolute;
            top: 10px;
            left: 10px;
            z-index: 100;
        }}

        .control-btn {{
            background: #3498db;
            color: white;
            border: none;
            padding: 8px 12px;
            margin: 2px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
        }}

        .control-btn:hover {{
            background: #2980b9;
        }}

        .legend {{
            position: absolute;
            bottom: 10px;
            left: 10px;
            background: rgba(255, 255, 255, 0.9);
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            margin: 3px 0;
        }}

        .legend-color {{
            width: 15px;
            height: 15px;
            border-radius: 50%;
            margin-right: 8px;
        }}

        #network-graph {{
            width: 100%;
            height: 600px;
        }}

        .node {{
            cursor: pointer;
            stroke: #333;
            stroke-width: 2px;
        }}

        .link {{
            stroke: #999;
            stroke-opacity: 0.6;
            stroke-width: 2px;
        }}

        .node-label {{
            font-size: 11px;
            font-weight: bold;
            text-anchor: middle;
            pointer-events: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 Interactive Network Topology</h1>
            <div class="subtitle">
                Target: {session.get('target_network', 'Unknown')} | 
                Scan ID: {session.get('id', 'Unknown')[:20]}... | 
                Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
        </div>

        <div class="main-content">
            <div class="graph-container">
                <div class="controls">
                    <button class="control-btn" onclick="colorByDevice()">Device Types</button>
                    <button class="control-btn" onclick="colorBySecurity()">Security Risk</button>
                    <button class="control-btn" onclick="resetZoom()">Reset View</button>
                </div>

                <div class="legend">
                    <div id="legend-content">
                        <!-- Legend will be populated by JavaScript -->
                    </div>
                </div>

                <svg id="network-graph"></svg>
                <div class="tooltip" id="tooltip" style="display: none;"></div>
            </div>

            <div class="sidebar">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{total_hosts}</div>
                        <div class="stat-label">Total Hosts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{sum(node['open_ports'] for node in nodes_data)}</div>
                        <div class="stat-label">Open Ports</div>
                    </div>
                </div>

                <div class="section">
                    <h3>📊 Device Types</h3>
                    <div class="device-stats">
                        {self._generate_device_stats_html(device_stats)}
                    </div>
                </div>

                <div class="section">
                    <h3>🔒 Security Overview</h3>
                    <div class="security-stats">
                        {self._generate_security_stats_html(risk_stats)}
                    </div>
                </div>

                <div class="section">
                    <h3>🖥️ Network Devices</h3>
                    <div class="device-list">
                        {self._generate_device_list_html(nodes_data)}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Network data
        const nodes = {nodes_json};
        const links = {edges_json};

        // Color schemes
        const deviceColors = {{
            'router': '#FF6B6B',
            'switch': '#4ECDC4',
            'server': '#45B7D1',
            'workstation': '#96CEB4',
            'printer': '#FFEAA7',
            'iot': '#DDA0DD',
            'mobile': '#98D8C8',
            'unknown': '#95A5A6'
        }};

        const securityColors = {{
            'critical': '#E74C3C',
            'high': '#E67E22',
            'medium': '#F39C12',
            'low': '#27AE60',
            'secure': '#2ECC71'
        }};

        let currentColorScheme = 'device';

        // Set up SVG
        const svg = d3.select("#network-graph");
        const width = 800;
        const height = 600;

        svg.attr("width", width).attr("height", height);

        // Create zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on("zoom", (event) => {{
                g.attr("transform", event.transform);
            }});

        svg.call(zoom);

        // Create main group
        const g = svg.append("g");

        // Create simulation
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(30));

        // Create links
        const link = g.append("g")
            .selectAll("line")
            .data(links)
            .enter().append("line")
            .attr("class", "link");

        // Create nodes
        const node = g.append("g")
            .selectAll("circle")
            .data(nodes)
            .enter().append("circle")
            .attr("class", "node")
            .attr("r", d => Math.max(15, Math.min(30, 15 + d.open_ports * 2)))
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended))
            .on("mouseover", showTooltip)
            .on("mouseout", hideTooltip)
            .on("click", selectNode);

        // Create labels
        const label = g.append("g")
            .selectAll("text")
            .data(nodes)
            .enter().append("text")
            .attr("class", "node-label")
            .text(d => d.hostname || d.ip.split('.').pop());

        // Update colors
        function updateColors() {{
            node.style("fill", d => {{
                if (currentColorScheme === 'device') {{
                    return deviceColors[d.device_type] || '#95A5A6';
                }} else {{
                    return securityColors[d.risk_level] || '#95A5A6';
                }}
            }});
            updateLegend();
        }}

        // Update legend
        function updateLegend() {{
            const legendContent = d3.select("#legend-content");
            legendContent.html("");

            const colors = currentColorScheme === 'device' ? deviceColors : securityColors;

            Object.entries(colors).forEach(([key, color]) => {{
                const item = legendContent.append("div").attr("class", "legend-item");
                item.append("div").attr("class", "legend-color").style("background-color", color);
                item.append("span").text(key.charAt(0).toUpperCase() + key.slice(1));
            }});
        }}

        // Control functions
        function colorByDevice() {{
            currentColorScheme = 'device';
            updateColors();
        }}

        function colorBySecurity() {{
            currentColorScheme = 'security';
            updateColors();
        }}

        function resetZoom() {{
            svg.transition().duration(750).call(
                zoom.transform,
                d3.zoomIdentity
            );
        }}

        // Tooltip functions
        function showTooltip(event, d) {{
            const tooltip = d3.select("#tooltip");

            let content = `<strong>${{d.ip}}</strong><br/>`;
            if (d.hostname) content += `Hostname: ${{d.hostname}}<br/>`;
            content += `OS: ${{d.os}}<br/>`;
            content += `Device: ${{d.device_type}}<br/>`;
            content += `Risk: ${{d.risk_level}}<br/>`;
            content += `Open Ports: ${{d.open_ports}}<br/>`;
            if (d.ports_detail.length > 0) {{
                content += `Services: ${{d.ports_detail.slice(0, 5).join(', ')}}`;
                if (d.ports_detail.length > 5) content += ` (+${{d.ports_detail.length - 5}} more)`;
            }}

            tooltip.html(content)
                .style("display", "block")
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px");
        }}

        function hideTooltip() {{
            d3.select("#tooltip").style("display", "none");
        }}

        function selectNode(event, d) {{
            // Highlight selected node
            node.style("stroke-width", n => n === d ? 4 : 2);

            // Show detailed info in sidebar (could expand this)
            console.log("Selected node:", d);
        }}

        // Drag functions
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}

        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}

        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}

        // Simulation tick
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);

            label
                .attr("x", d => d.x)
                .attr("y", d => d.y + 5);
        }});

        // Initialize
        updateColors();

        // Auto-resize
        window.addEventListener('resize', () => {{
            const container = document.querySelector('.graph-container');
            const newWidth = container.clientWidth;
            const newHeight = container.clientHeight;

            svg.attr("width", newWidth).attr("height", newHeight);
            simulation.force("center", d3.forceCenter(newWidth / 2, newHeight / 2));
            simulation.alpha(0.3).restart();
        }});
    </script>
</body>
</html>'''

        return html_template

    def _generate_device_stats_html(self, device_stats):
        """Generate HTML for device statistics"""
        html = ""
        for device_type, count in device_stats.items():
            color = self.color_schemes['device_types'].get(device_type, '#95A5A6')
            html += f'''
        <div style="display: flex; align-items: center; margin: 5px 0;">
            <div style="width: 15px; height: 15px; background: {color}; border-radius: 50%; margin-right: 10px;"></div>
            <span>{device_type.title()}: <strong>{count}</strong></span>
        </div>
        '''
        return html

    def _generate_security_stats_html(self, risk_stats):
        """Generate HTML for security statistics"""
        html = ""
        for risk_level, count in risk_stats.items():
            color = self.color_schemes['security_levels'].get(risk_level, '#95A5A6')
            html += f'''
        <div style="display: flex; align-items: center; margin: 5px 0;">
            <div style="width: 15px; height: 15px; background: {color}; border-radius: 50%; margin-right: 10px;"></div>
            <span>{risk_level.title()}: <strong>{count}</strong></span>
        </div>
        '''
        return html

    def _generate_device_list_html(self, nodes_data):
        """Generate HTML for device list"""
        html = ""
        for node in nodes_data:
            ports_text = f"{node['open_ports']} ports" if node['open_ports'] > 0 else "No open ports"
            html += f'''
        <div class="device-item risk-{node['risk_level']}">
            <div>
                <span class="device-ip">{node['ip']}</span>
                <span class="device-type">{node['device_type'].upper()}</span>
                <span class="risk-badge risk-{node['risk_level']}">{node['risk_level'].upper()}</span>
            </div>
            <div style="font-size: 0.9em; color: #666; margin-top: 5px;">
                {node['hostname'] or 'No hostname'} | {node['os']} | {ports_text}
            </div>
        </div>
        '''
        return html

    def generate_comprehensive_report(self, scan_data=None, output_dir="network_visualizations"):
        """Generate comprehensive network visualization report"""

        if not scan_data:
            scan_data = self.load_scan_data()

        if not scan_data:
            print("❌ No scan data available")
            return

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        print(f"🎨 Generating comprehensive network visualization report...")
        print(f"📁 Output directory: {output_dir}")

        # Generate different visualizations
        visualizations = [
            ('device_types_spring', 'spring', 'device_type', 'Network Devices by Type (Spring Layout)'),
            ('device_types_hierarchical', 'hierarchical', 'device_type', 'Network Devices by Type (Hierarchical)'),
            ('security_risks_spring', 'spring', 'security', 'Network Security Risks (Spring Layout)'),
            ('security_risks_circular', 'circular', 'security', 'Network Security Risks (Circular Layout)'),
            ('os_distribution', 'spring', 'os_type', 'Operating System Distribution'),
        ]

        generated_files = []

        for filename, layout, color_by, title in visualizations:
            print(f"  📊 Creating {title}...")

            output_file = os.path.join(output_dir, f"{filename}.png")

            fig = self.create_network_graph(
                scan_data,
                layout=layout,
                color_by=color_by,
                show_labels=True,
                show_ports=True,
                show_security=(color_by == 'security'),
                output_file=output_file
            )

            if fig:
                plt.close(fig)
                generated_files.append(output_file)
                print(f"    ✅ Saved: {filename}.png")

        # Generate interactive HTML graph
        print("  🌐 Creating interactive HTML graph...")
        html_file = os.path.join(output_dir, "interactive_network.html")
        interactive_file = self.create_interactive_html_graph(scan_data, html_file)
        if interactive_file:
            generated_files.append(interactive_file)

        # Generate summary statistics
        print("  📊 Generating network statistics...")
        stats_file = self._generate_network_statistics(scan_data, output_dir)
        if stats_file:
            generated_files.append(stats_file)

        # Generate embedded HTML report
        print("  🌐 Creating embedded HTML report...")
        embedded_file = os.path.join(output_dir, "embedded_network_report.html")
        embedded_report = self.create_embedded_html_report(scan_data, embedded_file)
        if embedded_report:
            generated_files.append(embedded_report)

        print(f"\n✅ Comprehensive report generated!")
        print(f"📁 Files created in: {output_dir}/")
        for file in generated_files:
            print(f"   • {os.path.basename(file)}")

        return output_dir

    def _generate_network_statistics(self, scan_data, output_dir):
        """Generate network statistics and charts"""
        try:
            hosts = scan_data.get('hosts', [])

            # Collect statistics
            stats = {
                'total_hosts': len(hosts),
                'device_types': {},
                'os_distribution': {},
                'security_levels': {},
                'port_statistics': {},
                'risk_summary': []
            }

            for host in hosts:
                # Device types
                device_type = self.detect_device_type(host)
                stats['device_types'][device_type] = stats['device_types'].get(device_type, 0) + 1

                # OS distribution
                os_name = host.get('os_name', 'Unknown')
                stats['os_distribution'][os_name] = stats['os_distribution'].get(os_name, 0) + 1

                # Security levels
                risk_level, risk_factors = self.calculate_security_risk(host)
                stats['security_levels'][risk_level] = stats['security_levels'].get(risk_level, 0) + 1

                # Port statistics
                for port in host.get('ports', []):
                    if port.get('state') == 'open':
                        service = port.get('service', 'unknown')
                        stats['port_statistics'][service] = stats['port_statistics'].get(service, 0) + 1

                # Risk summary
                if risk_factors:
                    stats['risk_summary'].append({
                        'host': host.get('ip_address', ''),
                        'hostname': host.get('hostname', ''),
                        'risk_level': risk_level,
                        'issues': risk_factors
                    })

            # Save statistics as JSON
            stats_file = os.path.join(output_dir, "network_statistics.json")
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2)

            # Create statistics charts
            self._create_statistics_charts(stats, output_dir)

            print(f"    ✅ Statistics saved: network_statistics.json")
            return stats_file

        except Exception as e:
            print(f"❌ Error generating statistics: {e}")
            return None

    def _create_statistics_charts(self, stats, output_dir):
        """Create statistical charts"""
        try:
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
            fig.suptitle('Network Statistics Dashboard', fontsize=16, fontweight='bold')

            # Device types pie chart
            if stats['device_types']:
                device_types = list(stats['device_types'].keys())
                device_counts = list(stats['device_types'].values())
                colors = [self.color_schemes['device_types'].get(dt, '#95A5A6') for dt in device_types]

                ax1.pie(device_counts, labels=device_types, autopct='%1.1f%%',
                        colors=colors, startangle=90)
                ax1.set_title('Device Types Distribution')

            # Security levels bar chart
            if stats['security_levels']:
                security_levels = list(stats['security_levels'].keys())
                security_counts = list(stats['security_levels'].values())
                colors = [self.color_schemes['security_levels'].get(sl, '#95A5A6') for sl in security_levels]

                ax2.bar(security_levels, security_counts, color=colors)
                ax2.set_title('Security Risk Distribution')
                ax2.tick_params(axis='x', rotation=45)

            # OS distribution
            if stats['os_distribution']:
                os_names = list(stats['os_distribution'].keys())[:8]  # Top 8
                os_counts = list(stats['os_distribution'].values())[:8]

                ax3.barh(os_names, os_counts, color='#3498DB')
                ax3.set_title('Operating System Distribution')

            # Top services
            if stats['port_statistics']:
                top_services = dict(sorted(stats['port_statistics'].items(),
                                           key=lambda x: x[1], reverse=True)[:10])
                services = list(top_services.keys())
                counts = list(top_services.values())

                ax4.bar(services, counts, color='#2ECC71')
                ax4.set_title('Top 10 Services')
                ax4.tick_params(axis='x', rotation=45)

            plt.tight_layout()

            chart_file = os.path.join(output_dir, "network_statistics_charts.png")
            plt.savefig(chart_file, dpi=300, bbox_inches='tight')
            plt.close()

            print(f"    ✅ Charts saved: network_statistics_charts.png")

        except Exception as e:
            print(f"❌ Error creating charts: {e}")


def main():
    """Main function to demonstrate network visualization"""
    print("🎨 Network Graph Visualizer")
    print("=" * 50)

    import argparse

    parser = argparse.ArgumentParser(description='Network Graph Visualizer')
    parser.add_argument('--session', '-s', help='Specific scan session ID')
    parser.add_argument('--layout', '-l', choices=['spring', 'circular', 'hierarchical', 'kamada_kawai'],
                        default='spring', help='Graph layout algorithm')
    parser.add_argument('--color', '-c', choices=['device_type', 'os_type', 'security'],
                        default='device_type', help='Node coloring scheme')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--interactive', '-i', action='store_true', help='Create interactive HTML graph')
    parser.add_argument('--comprehensive', '-comp', action='store_true', help='Generate comprehensive report')
    parser.add_argument('--data-path', '-d', default='scan_data', help='Scan data directory')

    args = parser.parse_args()

    # Initialize visualizer
    visualizer = NetworkVisualizer(args.data_path)

    # Load scan data
    print("📊 Loading scan data...")
    scan_data = visualizer.load_scan_data(args.session)

    if not scan_data:
        print("❌ No scan data found. Please run a network scan first.")
        print("💡 Use: python integrated_report_generator.py --auto")
        return

    hosts_count = len(scan_data.get('hosts', []))
    print(f"✅ Loaded scan data with {hosts_count} hosts")

    try:
        if args.comprehensive:
            # Generate comprehensive report
            output_dir = visualizer.generate_comprehensive_report(scan_data)
            print(f"\n🎯 Open the files in: {output_dir}/")

        elif args.interactive:
            # Create interactive graph
            output_file = args.output or "interactive_network.html"
            result = visualizer.create_interactive_html_graph(scan_data, output_file)
            if result:
                print(f"\n🌐 Open {result} in your browser to view the interactive graph")

        else:
            # Create static graph
            print(f"🎨 Creating {args.layout} layout graph colored by {args.color}")

            fig = visualizer.create_network_graph(
                scan_data,
                layout=args.layout,
                color_by=args.color,
                show_labels=True,
                show_ports=True,
                show_security=(args.color == 'security'),
                output_file=args.output
            )

            if fig:
                if not args.output:
                    plt.show()
                plt.close(fig)
                print("✅ Graph visualization completed!")

    except KeyboardInterrupt:
        print("\n👋 Visualization cancelled")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()

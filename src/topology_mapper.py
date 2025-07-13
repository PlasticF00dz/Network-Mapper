import subprocess
import re
import json
import sys
import time
from collections import defaultdict, deque
import ipaddress


class NetworkTopologyMapper:

    def __init__(self):
        self.network_graph = defaultdict(list)  # Adjacency list representation
        self.host_info = {}  # Store detailed host information
        self.topology_data = {
            'nodes': [],
            'edges': [],
            'subnets': [],
            'gateways': []
        }

    def discover_routes(self, target_hosts):

        print(f"🛣️  Discovering routes to {len(target_hosts)} hosts")

        routes = {}

        for host in target_hosts:
            print(f"🔍 Tracing route to {host}")
            route = self._traceroute(host)
            if route:
                routes[host] = route
                self._update_topology_from_route(host, route)

        return routes

    def _traceroute(self, host):

        try:
            # Platform-specific traceroute command
            if sys.platform.startswith('win'):
                cmd = ['tracert', '-h', '15', '-w', '3000', host]
            else:
                cmd = ['traceroute', '-m', '15', '-w', '3', host]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                return self._parse_traceroute_output(result.stdout)
            else:
                print(f"❌ Traceroute failed for {host}")
                return None

        except Exception as e:
            print(f"❌ Traceroute error for {host}: {e}")
            return None

    def _parse_traceroute_output(self, output):

        hops = []
        lines = output.strip().split('\n')

        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'

        for line in lines:
            if 'traceroute' in line.lower() or 'tracing route' in line.lower():
                continue

            hop_match = re.search(r'^\s*(\d+)', line)
            if hop_match:
                hop_number = int(hop_match.group(1))

                ip_matches = re.findall(ip_pattern, line)

                if ip_matches:
                    hop_ip = ip_matches[0]

                    time_pattern = r'(\d+(?:\.\d+)?)\s*ms'
                    times = re.findall(time_pattern, line)
                    avg_time = sum(float(t) for t in times) / len(times) if times else 0

                    hops.append({
                        'hop': hop_number,
                        'ip': hop_ip,
                        'hostname': self._resolve_hostname(hop_ip),
                        'response_time': avg_time
                    })
                else:
                    hops.append({
                        'hop': hop_number,
                        'ip': '*',
                        'hostname': 'Timeout/Unreachable',
                        'response_time': 0
                    })

        return hops

    def _resolve_hostname(self, ip):

        try:
            import socket
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip

    def _update_topology_from_route(self, target, route):

        if not route:
            return

        if target not in self.host_info:
            self.host_info[target] = {
                'ip': target,
                'type': 'target',
                'reachable': True,
                'hop_count': len(route)
            }

        for i, hop in enumerate(route):
            hop_ip = hop['ip']

            if hop_ip == '*':
                continue

            if hop_ip not in self.host_info:
                self.host_info[hop_ip] = {
                    'ip': hop_ip,
                    'hostname': hop['hostname'],
                    'type': 'router' if i < len(route) - 1 else 'target',
                    'response_time': hop['response_time']
                }

            # Add edge to graph
            if i > 0:
                prev_hop = route[i - 1]['ip']
                if prev_hop != '*':
                    # Add bidirectional edge
                    if hop_ip not in self.network_graph[prev_hop]:
                        self.network_graph[prev_hop].append(hop_ip)
                    if prev_hop not in self.network_graph[hop_ip]:
                        self.network_graph[hop_ip].append(prev_hop)

    def analyze_network_structure(self):

        print("🔍 Analyzing network structure...")

        analysis = {
            'total_nodes': len(self.host_info),
            'total_edges': sum(len(edges) for edges in self.network_graph.values()) // 2,
            'subnets': self._detect_subnets(),
            'critical_nodes': self._find_critical_nodes(),
            'network_diameter': self._calculate_diameter(),
            'connectivity_stats': {}
        }

        # Calculate connectivity statistics
        node_degrees = {}
        for node, connections in self.network_graph.items():
            node_degrees[node] = len(connections)

        if node_degrees:
            analysis['connectivity_stats'] = {
                'avg_degree': sum(node_degrees.values()) / len(node_degrees),
                'max_degree': max(node_degrees.values()),
                'min_degree': min(node_degrees.values()),
                'most_connected': max(node_degrees.items(), key=lambda x: x[1])[0]
            }

        print(f"📊 Network Analysis Complete:")
        print(f"   Nodes: {analysis['total_nodes']}")
        print(f"   Edges: {analysis['total_edges']}")
        print(f"   Subnets: {len(analysis['subnets'])}")
        print(f"   Diameter: {analysis['network_diameter']}")

        return analysis

    def _detect_subnets(self):

        subnets = defaultdict(list)

        for ip in self.host_info.keys():
            if ip == '*':
                continue

            try:
                ip_obj = ipaddress.IPv4Address(ip)

                # Group by common /24 subnet
                subnet_24 = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                subnets[subnet_24].append(ip)

            except:
                continue


        subnet_list = []
        for subnet, hosts in subnets.items():
            if len(hosts) > 1:  # Only include subnets with multiple hosts
                subnet_list.append({
                    'subnet': subnet,
                    'hosts': hosts,
                    'host_count': len(hosts)
                })

        return subnet_list

    def _find_critical_nodes(self):

        critical_nodes = []

        for node, connections in self.network_graph.items():
            if len(connections) >= 3:  # Arbitrarily consider 3+ connections as critical
                critical_nodes.append({
                    'node': node,
                    'degree': len(connections),
                    'type': 'high_degree',
                    'hostname': self.host_info.get(node, {}).get('hostname', node)
                })

        return critical_nodes

    def _calculate_diameter(self):

        if not self.network_graph:
            return 0

        max_distance = 0
        for start_node in self.network_graph.keys():
            distances = self._bfs_shortest_paths(start_node)
            if distances:
                max_distance = max(max_distance, max(distances.values()))

        return max_distance

    def _bfs_shortest_paths(self, start_node):

        if start_node not in self.network_graph:
            return {}

        distances = {start_node: 0}
        queue = deque([start_node])
        visited = {start_node}

        while queue:
            current = queue.popleft()
            current_distance = distances[current]

            for neighbor in self.network_graph[current]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    distances[neighbor] = current_distance + 1
                    queue.append(neighbor)

        return distances

    def export_topology_data(self):

        nodes = []
        for ip, info in self.host_info.items():
            nodes.append({
                'id': ip,
                'label': info.get('hostname', ip),
                'type': info.get('type', 'unknown'),
                'ip': ip,
                'response_time': info.get('response_time', 0)
            })

        # Prepare edges
        edges = []
        processed_edges = set()

        for source, targets in self.network_graph.items():
            for target in targets:
                # Avoid duplicate edges
                edge_key = tuple(sorted([source, target]))
                if edge_key not in processed_edges:
                    processed_edges.add(edge_key)
                    edges.append({
                        'source': source,
                        'target': target,
                        'type': 'route'
                    })

        topology_data = {
            'nodes': nodes,
            'edges': edges,
            'metadata': {
                'timestamp': time.time(),
                'total_nodes': len(nodes),
                'total_edges': len(edges)
            }
        }

        return topology_data


if __name__ == "__main__":
    mapper = NetworkTopologyMapper()

    # Test with safe public hosts
    test_targets = ["8.8.8.8", "1.1.1.1"]

    print("🧪 Testing network topology mapping")
    print("=" * 50)

    # Discover routes
    routes = mapper.discover_routes(test_targets)

    # Analyze network structure
    analysis = mapper.analyze_network_structure()

    # Export topology data
    topology_data = mapper.export_topology_data()

    print(f"\n📊 Topology Summary:")
    print(f"Discovered routes: {len(routes)}")
    print(f"Network nodes: {len(topology_data['nodes'])}")
    print(f"Network edges: {len(topology_data['edges'])}")

    # Save topology data
    with open('network_topology.json', 'w') as f:
        json.dump(topology_data, f, indent=2)

    print("💾 Topology data saved to network_topology.json")
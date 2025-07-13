import ipaddress
import socket
import netifaces
def get_local_network():
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET]
        interface_name = default_gateway[1]
        interface_info = netifaces.ifaddresses(interface_name)
        ipv4_info = interface_info[netifaces.AF_INET][0]
        ip_address = ipv4_info['addr']
        netmask = ipv4_info['netmask']
        network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
        print(f"🔍 Detected Network: {network}")
        print(f"📍 Gateway: {default_gateway[0]}")
        print(f"🖥️  Interface: {interface_name}")
        return str(network)
    except Exception as e:
        print(f"❌ Error detecting network: {e}")
        return "192.168.1.0/24"

def validate_network(network_str):

    try:
        network = ipaddress.IPv4Network(network_str, strict=False)
        return network
    except ValueError as e:
        raise ValueError(f"Invalid network format: {e}")


if __name__ == "__main__":
    print("🌐 Network Detection Test")
    print("=" * 30)

    local_net = get_local_network()
    network = validate_network(local_net)

    print(f"Network: {network}")
    print(f"Network Address: {network.network_address}")
    print(f"Broadcast Address: {network.broadcast_address}")
    print(f"Total Hosts: {network.num_addresses - 2}")
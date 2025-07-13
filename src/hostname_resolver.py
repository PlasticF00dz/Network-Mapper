import socket
import threading
from concurrent.futures import ThreadPoolExecutor


class HostnameResolver:

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.hostname_cache = {}

    def resolve_hostname(self, ip_address):
        try:
            socket.setdefaulttimeout(self.timeout)

            hostname_info = socket.gethostbyaddr(ip_address)
            hostname = hostname_info[0]  # Primary hostname

            self.hostname_cache[ip_address] = hostname
            print(f"🏷️  {ip_address:15} -> {hostname}")
            return hostname

        except socket.herror:
            self.hostname_cache[ip_address] = "No PTR record"
            return "No PTR record"
        except socket.timeout:
            self.hostname_cache[ip_address] = "DNS timeout"
            return "DNS timeout"
        except Exception as e:
            self.hostname_cache[ip_address] = f"DNS error: {str(e)}"
            return f"DNS error: {str(e)}"

    def resolve_multiple_hostnames(self, ip_list, max_threads=20):
        print(f"🔍 Resolving hostnames for {len(ip_list)} hosts")

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_ip = {
                executor.submit(self.resolve_hostname, ip): ip
                for ip in ip_list
            }

            for future in future_to_ip:
                future.result()  # This will wait for completion

        return self.hostname_cache

    def get_hostname(self, ip_address):
        return self.hostname_cache.get(ip_address, "Unknown")


if __name__ == "__main__":
    test_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]

    resolver = HostnameResolver()

    print("🧪 Testing individual hostname resolution:")
    for ip in test_ips:
        hostname = resolver.resolve_hostname(ip)
        print(f"Result: {ip} -> {hostname}")

    print("\n🧪 Testing concurrent hostname resolution:")
    resolver2 = HostnameResolver()
    results = resolver2.resolve_multiple_hostnames(test_ips)

    print("\n📊 Final Results:")
    for ip, hostname in results.items():
        print(f"{ip:15} -> {hostname}")
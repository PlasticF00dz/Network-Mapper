import subprocess
import sys
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.netmapper import get_local_network


class PingScanner:


    def __init__(self, network, timeout=3):
        self.network = ipaddress.IPv4Network(network)
        self.timeout = timeout
        self.live_hosts = []
        self.lock = threading.Lock()  # Thread-safe operations

    def ping_single_host(self, ip_str):

        try:
            if sys.platform.startswith('win'):

                cmd = ['ping', '-n', '1', '-w', str(self.timeout * 1000), ip_str]
            else:

                cmd = ['ping', '-c', '1', '-W', str(self.timeout), ip_str]

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout + 1,
                text=True
            )
            if result.returncode == 0 and "TTL=" in result.stdout:
                with self.lock:  # Thread-safe list update
                    self.live_hosts.append(ip_str)
                print(f"✅ {ip_str} is alive")
                return ip_str
            else:
                print(f"❌ {ip_str} is down")
                return None

        except subprocess.TimeoutExpired:
            print(f"⏱️  {ip_str} timeout")
            return None
        except Exception as e:
            print(f"❌ Error pinging {ip_str}: {e}")
            return None

    def ping_sweep_sequential(self):

        print(f"🔍 Starting sequential ping sweep of {self.network}")
        start_time = time.time()

        for ip in self.network.hosts():
            self.ping_single_host(str(ip))

        end_time = time.time()
        print(f"⏱️  Sequential scan completed in {end_time - start_time:.2f} seconds")
        return self.live_hosts.copy()

    def ping_sweep_threaded(self, max_threads=50):

        print(f"🔍 Starting threaded ping sweep of {self.network} (max {max_threads} threads)")
        start_time = time.time()
        self.live_hosts = []
        target_ips = [str(ip) for ip in self.network.hosts()]
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_ip = {
                executor.submit(self.ping_single_host, ip): ip
                for ip in target_ips
            }

            for future in as_completed(future_to_ip):
                result = future.result()
        end_time = time.time()
        print(f"⏱️  Threaded scan completed in {end_time - start_time:.2f} seconds")
        print(f"📊 Found {len(self.live_hosts)} live hosts")
        return sorted(self.live_hosts, key=lambda x: ipaddress.IPv4Address(x))
if __name__ == "__main__":
    test_network =get_local_network()

    scanner = PingScanner(test_network)

    print("🧪 Testing Sequential Scan")
    sequential_results = scanner.ping_sweep_sequential()

    print("\n🧪 Testing Threaded Scan")
    threaded_results = scanner.ping_sweep_threaded()

    print(f"\n📊 Results Comparison:")
    print(f"Sequential: {len(sequential_results)} hosts")
    print(f"Threaded: {len(threaded_results)} hosts")
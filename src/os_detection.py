import subprocess
import re
import socket
import struct
import sys
import time


class OSDetector:
    def __init__(self):
        self.os_signatures = {
            'ttl_signatures': {
                (64, 64): ['Linux', 'Unix', 'macOS'],
                (128, 128): ['Windows'],
                (255, 255): ['Cisco', 'Network Device'],
                (30, 64): ['Linux (with firewall)'],
                (32, 32): ['Windows 95/98'],
            },
            'service_patterns': {
                'windows': ['microsoft', 'iis', 'sql server', 'exchange', 'smb'],
                'linux': ['apache', 'nginx', 'openssh', 'postfix', 'bind'],
                'macos': ['apache', 'ssh', 'afp', 'bonjour'],
                'unix': ['sendmail', 'named', 'rpcbind']
            }
        }

    def detect_ttl_os(self, host):

        print(f"🔍 TTL-based OS detection for {host}")

        try:

            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '3', host]
            else:
                cmd = ['ping', '-c', '3', host]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                ttl_pattern = r'ttl=(\d+)|TTL=(\d+)'
                ttl_matches = re.findall(ttl_pattern, result.stdout, re.IGNORECASE)

                if ttl_matches:
                    ttl_values = []
                    for match in ttl_matches:
                        ttl = int(match[0] or match[1])
                        ttl_values.append(ttl)

                    if ttl_values:
                        avg_ttl = sum(ttl_values) // len(ttl_values)

                        original_ttl = self._guess_original_ttl(avg_ttl)
                        hops = original_ttl - avg_ttl

                        for (min_ttl, max_ttl), os_types in self.os_signatures['ttl_signatures'].items():
                            if min_ttl <= original_ttl <= max_ttl:
                                print(f"🎯 TTL Analysis: {avg_ttl} (original ~{original_ttl}, {hops} hops)")
                                print(f"   Possible OS: {', '.join(os_types)}")
                                return {
                                    'method': 'ttl',
                                    'ttl_observed': avg_ttl,
                                    'ttl_original': original_ttl,
                                    'hops': hops,
                                    'possible_os': os_types,
                                    'confidence': 'medium'
                                }

        except Exception as e:
            print(f"❌ TTL detection error: {e}")

        return None

    def _guess_original_ttl(self, observed_ttl):

        common_ttls = [32, 64, 128, 255]

        for ttl in common_ttls:
            if ttl >= observed_ttl:
                return ttl

        return 255  # Default fallback

    def detect_service_os(self, host, port_scan_results):

        print(f"🔍 Service-based OS detection for {host}")

        if not port_scan_results or 'ports' not in port_scan_results:
            return None

        detected_services = []
        for port_info in port_scan_results['ports']:
            service_name = port_info.get('service', '').lower()
            product = port_info.get('product', '').lower()
            version = port_info.get('version', '').lower()

            service_string = f"{service_name} {product} {version}".strip()
            detected_services.append(service_string)

        os_scores = {}

        for os_name, patterns in self.os_signatures['service_patterns'].items():
            score = 0
            matched_patterns = []

            for pattern in patterns:
                for service in detected_services:
                    if pattern in service:
                        score += 1
                        matched_patterns.append(pattern)
                        break

            if score > 0:
                os_scores[os_name] = {
                    'score': score,
                    'matched_patterns': matched_patterns,
                    'total_patterns': len(patterns),
                    'confidence': score / len(patterns)
                }

        if os_scores:
            # Get best match
            best_os = max(os_scores.items(), key=lambda x: x[1]['score'])

            print(f"🎯 Service Analysis Results:")
            for os_name, details in sorted(os_scores.items(), key=lambda x: x[1]['score'], reverse=True):
                confidence = details['confidence'] * 100
                print(f"   {os_name.capitalize()}: {details['score']}/{details['total_patterns']} ({confidence:.1f}%)")
                print(f"      Matched: {', '.join(details['matched_patterns'])}")

            return {
                'method': 'service',
                'best_match': best_os[0],
                'confidence': best_os[1]['confidence'],
                'all_matches': os_scores,
                'detected_services': detected_services
            }

        return None

    def comprehensive_os_detection(self, host, port_scan_results=None):

        print(f"🎯 Comprehensive OS detection for {host}")

        detection_results = {
            'host': host,
            'timestamp': time.time(),
            'methods': {},
            'final_assessment': {}
        }

        ttl_result = self.detect_ttl_os(host)
        if ttl_result:
            detection_results['methods']['ttl'] = ttl_result

        if port_scan_results:
            service_result = self.detect_service_os(host, port_scan_results)
            if service_result:
                detection_results['methods']['service'] = service_result

        if detection_results['methods']:
            final_os = self._combine_detection_methods(detection_results['methods'])
            detection_results['final_assessment'] = final_os

            print(f"\n🏆 Final OS Assessment:")
            print(f"   Most Likely: {final_os['most_likely_os']}")
            print(f"   Confidence: {final_os['overall_confidence']:.1%}")
            print(f"   Methods Used: {', '.join(final_os['methods_used'])}")

        return detection_results

    def _combine_detection_methods(self, method_results):

        os_votes = {}
        methods_used = []

        method_weights = {
            'ttl': 0.3,
            'service': 0.7,
            'nmap': 0.9  # If available
        }

        for method_name, result in method_results.items():
            methods_used.append(method_name)
            weight = method_weights.get(method_name, 0.5)

            if method_name == 'ttl':
                for os_type in result['possible_os']:
                    os_votes[os_type] = os_votes.get(os_type, 0) + weight

            elif method_name == 'service':
                os_name = result['best_match']
                confidence = result['confidence']
                os_votes[os_name] = os_votes.get(os_name, 0) + (weight * confidence)

        if os_votes:

            max_vote = max(os_votes.values())


            best_os = max(os_votes.items(), key=lambda x: x[1])

            return {
                'most_likely_os': best_os[0],
                'overall_confidence': best_os[1] / max_vote,
                'all_candidates': dict(sorted(os_votes.items(), key=lambda x: x[1], reverse=True)),
                'methods_used': methods_used
            }

        return {
            'most_likely_os': 'Unknown',
            'overall_confidence': 0.0,
            'all_candidates': {},
            'methods_used': methods_used
        }


if __name__ == "__main__":
    detector = OSDetector()

    # Test hosts (use safe, public hosts)
    test_hosts = ["8.8.8.8", "1.1.1.1"]

    for host in test_hosts:
        print(f"\n{'=' * 50}")
        print(f"🧪 Testing OS detection for {host}")
        print('=' * 50)

        # Basic TTL detection
        ttl_result = detector.detect_ttl_os(host)

        # Mock port scan results for service detection
        mock_port_results = {
            'ports': [
                {'port': 53, 'service': 'dns', 'product': 'bind', 'version': '9.11'},
                {'port': 80, 'service': 'http', 'product': 'nginx', 'version': '1.18'}
            ]
        }

        # Comprehensive detection
        comprehensive_result = detector.comprehensive_os_detection(host, mock_port_results)
import json
import csv
import sqlite3
import os
import time
from datetime import datetime
import pickle


class DataManager:
    """
    Learn: Comprehensive data management for network scan results
    Concepts: File I/O, JSON serialization, CSV export, SQLite database
    """

    def __init__(self, data_dir="output"):
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, "netmapper.db")
        self.ensure_directories()
        self.init_database()

    def ensure_directories(self):

        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "scans"), exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "reports"), exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "exports"), exist_ok=True)

    def init_database(self):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create scan sessions table
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS scan_sessions
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           session_id
                           TEXT
                           UNIQUE,
                           network
                           TEXT,
                           start_time
                           TIMESTAMP,
                           end_time
                           TIMESTAMP,
                           total_hosts
                           INTEGER,
                           live_hosts
                           INTEGER,
                           scan_type
                           TEXT,
                           parameters
                           TEXT
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
                           os_guess
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
                           session_id
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
        print("✅ Database initialized")

    def save_scan_session(self, scan_data):

        session_id = scan_data.get('session_id', f"scan_{int(time.time())}")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Insert scan session
            cursor.execute('''
            INSERT OR REPLACE INTO scan_sessions 
            (session_id, network, start_time, end_time, total_hosts, live_hosts, scan_type, parameters)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                scan_data.get('network', ''),
                scan_data.get('start_time', time.time()),
                scan_data.get('end_time', time.time()),
                scan_data.get('total_hosts', 0),
                scan_data.get('live_hosts', 0),
                scan_data.get('scan_type', 'comprehensive'),
                json.dumps(scan_data.get('parameters', {}))
            ))

            # Insert hosts
            for host_data in scan_data.get('hosts', []):
                cursor.execute('''
                               INSERT INTO hosts
                               (session_id, ip_address, hostname, mac_address, os_guess, os_confidence, status,
                                response_time)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                               ''', (
                                   session_id,
                                   host_data.get('ip', ''),
                                   host_data.get('hostname', ''),
                                   host_data.get('mac_address', ''),
                                   host_data.get('os_guess', ''),
                                   host_data.get('os_confidence', 0.0),
                                   host_data.get('status', 'unknown'),
                                   host_data.get('response_time', 0.0)
                               ))

                host_id = cursor.lastrowid

                # Insert ports for this host
                for port_data in host_data.get('ports', []):
                    cursor.execute('''
                                   INSERT INTO ports
                                       (host_id, port_number, protocol, state, service, version)
                                   VALUES (?, ?, ?, ?, ?, ?)
                                   ''', (
                                       host_id,
                                       port_data.get('port', 0),
                                       port_data.get('protocol', 'tcp'),
                                       port_data.get('state', 'unknown'),
                                       port_data.get('service', ''),
                                       port_data.get('version', '')
                                   ))

            conn.commit()
            print(f"✅ Scan session {session_id} saved to database")
            return session_id

        except Exception as e:
            conn.rollback()
            print(f"❌ Database save error: {e}")
            return None
        finally:
            conn.close()

    def save_json_report(self, data, filename=None):

        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"

        filepath = os.path.join(self.data_dir, "reports", filename)

        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)

            print(f"✅ JSON report saved: {filepath}")
            return filepath

        except Exception as e:
            print(f"❌ JSON save error: {e}")
            return None

    def export_to_csv(self, session_id=None, filename=None):

        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_export_{timestamp}.csv"

        filepath = os.path.join(self.data_dir, "exports", filename)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Query for host and port data
            if session_id:
                query = '''
                        SELECT h.ip_address, \
                               h.hostname, \
                               h.mac_address, \
                               h.os_guess, \
                               h.os_confidence,
                               h.status, \
                               h.response_time, \
                               p.port_number, \
                               p.protocol, \
                               p.state, \
                               p.service, \
                               p.version
                        FROM hosts h
                                 LEFT JOIN ports p ON h.id = p.host_id
                        WHERE h.session_id = ?
                        ORDER BY h.ip_address, p.port_number \
                        '''
                cursor.execute(query, (session_id,))
            else:
                # Export all data
                query = '''
                        SELECT h.ip_address, \
                               h.hostname, \
                               h.mac_address, \
                               h.os_guess, \
                               h.os_confidence,
                               h.status, \
                               h.response_time, \
                               p.port_number, \
                               p.protocol, \
                               p.state, \
                               p.service, \
                               p.version
                        FROM hosts h
                                 LEFT JOIN ports p ON h.id = p.host_id
                        ORDER BY h.ip_address, p.port_number \
                        '''
                cursor.execute(query)

            rows = cursor.fetchall()

            # Write CSV file
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)

                # Write header
                writer.writerow([
                    'IP Address', 'Hostname', 'MAC Address', 'OS Guess', 'OS Confidence',
                    'Status', 'Response Time', 'Port', 'Protocol', 'Port State', 'Service', 'Version'
                ])

                # Write data rows
                for row in rows:
                    writer.writerow(row)

            print(f"✅ CSV export saved: {filepath}")
            return filepath

        except Exception as e:
            print(f"❌ CSV export error: {e}")
            return None
        finally:
            conn.close()

    def load_scan_session(self, session_id):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Get session info
            cursor.execute('SELECT * FROM scan_sessions WHERE session_id = ?', (session_id,))
            session_row = cursor.fetchone()

            if not session_row:
                print(f"❌ Session {session_id} not found")
                return None

            # Get hosts
            cursor.execute('SELECT * FROM hosts WHERE session_id = ?', (session_id,))
            host_rows = cursor.fetchall()

            # Reconstruct scan data
            scan_data = {
                'session_id': session_row[1],
                'network': session_row[2],
                'start_time': session_row[3],
                'end_time': session_row[4],
                'total_hosts': session_row[5],
                'live_hosts': session_row[6],
                'scan_type': session_row[7],
                'parameters': json.loads(session_row[8]) if session_row[8] else {},
                'hosts': []
            }

            # Get ports for each host
            for host_row in host_rows:
                host_id = host_row[0]

                cursor.execute('SELECT * FROM ports WHERE host_id = ?', (host_id,))
                port_rows = cursor.fetchall()

                host_data = {
                    'ip': host_row[2],
                    'hostname': host_row[3],
                    'mac_address': host_row[4],
                    'os_guess': host_row[5],
                    'os_confidence': host_row[6],
                    'status': host_row[7],
                    'response_time': host_row[8],
                    'ports': []
                }

                for port_row in port_rows:
                    port_data = {
                        'port': port_row[2],
                        'protocol': port_row[3],
                        'state': port_row[4],
                        'service': port_row[5],
                        'version': port_row[6]
                    }
                    host_data['ports'].append(port_data)

                scan_data['hosts'].append(host_data)

            print(f"✅ Loaded scan session: {session_id}")
            return scan_data

        except Exception as e:
            print(f"❌ Load session error: {e}")
            return None
        finally:
            conn.close()

    def list_scan_sessions(self):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                           SELECT session_id, network, start_time, live_hosts, scan_type
                           FROM scan_sessions
                           ORDER BY start_time DESC
                           ''')

            sessions = cursor.fetchall()

            print(f"📋 Found {len(sessions)} scan sessions:")
            for session in sessions:
                start_time = datetime.fromtimestamp(session[2]).strftime("%Y-%m-%d %H:%M:%S")
                print(f"   {session[0]}: {session[1]} ({session[3]} hosts) - {start_time}")

            return sessions

        except Exception as e:
            print(f"❌ List sessions error: {e}")
            return []
        finally:
            conn.close()


# Test data manager
if __name__ == "__main__":
    dm = DataManager()

    # Create test scan data
    test_scan = {
        'session_id': 'test_scan_001',
        'network': '192.168.1.0/24',
        'start_time': time.time() - 300,
        'end_time': time.time(),
        'total_hosts': 254,
        'live_hosts': 3,
        'scan_type': 'comprehensive',
        'parameters': {'timeout': 3, 'threads': 50},
        'hosts': [
            {
                'ip': '192.168.1.1',
                'hostname': 'router.local',
                'mac_address': '00:11:22:33:44:55',
                'os_guess': 'Linux',
                'os_confidence': 0.8,
                'status': 'up',
                'response_time': 1.2,
                'ports': [
                    {'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 7.4'},
                    {'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http', 'version': 'nginx 1.18'}
                ]
            },
            {
                'ip': '192.168.1.10',
                'hostname': 'workstation.local',
                'mac_address': '66:77:88:99:AA:BB',
                'os_guess': 'Windows',
                'os_confidence': 0.9,
                'status': 'up',
                'response_time': 2.1,
                'ports': [
                    {'port': 135, 'protocol': 'tcp', 'state': 'open', 'service': 'msrpc', 'version': ''},
                    {'port': 445, 'protocol': 'tcp', 'state': 'open', 'service': 'microsoft-ds', 'version': ''}
                ]
            }
        ]
    }

    print("🧪 Testing data management")
    print("=" * 50)

    # Save scan session
    session_id = dm.save_scan_session(test_scan)

    # Save JSON report
    json_path = dm.save_json_report(test_scan)

    # Export to CSV
    csv_path = dm.export_to_csv(session_id)

    # List all sessions
    dm.list_scan_sessions()

    # Load session back
    loaded_scan = dm.load_scan_session(session_id)
    if loaded_scan:
        print(f"✅ Successfully loaded session with {len(loaded_scan['hosts'])} hosts")
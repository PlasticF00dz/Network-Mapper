# 🌐 NetMapper - Advanced Network Discovery & Security Analysis Tool

NetMapper is a sophisticated network discovery and security analysis tool that combines multiple scanning techniques to provide comprehensive network intelligence. It's a Python-based alternative to Nmap with enhanced visualization and reporting capabilities.

## 🚀 Features

### 🔍 Network Discovery
- **Automatic Network Detection**: Detects local network and gateway automatically
- **Multi-threaded Host Discovery**: Fast ping sweep with up to 100 concurrent threads
- **ARP Scanning**: MAC address discovery using Scapy
- **Hostname Resolution**: Concurrent DNS resolution for discovered hosts

### 🔒 Security Analysis
- **Port Scanning**: Custom TCP/UDP port scanner with service detection
- **Operating System Detection**: TTL analysis and service fingerprinting
- **Security Risk Assessment**: Automatic vulnerability identification
- **Critical Port Detection**: Identifies high-risk services (Telnet, RDP, SMB, etc.)

### 🗺️ Network Topology
- **Route Discovery**: Maps network paths using traceroute
- **Subnet Detection**: Automatic network segmentation analysis
- **Device Classification**: Categorizes devices (router, server, workstation, IoT)
- **Network Graph Generation**: Visual topology mapping

### 📊 Visualization & Reporting
- **Interactive Network Graphs**: Beautiful HTML visualizations
- **Security Dashboard**: Color-coded risk assessment
- **Multiple Export Formats**: HTML, JSON, CSV, and text reports
- **SQLite Database**: Persistent storage with session management

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Nmap (optional, for enhanced scanning)






## 🎯 How NetMapper Works

NetMapper operates in multiple phases to provide comprehensive network intelligence:

### 1. **Network Discovery Phase**
- Automatically detects your local network configuration and gateway
- Performs high-speed ping sweeps using up to 100 concurrent threads
- Conducts ARP scanning to discover MAC addresses and device manufacturers
- Resolves hostnames through concurrent DNS queries

### 2. **Security Analysis Phase**
- Scans discovered hosts for open TCP and UDP ports
- Identifies running services and their versions through banner grabbing
- Performs operating system detection using TTL analysis and service fingerprinting
- Calculates security risk scores based on exposed services and vulnerabilities

### 3. **Topology Mapping Phase**
- Maps network routes using traceroute analysis
- Identifies network infrastructure and critical nodes
- Detects network segmentation and subnet boundaries
- Classifies devices by type (routers, servers, workstations, IoT devices)

### 4. **Data Processing & Storage**
- Stores all scan results in a SQLite database with session management
- Processes and correlates data from multiple scanning methods
- Generates comprehensive reports in multiple formats (HTML, JSON, CSV)
- Creates interactive network visualizations with security overlays



## 🎨 Visualization Features

### Network Graph Types
- **Device Type Coloring**: Routers, servers, workstations, IoT devices
- **Security Risk Levels**: Critical, high, medium, low risk visualization
- **OS-based Coloring**: Windows, Linux, macOS, network devices
- **Port Status Indicators**: Open, filtered, closed ports

### Interactive Features
- **Zoom and Pan**: Navigate large network topologies
- **Node Details**: Click for detailed host information
- **Port Visualization**: Visual port status indicators
- **Export Options**: PNG, SVG, HTML formats

## 📊 Sample Reports

### Security Dashboard
```
🔒 Security Analysis Results
═══════════════════════════════════════
Critical Risks: 2 hosts
High Risks: 5 hosts
Medium Risks: 12 hosts
Low Risks: 8 hosts

🚨 Critical Findings:
- 192.168.1.10: RDP (3389) exposed
- 192.168.1.15: Telnet (23) active
```

### Network Statistics
```
📊 Network Overview
═══════════════════════════════════════
Total Hosts: 27
Live Hosts: 23
Subnets: 3
Device Types:
  - Routers: 2
  - Servers: 4
  - Workstations: 15
  - IoT Devices: 2
```

## 🛡️ Security Features

### Risk Assessment
- **Critical Ports**: Telnet (23), RDP (3389), SMB (445)
- **High-Risk Services**: FTP (21), RPC (135), NetBIOS (139)
- **Secure Services**: HTTPS (443), SSH (22), IMAPS (993)

### Vulnerability Detection
- Unencrypted protocols identification
- Default service detection
- Open database ports
- Weak authentication services

## 🔍 Advanced Features

### Smart Scanning
- **Adaptive Timeouts**: Adjusts based on network responsiveness
- **Service-specific Probes**: Targeted service detection
- **Fallback Mechanisms**: Multiple scanning methods for reliability

### Performance Optimization
- **Concurrent Processing**: Multi-threaded scanning
- **Result Caching**: Hostname and service caching
- **Memory Efficient**: Streaming data processing

## 🔧 Technical Architecture

### Core Components
- **Network Detection Engine**: Uses `netifaces` for automatic network configuration discovery
- **Multi-threaded Scanning Engine**: Concurrent processing with configurable thread pools
- **Database Layer**: SQLite for persistent storage with session management
- **Visualization Engine**: `matplotlib` and `networkx` for graph generation
- **Reporting System**: Multi-format export capabilities (HTML, JSON, CSV)

### Scanning Technologies
- **ICMP Ping Scanning**: Cross-platform ping implementation
- **ARP Discovery**: Layer 2 network discovery using Scapy
- **TCP/UDP Port Scanning**: Custom socket-based port scanner
- **Service Detection**: Banner grabbing and service fingerprinting
- **OS Detection**: TTL analysis and service pattern matching

### Data Processing Pipeline
- **Real-time Processing**: Concurrent data collection and analysis
- **Result Correlation**: Combines multiple scanning methods for accuracy
- **Risk Assessment**: Automated security vulnerability scoring
- **Device Classification**: Intelligent device type detection

---

**⚠️ Disclaimer**: This tool is for educational and authorized network testing purposes only. Always ensure you have permission before scanning networks you don't own. 
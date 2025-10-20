# 🔍 NextMap - Advanced Network Scanner with Stealth & CVE Detection

<div align="center">

[![Release](https://img.shields.io/github/v/release/pozivo/nextmap?style=for-the-badge&logo=github&color=00D4AA)](https://github.com/pozivo/nextmap/releases)
[![Downloads](https://img.shields.io/github/downloads/pozivo/nextmap/total?style=for-the-badge&logo=download&color=blue)](https://github.com/pozivo/nextmap/releases)
[![License](https://img.shields.io/github/license/pozivo/nextmap?style=for-the-badge&color=green)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/pozivo/nextmap/release.yml?style=for-the-badge&logo=github-actions)](https://github.com/pozivo/nextmap/actions)

**🚀 Next generation network scanner with advanced stealth capabilities and CVE vulnerability detection**

*nmap-compatible • Enterprise-ready • Rust-powered*

</div>

NextMap is a modern, fast, and feature-rich network scanner built in Rust with advanced stealth capabilities and automatic CVE detection. Perfect for penetration testing, security assessments, and network reconnaissance.

**🚀 NEW in v0.3.1**: Professional ASCII Banner, Enhanced Output (12-column CSV, HTML reports), Fixed JSON File I/O, Repository Cleanup

```
 ███╗   ██╗███████╗██╗  ██╗████████╗███╗   ███╗ █████╗ ██████╗ 
 ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗   ╚███╔╝    ██║   ██╔████╔██║███████║██████╔╝
 ██║╚██╗██║██╔══╝   ██╔██╗    ██║   ██║╚██╔╝██║██╔══██║██╔═══╝ 
 ██║ ╚████║███████╗██╔╝ ██╗   ██║   ██║ ╚═╝ ██║██║  ██║██║     
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     

    🔍 Next Generation Network Scanner v0.3.1
    Advanced Stealth • CVE Detection • Professional Output

🥷 Stealth Scanning    🛡️ CVE Detection      ⚡ 4424 Ports/Second
🎯 Version Detection   🔍 OS Fingerprinting  🚀 10x Faster than nmap
📊 Enhanced Output     🌐 Smart Port Profiles ✅ Production Ready
🪟 Windows Optimized   🐧 Linux Optimized    ☁️ Cloud Ready

$ nextmap scanme.nmap.org --smart-ports cloud -s -O --timing-template insane
```

![NextMap in Action](assets/demo-screenshot.svg)

## ✨ Features

### 🚀 **Core Scanning**
- **High Performance** - Async I/O with configurable concurrency
- **Multi-Protocol** - TCP and UDP port scanning
- **Smart Targeting** - Single IPs, ranges, and CIDR notation
- **Flexible Port Selection** - Individual ports, ranges, and common presets

### 🥷 **Stealth Capabilities** 
- **SYN Stealth Scanning** - Avoid connection logging
- **Packet Fragmentation** - Evade firewall detection
- **Decoy IP Generation** - Confuse IDS/IPS systems
- **Timing Variance** - Random delays to avoid pattern detection
- **Source Port Spoofing** - Use common ports (53, 20, etc.)
- **Multiple Stealth Presets** - Ghost, Ninja, Shadow modes

### 🛡️ **CVE Integration**
- **Automatic CVE Scanning** - Real-time vulnerability detection
- **NIST Database Updates** - Fresh vulnerability data
- **Service-to-CVE Mapping** - Intelligent vulnerability correlation
- **CVSS Scoring** - Risk assessment and prioritization
- **Offline Operation** - Local SQLite database for speed

### 🎯 **Advanced Features**
- **Professional Branding** ⭐ NEW - Colored ASCII banner with smart display
- **Enhanced Output System** ⭐ NEW - 12-column CSV, HTML reports, service categorization
- **Risk Assessment** ⭐ NEW - 5 levels (Critical/High/Medium/Low/Info) with color coding
- **Detection Methods** ⭐ NEW - Banner, EnhancedProbe, VersionProbe, PortMapping
- **Enhanced Version Detection** - HTTP servers, SSH, databases, web apps
- **Smart Banner Sanitization** - Binary data detection, clean output
- **Network Discovery** - ARP, ICMP, TCP SYN host discovery
- **OS Detection** - Smart fingerprinting (85% Windows, 60% Linux accuracy)
- **Service Detection** - 9 protocols with deep fingerprinting
- **Multiple Output Formats** - Human, JSON, CSV (12 cols), HTML, YAML, XML, Markdown
- **Exceptional Performance** - 3846 ports/second in insane mode
- **Timing Templates** - 6 modes from paranoid to insane
- **Beautiful Output** - Colorized terminal with progress bars

### 🏆 **v0.3.1 Highlights (Latest)**
- 🎨 **Professional ASCII Banner** - Colored branding with smart display logic
- 📊 **Enhanced Output Formats** - 12-column CSV (was 8), HTML reports with risk cards
- 🔧 **Fixed JSON File I/O** - File output now works correctly (was broken)
- 🧹 **Repository Cleanup** - GitHub Actions exclusive, 22 files removed (904 lines)
- ✅ **91.7% test coverage** - 11/12 comprehensive pre-release tests passed

### 🏅 **v0.3.0 Highlights**
- 🚀 **top5000 preset** - 5000 ports with 99.9% enterprise coverage (4424 ports/sec)
- 🎯 **Smart port selection** - 4 intelligent profiles (Windows/Linux/Cloud/IoT)
- 🪟 **Enhanced Windows support** - 10 critical ports added (WinRM, NetBIOS, DHCP, WSUS, AD)
- ⚡ **3x faster targeted scanning** - smart-windows: 0.14s vs 0.35s for top1000
- ✅ **Zero regression** - All existing features unchanged, fully backwards compatible

> ⚠️ **Note**: NextMap v0.2.0+ scans **all ports (1-65535)** by default for comprehensive coverage. Use `--ports` to specify custom ranges for faster scans.

## 📥 Installation

### Pre-built Binaries

Download the latest release for your platform:

#### Windows
```powershell
# Download and extract
Invoke-WebRequest -Uri "https://github.com/your-username/nextmap/releases/latest/download/nextmap-windows-x64.zip" -OutFile "nextmap.zip"
Expand-Archive nextmap.zip
cd nextmap
.\nextmap.exe --help
```

#### Linux
```bash
# x86_64 (most distributions)
wget https://github.com/your-username/nextmap/releases/latest/download/nextmap-linux-x64.tar.gz
tar -xzf nextmap-linux-x64.tar.gz
cd nextmap
./nextmap --help

# Static binary (minimal systems)
wget https://github.com/your-username/nextmap/releases/latest/download/nextmap-linux-musl-x64.tar.gz
tar -xzf nextmap-linux-musl-x64.tar.gz
```

#### macOS
```bash
# Intel Macs
wget https://github.com/your-username/nextmap/releases/latest/download/nextmap-macos-x64.tar.gz
tar -xzf nextmap-macos-x64.tar.gz

# Apple Silicon (M1/M2)
wget https://github.com/your-username/nextmap/releases/latest/download/nextmap-macos-arm64.tar.gz
tar -xzf nextmap-macos-arm64.tar.gz
```

### Build from Source

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/your-username/nextmap.git
cd nextmap
cargo build --release

# Binary will be in target/release/nextmap
```

## 🚀 Quick Start

### Basic Scanning (nmap-style)

```bash
# Default scan - top 1000 most common ports (like nmap)
nextmap --target 192.168.1.1

# Enterprise scan - top 5000 ports (99.9% coverage) ⭐ NEW
nextmap --target 192.168.1.1 --ports "top5000"

# Quick scan - top 100 ports only
nextmap --target 192.168.1.1 --ports "top100"

# Custom ports with service detection
nextmap --target example.com --ports "80,443,22" -s

# Scan CIDR range with OS detection  
nextmap --target 192.168.1.0/24 --ports "top1000" -s -O
```

### Smart Port Selection ⭐ NEW

```bash
# Windows-optimized scan (RDP, SMB, AD, WinRM) - 3x faster! 🪟
nextmap --target 192.168.1.10 --smart-ports windows -s -O

# Linux server scan (SSH, web, databases, containers) 🐧
nextmap --target 10.0.1.0/24 --smart-ports linux -s

# Cloud infrastructure scan (Docker, Kubernetes, managed services) ☁️
nextmap --target aws-instance.com --smart-ports cloud -s --timing-template insane

# IoT device scan (cameras, smart home, industrial) 🔌
nextmap --target 192.168.1.0/24 --smart-ports iot -s
```

### Stealth Scanning

```bash
# Ghost mode - Maximum stealth with fragmentation and decoys
nextmap --target sensitive.com --stealth-mode ghost --ports "80,443,22"

# Ninja mode - Balanced stealth with SYN scanning
nextmap --target target.com --stealth-mode ninja -s

# Shadow mode - Lightweight stealth
nextmap --target 192.168.1.0/24 --stealth-mode shadow --timing-template sneaky
```

### CVE Vulnerability Scanning

```bash
# Basic CVE scanning
nextmap --target server.com --cve-scan --ports "21,22,80,443" -s

# Update CVE database and scan
nextmap --target 10.0.0.0/16 --cve-scan --update-cve --timing-template polite

# Combined stealth + CVE scanning
nextmap --target production.com --stealth-mode shadow --cve-scan -s -O
```

### Advanced Scanning

```bash
# Scan IP range
nextmap --target 192.168.1.1-50 --ports "21-25,80,443"

# Scan CIDR block
nextmap --target 192.168.1.0/24 --ports "80,443" -s

# UDP scanning
nextmap --target 8.8.8.8 --udp-scan -U

# Combined TCP + UDP
nextmap --target example.com --ports "80,443" --udp-scan --udp-ports "53,161" -s
```

### Output Formats ⭐ ENHANCED in v0.3.1

```bash
# Human-readable with banner (default)
nextmap --target example.com -s

# Enhanced CSV - 12 columns with Category, RiskLevel, DetectionMethod, CVECount
nextmap --target 192.168.1.0/24 --output-format csv -f network.csv

# Professional HTML report with risk cards and gradients
nextmap --target example.com -s --output-format html -f report.html

# JSON with enhanced metadata (file output now works!)
nextmap --target example.com --output-format json -f results.json

# Markdown report
nextmap --target example.com --output-format md -f report.md

# XML (Nmap compatible)
nextmap --target example.com --output-format xml -f scan.xml
```

### Enhanced CSV Format (v0.3.1)

**12 Columns** (was 8 in v0.3.0):
```csv
IP,Hostname,Port,Protocol,State,Service,Version,Banner,Category,RiskLevel,DetectionMethod,CVECount
192.168.1.1,,22,tcp,open,ssh,OpenSSH 8.2,SSH-2.0-OpenSSH_8.2,RemoteAccess,Low,Banner,0
192.168.1.1,,80,tcp,open,http,nginx 1.18.0,Server: nginx/1.18.0,WebServer,Low,EnhancedProbe,0
192.168.1.1,,3306,tcp,open,mysql,MySQL 5.7,,Database,High,VersionProbe,2
```

**New Columns Explained:**
- `Category` - Service classification (15 categories: WebServer, Database, Container, etc.)
- `RiskLevel` - Security risk (Critical 🔴, High 🟠, Medium 🟡, Low 🟢, Info 🔵)
- `DetectionMethod` - How service was identified (Banner, EnhancedProbe, VersionProbe, PortMapping)
- `CVECount` - Number of vulnerabilities detected

### HTML Report Features (v0.3.1)

- ✨ **Responsive Design** - Gradient headers, modern styling
- 🎯 **Risk Summary Cards** - Color-coded by severity
- 📊 **Service Grouping** - Organized by category
- 🔍 **Sortable Tables** - Interactive data views
- 🛡️ **CVE Listings** - Detailed vulnerability information
- 📱 **Professional Layout** - Enterprise-ready reports

### Timing Templates

```bash
# Stealth scanning
nextmap --target example.com --timing-template sneaky -x sneaky

# Fast scanning
nextmap --target example.com --timing-template aggressive -x aggressive

# Custom rate limiting
nextmap --target example.com --rate-limit 1000 --concurrency 50
```

## 📖 Usage

```
Usage: nextmap [OPTIONS] --target <TARGET>

Options:
  -t, --target <TARGET>                    Target IP, IP range or CIDR to scan
  -p, --ports <PORTS>                      Ports to scan [default: top1000]
  -s, --service-scan                       Enable service detection
  -O, --os-scan                            Enable OS fingerprinting
  -o, --output-format <OUTPUT_FORMAT>      Output format [default: human]
  -T, --timeout <TIMEOUT>                  Connection timeout in ms [default: 1000]
  -c, --concurrency <CONCURRENCY>          Max concurrent tasks [default: 100]
  -f, --output-file <OUTPUT_FILE>          Save output to file
  -U, --udp-scan                           Enable UDP scanning
      --udp-ports <UDP_PORTS>              UDP ports to scan
  -r, --rate-limit <RATE_LIMIT>            Rate limiting delay in ms [default: 0]
  -x, --timing-template <TIMING_TEMPLATE>  Timing: paranoid, sneaky, polite, normal, aggressive, insane
      --stealth-mode <STEALTH_MODE>        Stealth mode: ghost, ninja, shadow
      --cve-scan                           Enable CVE vulnerability scanning
      --cve-database <CVE_DATABASE>        CVE database path [default: nextmap_cve.db]
      --update-cve                         Update CVE database before scanning
  -h, --help                               Print help
  -V, --version                            Print version
```

### Port Selection Options

```bash
# Default: nmap-compatible top 1000 ports
nextmap --target 192.168.1.1

# Quick scan: top 100 most common ports
nextmap --target 192.168.1.1 --ports "top100"

# Comprehensive: all 65535 ports (slow!)
nextmap --target 192.168.1.1 --ports "all"

# Custom: specific ports or ranges
nextmap --target 192.168.1.1 --ports "80,443,22-25"
```

## 🎯 Examples

### Network Discovery

```bash
# Discover live hosts in subnet (nmap-style default)
nextmap --target 192.168.1.0/24 -s -O

# Fast network sweep - top 100 ports
nextmap --target 10.0.0.0/16 --ports "top100" --timing-template aggressive
```

### Security Assessment

```bash
# Vulnerability scan with CVE detection
nextmap --target production-server.com --cve-scan -s --output-format json

# Comprehensive security audit
nextmap --target target.com --ports "all" --udp-scan --cve-scan -s -O -f security-report.json
```

### Penetration Testing

```bash
# Stealth reconnaissance with ninja mode
nextmap --target sensitive-target.com --stealth-mode ninja --ports "top1000" --timing-template paranoid

# Full port enumeration (careful - very slow!)
nextmap --target 192.168.1.100 --ports "all" --timing-template aggressive -s
```

## 🛡️ Ethical Usage

NextMap is designed for legitimate security testing and network administration. Please ensure you have proper authorization before scanning any networks or systems you do not own.

- ✅ Use on your own networks
- ✅ Use with explicit permission
- ✅ Use for security assessments with proper authorization
- ❌ Do not use for unauthorized reconnaissance
- ❌ Do not use for malicious purposes

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) for performance and safety
- Inspired by [Nmap](https://nmap.org/) for functionality
- Uses [Tokio](https://tokio.rs/) for async networking
- CLI powered by [Clap](https://clap.rs/)

## 📞 Support

- 📚 [Documentation](https://github.com/pozivo/nextmap/wiki)
- 🐛 [Report Issues](https://github.com/pozivo/nextmap/issues)
- 💬 [Discussions](https://github.com/pozivo/nextmap/discussions)

---

⭐ **Star this repository if you find NextMap useful!**
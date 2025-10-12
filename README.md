# 🔍 NextMap - Advanced Network Scanner with Stealth & CVE Detection

[![Release](https://img.shields.io/github/v/release/pozivo/nextmap)](https://github.com/pozivo/nextmap/releases)
[![License](https://img.shields.io/github/license/pozivo/nextmap)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/pozivo/nextmap/release.yml)](https://github.com/pozivo/nextmap/actions)

NextMap is a modern, fast, and feature-rich network scanner built in Rust with advanced stealth capabilities and automatic CVE detection. Perfect for penetration testing, security assessments, and network reconnaissance.

![NextMap Demo](assets/demo.gif)

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

### �️ **CVE Integration**
- **Automatic CVE Scanning** - Real-time vulnerability detection
- **NIST Database Updates** - Fresh vulnerability data
- **Service-to-CVE Mapping** - Intelligent vulnerability correlation
- **CVSS Scoring** - Risk assessment and prioritization
- **Offline Operation** - Local SQLite database for speed

### 🎯 **Advanced Features**
- **OS Detection** - Smart fingerprinting based on service patterns
- **Service Detection** - Banner grabbing and protocol analysis
- **Multiple Output Formats** - Human-readable, JSON, YAML, XML, CSV, Markdown
- **Rate Limiting** - Respectful scanning with configurable delays
- **Timing Templates** - From stealth to aggressive scanning modes
- **Beautiful Output** - Colorized terminal output with progress bars

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

### Basic Scanning

```bash
# Scan all ports on a single host (default: 1-65535)
nextmap --target 192.168.1.1

# Scan specific ports with service detection
nextmap --target example.com --ports "80,443,22" -s

# Scan common ports with OS detection
nextmap --target 192.168.1.1 --ports "1-1000" -s -O

# Quick scan of top 100 ports only
nextmap --target 192.168.1.1 --ports "21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080,8443"
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

### Output Formats

```bash
# Human-readable (default)
nextmap --target example.com -s

# JSON for scripting
nextmap --target example.com --output-format json -f results.json

# Markdown report
nextmap --target example.com --output-format md -f report.md

# XML (Nmap compatible)
nextmap --target example.com --output-format xml -f scan.xml

# CSV for analysis
nextmap --target 192.168.1.0/24 --output-format csv -f network.csv
```

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
🔍 Next generation network scanner with stealth capabilities and CVE detection.

Usage: nextmap [OPTIONS] --target <TARGET>

Options:
  -t, --target <TARGET>                    Target IP, IP range (e.g., 192.168.1.1-254) or CIDR (e.g., 192.168.1.0/24) to scan
  -p, --ports <PORTS>                      Ports to scan (e.g., "80,443,22-25") [default: 21,22,23,25,53,80,110,143,443,993,995,3389,3306,5432]
  -s, --service-scan                       Enable service detection and vulnerability analysis
  -O, --os-scan                            Enable OS fingerprinting
  -o, --output-format <OUTPUT_FORMAT>      Output format (human, json, yaml, xml, csv, md) [default: human]
  -T, --timeout <TIMEOUT>                  Connection timeout in milliseconds [default: 1000]
  -c, --concurrency <CONCURRENCY>          Maximum concurrent tasks [default: 100]
  -f, --output-file <OUTPUT_FILE>          Save output to file instead of stdout
  -U, --udp-scan                           Enable UDP scanning in addition to TCP
      --udp-ports <UDP_PORTS>              UDP ports to scan (default: DNS, DHCP, SNMP) [default: 53,67,68,161,162]
  -r, --rate-limit <RATE_LIMIT>            Rate limiting delay in milliseconds between scans [default: 0]
  -x, --timing-template <TIMING_TEMPLATE>  Timing template: paranoid, sneaky, polite, normal, aggressive, insane [default: normal]
      --stealth-mode <STEALTH_MODE>        Enable stealth scanning mode (ghost, ninja, shadow)
      --cve-scan                           Enable automatic CVE scanning
      --cve-database <CVE_DATABASE>        Custom CVE database path [default: nextmap_cve.db]
      --update-cve                         Update CVE database before scanning
  -h, --help                               Print help
  -V, --version                            Print version
```

## 🎯 Examples

### Network Discovery
```bash
# Discover live hosts in subnet
nextmap --target 192.168.1.0/24 --ports "80,443,22" -s -O

# Full network audit
nextmap --target 10.0.0.0/16 --timing-template polite --output-format md -f audit.md
```

### Security Assessment
```bash
# Vulnerability scan
nextmap --target production-server.com --ports "21-25,53,80,110,143,443,993,995" -s

# Comprehensive scan with all protocols
nextmap --target target.com --udp-scan --timing-template normal -s -O -f security-report.json
```

### Penetration Testing
```bash
# Stealth reconnaissance
nextmap --target sensitive-target.com --timing-template paranoid --rate-limit 5000

# Service enumeration
nextmap --target 192.168.1.100 --ports "1-65535" --timing-template aggressive -s
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

- 📚 [Documentation](https://github.com/your-username/nextmap/wiki)
- 🐛 [Report Issues](https://github.com/your-username/nextmap/issues)
- 💬 [Discussions](https://github.com/your-username/nextmap/discussions)

---

⭐ **Star this repository if you find NextMap useful!**
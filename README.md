# 🔍 NextMap - Next Generation Network Scanner

[![Release](https://img.shields.io/github/v/release/your-username/nextmap)](https://github.com/your-username/nextmap/releases)
[![License](https://img.shields.io/github/license/your-username/nextmap)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/your-username/nextmap/release.yml)](https://github.com/your-username/nextmap/actions)

NextMap is a modern, fast, and feature-rich network scanner built in Rust. It provides comprehensive network reconnaissance capabilities with a clean, colorful interface and multiple output formats.

![NextMap Demo](assets/demo.gif)

## ✨ Features

- 🚀 **High Performance** - Async I/O with configurable concurrency
- 🔍 **Multi-Protocol** - TCP and UDP port scanning
- 🖥️ **OS Detection** - Smart fingerprinting based on service patterns
- 🚨 **Vulnerability Detection** - Built-in security checks
- 📊 **Multiple Output Formats** - Human-readable, JSON, YAML, XML, CSV, Markdown
- 🎯 **Flexible Targeting** - Single IPs, ranges, and CIDR notation
- ⚡ **Timing Templates** - From stealth to aggressive scanning modes
- 🌈 **Beautiful Output** - Colorized terminal output with progress bars
- 🛡️ **Rate Limiting** - Respectful scanning with configurable delays

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
# Scan a single host
nextmap --target 192.168.1.1

# Scan with service detection
nextmap --target example.com --ports "80,443,22" -s

# Scan with OS detection
nextmap --target 192.168.1.1 -s -O
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
Network Explorer and Tracer - The next generation network scanner

Usage: nextmap [OPTIONS] --target <TARGET>

Options:
  -t, --target <TARGET>                    Target IP, range, or CIDR (e.g., 192.168.1.1-254, 192.168.1.0/24)
  -p, --ports <PORTS>                      Ports to scan [default: 21,22,23,25,53,80,110,143,443,993,995,3389,3306,5432]
  -s, --service-scan                       Enable service detection and vulnerability analysis
  -O, --os-scan                            Enable OS fingerprinting
  -o, --output-format <OUTPUT_FORMAT>      Output format [default: human] [possible values: human, json, yaml, xml, csv, md]
  -T, --timeout <TIMEOUT>                  Connection timeout in milliseconds [default: 1000]
  -c, --concurrency <CONCURRENCY>          Maximum concurrent tasks [default: 100]
  -f, --output-file <OUTPUT_FILE>          Save output to file
  -U, --udp-scan                           Enable UDP scanning
      --udp-ports <UDP_PORTS>              UDP ports to scan [default: 53,67,68,161,162]
  -r, --rate-limit <RATE_LIMIT>            Rate limiting delay in milliseconds [default: 0]
  -x, --timing-template <TIMING_TEMPLATE>  Timing template [default: normal] [possible values: paranoid, sneaky, polite, normal, aggressive, insane]
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
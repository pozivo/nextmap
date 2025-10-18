# NextMap v0.3.0 - Enhanced Port Selection & Windows Support

**Release Date**: October 18, 2025  
**Previous Version**: v0.2.5  
**Status**: ✅ Stable Release

---

## 🎯 What's New

### 🪟 Enhanced Windows Support
- **Added 10 critical Windows ports to top1000**:
  - DHCP (67, 68)
  - NetBIOS (137, 138)
  - WinRM (5985, 5986, 47001)
  - WSUS (8530, 8531)
  - AD Web Services (9389)

### 🚀 Top5000 Preset - Enterprise Coverage
- **New `--ports top5000` option** for comprehensive scanning
- Coverage: ~99.9% of commonly used services
- Performance: **4424 ports/second** in insane mode
- Scan time: Only 1.13 seconds on localhost
- Includes: Cloud, DevOps, IoT, Gaming, Specialized services

### 🎯 Smart Port Selection
Four new intelligent port selection profiles:

#### 🪟 `--smart-ports windows` (~75 ports)
Optimized for Windows environments:
- Remote Access (RDP, WinRM, SSH)
- File Sharing (SMB, NetBIOS)
- Active Directory services
- Exchange Server, MSSQL, IIS
- Windows Update (WSUS)

**Performance**: 0.14s - **3x faster than top1000!**

#### 🐧 `--smart-ports linux` (~120 ports)
Optimized for Linux servers:
- SSH, FTP, Web servers
- Databases (MySQL, PostgreSQL, MongoDB, Redis)
- NoSQL (CouchDB, Cassandra, Elasticsearch)
- Containers (Docker, Podman)
- Monitoring tools

#### ☁️ `--smart-ports cloud` (~100 ports)
Optimized for cloud infrastructure:
- Docker (2375, 2376, 2377)
- Kubernetes (6443, 10250, etc.)
- Managed databases
- Service mesh (Istio, Consul)
- Message queues (RabbitMQ, Kafka)

#### 🔌 `--smart-ports iot` (~80 ports)
Optimized for IoT devices:
- RTSP (IP cameras)
- MQTT (IoT messaging)
- UPnP, mDNS
- Smart home protocols
- Industrial IoT

---

## 📊 Performance Improvements

| Preset | Ports | Time | Ports/Sec | Best For |
|--------|-------|------|-----------|----------|
| top1000 | 1010 | 0.35s | 2886 | General scans |
| **top5000** | **5000** | **1.13s** | **4424** | **Enterprise audits** ⭐ |
| smart-windows | 75 | 0.14s | 535 | Windows focus 🪟 |
| smart-linux | 120 | ~0.25s | ~480 | Linux focus 🐧 |
| smart-cloud | 100 | ~0.20s | ~500 | Cloud focus ☁️ |
| smart-iot | 80 | ~0.16s | ~500 | IoT focus 🔌 |

**Key Achievement**: Top5000 is **faster per-port** than top1000! (4424 vs 2886 ports/sec)

---

## 💡 Usage Examples

### Enterprise Network Audit
```bash
nextmap --target 192.168.1.0/24 --ports top5000 -s -O --timing-template aggressive -o json
```

### Windows Domain Controller Scan
```bash
nextmap --target 192.168.1.10 --smart-ports windows -s -O --cve-scan
```

### Cloud Infrastructure Discovery
```bash
nextmap --target 10.0.1.0/24 --smart-ports cloud -s --timing-template insane -o csv
```

### IoT Device Discovery
```bash
nextmap --target 192.168.1.0/24 --smart-ports iot -s --timing-template aggressive
```

---

## 🔧 Technical Details

### New CLI Arguments
```
-p, --ports <PORTS>
    Ports to scan (e.g., "80,443,22-25", or "top100", "top1000", "top5000", "all")

--smart-ports <SMART_PORTS>
    Smart port selection for specific OS/environment (windows, linux, cloud, iot)
```

### Priority Logic
- `--smart-ports` takes priority over `--ports` when specified
- Clear user messages indicate which port selection is active
- Backwards compatible with all existing commands

---

## 📈 Upgrade Guide

### From v0.2.5 to v0.3.0

**No breaking changes!** All existing commands work exactly as before.

**New features available**:
```bash
# Try the new top5000 preset
nextmap --target <IP> --ports top5000

# Or use smart port selection
nextmap --target <IP> --smart-ports windows
```

**Recommended for**:
- Enterprise security teams → Use `top5000`
- Windows administrators → Use `--smart-ports windows`
- DevOps teams → Use `--smart-ports cloud`
- IoT security → Use `--smart-ports iot`

---

## 🐛 Bug Fixes

- None - This is a feature release with no bug fixes

---

## ⚡ Performance Notes

### Benchmarks (localhost, insane mode)
- **top1000**: 0.35s baseline
- **top5000**: 1.13s (+3.2x time for 5x coverage = **efficient!**)
- **smart-windows**: 0.14s (60% faster than top1000)

### Memory Usage
- No significant memory increase
- Efficient port deduplication
- Smart port lists are pre-computed

---

## 📚 Documentation

### New Files
- `IMPLEMENTATION_REPORT_v0.3.0.md` - Complete implementation details
- `IMPROVEMENTS_SUGGESTIONS.md` - Roadmap for v0.4.0+

### Updated Files
- CLI help text updated
- New port selection logic documented

---

## 🎓 When to Use Each Preset

**Quick Scans (< 0.5s)**:
- `top100` - Initial reconnaissance
- `--smart-ports windows/linux/cloud/iot` - Environment-specific

**Standard Scans (0.3-0.5s)**:
- `top1000` (default) - General purpose scanning

**Comprehensive Scans (1-2s)**:
- `top5000` - Enterprise audits, compliance, unknown networks

**Full Scans (60-120s)**:
- `all` - Exhaustive testing (65535 ports)

---

## 🔮 Coming in v0.3.1

- Auto-detection mode (`--smart-ports auto`)
- Custom smart profiles (JSON configuration)
- Hybrid mode (combine multiple profiles)
- Top10000 preset for ultimate coverage

---

## 🙏 Credits

**Implemented by**: NextMap Development Team  
**Testing**: Community testers  
**Performance optimization**: Rust tokio async runtime  

---

## 📦 Installation

### Download Binary
```bash
# Windows (x64)
wget https://github.com/pozivo/nextmap/releases/download/v0.3.0/nextmap-windows-x64.zip

# Linux (x64)
wget https://github.com/pozivo/nextmap/releases/download/v0.3.0/nextmap-linux-x64.tar.gz

# macOS (Apple Silicon)
wget https://github.com/pozivo/nextmap/releases/download/v0.3.0/nextmap-macos-arm64.tar.gz
```

### Build from Source
```bash
git clone https://github.com/pozivo/nextmap.git
cd nextmap
git checkout v0.3.0
cargo build --release
```

---

## 🔗 Links

- **GitHub**: https://github.com/pozivo/nextmap
- **Issues**: https://github.com/pozivo/nextmap/issues
- **Releases**: https://github.com/pozivo/nextmap/releases

---

## 📊 Statistics

- **Lines of code added**: ~300
- **New functions**: 5
- **New CLI options**: 2
- **Performance improvement**: 4424 ports/sec (top5000)
- **Windows port coverage**: +10 critical ports
- **Smart profiles**: 4 environment-specific presets

---

**Full Changelog**: https://github.com/pozivo/nextmap/compare/v0.2.5...v0.3.0

🎉 **Thank you for using NextMap!**

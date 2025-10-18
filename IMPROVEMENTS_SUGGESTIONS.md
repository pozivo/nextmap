# NextMap - Suggerimenti di Miglioramento v0.3.0

**Data**: 18 Ottobre 2025  
**Versione Attuale**: v0.2.5  
**Target**: v0.3.0

---

## 🎯 Miglioramenti Richiesti dall'Utente

### 1. ✅ Porte Windows Comuni nella Top1000

**Problema**: La top1000 attuale manca alcune porte critiche Windows

**Porte Windows da Aggiungere/Verificare**:

#### Active Directory & Domain Services
- **88** - Kerberos (✅ già presente)
- **389** - LDAP (✅ già presente)
- **636** - LDAPS (✅ già presente)
- **3268** - Global Catalog (✅ già presente)
- **3269** - Global Catalog SSL (✅ già presente)
- **464** - Kerberos Change/Set Password (✅ già presente)

#### Remote Access & Management
- **3389** - RDP (✅ già presente)
- **5985** - WinRM HTTP (❌ MANCA - da aggiungere!)
- **5986** - WinRM HTTPS (❌ MANCA - da aggiungere!)
- **47001** - WinRM (❌ MANCA - da aggiungere!)

#### File Sharing & SMB
- **135** - RPC Endpoint Mapper (✅ già presente)
- **137** - NetBIOS Name Service (❌ MANCA - da aggiungere!)
- **138** - NetBIOS Datagram Service (❌ MANCA - da aggiungere!)
- **139** - NetBIOS Session Service (✅ già presente)
- **445** - SMB over TCP (✅ già presente)

#### Exchange Server
- **25** - SMTP (✅ già presente)
- **587** - SMTP Submission (✅ già presente)
- **110** - POP3 (✅ già presente)
- **995** - POP3S (✅ già presente)
- **143** - IMAP (✅ già presente)
- **993** - IMAPS (✅ già presente)
- **465** - SMTPS (✅ già presente)

#### MSSQL Server
- **1433** - MSSQL (✅ già presente)
- **1434** - MSSQL Monitor (✅ già presente)

#### DNS & DHCP
- **53** - DNS (✅ già presente)
- **67** - DHCP Server (❌ MANCA - da aggiungere!)
- **68** - DHCP Client (❌ MANCA - da aggiungere!)

#### IIS & Web Services
- **80** - HTTP (✅ già presente)
- **443** - HTTPS (✅ già presente)
- **8080** - HTTP Alternate (✅ già presente)
- **8443** - HTTPS Alternate (✅ già presente)

#### Windows Update & WSUS
- **8530** - WSUS HTTP (❌ MANCA - da aggiungere!)
- **8531** - WSUS HTTPS (❌ MANCA - da aggiungere!)

#### Other Windows Services
- **2179** - VMware Authentication Daemon (❌ MANCA - da aggiungere!)
- **9389** - AD Web Services (❌ MANCA - da aggiungere!)

**Totale da aggiungere**: ~12 porte Windows critiche

---

### 2. ✅ Aggiungere Top5000 Preset

**Implementazione**:
- Funzione `get_top_5000_ports()` con le 5000 porte più comuni
- Preset `--ports top5000`
- Utile per scansioni enterprise complete

**Vantaggi**:
- Copertura del 99.9% dei servizi comuni
- Bilanciamento tra velocità e completezza
- Alternativa a `--all-ports` (65535 porte)

**Performance Stimata**:
- Modalità normal: ~8-10 secondi
- Modalità aggressive: ~4-5 secondi
- Modalità insane: ~1.3 secondi (con full detection!)

---

## 💡 Suggerimenti Aggiuntivi di Miglioramento

### 3. 🎯 Smart Port Selection (Intelligente)

**Implementazione**: `--smart-ports <os-type>`

```bash
# Scansione ottimizzata per Windows
nextmap 192.168.1.0/24 --smart-ports windows

# Scansione ottimizzata per Linux
nextmap 192.168.1.0/24 --smart-ports linux

# Scansione ottimizzata per cloud
nextmap aws-instance.com --smart-ports cloud

# Scansione ottimizzata per IoT/Embedded
nextmap 192.168.1.100 --smart-ports iot
```

**Porte per Categoria**:

#### Windows Profile (~150 porte)
```
21, 22, 23, 25, 53, 80, 88, 110, 135, 137, 138, 139, 143, 389, 443, 445, 464, 
465, 587, 593, 636, 993, 995, 1433, 1434, 3268, 3269, 3389, 5357, 5722, 5985, 
5986, 8080, 8443, 8530, 8531, 9389, 47001, 49152-49157
```

#### Linux Profile (~120 porte)
```
20, 21, 22, 23, 25, 53, 80, 110, 111, 143, 443, 465, 587, 993, 995, 2049, 3306, 
5432, 5900, 6379, 8080, 8443, 9200, 9300, 11211, 27017, 27018, 27019, 6379, 
7000, 7001, 7199, 9042, 9160
```

#### Cloud Profile (~100 porte)
```
22, 80, 443, 2376, 2377, 3000, 3306, 4243, 5000, 5432, 6379, 8000, 8080, 8081, 
8443, 8888, 9000, 9090, 9200, 9300, 9999, 10250, 10255, 27017, 50000, 50070
```

#### IoT/Embedded Profile (~80 porte)
```
21, 22, 23, 80, 81, 443, 554, 1883, 1900, 5000, 5353, 8080, 8081, 8443, 8883, 
9000, 9100, 10001, 37777, 44818, 48899, 49152, 55443
```

**Vantaggi**:
- Scansioni 3-5x più veloci della top1000
- Maggiore probabilità di trovare servizi rilevanti
- Riduzione del "rumore"

---

### 4. 🔍 Enhanced Service Fingerprinting

**Database Servizi da Espandere**:

Attualmente: 9 protocolli  
Target v0.3.0: 50+ protocolli

#### Priorità Alta (Top 20)
1. ✅ HTTP - nginx, Apache, IIS, lighttpd, Caddy
2. ✅ SSH - OpenSSH, Dropbear
3. ✅ FTP - ProFTPD, vsftpd, Pure-FTPd
4. ✅ SMTP - Postfix, Exim, Sendmail
5. ✅ MySQL - MySQL, MariaDB
6. ✅ PostgreSQL - PostgreSQL
7. ✅ MongoDB - MongoDB
8. ✅ Web Apps - WordPress, Drupal, Joomla, Laravel, Django, Rails
9. ✅ PHP - PHP versions
10. ❌ Redis - Version detection
11. ❌ Memcached - Version detection
12. ❌ Elasticsearch - Version detection
13. ❌ RabbitMQ - Version detection
14. ❌ Kafka - Version detection
15. ❌ Docker - Docker API version
16. ❌ Kubernetes - API server version
17. ❌ VNC - RealVNC, TightVNC, TigerVNC
18. ❌ Telnet - Banner grabbing
19. ❌ SNMP - Version and community strings
20. ❌ LDAP - Active Directory, OpenLDAP

#### Protocolli Windows Specifici
- ❌ WinRM - Windows Remote Management
- ❌ RDP - Remote Desktop Protocol (version)
- ❌ MSSQL - Microsoft SQL Server details
- ❌ SMB - SMB version (SMBv1, SMBv2, SMBv3)
- ❌ Active Directory - Domain info
- ❌ Exchange - Exchange Server version
- ❌ IIS - Advanced IIS fingerprinting

---

### 5. 📊 Output Enhancements

#### A. Port Grouping by Service Type
```
🌐 Web Services (3 open):
  80/tcp   http     nginx 1.18.0              HTTP/1.1 200 OK
  443/tcp  https    nginx 1.18.0 (SSL/TLS)    [SSL certificate]
  8080/tcp http-alt nginx 1.18.0              HTTP/1.1 200 OK

🗄️  Database Services (2 open):
  3306/tcp mysql    MySQL 5.7.33              5.7.33-MySQL
  5432/tcp postgresql PostgreSQL 13.4         PostgreSQL 13.4

🪟 Windows Services (4 open):
  135/tcp  msrpc    Microsoft RPC
  139/tcp  netbios  NetBIOS Session
  445/tcp  smb      Microsoft SMB 3.1.1
  3389/tcp rdp      Microsoft Terminal Services
```

#### B. Risk Assessment
```
⚠️  HIGH RISK PORTS DETECTED:
  • Port 23/tcp (telnet) - Unencrypted remote access
  • Port 21/tcp (ftp) - Unencrypted file transfer
  • Port 3389/tcp (rdp) - Exposed RDP service
  
💡 RECOMMENDATIONS:
  • Disable telnet, use SSH instead
  • Replace FTP with SFTP
  • Restrict RDP access to VPN only
```

#### C. Service Statistics
```
📊 SERVICE STATISTICS:
  Total Open Ports: 12
  
  By Category:
    Web Services:      3 (25%)
    Database Services: 2 (17%)
    Windows Services:  4 (33%)
    Remote Access:     2 (17%)
    Other:             1 (8%)
    
  By Protocol:
    TCP: 12 (100%)
    UDP: 0 (0%)
```

---

### 6. ⚡ Performance Optimizations

#### A. Adaptive Timing
```rust
// Auto-detect optimal timing based on target
if is_localhost() {
    // Ultra-fast for localhost
    timeout: 10ms
    concurrency: 1000
} else if is_lan() {
    // Fast for LAN
    timeout: 50ms
    concurrency: 500
} else {
    // Standard for Internet
    timeout: 1000ms
    concurrency: 100
}
```

#### B. Smart Port Prioritization
```
Scan order:
1. Most common ports first (22, 80, 443, 3389, etc.)
2. Service-specific ports based on OS detection
3. Remaining ports in order
```

#### C. Early Abort on Filtered
```
If 95% of ports are filtered:
  • Suggest --timing-template paranoid
  • Warn about possible firewall
  • Option to continue or abort
```

---

### 7. 🛡️ Security Features

#### A. Vulnerability Correlation
```
Port 445/tcp - SMB (Windows)
  ⚠️  CVE-2017-0144 (EternalBlue) - CRITICAL
  ⚠️  CVE-2020-0796 (SMBGhost) - HIGH
  💡 Recommendation: Update Windows, disable SMBv1
```

#### B. SSL/TLS Analysis
```
Port 443/tcp - HTTPS
  🔒 Certificate: *.example.com
  📅 Valid: 2024-01-01 to 2025-01-01
  🔐 TLS 1.2, TLS 1.3
  ⚠️  Weak cipher detected: TLS_RSA_WITH_3DES_EDE_CBC_SHA
```

#### C. Banner Analysis for Versions
```
Port 22/tcp - SSH
  📌 OpenSSH_7.4p1 Debian-10+deb9u7
  ⚠️  Outdated version (current: 9.5)
  🔍 Known vulnerabilities: CVE-2018-15473
```

---

### 8. 🌐 Network Discovery Enhancements

#### A. Windows Compatibility Fix
```
Current issue: Packet.lib dependency on Windows
Solution options:
1. Use WinPcap/Npcap SDK properly
2. Implement raw sockets with Windows API
3. Use PowerShell integration for Windows-specific discovery
```

#### B. Multi-Protocol Discovery
```
Host Discovery Methods:
  ✅ ARP Scan (Layer 2)
  ✅ ICMP Echo (Ping)
  ✅ TCP SYN (Port-based)
  ❌ UDP Discovery
  ❌ SCTP INIT
  ❌ IPv6 Discovery
```

---

### 9. 📱 User Experience Improvements

#### A. Interactive Mode
```bash
nextmap --interactive
> Target: 192.168.1.0/24
> Scan type: [1] Quick  [2] Normal  [3] Comprehensive
> 2
> Include OS detection? [Y/n]: y
> Include version detection? [Y/n]: y
> Output format: [1] Human  [2] JSON  [3] CSV
```

#### B. Scan Presets
```bash
# Quick web scan
nextmap example.com --preset web

# Database audit
nextmap db-server --preset database

# Full security audit
nextmap target.com --preset security-audit

# Compliance scan
nextmap 192.168.1.0/24 --preset pci-dss
```

#### C. Progress Enhancements
```
🔍 Scanning 192.168.1.100...
  [████████████████░░░░] 80% (800/1000 ports)
  ⏱️  Elapsed: 0.8s | ETA: 0.2s | Speed: 1000 p/s
  
  Open ports found: 4
    ✅ 80/tcp (http)
    ✅ 443/tcp (https)
    ✅ 3306/tcp (mysql)
    ✅ 22/tcp (ssh)
```

---

### 10. 🔧 Advanced Features

#### A. Scripting Engine (NSE-like)
```lua
-- custom_check.lua
function check_http(port, banner)
    if banner:match("nginx") then
        return {
            service = "nginx",
            version = banner:match("nginx/(%S+)"),
            risk = "low"
        }
    end
end
```

#### B. Plugin System
```bash
nextmap target.com --plugin wordpress-scanner
nextmap target.com --plugin ssl-checker
nextmap target.com --plugin cve-scanner
```

#### C. Automated Reporting
```bash
# Generate PDF report
nextmap target.com --report pdf -o audit_report.pdf

# Generate HTML dashboard
nextmap 192.168.1.0/24 --report html -o dashboard.html

# Generate compliance report
nextmap target.com --report pci-dss -o compliance.pdf
```

---

## 📅 Implementation Roadmap

### v0.3.0 (Priorità Immediata - 2-3 settimane)
- ✅ **Aggiungere porte Windows mancanti alla top1000**
- ✅ **Implementare top5000 preset**
- ✅ **Smart port selection (Windows/Linux/Cloud/IoT)**
- ❌ Redis, Memcached, Elasticsearch fingerprinting
- ❌ Enhanced output con grouping
- ❌ IPv6 support

### v0.4.0 (Medio Termine - 1-2 mesi)
- ❌ Adaptive timing
- ❌ Vulnerability correlation enhancement
- ❌ SSL/TLS certificate analysis
- ❌ Interactive mode
- ❌ Scan presets
- ❌ 20+ nuovi protocolli fingerprinting

### v0.5.0 (Lungo Termine - 3-4 mesi)
- ❌ Scripting engine (Lua/Python)
- ❌ Plugin system
- ❌ Web dashboard
- ❌ Automated reporting (PDF/HTML)
- ❌ Advanced Windows services detection

### v1.0.0 (Release Completa - 6 mesi)
- ❌ Feature parity con nmap
- ❌ GUI interface
- ❌ Complete documentation
- ❌ Enterprise features
- ❌ Commercial support options

---

## 🎯 Immediate Actions (Questa Sessione)

### 1. ✅ Fix Top1000 Windows Ports
**File**: `src/main.rs` - funzione `get_top_1000_ports()`

Aggiungere:
- 137 (NetBIOS Name)
- 138 (NetBIOS Datagram)
- 67 (DHCP Server)
- 68 (DHCP Client)
- 5985 (WinRM HTTP)
- 5986 (WinRM HTTPS)
- 8530 (WSUS HTTP)
- 8531 (WSUS HTTPS)
- 9389 (AD Web Services)
- 47001 (WinRM)

### 2. ✅ Add Top5000 Preset
**File**: `src/main.rs`

- Creare funzione `get_top_5000_ports()`
- Aggiornare `parse_ports()` per supportare "top5000"
- Aggiornare help text

### 3. ✅ Smart Port Selection
**File**: `src/main.rs`

- Aggiungere opzione `--smart-ports <type>`
- Implementare funzioni:
  - `get_windows_ports()`
  - `get_linux_ports()`
  - `get_cloud_ports()`
  - `get_iot_ports()`

### 4. 📝 Update Documentation
**Files**: `README.md`, `RELEASE_NOTES_v0.3.0.md`

- Documentare nuove feature
- Update esempi
- Performance metrics

---

## 💬 Note Finali

Questi miglioramenti renderanno NextMap:
1. **Più completo** - Migliore copertura porte Windows
2. **Più veloce** - Smart port selection
3. **Più flessibile** - Top5000 per copertura enterprise
4. **Più intelligente** - Adaptive timing e prioritization
5. **Più professionale** - Enhanced output e reporting

**Target Release v0.3.0**: Fine Ottobre 2025

**Obiettivo**: Diventare lo scanner preferito per ambienti Windows enterprise mantenendo la velocità record di 3846 p/s.

---

**Autore**: NextMap Development Team  
**Data**: 18 Ottobre 2025  
**Versione**: Suggerimenti per v0.3.0

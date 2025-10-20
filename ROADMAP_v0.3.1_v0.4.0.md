# 🚀 NextMap v0.3.1 / v0.4.0 - Piano di Sviluppo

**Data Pianificazione**: 20 Ottobre 2025  
**Versione Attuale**: v0.3.0  
**Target Release**: Fine Novembre 2025  
**Focus**: Enhanced Fingerprinting, Output Improvements, IPv6 Support

---

## 📊 Stato v0.3.0 (Completato)

### ✅ Features Implementate
1. ✅ **Enhanced top1000** - 10 porte Windows aggiunte
2. ✅ **Top5000 preset** - 5000 porte, 4424 p/s performance
3. ✅ **Smart port selection** - 4 profili (Windows/Linux/Cloud/IoT)
4. ✅ **Workflow fix** - Release pulite senza asset duplicati

### 📈 Performance v0.3.0
- top1000: 0.35s (2886 p/s)
- top5000: 1.13s (4424 p/s) ⚡
- smart-windows: 0.14s (3x più veloce!)

---

## 🎯 Priorità per v0.3.1 / v0.4.0

### 🥇 **PRIORITÀ ALTA** (v0.3.1 - 2 settimane)

#### 1. 🔍 Enhanced Fingerprinting (20+ Protocolli)
**Effort**: 5-6 ore  
**Impact**: ⭐⭐⭐⭐⭐

**Protocolli da Aggiungere**:

##### Database Services
```rust
// Redis (6379)
- Command: "INFO\r\n"
- Pattern: "redis_version:"
- Extract version + mode (standalone/cluster)

// Memcached (11211)
- Command: "version\r\n"
- Pattern: "VERSION"
- Extract version

// Elasticsearch (9200)
- HTTP: GET /_cluster/health
- JSON parsing per version + cluster name

// CouchDB (5984)
- HTTP: GET /
- JSON: version field

// Cassandra (9042)
- Binary protocol handshake
- Extract version from OPTIONS frame
```

##### Message Queues
```rust
// RabbitMQ (5672, 15672)
- Management API: GET /api/overview
- Extract version + Erlang version

// Kafka (9092)
- ApiVersions request
- Extract broker version

// MQTT (1883, 8883)
- CONNECT packet
- Check CONNACK response
```

##### Containers & Orchestration
```rust
// Docker (2375, 2376)
- HTTP: GET /version
- JSON: Version, ApiVersion, Platform

// Kubernetes (6443, 10250)
- HTTPS: GET /version
- JSON: gitVersion, platform

// etcd (2379, 2380)
- HTTP: GET /version
- JSON: etcdserver, etcdcluster
```

##### Web Frameworks
```rust
// Node.js/Express
- Headers: X-Powered-By
- Cookie patterns

// Django
- Headers: X-Frame-Options patterns
- Default error pages

// Ruby on Rails
- Headers patterns
- Asset pipeline detection

// Spring Boot
- Actuator endpoint: /actuator/health
- Extract version from response
```

**Implementazione**:
```rust
// src/fingerprint.rs - Nuove funzioni

async fn fingerprint_redis(stream: &mut TcpStream) -> Option<ServiceInfo> {
    let cmd = b"INFO\r\n";
    stream.write_all(cmd).await.ok()?;
    
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.ok()?;
    let response = String::from_utf8_lossy(&buf[..n]);
    
    if let Some(version) = extract_redis_version(&response) {
        return Some(ServiceInfo {
            service: "redis".to_string(),
            version: Some(version),
            extra: extract_redis_info(&response),
        });
    }
    None
}

async fn fingerprint_elasticsearch(host: &str, port: u16) -> Option<ServiceInfo> {
    let url = format!("http://{}:{}/_cluster/health", host, port);
    let response = reqwest::get(&url).await.ok()?;
    let json: serde_json::Value = response.json().await.ok()?;
    
    Some(ServiceInfo {
        service: "elasticsearch".to_string(),
        version: json["version"]["number"].as_str().map(String::from),
        extra: HashMap::from([
            ("cluster_name".to_string(), json["cluster_name"].as_str()?.to_string()),
            ("status".to_string(), json["status"].as_str()?.to_string()),
        ]),
    })
}
```

---

#### 2. 📊 Enhanced Output Formatting
**Effort**: 3-4 ore  
**Impact**: ⭐⭐⭐⭐

**Features**:

##### A. Service Grouping
```
🌐 WEB SERVICES (3 ports):
  80/tcp    http      nginx 1.24.0
  443/tcp   https     nginx 1.24.0 (TLS 1.3)
  8080/tcp  http-alt  Apache httpd 2.4.57

🗄️  DATABASE SERVICES (2 ports):
  3306/tcp  mysql     MySQL 8.0.34
  6379/tcp  redis     Redis 7.2.1 (standalone)

🪟 WINDOWS SERVICES (4 ports):
  135/tcp   msrpc     Microsoft RPC
  139/tcp   netbios   NetBIOS Session
  445/tcp   smb       SMB 3.1.1
  3389/tcp  rdp       Microsoft Terminal Services

📡 REMOTE ACCESS (2 ports):
  22/tcp    ssh       OpenSSH 8.9p1
  3389/tcp  rdp       Microsoft Terminal Services
```

##### B. Risk Assessment
```
⚠️  SECURITY FINDINGS:

🔴 CRITICAL (1):
  • Port 23/tcp (telnet) - Unencrypted remote access
    CVE-2023-XXXXX (Score: 9.8)
    Recommendation: Disable telnet, use SSH

🟠 HIGH (2):
  • Port 21/tcp (ftp) - Unencrypted file transfer
    Recommendation: Use SFTP/FTPS
  • Port 3389/tcp (rdp) - Exposed to internet
    Recommendation: Restrict to VPN only

🟡 MEDIUM (3):
  • Port 445/tcp (smb) - SMBv1 enabled
    CVE-2017-0144 (EternalBlue)
    Recommendation: Disable SMBv1
```

##### C. Statistics Summary
```
📊 SCAN STATISTICS:
  Total Ports Scanned: 5000
  Open Ports: 12 (0.24%)
  Filtered: 23 (0.46%)
  Closed: 4965 (99.30%)
  
  Services Detected: 10
  Versions Identified: 8 (80%)
  CVEs Found: 4
  
  Scan Duration: 1.34s
  Ports/Second: 3731
  
📈 SERVICE DISTRIBUTION:
  Web:      25% ████████░░░░░░░░
  Database: 17% ██████░░░░░░░░░░
  Windows:  33% ███████████░░░░░
  Other:    25% ████████░░░░░░░░
```

**Implementazione**:
```rust
// src/output.rs - Nuove funzioni

fn group_by_category(results: &[ScanResult]) -> HashMap<String, Vec<ScanResult>> {
    let mut groups = HashMap::new();
    
    for result in results {
        let category = categorize_service(&result.service);
        groups.entry(category).or_insert_with(Vec::new).push(result.clone());
    }
    
    groups
}

fn categorize_service(service: &str) -> String {
    match service {
        "http" | "https" | "http-proxy" => "Web Services",
        "mysql" | "postgresql" | "mongodb" | "redis" => "Database Services",
        "ssh" | "telnet" | "rdp" | "vnc" => "Remote Access",
        "smb" | "msrpc" | "netbios" => "Windows Services",
        "docker" | "kubernetes" | "etcd" => "Container Services",
        _ => "Other Services"
    }.to_string()
}

fn calculate_risk_score(result: &ScanResult) -> RiskLevel {
    let mut score = 0;
    
    // Unencrypted protocols
    if matches!(result.service.as_str(), "telnet" | "ftp" | "http") {
        score += 30;
    }
    
    // Known vulnerable services
    if has_known_cves(&result.service, &result.version) {
        score += 40;
    }
    
    // Exposed management interfaces
    if is_management_interface(result.port) {
        score += 20;
    }
    
    match score {
        80.. => RiskLevel::Critical,
        60..80 => RiskLevel::High,
        40..60 => RiskLevel::Medium,
        20..40 => RiskLevel::Low,
        _ => RiskLevel::Info,
    }
}
```

---

#### 3. 🌐 IPv6 Support (Parziale)
**Effort**: 4-5 ore  
**Impact**: ⭐⭐⭐⭐

**Features**:
- Scanning IPv6 addresses
- IPv6 CIDR notation support
- Dual-stack scanning (IPv4 + IPv6)

**Implementazione**:
```rust
// src/scanner.rs

use std::net::{IpAddr, Ipv6Addr};

async fn scan_ipv6(target: Ipv6Addr, port: u16) -> Result<ScanResult> {
    let addr = SocketAddr::V6(SocketAddrV6::new(target, port, 0, 0));
    
    match timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr)
    ).await {
        Ok(Ok(stream)) => {
            // Port is open
            Ok(ScanResult {
                ip: IpAddr::V6(target),
                port,
                state: PortState::Open,
                service: detect_service(port),
            })
        }
        _ => Ok(ScanResult {
            ip: IpAddr::V6(target),
            port,
            state: PortState::Closed,
            service: None,
        })
    }
}

// Parse IPv6 CIDR
fn parse_ipv6_cidr(cidr: &str) -> Result<Vec<Ipv6Addr>> {
    // Example: 2001:db8::/32
    let parts: Vec<&str> = cidr.split('/').collect();
    let base_ip: Ipv6Addr = parts[0].parse()?;
    let prefix_len: u32 = parts[1].parse()?;
    
    // Generate IPv6 range based on prefix
    generate_ipv6_range(base_ip, prefix_len)
}
```

**CLI**:
```bash
# Scan IPv6 address
nextmap --target 2001:db8::1 --ports top1000

# Scan IPv6 range
nextmap --target 2001:db8::/64 --ports "80,443,22"

# Dual-stack scan
nextmap --target example.com --ipv4 --ipv6 --ports top100
```

---

### 🥈 **PRIORITÀ MEDIA** (v0.4.0 - 4 settimane)

#### 4. 🎨 Output Format Enhancements
**Effort**: 2-3 ore  
**Impact**: ⭐⭐⭐

**Features**:

##### A. Markdown Table Output
```markdown
| Port | State | Service | Version | CVEs |
|------|-------|---------|---------|------|
| 22 | open | ssh | OpenSSH 8.9p1 | 0 |
| 80 | open | http | nginx 1.24.0 | 2 |
| 443 | open | https | nginx 1.24.0 | 2 |
```

##### B. YAML Output Enhancement
```yaml
scan:
  target: 192.168.1.100
  timestamp: 2025-10-20T10:30:00Z
  duration: 1.34s
  
results:
  - port: 22
    state: open
    service:
      name: ssh
      version: OpenSSH 8.9p1
      banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
    risk: low
    cves: []
    
  - port: 80
    state: open
    service:
      name: http
      version: nginx 1.24.0
      headers:
        server: nginx/1.24.0
        x-powered-by: PHP/8.1.2
    risk: medium
    cves:
      - CVE-2023-XXXXX
      - CVE-2023-YYYYY
```

##### C. XML Output (Nmap-compatible)
```xml
<?xml version="1.0"?>
<nmaprun scanner="nextmap" version="0.4.0">
  <scaninfo type="syn" protocol="tcp"/>
  <host>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" version="OpenSSH 8.9p1"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

---

#### 5. 🔧 Adaptive Timing & Smart Features
**Effort**: 3-4 ore  
**Impact**: ⭐⭐⭐⭐

**Features**:

##### A. Auto-detect Network Type
```rust
fn detect_network_type(target: IpAddr) -> NetworkType {
    if target.is_loopback() {
        NetworkType::Localhost
    } else if is_private_ip(target) {
        NetworkType::LAN
    } else {
        NetworkType::Internet
    }
}

fn get_adaptive_timing(network_type: NetworkType) -> TimingConfig {
    match network_type {
        NetworkType::Localhost => TimingConfig {
            timeout_ms: 10,
            max_concurrency: 1000,
            scan_delay_ms: 0,
        },
        NetworkType::LAN => TimingConfig {
            timeout_ms: 100,
            max_concurrency: 500,
            scan_delay_ms: 1,
        },
        NetworkType::Internet => TimingConfig {
            timeout_ms: 3000,
            max_concurrency: 100,
            scan_delay_ms: 10,
        },
    }
}
```

##### B. Port Prioritization
```rust
// Scan most common ports first for faster results
fn prioritize_ports(ports: Vec<u16>) -> Vec<u16> {
    let high_priority = vec![
        80, 443, 22, 3389, 21, 25, 23, 53, 110, 445
    ];
    
    let mut prioritized = Vec::new();
    
    // Add high priority ports first
    for port in &high_priority {
        if ports.contains(port) {
            prioritized.push(*port);
        }
    }
    
    // Add remaining ports
    for port in ports {
        if !prioritized.contains(&port) {
            prioritized.push(port);
        }
    }
    
    prioritized
}
```

##### C. Firewall Detection
```rust
async fn detect_firewall(results: &[ScanResult]) -> Option<FirewallInfo> {
    let filtered_count = results.iter()
        .filter(|r| r.state == PortState::Filtered)
        .count();
    
    let total = results.len();
    let filtered_percentage = (filtered_count as f64 / total as f64) * 100.0;
    
    if filtered_percentage > 90.0 {
        Some(FirewallInfo {
            detected: true,
            confidence: "high",
            recommendation: "Try --timing-template paranoid or use stealth mode",
        })
    } else {
        None
    }
}
```

---

#### 6. 📱 User Experience Improvements
**Effort**: 2-3 ore  
**Impact**: ⭐⭐⭐

**Features**:

##### A. Progress Indicators
```
🔍 Scanning 192.168.1.0/24 (256 hosts)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 45% (115/256)
Current: 192.168.1.115 | Found: 12 hosts up | ETA: 2m 30s
```

##### B. Real-time Results Stream
```bash
# Show results as they're found
nextmap 192.168.1.0/24 --stream

# Output:
[10:30:01] 192.168.1.1 - 22/tcp OPEN (ssh)
[10:30:01] 192.168.1.1 - 80/tcp OPEN (http)
[10:30:02] 192.168.1.5 - 3389/tcp OPEN (rdp)
[10:30:03] 192.168.1.10 - 445/tcp OPEN (smb)
```

##### C. Scan Presets
```bash
# Web application audit
nextmap target.com --preset webapp
# Scans: 80, 443, 8080, 8443, 3000, 4443, 5000, 8000, 8888, 9000

# Database server audit
nextmap db-server --preset database
# Scans: 1433, 3306, 5432, 6379, 9200, 27017, 5984, 9042

# Windows domain controller
nextmap dc.example.com --preset windows-dc
# Scans: 88, 135, 139, 389, 445, 636, 3268, 3269, 3389, 5985, 5986

# Cloud infrastructure
nextmap 10.0.0.0/24 --preset cloud
# Scans: Docker, Kubernetes, AWS metadata, etc.
```

---

### 🥉 **PRIORITÀ BASSA** (v0.5.0 - 2-3 mesi)

#### 7. 🔌 Plugin System
**Effort**: 10-15 ore  
**Impact**: ⭐⭐⭐⭐⭐

**Concept**:
```rust
// Plugin trait
trait ScanPlugin {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn scan(&self, target: &ScanTarget) -> Result<PluginResult>;
}

// Example plugin
struct WordPressScanner;

impl ScanPlugin for WordPressScanner {
    fn scan(&self, target: &ScanTarget) -> Result<PluginResult> {
        // Check for WordPress
        // Enumerate themes/plugins
        // Check for known vulnerabilities
    }
}
```

---

#### 8. 📊 Web Dashboard
**Effort**: 20-30 ore  
**Impact**: ⭐⭐⭐⭐⭐

**Tech Stack**:
- Backend: Rust (Axum/Actix)
- Frontend: React/Vue.js
- WebSocket for real-time updates
- SQLite for scan history

**Features**:
- Real-time scan monitoring
- Historical scan results
- Vulnerability tracking
- Target management
- Report generation

---

## 📅 Roadmap Timeline

```
v0.3.1 (2 settimane - Fine Ottobre 2025)
├── Enhanced Fingerprinting (20+ protocolli)
├── Output Grouping & Risk Assessment
├── IPv6 Support (basic)
└── Statistics Summary

v0.4.0 (4 settimane - Fine Novembre 2025)
├── Adaptive Timing
├── Port Prioritization
├── Firewall Detection
├── Enhanced Output Formats (MD, YAML, XML)
├── Progress Indicators
└── Scan Presets

v0.5.0 (2-3 mesi - Gennaio 2026)
├── Plugin System
├── Scripting Engine (Lua)
├── Advanced CVE Integration
└── Automated Reporting (PDF/HTML)

v1.0.0 (6 mesi - Aprile 2026)
├── Web Dashboard
├── GUI Desktop App
├── Enterprise Features
├── Commercial Support
└── Complete Documentation
```

---

## 🎯 Raccomandazione Immediata

### Per v0.3.1 (Prossimi 7 giorni):

**Focus su 3 features ad alto impatto**:

1. **Enhanced Fingerprinting** (6 ore)
   - Redis, Memcached, Elasticsearch
   - RabbitMQ, Kafka
   - Docker, Kubernetes
   - Impatto: ⭐⭐⭐⭐⭐

2. **Output Grouping** (4 ore)
   - Service categorization
   - Risk assessment
   - Statistics summary
   - Impatto: ⭐⭐⭐⭐

3. **IPv6 Basic Support** (3 ore)
   - Single IPv6 address scanning
   - IPv6 CIDR support
   - Dual-stack detection
   - Impatto: ⭐⭐⭐⭐

**Totale effort**: ~13 ore di sviluppo  
**Risultato**: NextMap v0.3.1 con fingerprinting significativamente migliorato

---

## 💡 Quale Feature Iniziamo?

**Opzioni suggerite**:

### Opzione A: Enhanced Fingerprinting ⭐⭐⭐⭐⭐
- **Tempo**: 6 ore
- **Difficoltà**: Media
- **Impatto**: Molto Alto
- **Valore**: Migliora detection quality del 200%

### Opzione B: Output Grouping ⭐⭐⭐⭐
- **Tempo**: 4 ore
- **Difficoltà**: Bassa
- **Impatto**: Alto
- **Valore**: Output professionale enterprise-grade

### Opzione C: IPv6 Support ⭐⭐⭐⭐
- **Tempo**: 3 ore
- **Difficoltà**: Media
- **Impatto**: Alto
- **Valore**: Modernità e compatibilità futura

---

**Quale preferisci iniziare?** 🚀

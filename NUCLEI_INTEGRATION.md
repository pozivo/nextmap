# 🎯 Nuclei Integration - NextMap v0.4.0

**Active Vulnerability Scanning with 6,000+ CVE Templates**

---

## 📊 Overview

NextMap v0.4.0 integrates **ProjectDiscovery's Nuclei scanner** for active vulnerability detection, complementing the existing passive banner grabbing and Metasploit exploitation capabilities.

### **Why Nuclei?**

| Feature | Passive Scanning (Current) | Active Scanning (Nuclei) |
|---------|---------------------------|--------------------------|
| **Detection Method** | Banner matching | Payload fuzzing + response validation |
| **CVE Coverage** | 100 (Metasploit database) | 6,000+ (Nuclei templates) |
| **False Positives** | High (version-based only) | Low (confirmed exploitation) |
| **Update Frequency** | Manual (code commits) | Automatic (`nuclei -update-templates`) |
| **Web-Specific Tests** | Limited (HTTP headers) | Extensive (XSS, SQLi, RCE, LFI, SSRF, etc.) |
| **Zero-Day Coverage** | No | Yes (community templates) |

---

## ✨ Features

### 🔍 **Active Vulnerability Scanning**
- **6,000+ Templates**: CVEs, exploits, misconfigurations, exposures
- **Smart Targeting**: Auto-selects relevant templates based on detected service
- **Severity Filtering**: critical, high, medium, low, info
- **Tag-Based Filtering**: cve, rce, sqli, xss, lfi, ssrf, etc.

### ⚡ **Performance Optimized**
- **Rate Limiting**: 150 requests/second (configurable)
- **Concurrent Execution**: 25 parallel templates
- **Smart Timeout**: 10 seconds per template
- **Efficient Scanning**: Only HTTP/HTTPS ports (80, 443, 8080, 8443)

### 🔄 **Auto-Update System**
- **Daily Template Updates**: `--nuclei-update` flag
- **Community-Driven**: 6,000+ templates from security researchers
- **Zero-Day Coverage**: New templates added within hours of disclosure

### 📊 **Enhanced Detection**
- **CVE Extraction**: Auto-extracts CVE IDs from templates
- **Version Correlation**: Matches with banner-detected versions
- **Service-Specific**: nginx, apache, wordpress, drupal, jenkins, etc.
- **Detection Method Tracking**: Marks findings as "ActiveScan"

---

## 🚀 Installation

### **1. Install Nuclei**

**Linux/Mac:**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Windows (PowerShell):**
```powershell
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Manual Download:**
- GitHub Releases: https://github.com/projectdiscovery/nuclei/releases
- Extract to PATH or use `--nuclei-path` flag

### **2. Update Templates (Recommended)**
```bash
nuclei -update-templates
```

### **3. Verify Installation**
```bash
nuclei -version
```

Expected output:
```
Nuclei Engine Version: v3.x.x
```

---

## 📖 Usage

### **Basic Scan (Critical & High Severity)**
```powershell
nextmap.exe -t 192.168.1.100 -p 80,443,8080 -s --cve-scan --nuclei-scan
```

**What happens:**
1. Port scan (80, 443, 8080)
2. Banner grabbing (nginx/1.18.0, Apache/2.4.41)
3. CVE database matching (passive)
4. **🆕 Nuclei active scanning** (fuzzing payloads)
5. Metasploit exploitation (if --msf-exploit)

### **All Severity Levels**
```powershell
nextmap.exe -t example.com --nuclei-scan --nuclei-severity critical,high,medium,low
```

### **Specific Tags (RCE + SQL Injection)**
```powershell
nextmap.exe -t webapp.com -p 80,443 --nuclei-scan --nuclei-tags cve,rce,sqli
```

### **Update Templates Before Scanning**
```powershell
nextmap.exe -t target.com --nuclei-scan --nuclei-update
```

### **Custom Nuclei Path**
```powershell
nextmap.exe -t target.com --nuclei-scan --nuclei-path "C:\tools\nuclei.exe"
```

### **Rate Limit Control**
```powershell
# Slower (respectful)
nextmap.exe -t target.com --nuclei-scan --nuclei-rate-limit 50

# Faster (aggressive)
nextmap.exe -t target.com --nuclei-scan --nuclei-rate-limit 300
```

### **Verbose Output**
```powershell
nextmap.exe -t target.com --nuclei-scan --nuclei-verbose
```

---

## 🎯 Service-Specific Scanning

Nuclei automatically selects relevant templates based on detected service:

### **Apache Web Server**
```powershell
# Detected: Apache/2.4.41
# Auto-applies tags: apache
# Templates checked: CVE-2021-41773 (Path Traversal), CVE-2023-25690, etc.
```

### **WordPress**
```powershell
# Detected: WordPress 6.2
# Auto-applies tags: wordpress, wp
# Templates checked: Plugin vulns, theme exploits, core CVEs
```

### **Jenkins**
```powershell
# Detected: Jenkins 2.400
# Auto-applies tags: jenkins
# Templates checked: CVE-2024-23897, script console, auth bypass
```

### **GitLab**
```powershell
# Detected: GitLab 16.5
# Auto-applies tags: gitlab
# Templates checked: CVE-2023-7028 (Account Takeover), RCE, SSRF
```

### **Full Service Support**
- **Web Servers**: apache, nginx, iis, tomcat, weblogic
- **CMS**: wordpress, drupal, joomla
- **CI/CD**: jenkins, gitlab
- **Frameworks**: php, laravel, django, spring
- **Other**: Custom tag filtering with `--nuclei-tags`

---

## 📊 Output Examples

### **Human-Readable Output**
```
🎯 Initializing Nuclei scanner...
✅ Nuclei Engine Version: v3.1.4

🚀 Starting NextMap scan...
🛡️ CVE scanning: ENABLED
🎯 Nuclei active scanning: ENABLED

Scanning 192.168.1.100...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PORT    STATE    SERVICE        VERSION
80      open     http           Apache/2.4.41 (Ubuntu)
  🎯 Nuclei found 3 vulnerabilities on 192.168.1.100:80
  
  CVE-2021-41773 [CRITICAL]
  - Apache HTTP Server Path Traversal RCE
  - Nuclei template: CVE-2021-41773
  - Severity: CRITICAL
  
  CVE-2023-25690 [HIGH]
  - Apache HTTP Request Smuggling
  - Nuclei template: CVE-2023-25690
  - Severity: HIGH
  
  apache-detect [INFO]
  - Apache Server Detection
  - Nuclei template: tech/apache-detect
  - Severity: INFO

443     open     https          Apache/2.4.41 (Ubuntu)
  🎯 Nuclei found 1 vulnerability on 192.168.1.100:443
  
  ssl-weak-cipher [MEDIUM]
  - Weak TLS Cipher Suite Detected
  - Nuclei template: ssl/weak-cipher.yaml
  - Severity: MEDIUM
```

### **JSON Output**
```json
{
  "timestamp": "2025-10-20T14:30:00Z",
  "hosts": [{
    "ip_address": "192.168.1.100",
    "ports": [{
      "port_id": 80,
      "state": "open",
      "service_name": "http",
      "service_version": "Apache/2.4.41 (Ubuntu)",
      "detection_method": "ActiveScan",
      "vulnerabilities": [{
        "cve_id": "CVE-2021-41773",
        "severity": "CRITICAL",
        "description_short": "Apache HTTP Server Path Traversal RCE",
        "service_port": 80
      }]
    }]
  }]
}
```

---

## 🔧 CLI Reference

### **Nuclei Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--nuclei-scan` | `false` | Enable Nuclei active scanning |
| `--nuclei-path` | Auto-detect | Path to nuclei binary |
| `--nuclei-severity` | `critical,high` | Severity filter (comma-separated) |
| `--nuclei-tags` | None | Tags filter (e.g., cve,rce,sqli) |
| `--nuclei-rate-limit` | `150` | Requests per second |
| `--nuclei-update` | `false` | Update templates before scan |
| `--nuclei-verbose` | `false` | Enable verbose output |

### **Severity Levels**
- `critical`: CVSS 9.0-10.0 (RCE, Auth Bypass, Data Leaks)
- `high`: CVSS 7.0-8.9 (Privilege Escalation, SQLi, XSS)
- `medium`: CVSS 4.0-6.9 (Info Disclosure, Config Issues)
- `low`: CVSS 0.1-3.9 (Minor Issues)
- `info`: Informational (Tech Detection, Port Scanning)

### **Common Tags**
- `cve`: CVE-identified vulnerabilities
- `rce`: Remote Code Execution
- `sqli`: SQL Injection
- `xss`: Cross-Site Scripting
- `lfi`: Local File Inclusion
- `ssrf`: Server-Side Request Forgery
- `iot`: IoT device vulnerabilities
- `panel`: Admin panel exposures
- `auth-bypass`: Authentication bypasses
- `config`: Misconfigurations

---

## 🎯 Workflow Integration

### **Complete Security Assessment**
```powershell
# Full stack: Port Scan → Banner → CVE Match → Nuclei → Metasploit
nextmap.exe -t webapp.com `
    -p 1-10000 `
    -s `
    --cve-scan `
    --nuclei-scan `
    --nuclei-severity critical,high `
    --nuclei-update `
    --msf-exploit `
    --msf-lhost 192.168.1.50 `
    --msf-dry-run `
    -o json `
    -f scan_results.json
```

**Workflow:**
1. ✅ **Port Scan** (1-10000)
2. ✅ **Banner Grab** (HTTP, SSH, FTP, etc.)
3. ✅ **Version Detection** (Apache/2.4.41, nginx/1.18.0)
4. ✅ **CVE Database Match** (100 MSF exploits)
5. ✅ **Nuclei Active Scan** (6,000+ templates)
6. ✅ **Metasploit Auto-Exploit** (dry-run mode)
7. ✅ **JSON Report** (scan_results.json)

---

## 📈 Performance Tuning

### **Fast Scan (Aggressive)**
```powershell
nextmap.exe -t target.com `
    --nuclei-scan `
    --nuclei-severity critical `
    --nuclei-rate-limit 300 `
    --nuclei-tags cve,rce
```
- **Speed**: ~30 seconds for 500 templates
- **Noise**: High (may trigger WAF/IDS)

### **Balanced Scan (Recommended)**
```powershell
nextmap.exe -t target.com `
    --nuclei-scan `
    --nuclei-severity critical,high `
    --nuclei-rate-limit 150
```
- **Speed**: ~60 seconds for 1,000 templates
- **Noise**: Medium (normal web traffic)

### **Stealth Scan (Careful)**
```powershell
nextmap.exe -t target.com `
    --nuclei-scan `
    --nuclei-severity critical `
    --nuclei-rate-limit 50 `
    --stealth-mode sneaky
```
- **Speed**: ~3 minutes for 500 templates
- **Noise**: Low (blends with normal traffic)

---

## ⚠️ Security Warnings

### **CRITICAL DISCLAIMERS**

1. **Legal Authorization Required**
   - Nuclei performs **ACTIVE exploitation** attempts
   - Only use on systems you own or have explicit permission to test
   - Unauthorized scanning is illegal in most jurisdictions

2. **Production System Risks**
   - Active scans may crash applications
   - Payloads can trigger security alerts (WAF, IDS, SIEM)
   - Some templates perform write operations (file creation, DB inserts)

3. **Network Impact**
   - High rate limits (300+ req/s) can cause DoS
   - Some templates send large payloads
   - May consume significant bandwidth

4. **False Positive Validation**
   - Not all matches are exploitable
   - Verify findings manually before reporting
   - Cross-reference with CVE database versions

### **Best Practices**

✅ **Always test in LAB environment first**  
✅ **Use `--nuclei-dry-run` equivalent (review templates)**  
✅ **Start with `--nuclei-severity critical` only**  
✅ **Monitor target system during scan**  
✅ **Coordinate with system owners**  
✅ **Document all scanning activities**  

❌ **Never scan production without approval**  
❌ **Never use aggressive settings on live systems**  
❌ **Never scan third-party systems**  
❌ **Never ignore rate limiting on critical infrastructure**  

---

## 🧪 Testing

### **Test Against DVWA (Damn Vulnerable Web Application)**
```powershell
# Setup DVWA: docker run -p 80:80 vulnerables/web-dvwa

nextmap.exe -t localhost -p 80 `
    --nuclei-scan `
    --nuclei-severity critical,high,medium `
    --nuclei-tags sqli,xss,lfi
```

**Expected Results:**
- SQL Injection vulnerabilities detected
- XSS vulnerabilities detected
- LFI (Local File Inclusion) detected

### **Test Against WebGoat**
```powershell
# Setup WebGoat: docker run -p 8080:8080 webgoat/webgoat

nextmap.exe -t localhost -p 8080 `
    --nuclei-scan `
    --nuclei-severity high
```

---

## 🔄 Update & Maintenance

### **Weekly Template Updates**
```powershell
# Automated script
$scan = {
    nuclei -update-templates
    nextmap.exe -t targets.txt --nuclei-scan --nuclei-severity critical,high
}

# Schedule weekly (Windows Task Scheduler)
```

### **Monitor Template Count**
```bash
nuclei -tl | wc -l  # Should show 6,000+
```

---

## 📚 Resources

- **Nuclei GitHub**: https://github.com/projectdiscovery/nuclei
- **Template Repository**: https://github.com/projectdiscovery/nuclei-templates
- **Documentation**: https://docs.nuclei.sh/
- **Community Discord**: https://discord.gg/projectdiscovery

---

## 🛣️ Future Enhancements

### **v0.4.1 (Planned)**
- [ ] Custom template directory support
- [ ] Nuclei template filtering by author
- [ ] Parallel multi-target scanning
- [ ] Template success rate tracking

### **v0.5.0 (Vision)**
- [ ] Custom template creation wizard
- [ ] Integration with Burp Suite
- [ ] Vulnerability remediation suggestions
- [ ] Automated patch verification

---

**NextMap v0.4.0** - Complete Offensive Security Toolkit  
*Banner Grabbing → CVE Detection → Active Scanning → Auto-Exploitation*

---

**Document Version**: 1.0  
**Last Updated**: 2025-10-20  
**Nuclei Integration Status**: ✅ COMPLETE  

*Developed with ❤️ for penetration testers and security researchers*

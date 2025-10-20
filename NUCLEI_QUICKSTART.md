# 🚀 Nuclei Integration - Quick Start Guide

> **Status:** ✅ Phase 5 Complete - Ready to Test!  
> **Version:** NextMap v0.4.0 (pre-release)  
> **Date:** October 20, 2025

---

## ⚡ 5-Minute Quick Start

### 1. **Test the Integration (Without Nuclei)**
```powershell
# Build NextMap
cargo build --release

# Quick validation (checks CLI flags)
.\test_nuclei_quick.ps1 -SkipBuild
```

**Expected:** CLI flags validated ✅

---

### 2. **Install Nuclei (Optional but Recommended)**
```powershell
# Install via Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Verify installation
nuclei -version
```

**Expected:** `Nuclei v3.x.x` displayed

---

### 3. **Run Quick Tests**
```powershell
# With Nuclei installed
.\test_nuclei_quick.ps1

# Expected: 5/5 tests passed ✅
```

---

### 4. **Try Your First Scan**
```powershell
# Safe public target (scanme.nmap.org)
.\target\release\nextmap.exe -t scanme.nmap.org -p 80 --nuclei-scan --nuclei-severity critical
```

**Expected:** Active vulnerability scanning with Nuclei templates

---

### 5. **Run Full Test Suite (Optional)**
```powershell
# Comprehensive testing (15-20 min)
.\test_nuclei.ps1

# Expected: 60+ tests, >90% pass rate
```

---

## 📚 Test Scripts Overview

### **test_nuclei_quick.ps1** ⚡ (Fast - 2 min)
**Purpose:** Rapid validation during development

**Usage:**
```powershell
# Standard test
.\test_nuclei_quick.ps1

# Skip build (faster)
.\test_nuclei_quick.ps1 -SkipBuild

# Custom target
.\test_nuclei_quick.ps1 -Target example.com
```

**Tests:**
- ✅ Build verification
- ✅ Nuclei detection
- ✅ CLI flags validation
- ✅ Quick functional test
- ✅ Output format check

---

### **test_nuclei.ps1** 🧪 (Comprehensive - 15-20 min)
**Purpose:** Full validation before releases

**Usage:**
```powershell
# Run all tests
.\test_nuclei.ps1

# View results
cd test_results_nuclei
ls
```

**Tests (12 Suites):**
1. Binary Detection
2. Help Text Validation
3. Template Update Mechanism
4. Severity Filtering (5 levels)
5. Tag-Based Filtering (5 tags)
6. Rate Limiting (3 modes)
7. Service-Specific Scanning
8. Output Format Validation
9. Error Handling
10. Performance Monitoring
11. Integration with Existing Features
12. Real-World Scenario

---

### **test_dvwa.ps1** 🎯 (Real Vulnerabilities - 5-10 min)
**Purpose:** Validate against intentionally vulnerable apps

**Usage:**
```powershell
# Test DVWA (requires Docker)
.\test_dvwa.ps1 -Target DVWA

# Test WebGoat
.\test_dvwa.ps1 -Target WebGoat

# Test both
.\test_dvwa.ps1 -Target Both

# Cleanup
.\test_dvwa.ps1 -StopContainers
```

**Tests:**
- ✅ Critical & High severity scan
- ✅ All severity levels
- ✅ RCE & SQLi focused
- ✅ Performance benchmarking

---

## 🎯 Usage Examples

### Basic Scan
```powershell
nextmap.exe -t 192.168.1.100 -p 80,443 --nuclei-scan
```
**What it does:** Scans HTTP/HTTPS with critical & high severity templates

---

### All Severity Levels
```powershell
nextmap.exe -t example.com --nuclei-scan --nuclei-severity critical,high,medium,low,info
```
**What it does:** Comprehensive scan with all severity levels

---

### Focus on RCE & SQLi
```powershell
nextmap.exe -t webapp.com --nuclei-scan --nuclei-tags rce,sqli
```
**What it does:** Only test for RCE and SQL Injection vulnerabilities

---

### Update Templates First
```powershell
nextmap.exe -t target.com --nuclei-scan --nuclei-update
```
**What it does:** Updates Nuclei templates before scanning (recommended weekly)

---

### Stealth Mode (Slow & Quiet)
```powershell
nextmap.exe -t target.com --nuclei-scan --nuclei-rate-limit 50
```
**What it does:** Limits to 50 requests/second to avoid IDS detection

---

### Fast Mode (Aggressive)
```powershell
nextmap.exe -t target.com --nuclei-scan --nuclei-rate-limit 300
```
**What it does:** 300 requests/second for quick results

---

### Full Workflow (Complete Assessment)
```powershell
nextmap.exe -t example.com -p 1-1000 `
  --nuclei-scan `
  --nuclei-severity critical,high `
  --nuclei-tags cve,rce,sqli `
  --banner `
  --cve-db `
  --msf-search `
  -f html `
  -o complete_scan.html
```
**What it does:**
1. Port scan (1-1000)
2. Banner grabbing
3. CVE database lookup
4. Nuclei active scanning (critical/high, cve/rce/sqli)
5. MSF exploit search
6. HTML report output

---

## 🔍 Checking Results

### Command Line Output
```
[*] Nuclei detected: v3.3.2
[*] Updating Nuclei templates...
[+] Templates updated: 6,847 templates

Scanning 192.168.1.100:80...
[+] Port 80: HTTP/1.1 (Apache/2.4.41)
[*] Running Nuclei active scan...
[!] CRITICAL: CVE-2021-41773 - Apache HTTP Server Path Traversal
[!] HIGH: CVE-2021-42013 - Apache HTTP Server RCE

Scan completed in 23.4s
Vulnerabilities found: 2 (Nuclei Active Scan)
```

---

### JSON Output
```json
{
  "scan_results": [
    {
      "port": 80,
      "service": "HTTP",
      "detection_method": "ActiveScan",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2021-41773",
          "severity": "CRITICAL",
          "description_short": "Apache HTTP Server Path Traversal",
          "service_port": 80
        }
      ]
    }
  ]
}
```

---

### CSV Output
```csv
Target,Port,Service,CVE,Severity,Description,Detection Method
192.168.1.100,80,HTTP,CVE-2021-41773,CRITICAL,Apache HTTP Server Path Traversal,ActiveScan
```

---

## 🐛 Troubleshooting

### ❌ "Nuclei not found in PATH"
**Solution:**
```powershell
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

### ❌ "Failed to update templates"
**Solution:**
```powershell
# Update manually
nuclei -update-templates

# Then run scan
nextmap.exe -t target.com --nuclei-scan
```

---

### ❌ "No vulnerabilities found"
**Possible reasons:**
1. Target is well-secured (good!)
2. Wrong severity filter (try `--nuclei-severity critical,high,medium`)
3. Wrong tags (try `--nuclei-tags cve,rce,sqli,xss`)
4. Nuclei templates outdated (run with `--nuclei-update`)

---

### ❌ "Docker container failed to start"
**Solution:**
```powershell
# Check Docker status
docker ps

# Pull image manually
docker pull vulnerables/web-dvwa

# Restart Docker Desktop if needed
```

---

### ❌ "Tests taking too long"
**Solution:**
```powershell
# Use quick test instead
.\test_nuclei_quick.ps1

# Or run specific test sections in test_nuclei.ps1
# (edit script to comment out slow tests)
```

---

## 📖 Documentation

### Full Documentation
- **NUCLEI_INTEGRATION.md** (450+ lines)
  - Complete integration guide
  - Installation instructions
  - 10+ usage examples
  - Performance tuning
  - Security best practices

### Implementation Details
- **NUCLEI_IMPLEMENTATION_REPORT.md** (550+ lines)
  - Technical implementation details
  - Code structure
  - Architecture decisions
  - Testing coverage

### Testing Guide
- **TEST_SUITE_SUMMARY.md** (400+ lines)
  - Test suite overview
  - Test execution workflows
  - Expected results
  - Troubleshooting

---

## ⚠️ Important Notes

### Legal & Ethical
> ⚠️ **WARNING:** Only scan systems you own or have written permission to test.  
> Unauthorized scanning is illegal in most jurisdictions.

### Production Environments
> ⚠️ **CAUTION:** Active scanning can trigger IDS/IPS alerts and may cause service disruption.  
> Always test in development environments first.

### False Positives
> ℹ️ **NOTE:** Nuclei findings should be manually validated before reporting.  
> Not all matches are exploitable vulnerabilities.

---

## 🚀 Next Steps

1. ✅ **Run Quick Test**
   ```powershell
   .\test_nuclei_quick.ps1
   ```

2. ✅ **Try First Scan**
   ```powershell
   nextmap.exe -t scanme.nmap.org -p 80 --nuclei-scan
   ```

3. ✅ **Read Full Docs**
   ```powershell
   cat NUCLEI_INTEGRATION.md
   ```

4. ✅ **Test Against DVWA** (optional)
   ```powershell
   .\test_dvwa.ps1 -Target DVWA
   ```

5. ✅ **Report Issues**
   - GitHub: https://github.com/pozivo/nextmap/issues

---

## 🎉 You're Ready!

The Nuclei integration is fully functional and ready to use.

**Happy Scanning! 🔍**

---

**Quick Start Author:** GitHub Copilot + pozivo  
**Last Updated:** October 20, 2025  
**Version:** NextMap v0.4.0 (pre-release)

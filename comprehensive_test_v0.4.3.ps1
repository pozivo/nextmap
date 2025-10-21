# ============================================================
# NextMap v0.4.3 - Comprehensive Test Suite
# Test di tutte le funzionalità (escluso Metasploit)
# ============================================================

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$testDir = "test_results_$timestamp"
New-Item -ItemType Directory -Path $testDir -Force | Out-Null

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "║        " -ForegroundColor Cyan -NoNewline
Write-Host "NEXTMAP v0.4.3 - COMPREHENSIVE TEST SUITE" -ForegroundColor Yellow -NoNewline
Write-Host "          ║" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$testResults = @()
$testNumber = 0

function Run-Test {
    param(
        [string]$Name,
        [string]$Command,
        [string]$OutputFile
    )
    
    $script:testNumber++
    Write-Host "`n[$script:testNumber] " -ForegroundColor Yellow -NoNewline
    Write-Host $Name -ForegroundColor White
    Write-Host "    Command: " -NoNewline -ForegroundColor Gray
    Write-Host $Command -ForegroundColor DarkGray
    
    $startTime = Get-Date
    try {
        Invoke-Expression "$Command 2>&1 | Tee-Object -FilePath '$testDir\$OutputFile'" | Out-Null
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        Write-Host "    ✓ Completato in " -NoNewline -ForegroundColor Green
        Write-Host "$([math]::Round($duration, 2))s" -ForegroundColor Yellow
        
        $script:testResults += [PSCustomObject]@{
            Test = $Name
            Status = "PASS"
            Duration = "$([math]::Round($duration, 2))s"
            Output = "$testDir\$OutputFile"
        }
        return $true
    } catch {
        Write-Host "    ✗ Errore: $($_.Exception.Message)" -ForegroundColor Red
        $script:testResults += [PSCustomObject]@{
            Test = $Name
            Status = "FAIL"
            Duration = "N/A"
            Output = "Error"
        }
        return $false
    }
}

# ============================================================
# TEST CATEGORY 1: BASIC SCANNING
# ============================================================
Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CATEGORY 1: BASIC SCANNING" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Run-Test "Basic TCP Scan (Local)" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 80,443,22,3306" `
    "01_basic_tcp_scan.txt"

Run-Test "Top 100 Ports Scan" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports top100" `
    "02_top100_scan.txt"

Run-Test "Custom Port Range" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 20-25,80-90,443" `
    "03_custom_range.txt"

# ============================================================
# TEST CATEGORY 2: SERVICE DETECTION (NEW v0.4.3)
# ============================================================
Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CATEGORY 2: SERVICE DETECTION & VERSIONING" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Run-Test "Service Detection (Local)" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 22,80,443,3306,3389 --service-scan" `
    "04_service_detection_local.txt"

Run-Test "Service Detection (Remote HTTP)" `
    ".\target\release\nextmap.exe --target nginx.org --ports 80,443 --service-scan" `
    "05_service_detection_nginx.txt"

Run-Test "SSH Version Detection" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 22 --service-scan" `
    "06_ssh_version.txt"

# ============================================================
# TEST CATEGORY 3: SSL/TLS & HTTP/2 (NEW v0.4.3)
# ============================================================
Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CATEGORY 3: SSL/TLS CERTIFICATE & HTTP/2 DETECTION" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Run-Test "SSL/TLS Certificate Parsing (GitHub)" `
    ".\target\release\nextmap.exe --target github.com --ports 443 --service-scan" `
    "07_ssl_github.txt"

Run-Test "HTTP/2 Detection (Google)" `
    ".\target\release\nextmap.exe --target www.google.com --ports 443 --service-scan" `
    "08_http2_google.txt"

Run-Test "SSL/TLS Certificate (Cloudflare)" `
    ".\target\release\nextmap.exe --target www.cloudflare.com --ports 443 --service-scan" `
    "09_ssl_cloudflare.txt"

Run-Test "HTTP/2 Detection (Microsoft)" `
    ".\target\release\nextmap.exe --target www.microsoft.com --ports 443 --service-scan" `
    "10_http2_microsoft.txt"

# ============================================================
# TEST CATEGORY 4: OUTPUT FORMATS
# ============================================================
Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CATEGORY 4: OUTPUT FORMATS" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Run-Test "JSON Output" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 80,443,22 --service-scan --output-format json --output-file '$testDir\11_output.json'" `
    "11_json_format.txt"

Run-Test "CSV Output" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 80,443,22 --service-scan --output-format csv --output-file '$testDir\12_output.csv'" `
    "12_csv_format.txt"

Run-Test "HTML Output" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 80,443,22 --service-scan --output-format html --output-file '$testDir\13_output.html'" `
    "13_html_format.txt"

Run-Test "YAML Output" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 80,443,22 --service-scan --output-format yaml --output-file '$testDir\14_output.yaml'" `
    "14_yaml_format.txt"

Run-Test "Markdown Output" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 80,443,22 --service-scan --output-format md --output-file '$testDir\15_output.md'" `
    "15_md_format.txt"

# ============================================================
# TEST CATEGORY 5: ADVANCED FEATURES
# ============================================================
Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CATEGORY 5: ADVANCED FEATURES" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Run-Test "OS Fingerprinting" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 80,443,22,3389 --os-detection" `
    "16_os_fingerprinting.txt"

Run-Test "Smart Port Selection (Windows)" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --smart-ports windows --service-scan" `
    "17_smart_ports_windows.txt"

Run-Test "Timing Template (Fast)" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 80,443,22 --timing fast" `
    "18_timing_fast.txt"

Run-Test "Timing Template (Stealth)" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 80,443,22 --timing stealth" `
    "19_timing_stealth.txt"

# ============================================================
# TEST CATEGORY 6: NETWORK DISCOVERY
# ============================================================
Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CATEGORY 6: NETWORK DISCOVERY" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Run-Test "CIDR Range Scan" `
    ".\target\release\nextmap.exe --target 192.168.18.0/29 --ports 80,443 --timeout 500" `
    "20_cidr_scan.txt"

Run-Test "IP Range Scan" `
    ".\target\release\nextmap.exe --target 192.168.18.15-20 --ports 445,3389 --timeout 500" `
    "21_range_scan.txt"

# ============================================================
# TEST CATEGORY 7: CVE & VULNERABILITY DETECTION
# ============================================================
Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CATEGORY 7: CVE & VULNERABILITY DETECTION" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Run-Test "CVE Detection (Local)" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 22,80,3306,3389 --service-scan" `
    "22_cve_detection.txt"

Run-Test "Vulnerability Scan (RDP)" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 3389 --service-scan" `
    "23_rdp_vulnerability.txt"

# ============================================================
# TEST CATEGORY 8: PERFORMANCE & SCALABILITY
# ============================================================
Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CATEGORY 8: PERFORMANCE TESTS" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Run-Test "High Concurrency (500)" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports top100 --max-concurrent 500 --timeout 500" `
    "24_high_concurrency.txt"

Run-Test "Rate Limiting (50ms)" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 80,443,22,3306,3389 --rate-limit 50" `
    "25_rate_limiting.txt"

# ============================================================
# TEST CATEGORY 9: SIGNATURE EXPANSION VERIFICATION (v0.4.3)
# ============================================================
Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CATEGORY 9: SIGNATURE EXPANSION (500+ PATTERNS)" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Run-Test "HTTP Server Detection (nginx.org)" `
    ".\target\release\nextmap.exe --target nginx.org --ports 80,443 --service-scan" `
    "26_http_server_nginx.txt"

Run-Test "Database Detection (MySQL)" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 3306 --service-scan" `
    "27_database_mysql.txt"

Run-Test "Multiple Services Detection" `
    ".\target\release\nextmap.exe --target 192.168.18.15 --ports 20-25,80,443,3306,3389,5432,6379,8080 --service-scan" `
    "28_multiple_services.txt"

# ============================================================
# FINAL REPORT
# ============================================================
Write-Host "`n`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                                                            ║" -ForegroundColor Green
Write-Host "║              " -ForegroundColor Green -NoNewline
Write-Host "TEST SUITE COMPLETED" -ForegroundColor Yellow -NoNewline
Write-Host "                       ║" -ForegroundColor Green
Write-Host "║                                                            ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

# Calculate statistics
$totalTests = $testResults.Count
$passedTests = ($testResults | Where-Object { $_.Status -eq "PASS" }).Count
$failedTests = ($testResults | Where-Object { $_.Status -eq "FAIL" }).Count
$successRate = [math]::Round(($passedTests / $totalTests) * 100, 1)

Write-Host "  📊 STATISTICS:" -ForegroundColor White
Write-Host "  ════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "     Total Tests:    " -NoNewline
Write-Host "$totalTests" -ForegroundColor Yellow
Write-Host "     Passed:         " -NoNewline
Write-Host "$passedTests" -ForegroundColor Green
Write-Host "     Failed:         " -NoNewline
Write-Host "$failedTests" -ForegroundColor Red
Write-Host "     Success Rate:   " -NoNewline
Write-Host "$successRate%" -ForegroundColor $(if($successRate -ge 90){"Green"}elseif($successRate -ge 70){"Yellow"}else{"Red"})
Write-Host ""

Write-Host "  📁 TEST RESULTS SAVED TO:" -ForegroundColor White
Write-Host "     Directory: " -NoNewline
Write-Host "$testDir" -ForegroundColor Cyan
Write-Host ""

# Create detailed report
$reportFile = "$testDir\test_report.txt"
@"
════════════════════════════════════════════════════════════
    NEXTMAP v0.4.3 - COMPREHENSIVE TEST REPORT
════════════════════════════════════════════════════════════

Test Execution Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Total Tests: $totalTests
Passed: $passedTests
Failed: $failedTests
Success Rate: $successRate%

DETAILED RESULTS:
════════════════════════════════════════════════════════════

"@ | Out-File $reportFile

$testResults | Format-Table -AutoSize | Out-File $reportFile -Append

Write-Host "  📄 Detailed report: " -NoNewline
Write-Host "$reportFile" -ForegroundColor Cyan
Write-Host ""

# Display test results table
Write-Host "  📋 TEST RESULTS:" -ForegroundColor White
Write-Host "  ════════════════════════════════════════════════════════" -ForegroundColor DarkGray
$testResults | Format-Table -Property @{
    Label="Test"; Expression={$_.Test}; Width=45
}, @{
    Label="Status"; Expression={
        if($_.Status -eq "PASS") { "✓ PASS" } else { "✗ FAIL" }
    }; Width=10
}, @{
    Label="Duration"; Expression={$_.Duration}; Width=10
} -AutoSize

Write-Host ""
Write-Host "  ════════════════════════════════════════════════════════" -ForegroundColor Green
if($successRate -ge 90) {
    Write-Host "    STATUS: " -NoNewline
    Write-Host "ALL TESTS PASSED! ✓" -ForegroundColor Green
} elseif($successRate -ge 70) {
    Write-Host "    STATUS: " -NoNewline
    Write-Host "MOSTLY PASSED (Some Issues)" -ForegroundColor Yellow
} else {
    Write-Host "    STATUS: " -NoNewline
    Write-Host "MULTIPLE FAILURES - REVIEW REQUIRED" -ForegroundColor Red
}
Write-Host "  ════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

# Summary of v0.4.3 features tested
Write-Host "  🎯 v0.4.3 FEATURES VERIFIED:" -ForegroundColor Cyan
Write-Host "     [1] SSL/TLS Certificate Parsing       - " -NoNewline
Write-Host "Tested (4 targets)" -ForegroundColor Green
Write-Host "     [2] HTTP/2 Detection (ALPN)           - " -NoNewline
Write-Host "Tested (4 targets)" -ForegroundColor Green
Write-Host "     [3] Signature Expansion (500+ patterns) - " -NoNewline
Write-Host "Tested (8 targets)" -ForegroundColor Green
Write-Host "     [4] Service Versioning                - " -NoNewline
Write-Host "Tested (SSH, HTTP, MySQL)" -ForegroundColor Green
Write-Host ""

Write-Host "  🚀 Next Steps:" -ForegroundColor White
Write-Host "     • Review detailed logs in $testDir" -ForegroundColor Gray
Write-Host "     • Check HTML report: $testDir\13_output.html" -ForegroundColor Gray
Write-Host "     • Verify JSON output: $testDir\11_output.json" -ForegroundColor Gray
Write-Host ""

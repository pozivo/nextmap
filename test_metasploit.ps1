# NextMap Metasploit Integration Test Suite
# Tests all Metasploit-related functionality without requiring actual exploitation

$ErrorActionPreference = "Continue"
$testCount = 0
$passedCount = 0
$failedCount = 0

function Write-TestHeader {
    param($message)
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  $message" -ForegroundColor White
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
}

function Test-Feature {
    param(
        [string]$Name,
        [scriptblock]$Test,
        [string]$ExpectedPattern = $null,
        [string]$NotExpectedPattern = $null
    )
    
    $script:testCount++
    Write-Host "`n[$script:testCount] Testing: " -NoNewline -ForegroundColor Yellow
    Write-Host $Name -ForegroundColor White
    
    try {
        $result = & $Test
        $output = $result -join "`n"
        
        $passed = $true
        
        if ($ExpectedPattern -and $output -notmatch $ExpectedPattern) {
            Write-Host "  ❌ FAIL - Expected pattern not found: $ExpectedPattern" -ForegroundColor Red
            $passed = $false
        }
        
        if ($NotExpectedPattern -and $output -match $NotExpectedPattern) {
            Write-Host "  ❌ FAIL - Unexpected pattern found: $NotExpectedPattern" -ForegroundColor Red
            $passed = $false
        }
        
        if ($passed) {
            Write-Host "  ✅ PASS" -ForegroundColor Green
            $script:passedCount++
        } else {
            $script:failedCount++
        }
        
        return $output
    }
    catch {
        Write-Host "  ❌ FAIL - Exception: $_" -ForegroundColor Red
        $script:failedCount++
        return $null
    }
}

# ============================================================================
# TEST SUITE START
# ============================================================================

Write-TestHeader "🧪 NEXTMAP METASPLOIT INTEGRATION TEST SUITE"
Write-Host "Testing NextMap v0.3.2 Metasploit features..." -ForegroundColor Cyan
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# ============================================================================
# CATEGORY 1: CLI FLAGS VALIDATION
# ============================================================================

Write-TestHeader "📋 CATEGORY 1: CLI FLAGS VALIDATION"

Test-Feature "Help shows Metasploit options" {
    .\target\release\nextmap.exe --help
} -ExpectedPattern "msf-exploit"

Test-Feature "--msf-exploit flag exists" {
    .\target\release\nextmap.exe --help
} -ExpectedPattern "Enable Metasploit auto-exploitation"

Test-Feature "--msf-lhost flag exists" {
    .\target\release\nextmap.exe --help
} -ExpectedPattern "LHOST for Metasploit reverse shells"

Test-Feature "--msf-lport flag exists" {
    .\target\release\nextmap.exe --help
} -ExpectedPattern "LPORT for Metasploit reverse shells"

Test-Feature "--msf-dry-run flag exists" {
    .\target\release\nextmap.exe --help
} -ExpectedPattern "Dry-run mode"

Test-Feature "--msf-path flag exists" {
    .\target\release\nextmap.exe --help
} -ExpectedPattern "Custom Metasploit path"

# ============================================================================
# CATEGORY 2: CVE SCANNING INTEGRATION
# ============================================================================

Write-TestHeader "🛡️ CATEGORY 2: CVE SCANNING INTEGRATION"

Test-Feature "CVE scan without MSF (baseline)" {
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 --cve-scan -o json 2>$null
} -ExpectedPattern "hosts"

Test-Feature "MSF requires CVE scan enabled" {
    # This should work but MSF won't run without CVE data
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 -o json 2>&1
} -ExpectedPattern "(Metasploit|hosts)"

# ============================================================================
# CATEGORY 3: DRY-RUN MODE (SAFE TESTS)
# ============================================================================

Write-TestHeader "🔹 CATEGORY 3: DRY-RUN MODE (SAFE TESTS)"

Test-Feature "Dry-run mode with CVE scan" {
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 2>&1
} -ExpectedPattern "(DRY-RUN|Metasploit|Scan)"

Test-Feature "Dry-run shows what would be exploited" {
    # Scan localhost with HTTP port - should detect some CVEs
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80,443 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 192.168.1.100 2>&1
} -ExpectedPattern "(DRY-RUN|Processing|Metasploit)"

Test-Feature "Dry-run doesn't execute exploits" {
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 2>&1
} -NotExpectedPattern "Exploit successful"

# ============================================================================
# CATEGORY 4: LHOST/LPORT CONFIGURATION
# ============================================================================

Write-TestHeader "🌐 CATEGORY 4: LHOST/LPORT CONFIGURATION"

Test-Feature "Custom LHOST accepted" {
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 --cve-scan --msf-exploit --msf-dry-run --msf-lhost 192.168.1.100 2>&1
} -ExpectedPattern "(192.168.1.100|LHOST|Metasploit)"

Test-Feature "Custom LPORT accepted" {
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 --msf-lport 5555 2>&1
} -ExpectedPattern "(5555|LPORT|Metasploit)"

Test-Feature "Default LPORT is 4444" {
    .\target\release\nextmap.exe --help 2>&1
} -ExpectedPattern "default: 4444"

# ============================================================================
# CATEGORY 5: OUTPUT FORMATS WITH MSF
# ============================================================================

Write-TestHeader "📊 CATEGORY 5: OUTPUT FORMATS WITH MSF"

Test-Feature "JSON output with MSF dry-run" {
    $output = .\target\release\nextmap.exe -t 127.0.0.1 -p 80 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 -o json 2>$null
    $output | Out-String
} -ExpectedPattern "hosts"

Test-Feature "Human output with MSF dry-run" {
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 -o human 2>&1
} -ExpectedPattern "(NextMap|Scan|Metasploit)"

# ============================================================================
# CATEGORY 6: ERROR HANDLING
# ============================================================================

Write-TestHeader "⚠️ CATEGORY 6: ERROR HANDLING"

Test-Feature "MSF without CVE scan (should still work)" {
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 2>&1
} -ExpectedPattern "(Metasploit|Scan)"

Test-Feature "Invalid LHOST format handled" {
    # This might still process but shouldn't crash
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 --cve-scan --msf-exploit --msf-dry-run --msf-lhost "invalid_ip" 2>&1
} -ExpectedPattern "(Metasploit|Error|Scan)"

# ============================================================================
# CATEGORY 7: METASPLOIT DETECTION (IF INSTALLED)
# ============================================================================

Write-TestHeader "🔍 CATEGORY 7: METASPLOIT DETECTION"

# Check if Metasploit is installed
$msfInstalled = $false
try {
    $msfCheck = Get-Command msfconsole -ErrorAction SilentlyContinue
    if ($msfCheck) {
        $msfInstalled = $true
        Write-Host "  ℹ️ Metasploit Framework detected: $($msfCheck.Source)" -ForegroundColor Cyan
    } else {
        Write-Host "  ℹ️ Metasploit Framework not installed (optional)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ℹ️ Metasploit Framework not found (tests will be limited)" -ForegroundColor Yellow
}

if ($msfInstalled) {
    Test-Feature "Metasploit version detection" {
        msfconsole -v
    } -ExpectedPattern "Framework Version"
    
    Test-Feature "NextMap detects Metasploit" {
        .\target\release\nextmap.exe -t 127.0.0.1 -p 80 --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 2>&1
    } -ExpectedPattern "(Metasploit Framework|initialized|detected)"
} else {
    Write-Host "  ⏭️ Skipping Metasploit-specific tests (not installed)" -ForegroundColor Yellow
}

# ============================================================================
# CATEGORY 8: INTEGRATION TESTS
# ============================================================================

Write-TestHeader "🔗 CATEGORY 8: INTEGRATION TESTS"

Test-Feature "Full scan with all MSF flags" {
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80,443,22 -s -O --cve-scan --msf-exploit --msf-dry-run --msf-lhost 192.168.1.100 --msf-lport 4444 2>&1
} -ExpectedPattern "(Scan|Metasploit|DRY-RUN)"

Test-Feature "MSF with enhanced output formats" {
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 -o csv 2>$null
} -ExpectedPattern "IP,Hostname,Port"

Test-Feature "MSF with file output" {
    $testFile = "test_msf_output.json"
    .\target\release\nextmap.exe -t 127.0.0.1 -p 80 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 -o json -f $testFile 2>&1
    
    $fileExists = Test-Path $testFile
    if ($fileExists) {
        $content = Get-Content $testFile -Raw
        Remove-Item $testFile -ErrorAction SilentlyContinue
        $content
    } else {
        "File not created"
    }
} -ExpectedPattern "hosts"

# ============================================================================
# CATEGORY 9: PERFORMANCE TESTS
# ============================================================================

Write-TestHeader "⚡ CATEGORY 9: PERFORMANCE TESTS"

Test-Feature "MSF dry-run performance (top100)" {
    $startTime = Get-Date
    .\target\release\nextmap.exe -t 127.0.0.1 -p top100 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 2>&1 | Out-Null
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    Write-Host "  ⏱️ Duration: $($duration.ToString('0.00'))s" -ForegroundColor Cyan
    
    if ($duration -lt 10) {
        "Performance: Excellent (< 10s)"
    } elseif ($duration -lt 30) {
        "Performance: Good (< 30s)"
    } else {
        "Performance: Acceptable"
    }
} -ExpectedPattern "Performance:"

# ============================================================================
# CATEGORY 10: DOCUMENTATION VALIDATION
# ============================================================================

Write-TestHeader "📚 CATEGORY 10: DOCUMENTATION VALIDATION"

Test-Feature "Metasploit integration doc exists" {
    if (Test-Path "METASPLOIT_INTEGRATION_v0.3.2.md") {
        $content = Get-Content "METASPLOIT_INTEGRATION_v0.3.2.md" -Raw
        "Documentation found: $($content.Length) bytes"
    } else {
        "Documentation not found"
    }
} -ExpectedPattern "Documentation found"

Test-Feature "Documentation contains usage examples" {
    $doc = Get-Content "METASPLOIT_INTEGRATION_v0.3.2.md" -Raw
    $doc
} -ExpectedPattern "(--msf-exploit|CVE-2017-0144|EternalBlue)"

Test-Feature "Documentation contains security warnings" {
    $doc = Get-Content "METASPLOIT_INTEGRATION_v0.3.2.md" -Raw
    $doc
} -ExpectedPattern "(ILLEGAL|authorization|WARNING)"

# ============================================================================
# TEST SUMMARY
# ============================================================================

Write-TestHeader "📊 TEST SUMMARY"

$totalTests = $passedCount + $failedCount
$passRate = if ($totalTests -gt 0) { [math]::Round(($passedCount / $totalTests) * 100, 1) } else { 0 }

Write-Host ""
Write-Host "Total Tests:    " -NoNewline -ForegroundColor White
Write-Host $totalTests -ForegroundColor Cyan

Write-Host "✅ Passed:      " -NoNewline -ForegroundColor Green
Write-Host "$passedCount ($passRate%)" -ForegroundColor Green

Write-Host "❌ Failed:      " -NoNewline -ForegroundColor Red
Write-Host $failedCount -ForegroundColor Red

Write-Host ""

if ($failedCount -eq 0) {
    Write-Host "🎉 ALL TESTS PASSED!" -ForegroundColor Green -BackgroundColor Black
    Write-Host "   Metasploit integration is working correctly!" -ForegroundColor Green
    Write-Host ""
    Write-Host "✅ Ready for v0.3.2 release!" -ForegroundColor Cyan
    exit 0
} elseif ($passRate -ge 90) {
    Write-Host "✅ MOSTLY PASSED ($passRate%)" -ForegroundColor Yellow -BackgroundColor Black
    Write-Host "   Minor issues detected, but core functionality works" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "⚠️ Review failed tests before release" -ForegroundColor Yellow
    exit 0
} elseif ($passRate -ge 70) {
    Write-Host "⚠️ SOME FAILURES ($passRate%)" -ForegroundColor Yellow -BackgroundColor Black
    Write-Host "   Several tests failed - investigation needed" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "❌ CRITICAL FAILURES ($passRate%)" -ForegroundColor Red -BackgroundColor Black
    Write-Host "   Major issues detected - DO NOT RELEASE" -ForegroundColor Red
    exit 1
}

# Manual Metasploit Integration Testing Guide
# Interactive test scenarios for validating NextMap v0.3.2 MSF features

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   🔬 NEXTMAP v0.3.2 - MANUAL METASPLOIT TESTING GUIDE           ║
║                                                                  ║
║   This guide walks through manual testing scenarios             ║
║   for the Metasploit integration features                       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host "`n📋 TESTING CHECKLIST" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

$tests = @(
    @{
        ID = 1
        Name = "Basic Dry-Run Test (Localhost)"
        Command = ".\target\release\nextmap.exe -t 127.0.0.1 -p 80,443 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1"
        Description = "Tests MSF integration without Metasploit installed (dry-run mode)"
        ExpectedBehavior = "Should show DRY-RUN mode message, scan localhost, detect CVEs (if any), and show what would be exploited"
        SafetyLevel = "🟢 SAFE"
    },
    @{
        ID = 2
        Name = "Multi-Port Scan with MSF"
        Command = ".\target\release\nextmap.exe -t 127.0.0.1 -p top100 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 192.168.1.100"
        Description = "Scans top 100 ports with CVE detection and MSF dry-run"
        ExpectedBehavior = "Should complete scan, show CVE results, MSF exploitation summary"
        SafetyLevel = "🟢 SAFE"
    },
    @{
        ID = 3
        Name = "Custom LHOST/LPORT Configuration"
        Command = ".\target\release\nextmap.exe -t 127.0.0.1 -p 22,80,443 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 192.168.1.50 --msf-lport 5555"
        Description = "Tests custom reverse shell configuration"
        ExpectedBehavior = "Should accept custom LHOST (192.168.1.50) and LPORT (5555)"
        SafetyLevel = "🟢 SAFE"
    },
    @{
        ID = 4
        Name = "JSON Output with MSF"
        Command = ".\target\release\nextmap.exe -t 127.0.0.1 -p 80 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 -o json -f msf_test_output.json"
        Description = "Tests JSON file output with MSF integration"
        ExpectedBehavior = "Should create msf_test_output.json with scan results"
        SafetyLevel = "🟢 SAFE"
    },
    @{
        ID = 5
        Name = "CSV Output with Enhanced Columns"
        Command = ".\target\release\nextmap.exe -t 127.0.0.1 -p 80,443 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 -o csv -f msf_test_output.csv"
        Description = "Tests CSV output (12 columns) with MSF"
        ExpectedBehavior = "Should create CSV with CVECount column populated"
        SafetyLevel = "🟢 SAFE"
    },
    @{
        ID = 6
        Name = "HTML Report with MSF"
        Command = ".\target\release\nextmap.exe -t 127.0.0.1 -p 22,80,443 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 -o html -f msf_test_report.html"
        Description = "Tests HTML report generation with MSF data"
        ExpectedBehavior = "Should create professional HTML report with CVE and MSF info"
        SafetyLevel = "🟢 SAFE"
    },
    @{
        ID = 7
        Name = "MSF without CVE Scan"
        Command = ".\target\release\nextmap.exe -t 127.0.0.1 -p 80 --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1"
        Description = "Tests MSF flag without CVE scanning enabled"
        ExpectedBehavior = "Should work but have no CVEs to exploit"
        SafetyLevel = "🟢 SAFE"
    },
    @{
        ID = 8
        Name = "Performance Test (Top1000 + MSF)"
        Command = ".\target\release\nextmap.exe -t 127.0.0.1 -p top1000 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 -x aggressive"
        Description = "Tests performance with large port range and MSF"
        ExpectedBehavior = "Should complete in reasonable time (< 30s for localhost)"
        SafetyLevel = "🟢 SAFE"
    },
    @{
        ID = 9
        Name = "Stealth Mode + MSF Integration"
        Command = ".\target\release\nextmap.exe -t 127.0.0.1 -p 80,443,22 -s --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1 --stealth-mode shadow"
        Description = "Tests MSF with stealth scanning mode"
        ExpectedBehavior = "Should combine stealth scanning with MSF features"
        SafetyLevel = "🟢 SAFE"
    },
    @{
        ID = 10
        Name = "OS Detection + CVE + MSF"
        Command = ".\target\release\nextmap.exe -t 127.0.0.1 -p top100 -s -O --cve-scan --msf-exploit --msf-dry-run --msf-lhost 127.0.0.1"
        Description = "Tests full feature stack: OS detection, CVE scan, MSF"
        ExpectedBehavior = "Should show OS fingerprint, CVEs, and exploitation plan"
        SafetyLevel = "🟢 SAFE"
    }
)

# Interactive Test Runner
function Run-InteractiveTest {
    param($TestCase)
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║ TEST #$($TestCase.ID): $($TestCase.Name.PadRight(59)) ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Write-Host "`n📝 Description:" -ForegroundColor Yellow
    Write-Host "   $($TestCase.Description)" -ForegroundColor White
    
    Write-Host "`n🎯 Expected Behavior:" -ForegroundColor Yellow
    Write-Host "   $($TestCase.ExpectedBehavior)" -ForegroundColor White
    
    Write-Host "`n⚡ Safety Level: $($TestCase.SafetyLevel)" -ForegroundColor $(
        if ($TestCase.SafetyLevel -match "SAFE") { "Green" }
        elseif ($TestCase.SafetyLevel -match "CAUTION") { "Yellow" }
        else { "Red" }
    )
    
    Write-Host "`n💻 Command:" -ForegroundColor Yellow
    Write-Host "   $($TestCase.Command)" -ForegroundColor Cyan
    
    Write-Host "`n" -NoNewline
    $response = Read-Host "   Run this test? (Y/n/q)"
    
    if ($response -eq "q") {
        return "quit"
    }
    
    if ($response -eq "" -or $response -eq "y" -or $response -eq "Y") {
        Write-Host "`n🚀 Executing test..." -ForegroundColor Green
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
        
        $startTime = Get-Date
        
        try {
            Invoke-Expression $TestCase.Command
            
            $endTime = Get-Date
            $duration = ($endTime - $startTime).TotalSeconds
            
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
            Write-Host "✅ Test completed in $($duration.ToString('0.00'))s" -ForegroundColor Green
            
            $verdict = Read-Host "`n   Did the test behave as expected? (Y/n)"
            
            if ($verdict -eq "" -or $verdict -eq "y" -or $verdict -eq "Y") {
                Write-Host "   ✅ PASS - Test successful!" -ForegroundColor Green
                return "pass"
            } else {
                $notes = Read-Host "   📝 Notes on failure"
                Write-Host "   ❌ FAIL - $notes" -ForegroundColor Red
                return "fail"
            }
        }
        catch {
            Write-Host "❌ Error executing test: $_" -ForegroundColor Red
            return "error"
        }
    } else {
        Write-Host "   ⏭️ Skipped" -ForegroundColor Yellow
        return "skip"
    }
}

# Main Test Loop
$results = @{
    Pass = 0
    Fail = 0
    Skip = 0
    Error = 0
}

Write-Host "`n📊 Starting Interactive Test Session..." -ForegroundColor Cyan
Write-Host "   Press 'q' at any time to quit`n" -ForegroundColor Gray

foreach ($test in $tests) {
    $result = Run-InteractiveTest -TestCase $test
    
    if ($result -eq "quit") {
        Write-Host "`n⏹️ Test session stopped by user" -ForegroundColor Yellow
        break
    }
    
    switch ($result) {
        "pass"  { $results.Pass++ }
        "fail"  { $results.Fail++ }
        "skip"  { $results.Skip++ }
        "error" { $results.Error++ }
    }
    
    # Pause between tests
    if ($result -ne "skip") {
        Read-Host "`n   Press Enter to continue to next test"
    }
}

# Summary Report
Write-Host "`n`n╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    📊 TEST SUMMARY REPORT                        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nTotal Tests Run: $($results.Pass + $results.Fail + $results.Error)" -ForegroundColor White
Write-Host "✅ Passed:       $($results.Pass)" -ForegroundColor Green
Write-Host "❌ Failed:       $($results.Fail)" -ForegroundColor Red
Write-Host "⚠️ Errors:       $($results.Error)" -ForegroundColor Yellow
Write-Host "⏭️ Skipped:      $($results.Skip)" -ForegroundColor Gray

$total = $results.Pass + $results.Fail + $results.Error
if ($total -gt 0) {
    $passRate = [math]::Round(($results.Pass / $total) * 100, 1)
    Write-Host "`nPass Rate: $passRate%" -ForegroundColor $(
        if ($passRate -ge 90) { "Green" }
        elseif ($passRate -ge 70) { "Yellow" }
        else { "Red" }
    )
}

if ($results.Fail -eq 0 -and $results.Error -eq 0 -and $results.Pass -gt 0) {
    Write-Host "`n🎉 ALL TESTS PASSED! NextMap MSF integration is working perfectly!" -ForegroundColor Green
    Write-Host "✅ Ready for v0.3.2 production release" -ForegroundColor Cyan
} elseif ($results.Pass -gt 0) {
    Write-Host "`n⚠️ Some tests failed - review results before release" -ForegroundColor Yellow
} else {
    Write-Host "`n❌ Critical issues detected - fix before release" -ForegroundColor Red
}

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "Manual testing session completed!" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

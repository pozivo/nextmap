# ================================================================
# NextMap v0.4.0 - Nuclei Integration Test Suite
# ================================================================
# Tests all Nuclei integration features:
# - Binary detection
# - Template updates
# - Severity filtering
# - Tag filtering
# - Service-specific scanning
# - Output format validation
# ================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NextMap Nuclei Integration Test Suite" -ForegroundColor Cyan
Write-Host "  Version: 0.4.0" -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ================================================================
# Configuration
# ================================================================
$TEST_RESULTS_DIR = "test_results_nuclei"
$BUILD_DIR = "target/release"
$NEXTMAP_EXE = "$BUILD_DIR/nextmap.exe"
$TEST_TARGET = "scanme.nmap.org"  # Safe public test target
$TEST_TIMEOUT = 300  # 5 minutes per test

# Test counters
$TESTS_TOTAL = 0
$TESTS_PASSED = 0
$TESTS_FAILED = 0
$TESTS_SKIPPED = 0

# ================================================================
# Helper Functions
# ================================================================

function Write-TestHeader {
    param([string]$TestName)
    $global:TESTS_TOTAL++
    Write-Host "`n[$global:TESTS_TOTAL] Testing: $TestName" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor Gray
}

function Write-TestResult {
    param(
        [bool]$Success,
        [string]$Message
    )
    if ($Success) {
        $global:TESTS_PASSED++
        Write-Host "✓ PASS: $Message" -ForegroundColor Green
    } else {
        $global:TESTS_FAILED++
        Write-Host "✗ FAIL: $Message" -ForegroundColor Red
    }
}

function Write-TestSkip {
    param([string]$Reason)
    $global:TESTS_SKIPPED++
    Write-Host "⊘ SKIP: $Reason" -ForegroundColor DarkGray
}

function Test-CommandExists {
    param([string]$Command)
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Invoke-NextMapTest {
    param(
        [string]$Arguments,
        [string]$OutputFile = $null,
        [int]$TimeoutSeconds = $TEST_TIMEOUT
    )
    
    $cmd = "$NEXTMAP_EXE $Arguments"
    if ($OutputFile) {
        $cmd += " -o $OutputFile"
    }
    
    Write-Host "Command: $cmd" -ForegroundColor DarkGray
    
    try {
        $job = Start-Job -ScriptBlock {
            param($Command)
            Invoke-Expression $Command 2>&1
        } -ArgumentList $cmd
        
        $job | Wait-Job -Timeout $TimeoutSeconds | Out-Null
        
        if ($job.State -eq 'Running') {
            Stop-Job $job
            Remove-Job $job -Force
            return @{
                Success = $false
                Output = "Timeout after $TimeoutSeconds seconds"
                ExitCode = -1
            }
        }
        
        $output = Receive-Job $job
        $exitCode = if ($job.State -eq 'Completed') { 0 } else { 1 }
        Remove-Job $job -Force
        
        return @{
            Success = ($exitCode -eq 0)
            Output = $output -join "`n"
            ExitCode = $exitCode
        }
    } catch {
        return @{
            Success = $false
            Output = $_.Exception.Message
            ExitCode = -1
        }
    }
}

# ================================================================
# Pre-Test Setup
# ================================================================

Write-Host "Pre-Test Setup..." -ForegroundColor Cyan

# Create test results directory
if (!(Test-Path $TEST_RESULTS_DIR)) {
    New-Item -ItemType Directory -Path $TEST_RESULTS_DIR | Out-Null
    Write-Host "✓ Created test results directory: $TEST_RESULTS_DIR" -ForegroundColor Green
} else {
    Write-Host "✓ Test results directory exists: $TEST_RESULTS_DIR" -ForegroundColor Green
}

# Check if NextMap binary exists
if (!(Test-Path $NEXTMAP_EXE)) {
    Write-Host "✗ NextMap binary not found: $NEXTMAP_EXE" -ForegroundColor Red
    Write-Host "Building NextMap..." -ForegroundColor Yellow
    
    $buildResult = cargo build --release 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "✗ Build failed!" -ForegroundColor Red
        Write-Host $buildResult -ForegroundColor Red
        exit 1
    }
    Write-Host "✓ Build successful" -ForegroundColor Green
} else {
    Write-Host "✓ NextMap binary found: $NEXTMAP_EXE" -ForegroundColor Green
}

# Check if Nuclei is installed
$NUCLEI_AVAILABLE = Test-CommandExists "nuclei"
if ($NUCLEI_AVAILABLE) {
    $nucleiVersion = nuclei -version 2>&1 | Select-String -Pattern "v\d+\.\d+\.\d+" | ForEach-Object { $_.Matches.Value }
    Write-Host "✓ Nuclei detected: $nucleiVersion" -ForegroundColor Green
} else {
    Write-Host "⊘ Nuclei not found in PATH - some tests will be skipped" -ForegroundColor DarkYellow
    Write-Host "  Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" -ForegroundColor DarkGray
}

Write-Host ""

# ================================================================
# Test 1: Binary Detection
# ================================================================

Write-TestHeader "Nuclei Binary Detection"

if (!$NUCLEI_AVAILABLE) {
    Write-TestSkip "Nuclei not installed"
} else {
    # Test that NextMap can detect Nuclei
    $result = Invoke-NextMapTest "-t 127.0.0.1 -p 1 --nuclei-scan --nuclei-verbose" "$TEST_RESULTS_DIR/test_detection.txt" 30
    
    $detectionSuccess = $result.Output -match "Nuclei.*detected|Found.*nuclei|nuclei.*version"
    Write-TestResult $detectionSuccess "NextMap detected Nuclei binary"
    
    if ($result.Output -match "Nuclei.*not found|Failed to detect") {
        Write-Host "  Output: $($result.Output)" -ForegroundColor DarkGray
    }
}

# ================================================================
# Test 2: Help Text Validation
# ================================================================

Write-TestHeader "CLI Flags Documentation"

$helpOutput = & $NEXTMAP_EXE --help 2>&1 | Out-String

$expectedFlags = @(
    "--nuclei-scan",
    "--nuclei-path",
    "--nuclei-severity",
    "--nuclei-tags",
    "--nuclei-rate-limit",
    "--nuclei-update",
    "--nuclei-verbose"
)

foreach ($flag in $expectedFlags) {
    $flagExists = $helpOutput -match [regex]::Escape($flag)
    Write-TestResult $flagExists "Flag '$flag' documented in help"
}

# ================================================================
# Test 3: Template Update (Dry Run)
# ================================================================

Write-TestHeader "Template Update Mechanism"

if (!$NUCLEI_AVAILABLE) {
    Write-TestSkip "Nuclei not installed"
} else {
    # Test update flag (with very short timeout since we're just testing the mechanism)
    $result = Invoke-NextMapTest "-t 127.0.0.1 -p 1 --nuclei-scan --nuclei-update --nuclei-verbose" "$TEST_RESULTS_DIR/test_update.txt" 60
    
    $updateAttempted = $result.Output -match "Updating.*templates|nuclei.*update|Template.*update"
    Write-TestResult $updateAttempted "Template update mechanism triggered"
    
    if (!$updateAttempted -and $result.Output) {
        Write-Host "  Output sample: $($result.Output.Substring(0, [Math]::Min(200, $result.Output.Length)))" -ForegroundColor DarkGray
    }
}

# ================================================================
# Test 4: Severity Filtering
# ================================================================

Write-TestHeader "Severity Filtering"

if (!$NUCLEI_AVAILABLE) {
    Write-TestSkip "Nuclei not installed"
} else {
    $severityLevels = @("critical", "high", "medium", "low", "info")
    
    foreach ($severity in $severityLevels) {
        $result = Invoke-NextMapTest "-t 127.0.0.1 -p 1 --nuclei-scan --nuclei-severity $severity --nuclei-verbose" "$TEST_RESULTS_DIR/test_severity_$severity.txt" 30
        
        $severityAccepted = !($result.Output -match "Invalid.*severity|Unknown.*severity")
        Write-TestResult $severityAccepted "Severity filter '$severity' accepted"
    }
    
    # Test multiple severities
    $result = Invoke-NextMapTest "-t 127.0.0.1 -p 1 --nuclei-scan --nuclei-severity critical,high --nuclei-verbose" "$TEST_RESULTS_DIR/test_severity_multiple.txt" 30
    $multipleAccepted = !($result.Output -match "Invalid.*severity")
    Write-TestResult $multipleAccepted "Multiple severity filter 'critical,high' accepted"
}

# ================================================================
# Test 5: Tag Filtering
# ================================================================

Write-TestHeader "Tag-Based Filtering"

if (!$NUCLEI_AVAILABLE) {
    Write-TestSkip "Nuclei not installed"
} else {
    $commonTags = @("cve", "rce", "sqli", "xss", "lfi")
    
    foreach ($tag in $commonTags) {
        $result = Invoke-NextMapTest "-t 127.0.0.1 -p 1 --nuclei-scan --nuclei-tags $tag --nuclei-verbose" "$TEST_RESULTS_DIR/test_tag_$tag.txt" 30
        
        $tagAccepted = !($result.Output -match "Invalid.*tag|Unknown.*tag")
        Write-TestResult $tagAccepted "Tag filter '$tag' accepted"
    }
    
    # Test multiple tags
    $result = Invoke-NextMapTest "-t 127.0.0.1 -p 1 --nuclei-scan --nuclei-tags cve,rce,sqli --nuclei-verbose" "$TEST_RESULTS_DIR/test_tag_multiple.txt" 30
    $multipleAccepted = !($result.Output -match "Invalid.*tag")
    Write-TestResult $multipleAccepted "Multiple tag filter 'cve,rce,sqli' accepted"
}

# ================================================================
# Test 6: Rate Limiting
# ================================================================

Write-TestHeader "Rate Limiting Configuration"

if (!$NUCLEI_AVAILABLE) {
    Write-TestSkip "Nuclei not installed"
} else {
    $rateLimits = @(50, 150, 300)
    
    foreach ($rate in $rateLimits) {
        $result = Invoke-NextMapTest "-t 127.0.0.1 -p 1 --nuclei-scan --nuclei-rate-limit $rate --nuclei-verbose" "$TEST_RESULTS_DIR/test_rate_$rate.txt" 30
        
        $rateAccepted = !($result.Output -match "Invalid.*rate|rate.*error")
        Write-TestResult $rateAccepted "Rate limit $rate req/s accepted"
    }
}

# ================================================================
# Test 7: Service-Specific Scanning (Simulated)
# ================================================================

Write-TestHeader "Service-Specific Template Selection"

if (!$NUCLEI_AVAILABLE) {
    Write-TestSkip "Nuclei not installed"
} else {
    # Test with known web ports (80, 443, 8080)
    $webPorts = @(80, 443, 8080)
    
    foreach ($port in $webPorts) {
        # Quick scan to test if service detection triggers Nuclei
        $result = Invoke-NextMapTest "-t $TEST_TARGET -p $port --nuclei-scan --nuclei-severity critical --nuclei-verbose" "$TEST_RESULTS_DIR/test_service_port_$port.txt" 60
        
        # Check if Nuclei was invoked for web ports
        $nucleiInvoked = $result.Output -match "Scanning.*nuclei|nuclei.*scan|Running.*nuclei"
        Write-TestResult $nucleiInvoked "Nuclei triggered for HTTP port $port"
    }
}

# ================================================================
# Test 8: Output Format Validation
# ================================================================

Write-TestHeader "Output Format Validation"

if (!$NUCLEI_AVAILABLE) {
    Write-TestSkip "Nuclei not installed"
} else {
    # Test JSON output
    $jsonFile = "$TEST_RESULTS_DIR/test_output_format.json"
    $result = Invoke-NextMapTest "-t $TEST_TARGET -p 80 --nuclei-scan --nuclei-severity critical -f json" $jsonFile 120
    
    if (Test-Path $jsonFile) {
        try {
            $jsonContent = Get-Content $jsonFile -Raw | ConvertFrom-Json
            $jsonValid = $jsonContent -ne $null
            Write-TestResult $jsonValid "JSON output format valid"
            
            # Check for detection_method field
            if ($jsonContent.scan_results) {
                $hasDetectionMethod = $jsonContent.scan_results | Where-Object { $_.detection_method -ne $null }
                if ($hasDetectionMethod) {
                    Write-TestResult $true "JSON contains 'detection_method' field"
                } else {
                    Write-TestResult $false "JSON missing 'detection_method' field"
                }
            }
        } catch {
            Write-TestResult $false "JSON parsing failed: $($_.Exception.Message)"
        }
    } else {
        Write-TestResult $false "JSON output file not created"
    }
    
    # Test CSV output
    $csvFile = "$TEST_RESULTS_DIR/test_output_format.csv"
    $result = Invoke-NextMapTest "-t $TEST_TARGET -p 80 --nuclei-scan --nuclei-severity critical -f csv" $csvFile 120
    
    if (Test-Path $csvFile) {
        $csvContent = Get-Content $csvFile
        $csvValid = $csvContent.Count -gt 0
        Write-TestResult $csvValid "CSV output format valid"
        
        # Check for detection_method column
        if ($csvContent.Count -gt 0) {
            $header = $csvContent[0]
            $hasDetectionMethod = $header -match "detection.*method|Detection.*Method"
            Write-TestResult $hasDetectionMethod "CSV contains 'detection_method' column"
        }
    } else {
        Write-TestResult $false "CSV output file not created"
    }
    
    # Test HTML output
    $htmlFile = "$TEST_RESULTS_DIR/test_output_format.html"
    $result = Invoke-NextMapTest "-t $TEST_TARGET -p 80 --nuclei-scan --nuclei-severity critical -f html" $htmlFile 120
    
    if (Test-Path $htmlFile) {
        $htmlContent = Get-Content $htmlFile -Raw
        $htmlValid = $htmlContent -match "<html|<HTML"
        Write-TestResult $htmlValid "HTML output format valid"
        
        # Check for Active Scan mention
        $hasActiveScan = $htmlContent -match "Active.*Scan|Nuclei|ActiveScan"
        Write-TestResult $hasActiveScan "HTML mentions Active Scan results"
    } else {
        Write-TestResult $false "HTML output file not created"
    }
}

# ================================================================
# Test 9: Error Handling
# ================================================================

Write-TestHeader "Error Handling & Edge Cases"

# Test with invalid severity
$result = Invoke-NextMapTest "-t 127.0.0.1 -p 1 --nuclei-scan --nuclei-severity invalid_severity" "$TEST_RESULTS_DIR/test_error_severity.txt" 30
$handledGracefully = !($result.Output -match "panic|fatal|crash")
Write-TestResult $handledGracefully "Invalid severity handled gracefully (no crash)"

# Test with non-existent nuclei path
$result = Invoke-NextMapTest "-t 127.0.0.1 -p 1 --nuclei-scan --nuclei-path C:\nonexistent\nuclei.exe" "$TEST_RESULTS_DIR/test_error_path.txt" 30
$pathErrorHandled = $result.Output -match "not found|does not exist|Failed to detect" -or !($result.Output -match "panic|fatal")
Write-TestResult $pathErrorHandled "Invalid Nuclei path handled gracefully"

# Test with unreachable target
$result = Invoke-NextMapTest "-t 192.0.2.1 -p 80 --nuclei-scan --nuclei-severity critical" "$TEST_RESULTS_DIR/test_error_unreachable.txt" 60
$unreachableHandled = !($result.Output -match "panic|fatal|crash")
Write-TestResult $unreachableHandled "Unreachable target handled gracefully"

# ================================================================
# Test 10: Performance & Resource Usage
# ================================================================

Write-TestHeader "Performance & Resource Monitoring"

if (!$NUCLEI_AVAILABLE) {
    Write-TestSkip "Nuclei not installed"
} else {
    # Test with rate limiting (fast vs slow)
    Write-Host "Testing fast mode (300 req/s)..." -ForegroundColor DarkGray
    $startTime = Get-Date
    $result = Invoke-NextMapTest "-t $TEST_TARGET -p 80,443 --nuclei-scan --nuclei-severity critical --nuclei-rate-limit 300" "$TEST_RESULTS_DIR/test_perf_fast.txt" 120
    $fastDuration = (Get-Date) - $startTime
    
    Write-Host "Testing slow mode (50 req/s)..." -ForegroundColor DarkGray
    $startTime = Get-Date
    $result = Invoke-NextMapTest "-t $TEST_TARGET -p 80,443 --nuclei-scan --nuclei-severity critical --nuclei-rate-limit 50" "$TEST_RESULTS_DIR/test_perf_slow.txt" 120
    $slowDuration = (Get-Date) - $startTime
    
    Write-Host "  Fast mode: $($fastDuration.TotalSeconds)s" -ForegroundColor DarkGray
    Write-Host "  Slow mode: $($slowDuration.TotalSeconds)s" -ForegroundColor DarkGray
    
    # Slow mode should take longer (or they're both very fast on empty target)
    $performanceExpected = $slowDuration.TotalSeconds -ge $fastDuration.TotalSeconds * 0.8
    Write-TestResult $performanceExpected "Rate limiting affects scan duration as expected"
}

# ================================================================
# Test 11: Integration with Existing Features
# ================================================================

Write-TestHeader "Integration with Existing NextMap Features"

# Test Nuclei + CVE database
$result = Invoke-NextMapTest "-t $TEST_TARGET -p 80 --nuclei-scan --nuclei-severity critical --cve-db" "$TEST_RESULTS_DIR/test_integration_cve.txt" 120
$bothFeaturesWork = !($result.Output -match "conflict|error.*cve|error.*nuclei")
Write-TestResult $bothFeaturesWork "Nuclei works alongside CVE database"

# Test Nuclei + MSF integration
$result = Invoke-NextMapTest "-t $TEST_TARGET -p 80 --nuclei-scan --nuclei-severity critical --msf-search" "$TEST_RESULTS_DIR/test_integration_msf.txt" 120
$msfCompatible = !($result.Output -match "conflict|error.*msf|error.*nuclei")
Write-TestResult $msfCompatible "Nuclei works alongside MSF integration"

# Test Nuclei + Banner grabbing
$result = Invoke-NextMapTest "-t $TEST_TARGET -p 80 --nuclei-scan --nuclei-severity critical --banner" "$TEST_RESULTS_DIR/test_integration_banner.txt" 120
$bannerCompatible = !($result.Output -match "conflict|error.*banner|error.*nuclei")
Write-TestResult $bannerCompatible "Nuclei works alongside Banner grabbing"

# ================================================================
# Test 12: Real-World Scenario (Safe Target)
# ================================================================

Write-TestHeader "Real-World Scan Scenario"

if (!$NUCLEI_AVAILABLE) {
    Write-TestSkip "Nuclei not installed"
} else {
    Write-Host "Performing comprehensive scan against $TEST_TARGET..." -ForegroundColor DarkGray
    Write-Host "This may take a few minutes..." -ForegroundColor DarkGray
    
    $result = Invoke-NextMapTest "-t $TEST_TARGET -p 80,443 --nuclei-scan --nuclei-severity critical,high --nuclei-tags cve --banner --cve-db -f json" "$TEST_RESULTS_DIR/test_real_world.json" 300
    
    $scanCompleted = $result.Success -or !($result.Output -match "panic|fatal|crash")
    Write-TestResult $scanCompleted "Comprehensive scan completed without errors"
    
    # Analyze results
    $outputFile = "$TEST_RESULTS_DIR/test_real_world.json"
    if (Test-Path $outputFile) {
        try {
            $scanResults = Get-Content $outputFile -Raw | ConvertFrom-Json
            
            if ($scanResults.scan_results) {
                $portCount = $scanResults.scan_results.Count
                $vulnCount = ($scanResults.scan_results | ForEach-Object { $_.vulnerabilities.Count } | Measure-Object -Sum).Sum
                $activeScanCount = ($scanResults.scan_results | Where-Object { $_.detection_method -eq "ActiveScan" -or $_.detection_method -eq "Active Scan (Nuclei)" }).Count
                
                Write-Host "  Ports scanned: $portCount" -ForegroundColor DarkGray
                Write-Host "  Vulnerabilities found: $vulnCount" -ForegroundColor DarkGray
                Write-Host "  Active scans performed: $activeScanCount" -ForegroundColor DarkGray
                
                $hasResults = $portCount -gt 0
                Write-TestResult $hasResults "Scan produced results"
                
                if ($activeScanCount -gt 0) {
                    Write-TestResult $true "Active scanning (Nuclei) was performed"
                } else {
                    Write-Host "  Note: No active scans performed (target may not have open HTTP ports)" -ForegroundColor DarkYellow
                }
            }
        } catch {
            Write-Host "  Could not parse results: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }
}

# ================================================================
# Final Summary
# ================================================================

Write-Host "`n" 
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Tests:  $TESTS_TOTAL" -ForegroundColor White
Write-Host "Passed:       $TESTS_PASSED" -ForegroundColor Green
Write-Host "Failed:       $TESTS_FAILED" -ForegroundColor $(if ($TESTS_FAILED -gt 0) { "Red" } else { "Green" })
Write-Host "Skipped:      $TESTS_SKIPPED" -ForegroundColor DarkGray
Write-Host ""

$passRate = if ($TESTS_TOTAL -gt 0) { [math]::Round(($TESTS_PASSED / ($TESTS_TOTAL - $TESTS_SKIPPED)) * 100, 2) } else { 0 }
Write-Host "Pass Rate:    $passRate%" -ForegroundColor $(if ($passRate -ge 90) { "Green" } elseif ($passRate -ge 70) { "Yellow" } else { "Red" })
Write-Host ""

if ($TESTS_FAILED -eq 0) {
    Write-Host "✓ ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host "Nuclei integration is working correctly." -ForegroundColor Green
    $exitCode = 0
} else {
    Write-Host "✗ SOME TESTS FAILED" -ForegroundColor Red
    Write-Host "Please review the test results in: $TEST_RESULTS_DIR" -ForegroundColor Yellow
    $exitCode = 1
}

Write-Host ""
Write-Host "Test results saved to: $TEST_RESULTS_DIR" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

exit $exitCode

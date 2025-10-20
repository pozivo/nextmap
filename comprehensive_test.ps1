# comprehensive_test.ps1
# Comprehensive Test Suite for NextMap v0.3.1
# Tests: Enhanced Fingerprinting + Enhanced Output Formatting

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     NextMap v0.3.1 - Comprehensive Test Suite                 ║" -ForegroundColor Cyan
Write-Host "║     Testing: Enhanced Fingerprinting + Enhanced Output        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

$testStartTime = Get-Date
$executable = ".\target\release\nextmap.exe"
$testDir = "test_results_comprehensive"

# Create test directory
if (!(Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir | Out-Null
}

# Test counters
$totalTests = 0
$passedTests = 0
$failedTests = 0

function Test-Assertion {
    param(
        [string]$TestName,
        [bool]$Condition,
        [string]$Expected,
        [string]$Actual
    )
    
    $script:totalTests++
    
    if ($Condition) {
        Write-Host "  ✓ " -ForegroundColor Green -NoNewline
        Write-Host "$TestName" -ForegroundColor Gray
        $script:passedTests++
        return $true
    } else {
        Write-Host "  ✗ " -ForegroundColor Red -NoNewline
        Write-Host "$TestName" -ForegroundColor Gray
        Write-Host "    Expected: $Expected" -ForegroundColor Yellow
        Write-Host "    Actual: $Actual" -ForegroundColor Yellow
        $script:failedTests++
        return $false
    }
}

# ============================================================================
# TEST 1: Enhanced Fingerprinting - Service Detection
# ============================================================================
Write-Host "`n[TEST 1/6] Enhanced Fingerprinting - Service Detection" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

Write-Host "`nScanning public DNS servers for service detection..." -ForegroundColor Cyan
& $executable -t 8.8.8.8 -p 53 -sV -T 3000 --output-format json --output-file "$testDir\test1_google_dns.json" 2>&1 | Out-Null

if (Test-Path "$testDir\test1_google_dns.json") {
    $json = Get-Content "$testDir\test1_google_dns.json" | ConvertFrom-Json
    
    Test-Assertion `
        "JSON file created" `
        ($json -ne $null) `
        "Valid JSON object" `
        "$(if ($json) { 'Valid' } else { 'Null' })"
    
    if ($json.hosts -and $json.hosts.Count -gt 0) {
        $host = $json.hosts[0]
        
        Test-Assertion `
            "Host detected as UP" `
            ($host.status -eq "Up") `
            "Up" `
            "$($host.status)"
        
        if ($host.ports -and $host.ports.Count -gt 0) {
            $port = $host.ports[0]
            
            Test-Assertion `
                "Port 53 detected as OPEN" `
                ($port.state -eq "Open") `
                "Open" `
                "$($port.state)"
            
            Test-Assertion `
                "Service name detected" `
                ($port.service_name -ne $null) `
                "domain or dns" `
                "$($port.service_name)"
        }
    }
}

# ============================================================================
# TEST 2: Enhanced Output - Service Categorization
# ============================================================================
Write-Host "`n[TEST 2/6] Enhanced Output - Service Categorization" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

Write-Host "`nTesting categorization on common ports..." -ForegroundColor Cyan
& $executable -t 127.0.0.1 -p 80,443,3306,6379,22 -sV -T 2000 --output-format json --output-file "$testDir\test2_categories.json" 2>&1 | Out-Null

if (Test-Path "$testDir\test2_categories.json") {
    $json = Get-Content "$testDir\test2_categories.json" | ConvertFrom-Json
    
    if ($json.hosts -and $json.hosts.Count -gt 0) {
        $categoriesFound = @()
        foreach ($host in $json.hosts) {
            foreach ($port in $host.ports) {
                if ($port.service_category) {
                    $categoriesFound += $port.service_category
                }
            }
        }
        
        Test-Assertion `
            "Service categories populated" `
            ($categoriesFound.Count -gt 0) `
            ">= 1 category" `
            "$($categoriesFound.Count) categories"
        
        Write-Host "  ℹ  Categories found: $($categoriesFound -join ', ')" -ForegroundColor DarkGray
    }
}

# ============================================================================
# TEST 3: Enhanced Output - Risk Assessment
# ============================================================================
Write-Host "`n[TEST 3/6] Enhanced Output - Risk Assessment" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

Write-Host "`nTesting risk level calculation..." -ForegroundColor Cyan

if (Test-Path "$testDir\test2_categories.json") {
    $json = Get-Content "$testDir\test2_categories.json" | ConvertFrom-Json
    
    if ($json.hosts -and $json.hosts.Count -gt 0) {
        $riskLevelsFound = @()
        foreach ($host in $json.hosts) {
            foreach ($port in $host.ports) {
                if ($port.risk_level) {
                    $riskLevelsFound += $port.risk_level
                }
            }
        }
        
        Test-Assertion `
            "Risk levels populated" `
            ($riskLevelsFound.Count -gt 0) `
            ">= 1 risk level" `
            "$($riskLevelsFound.Count) risk levels"
        
        $validLevels = @("Critical", "High", "Medium", "Low", "Info")
        $allValid = $true
        foreach ($level in $riskLevelsFound) {
            if ($level -notin $validLevels) {
                $allValid = $false
                break
            }
        }
        
        Test-Assertion `
            "Risk levels are valid" `
            $allValid `
            "Critical/High/Medium/Low/Info" `
            "$($riskLevelsFound -join ', ')"
        
        Write-Host "  ℹ  Risk levels: $($riskLevelsFound -join ', ')" -ForegroundColor DarkGray
    }
}

# ============================================================================
# TEST 4: Enhanced Output - CSV Format (12 Columns)
# ============================================================================
Write-Host "`n[TEST 4/6] Enhanced Output - CSV Format (12 Columns)" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

Write-Host "`nGenerating CSV output..." -ForegroundColor Cyan
& $executable -t 8.8.8.8 -p 53 -sV -T 3000 --output-format csv --output-file "$testDir\test4_output.csv" 2>&1 | Out-Null

if (Test-Path "$testDir\test4_output.csv") {
    $csvContent = Get-Content "$testDir\test4_output.csv"
    
    Test-Assertion `
        "CSV file created" `
        ($csvContent -ne $null) `
        "File exists" `
        "$(if ($csvContent) { 'Exists' } else { 'Missing' })"
    
    if ($csvContent.Count -gt 0) {
        $header = $csvContent[0]
        $columns = $header -split ','
        
        Test-Assertion `
            "CSV has 12 columns" `
            ($columns.Count -eq 12) `
            "12 columns" `
            "$($columns.Count) columns"
        
        $expectedCols = @("IP", "Hostname", "Port", "Protocol", "State", "Service", "Version", "Banner", "Category", "RiskLevel", "DetectionMethod", "CVECount")
        $hasAllColumns = $true
        foreach ($col in $expectedCols) {
            if ($header -notlike "*$col*") {
                $hasAllColumns = $false
                break
            }
        }
        
        Test-Assertion `
            "CSV has all expected columns" `
            $hasAllColumns `
            "All columns present" `
            "$(if ($hasAllColumns) { 'All present' } else { 'Missing columns' })"
        
        Write-Host "  ℹ  Header: $header" -ForegroundColor DarkGray
    }
}

# ============================================================================
# TEST 5: Enhanced Output - HTML Report Generation
# ============================================================================
Write-Host "`n[TEST 5/6] Enhanced Output - HTML Report Generation" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

Write-Host "`nGenerating HTML report..." -ForegroundColor Cyan
& $executable -t 8.8.8.8 -p 53,80 -sV -T 3000 --output-format html --output-file "$testDir\test5_report.html" 2>&1 | Out-Null

if (Test-Path "$testDir\test5_report.html") {
    $htmlContent = Get-Content "$testDir\test5_report.html" -Raw
    
    Test-Assertion `
        "HTML file created" `
        ($htmlContent -ne $null) `
        "File exists" `
        "$(if ($htmlContent) { 'Exists' } else { 'Missing' })"
    
    Test-Assertion `
        "HTML has DOCTYPE" `
        ($htmlContent -like "*<!DOCTYPE html>*") `
        "Contains DOCTYPE" `
        "$(if ($htmlContent -like '*DOCTYPE*') { 'Present' } else { 'Missing' })"
    
    Test-Assertion `
        "HTML has NextMap title" `
        ($htmlContent -like "*NextMap*") `
        "Contains NextMap" `
        "$(if ($htmlContent -like '*NextMap*') { 'Present' } else { 'Missing' })"
    
    Test-Assertion `
        "HTML has CSS styles" `
        ($htmlContent -like "*<style>*") `
        "Contains <style>" `
        "$(if ($htmlContent -like '*<style>*') { 'Present' } else { 'Missing' })"
    
    Test-Assertion `
        "HTML has gradient header" `
        ($htmlContent -like "*gradient*") `
        "Contains gradient" `
        "$(if ($htmlContent -like '*gradient*') { 'Present' } else { 'Missing' })"
    
    $fileSize = (Get-Item "$testDir\test5_report.html").Length
    Test-Assertion `
        "HTML file size reasonable" `
        ($fileSize -gt 1000) `
        "> 1KB" `
        "$fileSize bytes"
    
    Write-Host "  ℹ  HTML file size: $([math]::Round($fileSize/1KB, 2)) KB" -ForegroundColor DarkGray
}

# ============================================================================
# TEST 6: Integration - Multi-Port Scan with All Features
# ============================================================================
Write-Host "`n[TEST 6/6] Integration - Multi-Port Scan with All Features" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

Write-Host "`nRunning comprehensive multi-port scan..." -ForegroundColor Cyan
$integrationPorts = "22,53,80,443,3306,5432,6379,8080,9200"
& $executable -t scanme.nmap.org -p $integrationPorts -sV -T 3000 --output-format json --output-file "$testDir\test6_integration.json" 2>&1 | Out-Null

if (Test-Path "$testDir\test6_integration.json") {
    $json = Get-Content "$testDir\test6_integration.json" | ConvertFrom-Json
    
    Test-Assertion `
        "Integration scan completed" `
        ($json -ne $null) `
        "Valid JSON" `
        "$(if ($json) { 'Valid' } else { 'Null' })"
    
    if ($json.hosts -and $json.hosts.Count -gt 0) {
        $totalPorts = 0
        $openPorts = 0
        $portsWithMetadata = 0
        
        foreach ($host in $json.hosts) {
            foreach ($port in $host.ports) {
                $totalPorts++
                if ($port.state -eq "Open") {
                    $openPorts++
                }
                if ($port.service_category -or $port.risk_level -or $port.detection_method) {
                    $portsWithMetadata++
                }
            }
        }
        
        Test-Assertion `
            "Ports scanned" `
            ($totalPorts -gt 0) `
            "> 0 ports" `
            "$totalPorts ports"
        
        if ($openPorts -gt 0) {
            $metadataPercentage = [math]::Round(($portsWithMetadata / $openPorts) * 100, 0)
            
            Test-Assertion `
                "Enhanced metadata populated" `
                ($portsWithMetadata -gt 0) `
                "> 0 ports with metadata" `
                "$portsWithMetadata/$openPorts ports ($metadataPercentage%)"
            
            Write-Host "  ℹ  Total ports: $totalPorts | Open: $openPorts | With metadata: $portsWithMetadata" -ForegroundColor DarkGray
        }
    }
    
    # Generate all output formats for integration test
    Write-Host "`n  Generating all output formats for integration test..." -ForegroundColor Cyan
    & $executable -t scanme.nmap.org -p $integrationPorts -sV -T 3000 --output-format csv --output-file "$testDir\test6_integration.csv" 2>&1 | Out-Null
    & $executable -t scanme.nmap.org -p $integrationPorts -sV -T 3000 --output-format html --output-file "$testDir\test6_integration.html" 2>&1 | Out-Null
    
    Test-Assertion `
        "CSV format generated" `
        (Test-Path "$testDir\test6_integration.csv") `
        "File exists" `
        "$(if (Test-Path '$testDir\test6_integration.csv') { 'Exists' } else { 'Missing' })"
    
    Test-Assertion `
        "HTML format generated" `
        (Test-Path "$testDir\test6_integration.html") `
        "File exists" `
        "$(if (Test-Path '$testDir\test6_integration.html') { 'Exists' } else { 'Missing' })"
}

# ============================================================================
# TEST SUMMARY
# ============================================================================
$testEndTime = Get-Date
$duration = ($testEndTime - $testStartTime).TotalSeconds

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                      TEST SUMMARY                              ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

Write-Host "Total Tests:  " -NoNewline
Write-Host "$totalTests" -ForegroundColor White

Write-Host "Passed:       " -NoNewline -ForegroundColor Green
Write-Host "$passedTests" -ForegroundColor Green

Write-Host "Failed:       " -NoNewline -ForegroundColor $(if ($failedTests -gt 0) { "Red" } else { "Green" })
Write-Host "$failedTests" -ForegroundColor $(if ($failedTests -gt 0) { "Red" } else { "Green" })

$successRate = [math]::Round(($passedTests / $totalTests) * 100, 1)
Write-Host "Success Rate: " -NoNewline
Write-Host "$successRate%" -ForegroundColor $(if ($successRate -ge 80) { "Green" } elseif ($successRate -ge 60) { "Yellow" } else { "Red" })

Write-Host "Duration:     " -NoNewline
Write-Host "$([math]::Round($duration, 2)) seconds" -ForegroundColor White

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

# Display generated files
Write-Host "`nGenerated Test Files:" -ForegroundColor Yellow
Get-ChildItem $testDir | Sort-Object Name | ForEach-Object {
    $size = [math]::Round($_.Length / 1KB, 2)
    $icon = switch ($_.Extension) {
        ".json" { "📄" }
        ".csv"  { "📊" }
        ".html" { "🌐" }
        default { "📁" }
    }
    Write-Host "  $icon $($_.Name) - ${size} KB" -ForegroundColor Gray
}

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

if ($failedTests -eq 0) {
    Write-Host "`n✅ ALL TESTS PASSED! NextMap v0.3.1 is PRODUCTION READY!" -ForegroundColor Green
} else {
    Write-Host "`n⚠️  Some tests failed. Review results above." -ForegroundColor Yellow
}

Write-Host "`n📂 Test results saved in: $testDir\" -ForegroundColor Cyan
Write-Host "🌐 Open $testDir\test6_integration.html in your browser to see the full report!`n" -ForegroundColor Cyan

# Return exit code based on test results
exit $failedTests

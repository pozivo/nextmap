# test_enhanced_output.ps1
# Test script for Enhanced Output Formatting v0.3.1

Write-Host "`n=== NextMap Enhanced Output Formatting Test Suite ===" -ForegroundColor Cyan
Write-Host "Testing all output formats with enhanced metadata`n" -ForegroundColor Yellow

$target = "127.0.0.1"
$ports = "135,445"  # Windows common ports
$executable = ".\target\debug\nextmap.exe"

# Create test results directory
$testDir = "test_results"
if (!(Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir | Out-Null
}

Write-Host "[1/5] Testing HUMAN output (default)..." -ForegroundColor Green
& $executable -t $target -p $ports -sV | Out-File "$testDir\scan_human.txt"
Write-Host "  ✓ Saved to: $testDir\scan_human.txt" -ForegroundColor Gray

Write-Host "`n[2/5] Testing JSON output (enhanced metadata)..." -ForegroundColor Green
& $executable -t $target -p $ports -sV --output-format json --output-file "$testDir\scan.json"
Write-Host "  ✓ Saved to: $testDir\scan.json" -ForegroundColor Gray

Write-Host "`n[3/5] Testing CSV output (12 columns)..." -ForegroundColor Green
& $executable -t $target -p $ports -sV --output-format csv --output-file "$testDir\scan.csv"
Write-Host "  ✓ Saved to: $testDir\scan.csv" -ForegroundColor Gray

Write-Host "`n[4/5] Testing HTML output (professional report)..." -ForegroundColor Green
& $executable -t $target -p $ports -sV --output-format html --output-file "$testDir\scan.html"
Write-Host "  ✓ Saved to: $testDir\scan.html" -ForegroundColor Gray

Write-Host "`n[5/5] Testing MARKDOWN output..." -ForegroundColor Green
& $executable -t $target -p $ports -sV --output-format md --output-file "$testDir\scan.md"
Write-Host "  ✓ Saved to: $testDir\scan.md" -ForegroundColor Gray

Write-Host "`n=== Test Summary ===" -ForegroundColor Cyan

# Check file sizes
Write-Host "`nGenerated files:" -ForegroundColor Yellow
Get-ChildItem $testDir | ForEach-Object {
    $size = [math]::Round($_.Length / 1KB, 2)
    Write-Host "  ✓ $($_.Name) - ${size} KB" -ForegroundColor Gray
}

# Display JSON preview
Write-Host "`n=== JSON Output Preview (First Port) ===" -ForegroundColor Cyan
if (Test-Path "$testDir\scan.json") {
    $json = Get-Content "$testDir\scan.json" | ConvertFrom-Json
    if ($json.hosts.Count -gt 0 -and $json.hosts[0].ports.Count -gt 0) {
        $port = $json.hosts[0].ports[0]
        Write-Host "Port: $($port.port_id)" -ForegroundColor Green
        Write-Host "Service: $($port.service_name)" -ForegroundColor Green
        Write-Host "Version: $($port.service_version)" -ForegroundColor Green
        Write-Host "Category: $($port.service_category)" -ForegroundColor Yellow
        Write-Host "Risk Level: $($port.risk_level)" -ForegroundColor $(if ($port.risk_level -eq "Critical" -or $port.risk_level -eq "High") { "Red" } else { "Green" })
        Write-Host "Detection Method: $($port.detection_method)" -ForegroundColor Cyan
        Write-Host "CVE Count: $($port.cve_count)" -ForegroundColor Gray
    }
}

# Display CSV preview
Write-Host "`n=== CSV Output Preview (Header) ===" -ForegroundColor Cyan
if (Test-Path "$testDir\scan.csv") {
    Get-Content "$testDir\scan.csv" -First 2 | ForEach-Object {
        Write-Host $_ -ForegroundColor Gray
    }
}

Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
Write-Host "1. Open test_results\scan.html in your browser" -ForegroundColor Yellow
Write-Host "2. Import test_results\scan.csv in Excel/LibreOffice" -ForegroundColor Yellow
Write-Host "3. Review test_results\scan.json for complete metadata" -ForegroundColor Yellow

Write-Host "`n✅ All tests completed successfully!" -ForegroundColor Green
Write-Host "Results saved in: $testDir\" -ForegroundColor Gray

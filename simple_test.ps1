# simple_test.ps1
# Simple test to verify enhanced features work

Write-Host "`n=== NextMap v0.3.1 - Quick Feature Test ===" -ForegroundColor Cyan

$exe = ".\target\release\nextmap.exe"

# Test 1: JSON with metadata
Write-Host "`n[1/3] Testing JSON output with enhanced metadata..." -ForegroundColor Yellow
$output = & $exe -t 8.8.8.8 -p 53 -sV -T 3000 --output-format json 2>&1 | Out-String
Write-Host "Output length: $($output.Length) characters" -ForegroundColor Gray

if ($output -like "*service_category*" -or $output -like "*risk_level*") {
    Write-Host "✓ Enhanced metadata fields detected in JSON!" -ForegroundColor Green
} else {
    Write-Host "⚠ Enhanced metadata not found in JSON output" -ForegroundColor Yellow
}

# Test 2: CSV with 12 columns
Write-Host "`n[2/3] Testing CSV output (12 columns)..." -ForegroundColor Yellow
$csvOutput = & $exe -t 8.8.8.8 -p 53 -T 3000 --output-format csv 2>&1 | Out-String
$lines = $csvOutput -split "`n"
$header = $lines | Where-Object { $_ -like "*IP,*Port*" } | Select-Object -First 1

if ($header) {
    $columns = ($header -split ',').Count
    Write-Host "CSV Header columns: $columns" -ForegroundColor Gray
    Write-Host "Header: $header" -ForegroundColor DarkGray
    
    if ($columns -ge 12) {
        Write-Host "✓ CSV has 12+ columns (enhanced format)!" -ForegroundColor Green
    } else {
        Write-Host "⚠ CSV has only $columns columns (expected 12)" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠ CSV header not found" -ForegroundColor Yellow
}

# Test 3: HTML generation
Write-Host "`n[3/3] Testing HTML report generation..." -ForegroundColor Yellow
$htmlOutput = & $exe -t 8.8.8.8 -p 53 -T 3000 --output-format html 2>&1 | Out-String

if ($htmlOutput -like "*<!DOCTYPE html>*") {
    Write-Host "✓ HTML DOCTYPE found!" -ForegroundColor Green
}
if ($htmlOutput -like "*NextMap*") {
    Write-Host "✓ NextMap branding found!" -ForegroundColor Green
}
if ($htmlOutput -like "*gradient*") {
    Write-Host "✓ Gradient CSS found!" -ForegroundColor Green
}
if ($htmlOutput -like "*Statistics*" -or $htmlOutput -like "*Risk*") {
    Write-Host "✓ Statistics/Risk sections found!" -ForegroundColor Green
}

$htmlLength = $htmlOutput.Length
Write-Host "HTML output length: $htmlLength characters" -ForegroundColor Gray

if ($htmlLength -gt 5000) {
    Write-Host "✓ HTML report generated successfully ($(([math]::Round($htmlLength/1024, 1))) KB)!" -ForegroundColor Green
} else {
    Write-Host "⚠ HTML output seems incomplete ($htmlLength chars)" -ForegroundColor Yellow
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan

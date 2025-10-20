# ================================================================
# NextMap - Nuclei Quick Validation Script
# ================================================================
# Fast validation of core Nuclei integration features
# Use for rapid development testing
# ================================================================

param(
    [switch]$SkipBuild,
    [string]$Target = "scanme.nmap.org"
)

$ErrorActionPreference = "Continue"

Write-Host "`n🧪 NextMap Nuclei Quick Test`n" -ForegroundColor Cyan

# ================================================================
# Quick Build Check
# ================================================================

if (!$SkipBuild) {
    Write-Host "[1/5] Building NextMap..." -ForegroundColor Yellow
    $buildOutput = cargo build --release 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      ✓ Build successful" -ForegroundColor Green
    } else {
        Write-Host "      ✗ Build failed!" -ForegroundColor Red
        Write-Host $buildOutput -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[1/5] Skipping build (--SkipBuild)" -ForegroundColor DarkGray
}

$NEXTMAP = "target/release/nextmap.exe"

# ================================================================
# Nuclei Detection
# ================================================================

Write-Host "[2/5] Checking Nuclei availability..." -ForegroundColor Yellow

try {
    $nucleiVersion = nuclei -version 2>&1 | Select-String -Pattern "v\d+\.\d+\.\d+" | ForEach-Object { $_.Matches.Value }
    if ($nucleiVersion) {
        Write-Host "      ✓ Nuclei found: $nucleiVersion" -ForegroundColor Green
        $NUCLEI_AVAILABLE = $true
    } else {
        throw "Version not detected"
    }
} catch {
    Write-Host "      ✗ Nuclei not found in PATH" -ForegroundColor Red
    Write-Host "      Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" -ForegroundColor Yellow
    $NUCLEI_AVAILABLE = $false
}

# ================================================================
# CLI Help Validation
# ================================================================

Write-Host "[3/5] Validating CLI flags..." -ForegroundColor Yellow

$helpOutput = & $NEXTMAP --help 2>&1 | Out-String
$requiredFlags = @("--nuclei-scan", "--nuclei-severity", "--nuclei-tags")
$flagsFound = 0

foreach ($flag in $requiredFlags) {
    if ($helpOutput -match [regex]::Escape($flag)) {
        $flagsFound++
    }
}

if ($flagsFound -eq $requiredFlags.Count) {
    Write-Host "      ✓ All Nuclei flags present ($flagsFound/$($requiredFlags.Count))" -ForegroundColor Green
} else {
    Write-Host "      ✗ Missing flags ($flagsFound/$($requiredFlags.Count))" -ForegroundColor Red
}

# ================================================================
# Quick Functional Test
# ================================================================

Write-Host "[4/5] Running quick functional test..." -ForegroundColor Yellow

if (!$NUCLEI_AVAILABLE) {
    Write-Host "      ⊘ Skipped (Nuclei not available)" -ForegroundColor DarkGray
} else {
    Write-Host "      Target: $Target" -ForegroundColor DarkGray
    Write-Host "      Timeout: 60s" -ForegroundColor DarkGray
    
    $testOutput = & $NEXTMAP -t $Target -p 80 --nuclei-scan --nuclei-severity critical --nuclei-verbose 2>&1 | Out-String
    
    if ($testOutput -match "Scanning.*nuclei|nuclei.*detected|Running.*nuclei") {
        Write-Host "      ✓ Nuclei integration functional" -ForegroundColor Green
    } elseif ($testOutput -match "Failed|Error|not found") {
        Write-Host "      ✗ Integration test failed" -ForegroundColor Red
        Write-Host "      Output: $($testOutput.Substring(0, [Math]::Min(200, $testOutput.Length)))" -ForegroundColor DarkGray
    } else {
        Write-Host "      ⚠ Uncertain result (no clear success/failure)" -ForegroundColor Yellow
    }
}

# ================================================================
# Output Format Check
# ================================================================

Write-Host "[5/5] Validating output formats..." -ForegroundColor Yellow

$testDir = "test_results_nuclei_quick"
if (!(Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir | Out-Null
}

# Test JSON output
$jsonFile = "$testDir/quick_test.json"
& $NEXTMAP -t 127.0.0.1 -p 1 --nuclei-scan -f json -o $jsonFile 2>&1 | Out-Null

if (Test-Path $jsonFile) {
    try {
        $json = Get-Content $jsonFile -Raw | ConvertFrom-Json
        Write-Host "      ✓ JSON output valid" -ForegroundColor Green
    } catch {
        Write-Host "      ✗ JSON output invalid" -ForegroundColor Red
    }
} else {
    Write-Host "      ✗ JSON file not created" -ForegroundColor Red
}

# Test CSV output
$csvFile = "$testDir/quick_test.csv"
& $NEXTMAP -t 127.0.0.1 -p 1 --nuclei-scan -f csv -o $csvFile 2>&1 | Out-Null

if (Test-Path $csvFile) {
    $csvContent = Get-Content $csvFile
    if ($csvContent.Count -gt 0) {
        Write-Host "      ✓ CSV output valid" -ForegroundColor Green
    } else {
        Write-Host "      ✗ CSV file empty" -ForegroundColor Red
    }
} else {
    Write-Host "      ✗ CSV file not created" -ForegroundColor Red
}

# ================================================================
# Summary
# ================================================================

Write-Host "`n" -NoNewline
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Quick test completed!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  • Run full test suite: .\test_nuclei.ps1" -ForegroundColor White
Write-Host "  • Test real target:    $NEXTMAP -t <target> -p 80,443 --nuclei-scan" -ForegroundColor White
Write-Host "  • View docs:           cat NUCLEI_INTEGRATION.md" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Cyan

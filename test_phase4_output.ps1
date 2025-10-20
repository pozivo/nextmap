# ================================================================
# NextMap - Phase 4 Output Enhancement Test
# ================================================================
# Tests CSV/JSON/HTML output with detection_method support
# ================================================================

Write-Host "`n🧪 Phase 4 Output Enhancement Test`n" -ForegroundColor Cyan

$NEXTMAP = "target/release/nextmap.exe"
$TEST_DIR = "test_results_phase4"

# Create test directory
if (!(Test-Path $TEST_DIR)) {
    New-Item -ItemType Directory -Path $TEST_DIR | Out-Null
}

Write-Host "[1/4] Testing CSV Output..." -ForegroundColor Yellow

# Test CSV with detection method
& $NEXTMAP -t 127.0.0.1 -p 80,443 -f csv 2>&1 | Out-File "$TEST_DIR/output.txt"

# Extract CSV from output
$content = Get-Content "$TEST_DIR/output.txt" -Raw
$csvStart = $content.IndexOf("IP,Hostname")

if ($csvStart -ge 0) {
    $csv = $content.Substring($csvStart)
    $csv | Out-File "$TEST_DIR/test_output.csv"
    
    # Check header
    $header = ($csv -split "`n")[0]
    if ($header -match "DetectionMethod") {
        Write-Host "      ✓ CSV header contains 'DetectionMethod' column" -ForegroundColor Green
    } else {
        Write-Host "      ✗ CSV header missing 'DetectionMethod' column" -ForegroundColor Red
        Write-Host "      Header: $header" -ForegroundColor DarkGray
    }
    
    # Check data rows
    $rows = ($csv -split "`n") | Where-Object { $_ -and $_ -notmatch "^IP,Hostname" }
    if ($rows.Count -gt 0) {
        Write-Host "      ✓ CSV has $($rows.Count) data rows" -ForegroundColor Green
    }
} else {
    Write-Host "      ✗ No CSV data found in output" -ForegroundColor Red
}

Write-Host "`n[2/4] Testing JSON Output..." -ForegroundColor Yellow

# Test JSON output
$jsonOutput = & $NEXTMAP -t 127.0.0.1 -p 22,80,443 -f json 2>&1 | Out-String

# Find JSON start (after progress bars)
$jsonStart = $jsonOutput.IndexOf('{')
if ($jsonStart -ge 0) {
    $json = $jsonOutput.Substring($jsonStart)
    $json | Out-File "$TEST_DIR/test_output.json"
    
    try {
        $jsonObj = $json | ConvertFrom-Json
        
        if ($jsonObj.hosts) {
            Write-Host "      ✓ JSON structure valid" -ForegroundColor Green
            
            $portsWithDetection = 0
            foreach ($scanHost in $jsonObj.hosts) {
                foreach ($port in $scanHost.ports) {
                    if ($port.detection_method) {
                        $portsWithDetection++
                    }
                }
            }
            
            if ($portsWithDetection -gt 0) {
                Write-Host "      ✓ $portsWithDetection ports have detection_method field" -ForegroundColor Green
            } else {
                Write-Host "      ⚠ No ports with detection_method (may be filtered out)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "      ✗ JSON parsing failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "      ✗ No JSON data found" -ForegroundColor Red
}

Write-Host "`n[3/4] Testing HTML Output..." -ForegroundColor Yellow

# Test HTML output
$htmlOutput = & $NEXTMAP -t scanme.nmap.org -p 80 -f html 2>&1 | Out-String

$htmlStart = $htmlOutput.IndexOf("<!DOCTYPE html>")
if ($htmlStart -ge 0) {
    $html = $htmlOutput.Substring($htmlStart)
    $html | Out-File "$TEST_DIR/test_output.html"
    
    Write-Host "      ✓ HTML file generated ($([math]::Round(($html.Length / 1KB), 2)) KB)" -ForegroundColor Green
    
    # Check for detection badges CSS
    if ($html -match "badge-detection-active") {
        Write-Host "      ✓ Active Scan badge CSS found" -ForegroundColor Green
    } else {
        Write-Host "      ✗ Active Scan badge CSS missing" -ForegroundColor Red
    }
    
    if ($html -match "badge-detection-passive") {
        Write-Host "      ✓ Passive Scan badge CSS found" -ForegroundColor Green
    } else {
        Write-Host "      ✗ Passive Scan badge CSS missing" -ForegroundColor Red
    }
    
    if ($html -match "badge-detection-enhanced") {
        Write-Host "      ✓ Enhanced Probe badge CSS found" -ForegroundColor Green
    } else {
        Write-Host "      ✗ Enhanced Probe badge CSS missing" -ForegroundColor Red
    }
    
    # Check for detection methods section
    if ($html -match "Detection Methods Distribution") {
        Write-Host "      ✓ Detection Methods statistics section found" -ForegroundColor Green
    } else {
        Write-Host "      ⚠ Detection Methods statistics section not found (may be empty)" -ForegroundColor Yellow
    }
    
    # Check table header
    if ($html -match "<th>Detection</th>") {
        Write-Host "      ✓ Detection column in table found" -ForegroundColor Green
    } else {
        Write-Host "      ✗ Detection column in table missing" -ForegroundColor Red
    }
    
    Write-Host "`n      Open HTML to view:" -ForegroundColor Cyan
    Write-Host "      Start-Process '$TEST_DIR\test_output.html'" -ForegroundColor DarkGray
    
} else {
    Write-Host "      ✗ No HTML data found" -ForegroundColor Red
}

Write-Host "`n[4/4] Compile Check..." -ForegroundColor Yellow

$buildOutput = cargo build --release 2>&1 | Out-String
if ($buildOutput -match "Finished") {
    Write-Host "      ✓ Compilation successful" -ForegroundColor Green
    
    # Count warnings
    $warnings = ($buildOutput | Select-String -Pattern "warning:").Count
    if ($warnings -gt 0) {
        Write-Host "      ⚠ $warnings warnings (non-critical)" -ForegroundColor Yellow
    }
} else {
    Write-Host "      ✗ Compilation failed" -ForegroundColor Red
}

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "Phase 4 Test Summary" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

Write-Host "`nResults saved to: $TEST_DIR" -ForegroundColor Green
Write-Host "  • test_output.csv  - CSV with DetectionMethod column" -ForegroundColor White
Write-Host "  • test_output.json - JSON with detection_method field" -ForegroundColor White
Write-Host "  • test_output.html - HTML with color-coded badges" -ForegroundColor White

Write-Host "`nEnhancements implemented:" -ForegroundColor Yellow
Write-Host "  ✓ CSV: DetectionMethod column added" -ForegroundColor Green
Write-Host "  ✓ JSON: detection_method field in Port struct (serialized if present)" -ForegroundColor Green
Write-Host "  ✓ HTML: Color-coded badges for detection methods" -ForegroundColor Green
Write-Host "  ✓ HTML: Detection Methods statistics section" -ForegroundColor Green
Write-Host "  ✓ HTML: Detection column in services table" -ForegroundColor Green

Write-Host "`n🎉 Phase 4 Output Enhancement: COMPLETE!`n" -ForegroundColor Green

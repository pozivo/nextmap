# ================================================================
# NextMap - DVWA/WebGoat Test Script
# ================================================================
# Tests Nuclei integration against intentionally vulnerable apps
# Requires Docker to be installed
# ================================================================

param(
    [ValidateSet("DVWA", "WebGoat", "Both")]
    [string]$Target = "DVWA",
    
    [switch]$SkipDockerSetup,
    [switch]$StopContainers
)

$ErrorActionPreference = "Continue"

Write-Host "`n🎯 NextMap Nuclei - Vulnerable App Test`n" -ForegroundColor Cyan
Write-Host "Target: $Target" -ForegroundColor Yellow
Write-Host ""

$NEXTMAP = "target/release/nextmap.exe"
$RESULTS_DIR = "test_results_vulnerable_apps"

# ================================================================
# Docker Check
# ================================================================

Write-Host "[Setup] Checking Docker..." -ForegroundColor Yellow

try {
    $dockerVersion = docker --version 2>&1
    Write-Host "        ✓ Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "        ✗ Docker not found!" -ForegroundColor Red
    Write-Host "        Install Docker Desktop: https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

# ================================================================
# Container Management
# ================================================================

function Start-VulnerableApp {
    param(
        [string]$AppName,
        [string]$Image,
        [int]$Port,
        [string]$ContainerName
    )
    
    Write-Host "[Setup] Starting $AppName container..." -ForegroundColor Yellow
    
    # Check if container already exists
    $existing = docker ps -a --filter "name=$ContainerName" --format "{{.Names}}" 2>&1
    
    if ($existing -eq $ContainerName) {
        Write-Host "        Container exists, checking state..." -ForegroundColor DarkGray
        $running = docker ps --filter "name=$ContainerName" --format "{{.Names}}" 2>&1
        
        if ($running -eq $ContainerName) {
            Write-Host "        ✓ Container already running" -ForegroundColor Green
            return $true
        } else {
            Write-Host "        Starting existing container..." -ForegroundColor DarkGray
            docker start $ContainerName 2>&1 | Out-Null
        }
    } else {
        Write-Host "        Pulling image and creating container..." -ForegroundColor DarkGray
        docker run -d --name $ContainerName -p ${Port}:$Port $Image 2>&1 | Out-Null
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "        ✓ Container started on port $Port" -ForegroundColor Green
        Write-Host "        Waiting for app to initialize (10s)..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 10
        return $true
    } else {
        Write-Host "        ✗ Failed to start container" -ForegroundColor Red
        return $false
    }
}

function Stop-VulnerableApp {
    param([string]$ContainerName)
    
    Write-Host "[Cleanup] Stopping $ContainerName..." -ForegroundColor Yellow
    docker stop $ContainerName 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "          ✓ Container stopped" -ForegroundColor Green
    }
}

# ================================================================
# Handle -StopContainers flag
# ================================================================

if ($StopContainers) {
    Write-Host "Stopping all test containers..." -ForegroundColor Yellow
    Stop-VulnerableApp "nextmap_dvwa"
    Stop-VulnerableApp "nextmap_webgoat"
    Write-Host "`nContainers stopped.`n" -ForegroundColor Green
    exit 0
}

# ================================================================
# Create Results Directory
# ================================================================

if (!(Test-Path $RESULTS_DIR)) {
    New-Item -ItemType Directory -Path $RESULTS_DIR | Out-Null
}

# ================================================================
# Test DVWA (Damn Vulnerable Web Application)
# ================================================================

if ($Target -eq "DVWA" -or $Target -eq "Both") {
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "Testing against DVWA" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    if (!$SkipDockerSetup) {
        $dvwaReady = Start-VulnerableApp -AppName "DVWA" -Image "vulnerables/web-dvwa" -Port 80 -ContainerName "nextmap_dvwa"
        
        if (!$dvwaReady) {
            Write-Host "Skipping DVWA tests (container failed to start)`n" -ForegroundColor Yellow
        }
    }
    
    if ($dvwaReady -or $SkipDockerSetup) {
        Write-Host "`n[Test 1] DVWA - Critical & High Severity Scan" -ForegroundColor Yellow
        Write-Host "Command: $NEXTMAP -t localhost -p 80 --nuclei-scan --nuclei-severity critical,high --nuclei-tags cve,sqli,xss -f json -o dvwa_critical.json" -ForegroundColor DarkGray
        
        & $NEXTMAP -t localhost -p 80 --nuclei-scan --nuclei-severity critical,high --nuclei-tags cve,sqli,xss --banner -f json -o "$RESULTS_DIR/dvwa_critical.json" 2>&1 | Out-Null
        
        if (Test-Path "$RESULTS_DIR/dvwa_critical.json") {
            try {
                $results = Get-Content "$RESULTS_DIR/dvwa_critical.json" -Raw | ConvertFrom-Json
                $vulnCount = ($results.scan_results | ForEach-Object { $_.vulnerabilities.Count } | Measure-Object -Sum).Sum
                
                Write-Host "        ✓ Scan completed" -ForegroundColor Green
                Write-Host "        Vulnerabilities found: $vulnCount" -ForegroundColor $(if ($vulnCount -gt 0) { "Cyan" } else { "DarkGray" })
                
                # DVWA should have vulnerabilities
                if ($vulnCount -gt 0) {
                    Write-Host "        ✓ Vulnerabilities detected (as expected for DVWA)" -ForegroundColor Green
                } else {
                    Write-Host "        ⚠ No vulnerabilities found (unexpected for DVWA)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "        ✗ Failed to parse results" -ForegroundColor Red
            }
        }
        
        Write-Host "`n[Test 2] DVWA - All Severity Levels" -ForegroundColor Yellow
        & $NEXTMAP -t localhost -p 80 --nuclei-scan --nuclei-severity critical,high,medium,low --nuclei-tags web,cve -f html -o "$RESULTS_DIR/dvwa_all.html" 2>&1 | Out-Null
        
        if (Test-Path "$RESULTS_DIR/dvwa_all.html") {
            $htmlSize = (Get-Item "$RESULTS_DIR/dvwa_all.html").Length
            Write-Host "        ✓ HTML report generated ($([math]::Round($htmlSize/1KB, 2)) KB)" -ForegroundColor Green
        }
        
        Write-Host "`n[Test 3] DVWA - RCE & SQLi Focus" -ForegroundColor Yellow
        & $NEXTMAP -t localhost -p 80 --nuclei-scan --nuclei-tags rce,sqli --nuclei-severity critical,high -f csv -o "$RESULTS_DIR/dvwa_rce_sqli.csv" 2>&1 | Out-Null
        
        if (Test-Path "$RESULTS_DIR/dvwa_rce_sqli.csv") {
            $csvLines = (Get-Content "$RESULTS_DIR/dvwa_rce_sqli.csv").Count
            Write-Host "        ✓ CSV report generated ($csvLines lines)" -ForegroundColor Green
        }
    }
}

# ================================================================
# Test WebGoat
# ================================================================

if ($Target -eq "WebGoat" -or $Target -eq "Both") {
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "Testing against WebGoat" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    if (!$SkipDockerSetup) {
        $webgoatReady = Start-VulnerableApp -AppName "WebGoat" -Image "webgoat/webgoat" -Port 8080 -ContainerName "nextmap_webgoat"
        
        if (!$webgoatReady) {
            Write-Host "Skipping WebGoat tests (container failed to start)`n" -ForegroundColor Yellow
        }
    }
    
    if ($webgoatReady -or $SkipDockerSetup) {
        Write-Host "`n[Test 1] WebGoat - Critical Vulnerabilities" -ForegroundColor Yellow
        Write-Host "Command: $NEXTMAP -t localhost -p 8080 --nuclei-scan --nuclei-severity critical --nuclei-tags cve,rce -f json -o webgoat_critical.json" -ForegroundColor DarkGray
        
        & $NEXTMAP -t localhost -p 8080 --nuclei-scan --nuclei-severity critical --nuclei-tags cve,rce --banner -f json -o "$RESULTS_DIR/webgoat_critical.json" 2>&1 | Out-Null
        
        if (Test-Path "$RESULTS_DIR/webgoat_critical.json") {
            try {
                $results = Get-Content "$RESULTS_DIR/webgoat_critical.json" -Raw | ConvertFrom-Json
                $vulnCount = ($results.scan_results | ForEach-Object { $_.vulnerabilities.Count } | Measure-Object -Sum).Sum
                
                Write-Host "        ✓ Scan completed" -ForegroundColor Green
                Write-Host "        Vulnerabilities found: $vulnCount" -ForegroundColor Cyan
            } catch {
                Write-Host "        ✗ Failed to parse results" -ForegroundColor Red
            }
        }
        
        Write-Host "`n[Test 2] WebGoat - Comprehensive Scan" -ForegroundColor Yellow
        & $NEXTMAP -t localhost -p 8080 --nuclei-scan --nuclei-severity critical,high,medium --nuclei-tags web,java,cve -f html -o "$RESULTS_DIR/webgoat_comprehensive.html" 2>&1 | Out-Null
        
        if (Test-Path "$RESULTS_DIR/webgoat_comprehensive.html") {
            Write-Host "        ✓ HTML report generated" -ForegroundColor Green
        }
    }
}

# ================================================================
# Performance Comparison
# ================================================================

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "Performance Comparison" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

Write-Host "`n[Benchmark] Passive Scan (Banner + CVE DB)" -ForegroundColor Yellow
$passiveStart = Get-Date
& $NEXTMAP -t localhost -p 80 --banner --cve-db -f json -o "$RESULTS_DIR/benchmark_passive.json" 2>&1 | Out-Null
$passiveDuration = (Get-Date) - $passiveStart

Write-Host "            Completed in: $([math]::Round($passiveDuration.TotalSeconds, 2))s" -ForegroundColor DarkGray

if (Test-CommandExists "nuclei") {
    Write-Host "`n[Benchmark] Active Scan (Nuclei Critical)" -ForegroundColor Yellow
    $activeStart = Get-Date
    & $NEXTMAP -t localhost -p 80 --nuclei-scan --nuclei-severity critical -f json -o "$RESULTS_DIR/benchmark_active.json" 2>&1 | Out-Null
    $activeDuration = (Get-Date) - $activeStart
    
    Write-Host "            Completed in: $([math]::Round($activeDuration.TotalSeconds, 2))s" -ForegroundColor DarkGray
    
    $ratio = $activeDuration.TotalSeconds / $passiveDuration.TotalSeconds
    Write-Host "`n            Active/Passive ratio: $([math]::Round($ratio, 2))x" -ForegroundColor Cyan
    
    if ($ratio -lt 5) {
        Write-Host "            ✓ Performance acceptable (less than 5x slower)" -ForegroundColor Green
    } elseif ($ratio -lt 10) {
        Write-Host "            ⚠ Performance moderate (5-10x slower)" -ForegroundColor Yellow
    } else {
        Write-Host "            ✗ Performance poor (>10x slower)" -ForegroundColor Red
    }
}

# ================================================================
# Summary
# ================================================================

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

Write-Host "`nResults saved to: $RESULTS_DIR" -ForegroundColor Green
Write-Host ""

Get-ChildItem $RESULTS_DIR -Filter "*.json" | ForEach-Object {
    $size = [math]::Round($_.Length / 1KB, 2)
    Write-Host "  • $($_.Name) - ${size} KB" -ForegroundColor White
}

Write-Host "`nView reports:" -ForegroundColor Yellow
Get-ChildItem $RESULTS_DIR -Filter "*.html" | ForEach-Object {
    Write-Host "  Start-Process '$($_.FullName)'" -ForegroundColor DarkGray
}

Write-Host "`nCleanup containers:" -ForegroundColor Yellow
Write-Host "  .\test_dvwa.ps1 -StopContainers" -ForegroundColor DarkGray

Write-Host "`n" + "=" * 60 + "`n" -ForegroundColor Cyan

# Helper function for Test-CommandExists
function Test-CommandExists {
    param([string]$Command)
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

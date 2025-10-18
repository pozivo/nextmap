# Script to clean up GitHub releases and remove duplicate/old assets
# This script ensures each release only has its correct version binaries

param(
    [string]$Action = "verify"
)

$ErrorActionPreference = "Stop"
$repo = "pozivo/nextmap"

Write-Host "🧹 Cleaning up GitHub releases for $repo" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Function to clean a specific release
function Clean-Release {
    param([string]$version)
    
    Write-Host "📦 Processing release: $version" -ForegroundColor Yellow
    
    # Get all assets for this release
    Write-Host "  📋 Fetching assets..." -ForegroundColor Gray
    $releaseInfo = gh release view $version --repo $repo --json assets | ConvertFrom-Json
    $assets = $releaseInfo.assets
    
    if ($assets.Count -eq 0) {
        Write-Host "  ℹ️  No assets found" -ForegroundColor Gray
        return
    }
    
    Write-Host "  Found $($assets.Count) assets" -ForegroundColor Gray
    
    # Delete all existing assets
    Write-Host "  🗑️  Removing assets..." -ForegroundColor Gray
    foreach ($asset in $assets) {
        Write-Host "    ❌ Deleting: $($asset.name)" -ForegroundColor Red
        try {
            gh release delete-asset $version $asset.name --repo $repo --yes 2>$null
        } catch {
            Write-Host "      ⚠️  Could not delete $($asset.name)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "  ✅ Release $version cleaned!" -ForegroundColor Green
}

# Function to verify a release
function Verify-Release {
    param([string]$version)
    
    Write-Host ""
    Write-Host "🔍 Verifying release: $version" -ForegroundColor Cyan
    
    try {
        $releaseInfo = gh release view $version --repo $repo --json assets | ConvertFrom-Json
        $assetCount = $releaseInfo.assets.Count
        
        Write-Host "  📊 Asset count: $assetCount" -ForegroundColor Gray
        
        if ($assetCount -eq 4) {
            Write-Host "  ✅ Release has correct number of assets (4)" -ForegroundColor Green
        } elseif ($assetCount -eq 0) {
            Write-Host "  ⚠️  Release has no assets (workflow will add them)" -ForegroundColor Yellow
        } else {
            Write-Host "  ⚠️  Release has $assetCount assets (expected 4)" -ForegroundColor Yellow
        }
        
        if ($assetCount -gt 0) {
            Write-Host "  📦 Current assets:" -ForegroundColor Gray
            foreach ($asset in $releaseInfo.assets) {
                $size = [math]::Round($asset.size / 1MB, 2)
                Write-Host "    • $($asset.name) ($size MB)" -ForegroundColor White
            }
        }
    } catch {
        Write-Host "  ❌ Could not verify release $version" -ForegroundColor Red
    }
}

# Main execution
Write-Host "Available actions:" -ForegroundColor Cyan
Write-Host "1) Clean v0.2.5 only" -ForegroundColor White
Write-Host "2) Clean v0.3.0 only" -ForegroundColor White
Write-Host "3) Clean both v0.2.5 and v0.3.0" -ForegroundColor White
Write-Host "4) Clean all releases" -ForegroundColor White
Write-Host "5) Verify only (no changes) [Default]" -ForegroundColor White
Write-Host ""

if ($Action -eq "verify") {
    $choice = Read-Host "Enter choice (1-5, default=5)"
    if ([string]::IsNullOrWhiteSpace($choice)) {
        $choice = "5"
    }
} else {
    $choice = $Action
}

Write-Host ""

switch ($choice) {
    "1" {
        Clean-Release "v0.2.5"
        Verify-Release "v0.2.5"
    }
    "2" {
        Clean-Release "v0.3.0"
        Verify-Release "v0.3.0"
    }
    "3" {
        Clean-Release "v0.2.5"
        Clean-Release "v0.3.0"
        Verify-Release "v0.2.5"
        Verify-Release "v0.3.0"
    }
    "4" {
        Write-Host "📋 Fetching all releases..." -ForegroundColor Gray
        $releases = gh release list --repo $repo --limit 100 --json tagName | ConvertFrom-Json
        
        foreach ($release in $releases) {
            Clean-Release $release.tagName
        }
        
        Write-Host ""
        Write-Host "📊 Verification Summary" -ForegroundColor Cyan
        Write-Host "=======================" -ForegroundColor Cyan
        
        foreach ($release in $releases) {
            Verify-Release $release.tagName
        }
    }
    "5" {
        Write-Host "📋 Fetching all releases..." -ForegroundColor Gray
        $releases = gh release list --repo $repo --limit 100 --json tagName | ConvertFrom-Json
        
        Write-Host ""
        Write-Host "📊 Current Release Status" -ForegroundColor Cyan
        Write-Host "=========================" -ForegroundColor Cyan
        
        foreach ($release in $releases) {
            Verify-Release $release.tagName
        }
    }
    default {
        Write-Host "❌ Invalid choice" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "✅ Done!" -ForegroundColor Green
Write-Host ""
Write-Host "📝 Note: After cleaning, the next workflow run will upload" -ForegroundColor Yellow
Write-Host "   only the correct 4 binaries for each release." -ForegroundColor Yellow
Write-Host ""
Write-Host "🔄 To trigger a new build for a release, use:" -ForegroundColor Cyan
Write-Host "   git tag -f v0.3.0 && git push -f origin v0.3.0" -ForegroundColor White

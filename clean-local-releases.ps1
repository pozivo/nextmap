# Clean Local Releases Script
# This removes all local release artifacts
# GitHub Actions will handle all releases automatically

Write-Host "`n🧹 Cleaning Local Release Artifacts..." -ForegroundColor Cyan
Write-Host "GitHub Actions will handle all future releases automatically.`n" -ForegroundColor Yellow

$items_to_remove = @(
    # Release directories
    "release-windows",
    "releases",
    
    # Zip files
    "nextmap-v*.zip",
    
    # Manual build scripts (deprecated - use GitHub Actions)
    "build-releases.bat",
    "build-releases.sh",
    "manual-release.bat",
    "manual-release.sh",
    "check-release-status.bat",
    "check-release-status.sh",
    "check-v0.2.5-status.bat",
    "analyze-workflow-errors.bat",
    
    # Old test output directories
    "csv",
    "json"
)

$removed_count = 0
$skipped_count = 0

foreach ($item in $items_to_remove) {
    if (Test-Path $item) {
        try {
            Remove-Item -Path $item -Recurse -Force -ErrorAction Stop
            Write-Host "  ✓ Removed: $item" -ForegroundColor Green
            $removed_count++
        } catch {
            Write-Host "  ✗ Failed to remove: $item - $_" -ForegroundColor Red
        }
    } else {
        Write-Host "  ⊘ Not found: $item" -ForegroundColor Gray
        $skipped_count++
    }
}

Write-Host "`n📊 Summary:" -ForegroundColor Cyan
Write-Host "  Removed: $removed_count items" -ForegroundColor Green
Write-Host "  Skipped: $skipped_count items (not found)" -ForegroundColor Gray

Write-Host "`n✅ Cleanup complete!" -ForegroundColor Green
Write-Host "   From now on, use GitHub Actions to create releases." -ForegroundColor Yellow
Write-Host "   Push a tag (e.g., 'v0.3.1') and GitHub will build for all platforms.`n" -ForegroundColor Yellow

#!/bin/bash

# Script to clean up GitHub releases and remove duplicate/old assets
# This script ensures each release only has its correct version binaries

set -e

REPO="pozivo/nextmap"

echo "🧹 Cleaning up GitHub releases for $REPO"
echo "============================================="

# Function to clean a specific release
clean_release() {
    local version=$1
    echo ""
    echo "📦 Processing release: $version"
    
    # Expected assets for this release
    local expected_assets=(
        "nextmap-linux-x64.tar.gz"
        "nextmap-windows-x64.zip"
        "nextmap-macos-x64.tar.gz"
        "nextmap-macos-arm64.tar.gz"
    )
    
    # Get all assets for this release
    echo "  📋 Fetching assets..."
    local assets=$(gh release view "$version" --repo "$REPO" --json assets --jq '.assets[].name')
    
    # Delete all existing assets
    echo "  🗑️  Removing old assets..."
    while IFS= read -r asset; do
        if [ -n "$asset" ]; then
            echo "    ❌ Deleting: $asset"
            gh release delete-asset "$version" "$asset" --repo "$REPO" --yes 2>/dev/null || echo "      ⚠️  Could not delete $asset"
        fi
    done <<< "$assets"
    
    echo "  ✅ Release $version cleaned!"
}

# Function to verify a release
verify_release() {
    local version=$1
    echo ""
    echo "🔍 Verifying release: $version"
    
    local asset_count=$(gh release view "$version" --repo "$REPO" --json assets --jq '.assets | length')
    echo "  📊 Asset count: $asset_count"
    
    if [ "$asset_count" -eq 4 ]; then
        echo "  ✅ Release has correct number of assets (4)"
    else
        echo "  ⚠️  Release has $asset_count assets (expected 4)"
    fi
    
    gh release view "$version" --repo "$REPO" --json assets --jq '.assets[].name' | while read -r asset; do
        echo "    📦 $asset"
    done
}

# Main execution
echo ""
echo "Which releases do you want to clean?"
echo "1) v0.2.5 only"
echo "2) v0.3.0 only"
echo "3) Both v0.2.5 and v0.3.0"
echo "4) All releases"
echo "5) Just verify (no changes)"
echo ""
read -p "Enter choice (1-5): " choice

case $choice in
    1)
        clean_release "v0.2.5"
        verify_release "v0.2.5"
        ;;
    2)
        clean_release "v0.3.0"
        verify_release "v0.3.0"
        ;;
    3)
        clean_release "v0.2.5"
        clean_release "v0.3.0"
        verify_release "v0.2.5"
        verify_release "v0.3.0"
        ;;
    4)
        # Get all release tags
        releases=$(gh release list --repo "$REPO" --limit 100 --json tagName --jq '.[].tagName')
        while IFS= read -r release; do
            if [ -n "$release" ]; then
                clean_release "$release"
            fi
        done <<< "$releases"
        
        echo ""
        echo "📊 Verification Summary"
        echo "======================="
        while IFS= read -r release; do
            if [ -n "$release" ]; then
                verify_release "$release"
            fi
        done <<< "$releases"
        ;;
    5)
        # Just verify all releases
        releases=$(gh release list --repo "$REPO" --limit 100 --json tagName --jq '.[].tagName')
        echo ""
        echo "📊 Current Release Status"
        echo "========================="
        while IFS= read -r release; do
            if [ -n "$release" ]; then
                verify_release "$release"
            fi
        done <<< "$releases"
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "✅ Done!"
echo ""
echo "📝 Note: After cleaning, the next workflow run will upload"
echo "   only the correct 4 binaries for each release."

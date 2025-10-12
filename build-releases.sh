#!/bin/bash

# Local multi-platform build script for NextMap
# Run this script to test cross-compilation locally

set -e

echo "🚀 Building NextMap for multiple platforms..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create releases directory
mkdir -p releases
cd releases

# Define targets
targets=(
    "x86_64-unknown-linux-gnu:linux-x64"
    "x86_64-unknown-linux-musl:linux-musl-x64"
    "x86_64-pc-windows-msvc:windows-x64"
    "x86_64-apple-darwin:macos-x64"
    "aarch64-apple-darwin:macos-arm64"
)

echo -e "${YELLOW}Installing required targets...${NC}"
for target_info in "${targets[@]}"; do
    target=$(echo $target_info | cut -d: -f1)
    echo "Adding target: $target"
    rustup target add $target || echo "Target $target already installed"
done

echo -e "${YELLOW}Building binaries...${NC}"

for target_info in "${targets[@]}"; do
    target=$(echo $target_info | cut -d: -f1)
    name=$(echo $target_info | cut -d: -f2)
    
    echo -e "${GREEN}Building for $target ($name)...${NC}"
    
    # Build
    if cargo build --release --target $target; then
        echo -e "${GREEN}✅ Build successful for $target${NC}"
        
        # Create release directory
        mkdir -p $name
        
        # Copy binary
        if [[ "$target" == *"windows"* ]]; then
            cp ../target/$target/release/nextmap.exe $name/
            binary_name="nextmap.exe"
        else
            cp ../target/$target/release/nextmap $name/
            binary_name="nextmap"
            # Strip binary for smaller size
            if command -v strip &> /dev/null; then
                strip $name/$binary_name
            fi
        fi
        
        # Copy documentation
        cp ../README.md $name/ 2>/dev/null || echo "README.md not found"
        cp ../LICENSE $name/ 2>/dev/null || echo "LICENSE not found"
        
        # Create archive
        if [[ "$target" == *"windows"* ]]; then
            if command -v 7z &> /dev/null; then
                7z a nextmap-$name.zip $name/*
            elif command -v zip &> /dev/null; then
                (cd $name && zip -r ../nextmap-$name.zip *)
            else
                echo -e "${RED}❌ No archive tool found for Windows build${NC}"
            fi
        else
            tar -czf nextmap-$name.tar.gz -C $name .
        fi
        
        # Cleanup
        rm -rf $name
        
        echo -e "${GREEN}✅ Archive created: nextmap-$name${NC}"
    else
        echo -e "${RED}❌ Build failed for $target${NC}"
    fi
    
    echo ""
done

echo -e "${GREEN}🎉 Build complete! Archives created in releases/ directory:${NC}"
ls -la *.{tar.gz,zip} 2>/dev/null || echo "No archives found"

echo ""
echo -e "${YELLOW}📝 Next steps:${NC}"
echo "1. Test the binaries on target platforms"
echo "2. Create a git tag: git tag v0.1.0"
echo "3. Push to GitHub: git push origin v0.1.0"
echo "4. GitHub Actions will automatically create the release"

cd ..
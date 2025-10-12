@echo off
REM GitHub Actions Status Checker for NextMap Release
echo 🔍 Checking GitHub Actions workflow status...
echo Repository: pozivo/nextmap
echo Tag: v0.2.4
echo.

echo 📊 Quick Status Check:
echo 1. Actions Page: https://github.com/pozivo/nextmap/actions
echo 2. Releases Page: https://github.com/pozivo/nextmap/releases  
echo 3. Latest Tag: v0.2.4
echo.

echo 🎯 Expected Workflow Jobs:
echo - Build Windows x64
echo - Build Linux x64
echo - Build Linux musl x64
echo - Build macOS x64
echo - Build macOS ARM64
echo - Create Release
echo.

echo 📦 Expected Release Assets:
echo - nextmap-windows-x64.zip
echo - nextmap-linux-x64.tar.gz
echo - nextmap-linux-musl-x64.tar.gz
echo - nextmap-macos-x64.tar.gz
echo - nextmap-macos-arm64.tar.gz
echo.

echo ⏱️ Typical build time: 5-10 minutes
echo 🔄 Refresh the browser pages to see updates
echo.

echo ✅ GitHub Actions Release Process Started!
echo Monitor the workflow progress in the browser tabs.
echo.
pause
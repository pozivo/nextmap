@echo off
REM Manual Release Creation Script for NextMap - Windows
REM Use when GitHub Actions workflow has issues

echo 🚀 NextMap Manual Release Creator (Windows)
echo ===============================================

set VERSION=v0.2.3
set REPO=pozivo/nextmap

echo.
echo 📋 This script helps create manual releases when automation fails
echo Version: %VERSION%
echo Repository: %REPO%
echo.

echo 📁 Local Build Instructions:
echo 1. Build for Windows:
echo    cargo build --release --target x86_64-pc-windows-msvc
echo.

echo 📦 Archive Creation:
echo 2. Create Windows archive:
echo    mkdir release-windows
echo    copy target\x86_64-pc-windows-msvc\release\nextmap.exe release-windows\
echo    copy README.md release-windows\
echo    copy LICENSE release-windows\
echo    cd release-windows
echo    powershell Compress-Archive -Path * -DestinationPath ..\nextmap-windows-x64.zip
echo    cd ..
echo.

echo 🌐 GitHub Release Creation:
echo 3. Manual upload to GitHub:
echo    - Go to: https://github.com/%REPO%/releases/new
echo    - Tag: %VERSION%
echo    - Title: NextMap %VERSION%
echo    - Upload nextmap-windows-x64.zip
echo.

echo 💡 Check Release Status:
echo 4. Monitor automated releases:
echo    - Actions: https://github.com/%REPO%/actions
echo    - Releases: https://github.com/%REPO%/releases
echo.

echo 🔧 GitHub Actions Troubleshooting:
echo Common issues and solutions:
echo - File pattern matching: Check *.zip and *.tar.gz patterns
echo - Permissions: Ensure GITHUB_TOKEN has contents:write
echo - Build failures: Check Rust toolchain and dependencies
echo - Upload failures: Verify artifact download step
echo.

echo ✅ Manual release creation ready!
echo Follow the steps above if automated workflow fails.
echo.
pause
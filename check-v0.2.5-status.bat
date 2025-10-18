@echo off
echo 🔍 NextMap v0.2.5 Workflow Analysis
echo Run ID: 18446875422
echo Job ID: 52554837964
echo Repository: pozivo/nextmap
echo.

echo 📊 Workflow Overview:
echo - Run URL: https://github.com/pozivo/nextmap/actions/runs/18446875422
echo - Specific Job: https://github.com/pozivo/nextmap/actions/runs/18446875422/job/52554837964
echo - Releases Page: https://github.com/pozivo/nextmap/releases
echo.

echo 🎯 v0.2.5 OpenSSL Fixes Applied:
echo ✅ Linux dependencies: pkg-config libssl-dev
echo ✅ Musl static linking: OPENSSL_STATIC=1 
echo ✅ Cross-compilation: PKG_CONFIG_ALLOW_CROSS=1
echo ✅ macOS homebrew: OpenSSL setup
echo ✅ Windows archiving: PowerShell Compress-Archive
echo.

echo 📋 Expected Job Matrix (5 + 1):
echo 1. Windows x64 (windows-latest, x86_64-pc-windows-msvc)
echo 2. Linux x64 (ubuntu-latest, x86_64-unknown-linux-gnu)  
echo 3. Linux musl (ubuntu-latest, x86_64-unknown-linux-musl)
echo 4. macOS Intel (macos-latest, x86_64-apple-darwin)
echo 5. macOS ARM64 (macos-latest, aarch64-apple-darwin)
echo 6. Release creation (ubuntu-latest, creates GitHub release)
echo.

echo 🔍 Status Check Points:
echo - Are all 5 build jobs green? ✅/❌
echo - Did the release job complete? ✅/❌  
echo - Are binaries available for download? ✅/❌
echo - Any remaining OpenSSL errors? ✅/❌
echo.

echo 🚀 Success Indicators:
echo ✅ All jobs show green checkmarks
echo ✅ Release v0.2.5 visible on releases page
echo ✅ 5 downloadable assets (zip + tar.gz files)
echo ✅ Professional release notes generated
echo.

echo 🔧 If Issues Remain:
echo - Check specific job logs for error details
echo - Look for compilation, archiving, or upload errors
echo - Review OpenSSL, dependencies, or artifact issues
echo.

echo 📊 Check the browser tabs to see current status!
echo.
pause
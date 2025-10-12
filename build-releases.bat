@echo off
REM Local multi-platform build script for NextMap (Windows version)
REM Run this script to test cross-compilation locally

echo 🚀 Building NextMap for multiple platforms...

REM Create releases directory
if not exist releases mkdir releases
cd releases

echo Installing required targets...
C:\Users\poziv\.cargo\bin\rustup.exe target add x86_64-unknown-linux-gnu
C:\Users\poziv\.cargo\bin\rustup.exe target add x86_64-unknown-linux-musl
C:\Users\poziv\.cargo\bin\rustup.exe target add x86_64-pc-windows-msvc
C:\Users\poziv\.cargo\bin\rustup.exe target add x86_64-apple-darwin
C:\Users\poziv\.cargo\bin\rustup.exe target add aarch64-apple-darwin

echo Building binaries...

REM Windows x64
echo Building for Windows x64...
C:\Users\poziv\.cargo\bin\cargo.exe build --release --target x86_64-pc-windows-msvc
if %errorlevel% equ 0 (
    echo ✅ Build successful for Windows x64
    mkdir windows-x64
    copy ..\target\x86_64-pc-windows-msvc\release\nextmap.exe windows-x64\
    copy ..\README.md windows-x64\ 2>nul
    copy ..\LICENSE windows-x64\ 2>nul
    powershell -command "Compress-Archive -Path windows-x64\* -DestinationPath nextmap-windows-x64.zip"
    rmdir /s /q windows-x64
    echo ✅ Archive created: nextmap-windows-x64.zip
) else (
    echo ❌ Build failed for Windows x64
)

REM Linux x64 (requires WSL or Docker for full cross-compilation)
echo Building for Linux x64...
C:\Users\poziv\.cargo\bin\cargo.exe build --release --target x86_64-unknown-linux-gnu
if %errorlevel% equ 0 (
    echo ✅ Build successful for Linux x64
    mkdir linux-x64
    copy ..\target\x86_64-unknown-linux-gnu\release\nextmap linux-x64\
    copy ..\README.md linux-x64\ 2>nul
    copy ..\LICENSE linux-x64\ 2>nul
    tar -czf nextmap-linux-x64.tar.gz -C linux-x64 .
    rmdir /s /q linux-x64
    echo ✅ Archive created: nextmap-linux-x64.tar.gz
) else (
    echo ❌ Build failed for Linux x64 (may require WSL or Docker)
)

echo.
echo 🎉 Build complete! Check releases\ directory for archives
dir *.zip *.tar.gz 2>nul

echo.
echo 📝 Next steps:
echo 1. Test the binaries on target platforms
echo 2. Create a git tag: git tag v0.1.0
echo 3. Push to GitHub: git push origin v0.1.0
echo 4. GitHub Actions will automatically create the release

cd ..
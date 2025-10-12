@echo off
REM NextMap nmap-style Behavior Test v0.2.1
REM Test dei nuovi preset di porte e comportamenti

echo 🧪 ==============================================
echo 🔍 NextMap nmap-style Behavior Test v0.2.1
echo 🧪 ==============================================

set NEXTMAP=.\target\debug\nextmap.exe

echo.
echo 🔧 Pre-test setup
echo Checking NextMap binary...

if not exist "%NEXTMAP%" (
    echo ❌ NextMap binary not found - trying release build...
    set NEXTMAP=.\target\release\nextmap.exe
    if not exist "!NEXTMAP!" (
        echo ❌ NextMap binary not found at !NEXTMAP!
        echo 💡 Build first with: cargo build --release
        pause
        exit /b 1
    )
)

echo ✅ NextMap binary found: %NEXTMAP%
echo.

echo 📋 TESTING NMAP-STYLE PORT BEHAVIOR:
echo ==========================================
echo.

echo 🧪 TEST 1: Default behavior (should be top1000)
echo --------------------------------------------------
echo Command: %NEXTMAP% --target 127.0.0.1 --timeout 1000
echo Expected: "TCP Ports: 1000 (top 1000 common ports - nmap default)"
echo.
%NEXTMAP% --target 127.0.0.1 --timeout 1000 | findstr /C:"TCP Ports"
echo.

echo 🧪 TEST 2: Top 100 preset
echo --------------------------------------------------
echo Command: %NEXTMAP% --target 127.0.0.1 --ports "top100" --timeout 1000
echo Expected: "TCP Ports: 100 (top 100 common ports)"
echo.
%NEXTMAP% --target 127.0.0.1 --ports "top100" --timeout 1000 | findstr /C:"TCP Ports"
echo.

echo 🧪 TEST 3: All ports preset (should show WARNING)
echo --------------------------------------------------
echo Command: %NEXTMAP% --target 127.0.0.1 --ports "all" --timeout 1000
echo Expected: "TCP Ports: 65535 (all ports)" + WARNING messages
echo.
%NEXTMAP% --target 127.0.0.1 --ports "all" --timeout 1000 | findstr /C:"TCP Ports\|WARNING\|TIP"
echo.

echo 🧪 TEST 4: Custom ports
echo --------------------------------------------------
echo Command: %NEXTMAP% --target 127.0.0.1 --ports "80,443,22" --timeout 1000
echo Expected: "TCP Ports: 3 custom ports"
echo.
%NEXTMAP% --target 127.0.0.1 --ports "80,443,22" --timeout 1000 | findstr /C:"TCP Ports"
echo.

echo 🧪 TEST 5: Large range (should show warning)
echo --------------------------------------------------
echo Command: %NEXTMAP% --target 127.0.0.1 --ports "1-6000" --timeout 1000
echo Expected: "TCP Ports: 6000 custom ports" + WARNING for large range
echo.
%NEXTMAP% --target 127.0.0.1 --ports "1-6000" --timeout 1000 | findstr /C:"TCP Ports\|WARNING"
echo.

echo 🧪 ==============================================
echo ✅ NMAP-STYLE BEHAVIOR TESTING COMPLETE
echo 🧪 ==============================================
echo.
echo 📋 MANUAL VERIFICATION CHECKLIST:
echo.
echo ✅ Default scan should use 1000 ports (top1000)
echo ✅ top100 preset should use 100 ports
echo ✅ all preset should show WARNING and use 65535 ports
echo ✅ Custom ports should show correct count
echo ✅ Large ranges (5000+) should show WARNING
echo ✅ Full port scan should show comprehensive warning
echo.
echo 🎯 NextMap now behaves like nmap by default!
echo 💡 Use --ports "all" for comprehensive scanning
echo.
pause
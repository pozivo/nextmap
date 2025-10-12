@echo off
REM NextMap Test Suite v0.2.0 - Windows PowerShell version
REM Comprehensive testing script for all features

echo 🧪 ==============================================
echo 🔍 NextMap Test Suite v0.2.0 (Windows)
echo 🧪 ==============================================

set NEXTMAP=.\target\debug\nextmap.exe
set TESTS_TOTAL=0
set TESTS_PASSED=0
set TESTS_FAILED=0

echo.
echo 🔧 Pre-test setup
echo Checking NextMap binary...

if not exist "%NEXTMAP%" (
    echo ❌ NextMap binary not found at %NEXTMAP%
    exit /b 1
)

echo ✅ NextMap binary found

REM Test function simulation via labels
call :run_test "Version Check" "%NEXTMAP% --version"
call :run_test "Help Output" "%NEXTMAP% --help >nul"
call :run_test "Basic TCP Scan" "%NEXTMAP% --target 127.0.0.1 --ports 80,443 --timeout 2000"
call :run_test "Service Detection" "%NEXTMAP% --target 127.0.0.1 --ports 80 -s --timeout 2000"
call :run_test "OS Detection" "%NEXTMAP% --target 127.0.0.1 --ports 80 -O --timeout 2000"
call :run_test "Stealth Mode Shadow" "%NEXTMAP% --target 8.8.8.8 --ports 53 --stealth-mode shadow --timeout 3000"
call :run_test "UDP Scanning" "%NEXTMAP% --target 8.8.8.8 --udp-scan --udp-ports 53 --timeout 3000"
call :run_test "JSON Output" "%NEXTMAP% --target 127.0.0.1 --ports 80 --output-format json --timeout 2000"
call :run_test "XML Output" "%NEXTMAP% --target 127.0.0.1 --ports 80 --output-format xml --timeout 2000"
call :run_test "Markdown Output" "%NEXTMAP% --target 127.0.0.1 --ports 80 --output-format md --timeout 2000"

echo.
echo 🧪 ==============================================
echo 📊 TEST RESULTS SUMMARY  
echo 🧪 ==============================================
echo 📋 Total Tests: %TESTS_TOTAL%
echo ✅ Passed: %TESTS_PASSED%
echo ❌ Failed: %TESTS_FAILED%

if %TESTS_FAILED%==0 (
    echo.
    echo 🎉 ALL TESTS PASSED! NextMap v0.2.0 is working perfectly!
    exit /b 0
) else (
    echo.
    echo ⚠️ Some tests failed. Please review the results above.
    exit /b 1
)

:run_test
set /a TESTS_TOTAL+=1
echo.
echo 📋 Test %TESTS_TOTAL%: %~1
echo Command: %~2

%~2
if %errorlevel%==0 (
    echo ✅ PASSED
    set /a TESTS_PASSED+=1
) else (
    echo ❌ FAILED - Exit code: %errorlevel%
    set /a TESTS_FAILED+=1
)
goto :eof
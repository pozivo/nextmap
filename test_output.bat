@echo off
echo Testing Enhanced Output Formatting...
echo.

echo [1/4] Testing JSON output...
.\target\release\nextmap.exe -t 8.8.8.8 -p 53 -sV --output-format json > test_output.json 2>&1
echo Done. File size:
dir test_output.json | find "test_output.json"
echo.

echo [2/4] Testing CSV output...
.\target\release\nextmap.exe -t 8.8.8.8 -p 53 -sV --output-format csv > test_output.csv 2>&1
echo Done. File size:
dir test_output.csv | find "test_output.csv"
echo.

echo [3/4] Testing HTML output...
.\target\release\nextmap.exe -t 8.8.8.8 -p 53 -sV --output-format html > test_output.html 2>&1
echo Done. File size:
dir test_output.html | find "test_output.html"
echo.

echo [4/4] Displaying JSON content...
type test_output.json
echo.

echo.
echo === Test Complete ===
echo Open test_output.html in your browser to see the report!

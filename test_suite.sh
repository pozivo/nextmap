#!/bin/bash
# NextMap Test Suite v0.2.0
# Comprehensive testing script for all features

echo "🧪 =============================================="
echo "🔍 NextMap Test Suite v0.2.0"
echo "🧪 =============================================="

NEXTMAP="./target/debug/nextmap.exe"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local command="$2"
    local expected_exit_code="${3:-0}"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo -e "\n${BLUE}📋 Test $TESTS_TOTAL: $test_name${NC}"
    echo -e "${YELLOW}Command: $command${NC}"
    
    if eval "$command"; then
        actual_exit_code=$?
        if [ $actual_exit_code -eq $expected_exit_code ]; then
            echo -e "${GREEN}✅ PASSED${NC}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}❌ FAILED - Exit code: $actual_exit_code (expected: $expected_exit_code)${NC}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        echo -e "${RED}❌ FAILED - Command execution error${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

echo -e "\n🔧 Pre-test setup"
echo "Checking NextMap binary..."
if [ ! -f "$NEXTMAP" ]; then
    echo -e "${RED}❌ NextMap binary not found at $NEXTMAP${NC}"
    exit 1
fi

echo -e "${GREEN}✅ NextMap binary found${NC}"

# Test 1: Version check
run_test "Version Check" "$NEXTMAP --version"

# Test 2: Help output
run_test "Help Output" "$NEXTMAP --help > /dev/null"

# Test 3: Basic localhost scan
run_test "Basic TCP Scan (localhost)" "$NEXTMAP --target 127.0.0.1 --ports 80,443 --timeout 2000"

# Test 4: Service detection
run_test "Service Detection" "$NEXTMAP --target 127.0.0.1 --ports 80 -s --timeout 2000"

# Test 5: OS detection
run_test "OS Detection" "$NEXTMAP --target 127.0.0.1 --ports 80 -O --timeout 2000"

# Test 6: Stealth mode - Shadow
run_test "Stealth Mode (Shadow)" "$NEXTMAP --target 8.8.8.8 --ports 53 --stealth-mode shadow --timeout 3000"

# Test 7: Stealth mode - Ninja  
run_test "Stealth Mode (Ninja)" "$NEXTMAP --target 8.8.8.8 --ports 53 --stealth-mode ninja --timeout 3000"

# Test 8: Stealth mode - Ghost
run_test "Stealth Mode (Ghost)" "$NEXTMAP --target 8.8.8.8 --ports 53 --stealth-mode ghost --timeout 5000"

# Test 9: UDP scanning
run_test "UDP Scanning" "$NEXTMAP --target 8.8.8.8 --udp-scan --udp-ports 53 --timeout 3000"

# Test 10: Combined TCP+UDP
run_test "Combined TCP+UDP Scan" "$NEXTMAP --target 8.8.8.8 --ports 53,80 --udp-scan --udp-ports 53 --timeout 3000"

# Test 11: JSON output
run_test "JSON Output Format" "$NEXTMAP --target 127.0.0.1 --ports 80 --output-format json --timeout 2000"

# Test 12: YAML output
run_test "YAML Output Format" "$NEXTMAP --target 127.0.0.1 --ports 80 --output-format yaml --timeout 2000"

# Test 13: XML output
run_test "XML Output Format" "$NEXTMAP --target 127.0.0.1 --ports 80 --output-format xml --timeout 2000"

# Test 14: CSV output
run_test "CSV Output Format" "$NEXTMAP --target 127.0.0.1 --ports 80 --output-format csv --timeout 2000"

# Test 15: Markdown output
run_test "Markdown Output Format" "$NEXTMAP --target 127.0.0.1 --ports 80 --output-format md --timeout 2000"

# Test 16: File output
run_test "File Output" "$NEXTMAP --target 127.0.0.1 --ports 80 --output-file test_results.json --output-format json --timeout 2000"

# Test 17: Rate limiting
run_test "Rate Limiting" "$NEXTMAP --target 127.0.0.1 --ports 80,443 --rate-limit 500 --timeout 2000"

# Test 18: Timing templates
run_test "Timing Template (Sneaky)" "$NEXTMAP --target 127.0.0.1 --ports 80 --timing-template sneaky --timeout 5000"

# Test 19: Timing template (Aggressive)
run_test "Timing Template (Aggressive)" "$NEXTMAP --target 127.0.0.1 --ports 80 --timing-template aggressive --timeout 500"

# Test 20: CIDR scanning
run_test "CIDR Scanning (small range)" "$NEXTMAP --target 127.0.0.1/32 --ports 80 --timeout 2000"

# Test 21: IP range scanning
run_test "IP Range Scanning" "$NEXTMAP --target 127.0.0.1-127.0.0.1 --ports 80 --timeout 2000"

# Test 22: Invalid target (should fail gracefully)
run_test "Invalid Target Handling" "$NEXTMAP --target invalid.target.test --ports 80 --timeout 1000" 1

# Test 23: Invalid port range
run_test "Invalid Port Range" "$NEXTMAP --target 127.0.0.1 --ports 70000 --timeout 1000" 1

# Test 24: Combined stealth + service detection
run_test "Stealth + Service Detection" "$NEXTMAP --target 8.8.8.8 --ports 53 --stealth-mode shadow -s --timeout 3000"

# Final results
echo -e "\n🧪 =============================================="
echo -e "📊 TEST RESULTS SUMMARY"
echo -e "🧪 =============================================="
echo -e "📋 Total Tests: $TESTS_TOTAL"
echo -e "${GREEN}✅ Passed: $TESTS_PASSED${NC}"
echo -e "${RED}❌ Failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n🎉 ${GREEN}ALL TESTS PASSED! NextMap v0.2.0 is working perfectly!${NC}"
    exit 0
else
    echo -e "\n⚠️ ${YELLOW}Some tests failed. Please review the results above.${NC}"
    exit 1
fi
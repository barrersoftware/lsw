#!/bin/bash
# LSW Comprehensive Test Suite

export LD_LIBRARY_PATH=./build/lib
LOADER=./build/bin/lsw-pe-loader

echo "🏴‍☠️ LSW COMPREHENSIVE TEST SUITE"
echo "=================================="
echo ""

PASS=0
FAIL=0
TOTAL=0

run_test() {
    local test_name=$1
    local test_exe=$2
    TOTAL=$((TOTAL + 1))
    
    echo "[$TOTAL] Testing: $test_name"
    echo "    File: $test_exe"
    
    if [ ! -f "$test_exe" ]; then
        echo "    ❌ SKIP - File not found"
        echo ""
        return
    fi
    
    # Run the test and capture output
    if timeout 5 $LOADER --launch "$test_exe" > /tmp/lsw_test_$TOTAL.log 2>&1; then
        echo "    ✅ PASS - Exit code 0"
        PASS=$((PASS + 1))
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo "    ⏱️  TIMEOUT - Test took >5 seconds"
        else
            echo "    ❌ FAIL - Exit code $exit_code"
        fi
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

# Run all tests
run_test "Command Line Args" "./test_args.exe"
run_test "Command Line Parsing" "./test_cmdline.exe"
run_test "Console I/O" "./test_console.exe"
run_test "Console + File I/O" "./test_console_and_file.exe"
run_test "Environment Variables" "./test_env.exe"
run_test "Exit Codes" "./test_exit.exe"
run_test "C: Drive File Access" "./test_file_cdrive.exe"
run_test "File Operations" "./test_fileops.exe"
run_test "Handle Management" "./test_handle.exe"
run_test "Network Sockets" "./test_network.exe"
run_test "File Read/Write" "./test_readwrite.exe"
run_test "Full Read/Write" "./test_readwrite_full.exe"
run_test "Read/Write v2" "./test_readwrite_v2.exe"
run_test "Registry Access" "./test_registry.exe"
run_test "Registry Environment" "./test_registry_env.exe"
run_test "Threading" "./test_thread.exe"
run_test "Threading Complete" "./test_threading_complete.exe"
run_test "Write Operations" "./test_write.exe"

# Also test original hello.exe
run_test "Hello World (Original)" "./hello.exe"
run_test "Test Demo" "./test.exe"

echo "=================================="
echo "🏴‍☠️ TEST RESULTS SUMMARY"
echo "=================================="
echo "Total Tests: $TOTAL"
echo "✅ Passed: $PASS"
echo "❌ Failed: $FAIL"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED! 🎉"
else
    echo "⚠️  Some tests failed. Check logs in /tmp/lsw_test_*.log"
fi

#!/bin/bash
# K-Scanner test runner
# Executes basic functionality tests

echo "Running K-Scanner tests..."

# Test 1: Basic execution
./bin/kscanner > /tmp/kscanner_test.txt
if [ $? -eq 0 ]; then
    echo "✅ Test passed: Basic execution"
else
    echo "❌ Test failed: Basic execution"
    exit 1
fi

# Test 2: Version output
./bin/kscanner -v | grep -q "K-Scanner version"
if [ $? -eq 0 ]; then
    echo "✅ Test passed: Version display"
else
    echo "❌ Test failed: Version display"
    exit 1
fi

echo "All tests completed successfully"

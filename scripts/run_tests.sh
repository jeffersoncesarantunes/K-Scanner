#!/bin/bash
# K-Scanner test runner
# Executes basic functionality tests

TARGET="./kscanner"

echo "Running K-Scanner tests..."

TMPDIR=$(mktemp -d /tmp/kscanner_test_XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

# Test 1: Help output
$TARGET --help > "$TMPDIR/help.txt" 2>&1
if [ $? -eq 0 ] && grep -q "K-Scanner" "$TMPDIR/help.txt"; then
    echo "Test passed: Help output"
else
    echo "Test failed: Help output"
    exit 1
fi

# Test 2: JSON export (headless, no TUI)
$TARGET --json > "$TMPDIR/json.txt" 2>&1
if [ $? -eq 0 ] && grep -q '^\[' "$TMPDIR/json.txt"; then
    echo "Test passed: JSON export"
else
    echo "Test failed: JSON export"
    exit 1
fi

# Test 3: CSV export (headless, no TUI)
$TARGET --csv > "$TMPDIR/csv.txt" 2>&1
if [ $? -eq 0 ] && grep -q "PID,PROCESS_NAME" "$TMPDIR/csv.txt"; then
    echo "Test passed: CSV export"
else
    echo "Test failed: CSV export"
    exit 1
fi

echo "All tests completed successfully"

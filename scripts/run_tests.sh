#!/bin/bash
TARGET="./kscanner"
echo "Running K-Scanner tests..."
TMPDIR=$(mktemp -d /tmp/kscanner_test_XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

$TARGET --help > "$TMPDIR/help.txt" 2>&1
if grep -q "Usage:" "$TMPDIR/help.txt"; then
    echo "Test passed: Help output"
else
    echo "Test failed: Help output"
    exit 1
fi

$TARGET --json > "$TMPDIR/json.txt" 2>&1
if grep -q '^\[' "$TMPDIR/json.txt"; then
    echo "Test passed: JSON export"
else
    echo "Test failed: JSON export"
    exit 1
fi

$TARGET --csv > "$TMPDIR/csv.txt" 2>&1
if grep -q "PID,PROCESS_NAME" "$TMPDIR/csv.txt"; then
    echo "Test passed: CSV export"
else
    echo "Test failed: CSV export"
    exit 1
fi

echo "All tests completed successfully"

#!/bin/bash
# K-Scanner diagnostic tool
# Provides multiple levels of system checking

echo "K-Scanner Diagnostic Tool"
echo "=========================="

echo "1) Quick check (source stats)"
echo "2) Deep analyze (TODOs/FIXMEs)"
echo "3) Final verification (build + test)"
read -p "Option: " opt

case $opt in
    1)
        echo "Running quick check..."
        find src -name "*.c" | xargs wc -l
        ;;
    2)
        echo "Running deep analysis..."
        grep -r "TODO\|FIXME" src/
        ;;
    3)
        echo "Running final verification..."
        make clean && make
        ./bin/kscanner --help
        ;;
esac

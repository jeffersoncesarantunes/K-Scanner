#!/bin/bash
# K-Scanner forensic triage for a given PID
set -e
PID=${1:-}
if [ -z "$PID" ]; then
    echo "Usage: $0 <pid>"
    exit 1
fi
if [ ! -d "/proc/$PID" ]; then
    echo "PID $PID not found"
    exit 1
fi
echo "=== Forensic Triage: PID $PID ==="
echo "Process: $(cat "/proc/$PID/comm" 2>/dev/null || echo '?')"
echo "Exe: $(readlink -f "/proc/$PID/exe" 2>/dev/null || echo '?')"
echo "Cmdline: $(tr '\0' ' ' < "/proc/$PID/cmdline" 2>/dev/null || echo '?')"
echo "--- Memory Maps (RWX) ---"
awk '/rwxp/ { print $1, $2, $NF }' "/proc/$PID/maps" 2>/dev/null || echo "No RWX regions"
echo "--- Open FDs ---"
find "/proc/$PID/fd/" -maxdepth 1 2>/dev/null | wc -l | xargs echo "FD count:"
echo "--- Status ---"
grep -E "^(State|VmRSS|Threads|Seccomp)" "/proc/$PID/status" 2>/dev/null || true

#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/kscanner"
TMP="$(mktemp -d /tmp/kscanner_test_XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0
ok() { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

[[ -x "$BIN" ]] || { echo "missing binary"; exit 1; }

echo "--- Test 1: help ---"
if "$BIN" --help | grep -q "Usage:"; then ok "help"; else bad "help"; fi

echo "--- Test 2: JSON export ---"
"$BIN" --json > "$TMP/report.json"
if python3 - "$TMP/report.json" <<'PY'
import json,sys
with open(sys.argv[1], encoding="utf-8") as f: json.load(f)
PY
then ok "valid JSON"; else bad "invalid JSON"; fi

echo "--- Test 3: CSV export ---"
"$BIN" --csv > "$TMP/report.csv"
if head -1 "$TMP/report.csv" | grep -q "PID,PROCESS_NAME"; then ok "CSV header"; else bad "CSV header"; fi

echo "--- Test 4: watch JSON Lines ---"
timeout 4 "$BIN" --watch --json > "$TMP/watch.jsonl" || true
if python3 - "$TMP/watch.jsonl" <<'PY'
import json,sys
lines=[l for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
assert lines, "no output"
for line in lines: json.loads(line)
PY
then ok "valid JSONL"; else bad "invalid JSONL"; fi

echo "--- Test 5: BPF object ---"
if [[ -f "$ROOT/build/bpf/rwx_monitor.bpf.o" ]] && readelf -S "$ROOT/build/bpf/rwx_monitor.bpf.o" >/dev/null 2>&1; then
  ok "BPF object"
else
  bad "BPF object"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]

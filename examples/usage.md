# K-Scanner Usage Examples

## Quick Start

```bash
# TUI mode (interactive dashboard)
sudo ./kscanner
```

That's the simplest way to get started — it drops you into the ncurses dashboard where you can see all running processes and their RWX status.

## Export Modes

```bash
# JSON output (headless)
sudo ./kscanner --json

# CSV output (headless)
sudo ./kscanner --csv
```

Handy if you want to pipe output into other tools or log scans for later review.

## Live Regex Memory Hunting

You can search for specific patterns inside a process's memory space:

```bash
# Search for password-like strings in PID 1234
sudo ./kscanner --live 1234 '(pass|token|secret|key)[[:space:]]*[:=]'

# Find HTTP endpoints in a process
sudo ./kscanner --live 5678 'https?://[a-zA-Z0-9./]+'
```

## eBPF Real-time Monitoring

Watch the whole system for processes allocating RWX memory:

```bash
# Enable eBPF telemetry alongside the TUI
sudo ./kscanner --bpf

# Headless mode with eBPF (alerts printed to stdout)
sudo ./kscanner --json --bpf
```

eBPF events show up in the TUI status bar as they happen — you'll see the PID, process name, and the address of each RWX allocation.

## Forensic Memory Dump

Inside the TUI:
1. Navigate to a process with a red `RWX ALERT` row
2. Press `ENTER` to dump the suspicious memory region
3. Artifacts land in `build/dumps/`:
   - `pid_<PID>_<ADDR>.bin` — raw memory dump
   - `.sha256` — integrity hash
   - `.strings.txt` — extracted printable strings
   - `.hex.txt` — hexadecimal preview

## Full Pipeline

```bash
# Single scan with all features
sudo ./kscanner --bpf --json | tee scan-report.json
```

## Analysis of Dumps

```bash
cd build/dumps
sha256sum -c *.sha256
grep -iE "http|ssh|cmd|bash|token" *.strings.txt
head -20 *.hex.txt
```

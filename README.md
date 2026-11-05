# K-Scanner

Linux memory auditing tool for RWX (W^X) detection and automated forensic
triage.

[![CI](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/K-Scanner/ci.yml?style=flat-square&logo=githubactions&label=CI)](https://github.com/jeffersoncesarantunes/K-Scanner/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/K-Scanner/codeql.yml?style=flat-square&logo=codeql&label=CodeQL)](https://github.com/jeffersoncesarantunes/K-Scanner/actions/workflows/codeql.yml)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)

## What K-Scanner is

K-Scanner inspects active Linux processes for memory regions violating the
**W^X (Write XOR Execute)** principle. It reads `/proc/[PID]/maps`, classifies
RWX violations by confidence, and extracts forensic evidence — all without
process injection.

It is written in C99 with an interactive ncurses TUI and optional eBPF
telemetry. Host memory inspection requires root privileges and a native Linux
kernel; containers see only their own namespace unless given host-level access.

## Forensic workflow

1. **Detect** — the TUI lists processes and flags RWX regions as LOW / MEDIUM /
   CRITICAL confidence.
2. **Extract** — press `ENTER` on an alert to dump the region, generate a SHA256
   checksum, and produce strings, hex, and disassembly previews.
3. **Verify** — validate dumps with `sha256sum -c` and triage strings for IOCs.

## Get started

```bash
git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner && make bpf && make
sudo ./kscanner
```

## Usage modes

| Mode | Command | Purpose |
| :--- | :--- | :--- |
| TUI | `sudo ./kscanner` | Interactive process inspection |
| Watch | `sudo ./kscanner --watch` | Headless continuous monitoring (2s cycles) |
| JSON | `sudo ./kscanner --json` | Machine-readable export |
| CSV | `sudo ./kscanner --csv` | Spreadsheet-friendly export |
| Live hunt | `sudo ./kscanner --live <PID> '<regex>'` | Regex memory scan in one process |
| eBPF | `sudo ./kscanner --bpf` | Real-time RWX telemetry (`mmap`, `mprotect`, `shmat`, `execve`) |
| YARA | `sudo ./kscanner --yara rules.yara` | Scan dumps against YARA rules |
| Silent JIT | `sudo ./kscanner --silent-jit` | Suppress JIT false positives |

## Example output

```text
 PID    PROCESS              STATUS       CONFIDENCE  MAP_ADDR
 1132   python3              RWX ALERT    LOW         7fc163862000
 1135   fail2ban-server      RWX ALERT    CRITICAL    7f59a964f000
 1426   Xorg                 SAFE         SAFE        n/a

 [ENTER] ANALYZE | [Q] EXIT | ALERTS: 12 | BPF: OFF
```

Not every RWX region is malicious. Browsers, Python, Node.js, and Electron may
allocate RWX memory for JIT compilation. Anonymous executable pages or RWX
regions in non-JIT processes warrant forensic priority.

## Extracted artifacts

Each memory dump produces:

* `.bin` — raw binary dump
* `.sha256` — integrity checksum
* `.strings.txt` — printable strings
* `.hex.txt` — hexadecimal preview
* `.disasm.txt` — x86-64 disassembly
* `.shellcode.txt` — shellcode pattern analysis
* `.yara.txt` — YARA matches (when `--yara` is active)

Verify integrity:

```bash
cd build/dumps
sha256sum -c *.sha256
```

## Project in Action

![Live Scan](./Images/kscanner1.png)

![RWX Detection](./Images/kscanner2.png)

![Forensic Extraction](./Images/kscanner3.png)

## When not to use K-Scanner

* You are inside a container without host PID/memory namespace access.
* You do not have root privileges — `/proc/[PID]/maps` of other processes is
  not readable.
* You need a network-facing SIEM agent — K-Scanner is a local forensic tool,
  not a remote sensor.

## Security

See [SECURITY.md](./SECURITY.md). Do not open public issues for security
vulnerabilities.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

[MIT](LICENSE)

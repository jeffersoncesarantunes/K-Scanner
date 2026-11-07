# K-Scanner

Linux memory auditing tool for RWX (W^X) detection and automated forensic triage.

[![CI](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/K-Scanner/ci.yml?style=flat-square&logo=githubactions&label=CI)](https://github.com/jeffersoncesarantunes/K-Scanner/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/K-Scanner/codeql.yml?style=flat-square&logo=codeql&label=CodeQL)](https://github.com/jeffersoncesarantunes/K-Scanner/actions/workflows/codeql.yml)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Tested-On](https://img.shields.io/badge/Tested%20on-Linux%20x86_64-1793D1?style=flat-square)](https://www.kernel.org/)

K-Scanner inspects running processes for memory regions that violate the
W^X (Write XOR Execute) principle. It reads `/proc/[PID]/maps`, flags RWX
regions by confidence, and extracts forensic artifacts — all read-only,
without ptrace or process injection.

It is written in C99 with an optional ncurses TUI and optional eBPF
telemetry. Root is required to inspect other processes' memory.

## Core

- Walk `/proc` and classify RWX mappings per process
- Confidence levels: SAFE, LOW, MEDIUM, CRITICAL
- Interactive TUI (ncurses) to browse alerts and dump memory
- Forensic extraction per region: `.bin`, `.sha256`, `.strings.txt`,
  `.hex.txt`, `.shellcode.txt`
- Structured export: JSON and CSV
- Container ID detection via `/proc/[PID]/cgroup`

## Optional

- eBPF real-time RWX telemetry (`--bpf`, requires libbpf + root)
- Live regex memory hunt (`--live <PID> '<pattern>'`)
- YARA rule scanning on dumps (`--yara rules.yara`)
- Headless watch mode (`--watch`, 2s cycles)
- Suppress JIT false positives (`--silent-jit`)

## Build

```bash
git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner
make bpf && make
sudo ./kscanner
```

`make bpf` compiles the BPF object; `make` builds the binary. `libbpf` is
detected automatically for eBPF support.

## Usage

```
sudo ./kscanner              # TUI, interactive
sudo ./kscanner --watch      # headless monitoring
sudo ./kscanner --json       # JSON export
sudo ./kscanner --csv        # CSV export
sudo ./kscanner --live 1132 'pattern'   # regex hunt in one PID
sudo ./kscanner --bpf        # eBPF real-time telemetry
```

In the TUI, press `ENTER` on an alert to dump the region and generate
forensic artifacts into `build/dumps/`.

## Limitations

- Requires root to read `/proc/[PID]/mem` of other processes.
- Containers see only their own namespace unless given host-level access.
- Not a network sensor or SIEM agent; it is a local forensic tool.
- Not every RWX region is malicious (browsers, Node, Python, Electron
  use RWX for JIT). Use `--silent-jit` to reduce noise.

## Security

See [SECURITY.md](./SECURITY.md). Do not open public issues for
vulnerabilities.

## License

[MIT](LICENSE)

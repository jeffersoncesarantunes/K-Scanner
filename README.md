# K-Scanner

Linux memory auditing tool for RWX (W^X) detection and automated forensic triage.

[![CI](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/K-Scanner/ci.yml?style=flat-square&logo=githubactions&label=CI)](https://github.com/jeffersoncesarantunes/K-Scanner/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/K-Scanner/codeql.yml?style=flat-square&logo=codeql&label=CodeQL)](https://github.com/jeffersoncesarantunes/K-Scanner/actions/workflows/codeql.yml)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Tested-On](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square)](https://archlinux.org/)

## Why it exists

I built K-Scanner because existing forensics tools are heavy, rely on ptrace, or inject code into the target process. I wanted something that reads only `/proc`, doesn't modify the target system, runs fast enough on a production server without taking it down, and gives me concrete evidence (dump, hash, strings, disassembly) when it finds a suspicious RWX region. It's a local triage tool, not a replacement for an EDR or SIEM.

## What it does

Reads `/proc/[PID]/maps`, maps memory regions per process, detects W^X (Write XOR Execute) violations, classifies them by confidence level, and — when asked — extracts forensic artifacts (`.bin`, `.sha256`, `.strings.txt`, `.hex.txt`, `.shellcode.txt`) straight into `build/dumps/`. Everything is read-only: no ptrace, no injection, nothing changes on the target process.

Optionally there's an ncurses TUI, eBPF for real-time telemetry, live in-memory regex search (`--live`), YARA scanning on dumps (`--yara`), headless mode (`--watch`), and JIT false-positive suppression (`--silent-jit`).

## What it doesn't do

- Not a network scanner or SIEM agent.
- Doesn't identify malware by itself — it just flags RWX regions; browsers, Node, Python, and Electron use RWX for JIT and that's legitimate.
- Can't see inside containers unless you have access to the host namespace.
- Requires root to inspect memory of other processes.

## Real-world use cases

Audit a web server after suspected shellcode injection: see which processes have RWX regions and dump them for offline analysis.

Investigate abnormal load on a host: list processes with active RWX and check for reflective payloads or injected code loading.

Validate hardening on your own binary: confirm your process doesn't keep memory both writable and executable outside known JIT sections.

Light continuous monitoring: `--watch` in a 2s loop to alert only when something changes, without running a heavy agent.

## Example output

Interactive mode (TUI):

```
PID   PROCESS           STATUS      CONFIDENCE  INFO          CTN
1234  firefox           RWX ALERT   LOW         01dx JIT      n/a
5678  mystery-bin       RWX ALERT   CRITICAL    03dx anon       abc123def456
9101  sshd              SAFE        SAFE        STABLE        n/a
```

Press `ENTER` on an alert to generate the forensic report in `build/dumps/`:

```
pid_5678_0x7f1234000000.bin
pid_5678_0x7f1234000000.sha256
pid_5678_0x7f1234000000.strings.txt
pid_5678_0x7f1234000000.hex.txt
pid_5678_0x7f1234000000.shellcode.txt
```

JSON/CSV export:

```bash
sudo ./kscanner --json
# [
#   {"pid":5678,"process":"mystery-bin","status":"RWX ALERT","confidence":"CRITICAL",...},
#   ...
# ]
```

## Project in Action

![Live Scan](./Images/kscanner1.png)

![RWX Detection](./Images/kscanner2.png)

![Forensic Extraction](./Images/kscanner3.png)

## How to build and use

```bash
git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner
make bpf && make
sudo ./kscanner              # interactive TUI
sudo ./kscanner --watch      # headless monitoring (2s)
sudo ./kscanner --json       # export JSON
sudo ./kscanner --csv        # export CSV
sudo ./kscanner --live 1132 'pattern'   # regex search in a PID's memory
sudo ./kscanner --bpf        # real-time eBPF telemetry
```

`make bpf` compiles the BPF object; `make` builds the binary. `libbpf` is detected automatically for eBPF support.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

See [SECURITY.md](./SECURITY.md). Don't open public issues for vulnerabilities.

## License

See [LICENSE](./LICENSE)

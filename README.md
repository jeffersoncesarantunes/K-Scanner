# 🐧 K-Scanner

Lightweight Linux memory auditing tool focused on RWX detection and forensic triage.

> **Project:** K-Scanner (Kernel-level Security Scanner)  
> **Author:** Jefferson Cesar Antunes  
> **License:** MIT  
> **Version:** 1.0.0  
> **Description:** Active Security Auditing & Hardening Tool for Linux Systems.

---

● Etymology & Origin

The name **k-scanner** was born from the project's focus on the **Kernel** (the heart of the Linux Operating System). 

The "k" symbolizes the tool's mission to dive deep into system-level configurations, permissions, and sensitive files. It acts as a sentinel, scanning the "foundations" (Kernel-space and System-space) to ensure that the base of the OS is hardened against potential threats.

● Overview

K-Scanner is a minimal forensic utility designed to audit memory protection flags of active Linux processes.

It analyzes the `/proc` virtual filesystem to identify memory regions that violate the W^X (Write XOR Execute) security principle — a condition commonly associated with:

- Shellcode injection
- JIT-compiled regions
- Packed executables
- Fileless malware techniques

The project is written in pure C (C99) with emphasis on performance, clarity, and forensic integrity.

● Why

Modern Linux systems rely heavily on memory protection mechanisms. However, visibility into runtime RWX memory regions is not centralized.

K-Scanner provides:
- Deterministic RWX detection
- System-wide process inspection
- Live forensic triage support
- Lightweight incident response tooling

It focuses strictly on observable memory metadata.

● How It Works

K-Scanner parses the virtual maps of active processes:

```bash
/proc/[PID]/maps
```

For each running process, it inspects memory segments and evaluates their permission flags. If a memory region simultaneously contains **W (Write)** and **X (Execute)**, an RWX alert is triggered.

The scanner operates through read-only metadata inspection and does not rely on intrusive debugging mechanisms such as `ptrace`.

● Example Output

```text
┌────────┬──────────────────────────────────┬────────────────────┬────────────────────┐
│  PID   │ PROCESS NAME                     │ STATUS             │ MEM ADDRESS        │
├────────┼──────────────────────────────────┼────────────────────┼────────────────────┤
│ 2327   │ xdg-desktop-por                  │ SAFE               │ 0x00000000         │
│ 2378   │ Privileged Cont                  │ RWX ALERT          │ 38113397b000       │
│ 2497   │ WebExtensions                    │ RWX ALERT          │ 1dcb66314000       │
│ 2557   │ Isolated Web Co                  │ RWX ALERT          │ 3da6521ae000       │
│ 2708   │ Web Content                      │ RWX ALERT          │ 32071f8e1000       │
│ 3021   │ bash                             │ SAFE               │ 0x00000000         │
└────────┴──────────────────────────────────┴────────────────────┴────────────────────┘
```

● Project in Action

1. **Live Scan:** System-wide RWX memory scan.
2. **RWX Detection:** Region detection with alert classification.
3. **Forensic Workflow:** Memory extraction and integrity verification.

● Features

- System-wide PID scanning.
- RWX memory detection engine.
- SAFE / ALERT classification.
- Clean terminal output.
- Low memory footprint.
- Designed for forensic triage scenarios.

● Operational Integrity

K-Scanner is built for stability and forensic neutrality:

1. **Simplicity:** No kernel modules, no injection, no process suspension.
2. **Forensic Integrity:** Does not modify process memory or execution state.
3. **Performance:** Optimized C implementation for minimal overhead during live analysis.
4. **Passive Inspection:** Uses read-only metadata via /proc.

● Investigation Workflow

After detecting an RWX region, analysts may proceed with:

1. **Binary Validation:**
```bash
sha256sum /proc/[PID]/exe
```

2. **Advanced Memory Extraction:**
```bash
sudo dd if=/proc/[PID]/mem of=dump.bin bs=1 skip=<offset> count=<size>
```

3. **Artifact Inspection:**
Use `strings` or `hexdump` on the generated dump to identify malicious payloads.

● Deployment

**Requirements:**
- Linux OS (Tested on Arch Linux 6.x).
- gcc & make.
- Sudo privileges.

**Build and Execute:**
```bash
git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner
make clean && make
sudo ./build/kscanner
```

● Tech Stack

- **Language:** C (C99)
- **Data Source:** /proc filesystem
- **Build Tool:** GNU Make
- **Target:** Linux Kernel 4.x / 5.x / 6.x

● Roadmap

- [x] RWX detection engine
- [x] Structured output format
- [ ] JSON export for SIEM integration
- [ ] Interactive TUI interface
- [ ] Automated memory dump for flagged PIDs

● License

Distributed under the MIT License. See LICENSE for details.

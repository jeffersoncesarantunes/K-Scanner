# 🐧 K-Scanner

Lightweight Linux memory auditing tool focused on RWX detection and forensic triage.

[![Linux](https://img.shields.io/badge/platform-linux-blue)](https://kernel.org)
[![Language](https://img.shields.io/badge/language-C-blue)](https://gcc.gnu.org/)
[![License](https://img.shields.io/badge/license-MIT-red)](LICENSE)
![Version](https://img.shields.io/badge/version-1.0.0-orange)
![Status](https://img.shields.io/badge/status-active-success)

## 🌐 Contact

[![Discord](https://img.shields.io/badge/Discord-Jefferson-5865F2?logo=discord&logoColor=white)](https://discord.com/users/1476405883733807247)
[![X](https://img.shields.io/badge/@j3ff3rsonc3sar-000000?logo=x&logoColor=white)](https://x.com/j3ff3rsonc3sar)
[![Mastodon](https://img.shields.io/badge/Mastodon-@jeffersoncesar-6364FF?logo=mastodon&logoColor=white)](https://mastodon.social/@jeffersoncesar)

> **Project:** K-Scanner (Kernel-level Security Scanner)  
> **Author:** Jefferson Cesar Antunes  
> **License:** MIT  
> **Version:** 1.0.0  
> **Description:** Active Security Auditing & Hardening Tool for Linux Systems.

## ● Etymology & Origin

The name **K-Scanner** was born from the project's focus on the **Kernel** (the heart of the Linux Operating System).

The "K" symbolizes the tool's mission to dive deep into system-level configurations, permissions, and sensitive files. It acts as a sentinel, scanning the "foundations" (Kernel-space and System-space) to ensure that the base of the OS is hardened against potential threats.

## ● Overview

K-Scanner is a minimal forensic utility designed to audit memory protection flags of active Linux processes.

It analyzes the `/proc` virtual filesystem to identify memory regions that violate the W^X (Write XOR Execute) security principle — a condition commonly associated with:

- Shellcode injection
- JIT-compiled regions
- Packed executables
- Fileless malware techniques

The project is written in pure C (C99) with emphasis on performance, clarity, and forensic integrity.

## ● Why

Modern Linux systems rely heavily on memory protection mechanisms. However, visibility into runtime RWX memory regions is not centralized.

K-Scanner provides:

- Deterministic RWX detection
- System-wide process inspection
- Live forensic triage support
- Lightweight incident response tooling

It focuses strictly on observable memory metadata.

## ● How It Works

K-Scanner parses the virtual maps of active processes:

```bash
/proc/[PID]/maps
```

For each running process, it inspects memory segments and evaluates their permission flags. If a memory segment contains both **Write (W)** and **Execute (X)** permissions simultaneously, an RWX alert is triggered.

The scanner operates through read-only metadata inspection and does not rely on intrusive debugging mechanisms such as `ptrace`.

## ● Example Output

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

## ● Project in Action

![Initial Scan](./Imagens/kscanner1.png)
*1- Automated baseline evaluation of global memory posture.*

![RWX Detection](./Imagens/kscanner2.png)
*2- Real-time detection of memory regions violating W^X principles.*

![Forensic Summary](./Imagens/kscanner3.png)
*3- Forensic audit reporting and risk assessment for flagged PIDs.*

## ● Features

- System-wide PID scanning
- RWX memory detection engine
- SAFE / ALERT classification
- Clean terminal output
- Low memory footprint
- Designed for forensic triage scenarios

## ● Operational Integrity

K-Scanner is built for stability and forensic neutrality:

1. **Simplicity:** No kernel modules, no injection, no process suspension.
2. **Forensic Integrity:** Does not modify process memory or execution state.
3. **Performance:** Optimized C implementation for minimal overhead during live analysis.
4. **Passive Inspection:** Uses read-only metadata via /proc.

## ● Investigation Workflow

After detecting an RWX region, analysts may proceed with:

1. **Binary Validation**

```bash
sha256sum /proc/[PID]/exe
```

2. **Advanced Memory Extraction**

```bash
sudo dd if=/proc/[PID]/mem of=dump.bin bs=1 skip=<offset> count=<size>
```

3. **Artifact Inspection**

Use `strings` or `hexdump` on the generated dump to identify suspicious payloads.

## ● Deployment

**Requirements:**

- Linux OS (Tested on Arch Linux 6.x)
- gcc & make
- sudo privileges

**Build and Execute:**

```bash
git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner
make clean && make
sudo ./build/kscanner
```

## ● Tech Stack

- **Language:** C (C99)
- **Data Source:** /proc filesystem
- **Build Tool:** GNU Make
- **Target:** Linux Kernel 4.x / 5.x / 6.x

## ● Roadmap

- [x] RWX detection engine
- [x] Structured output format
- [ ] JSON export for SIEM integration
- [ ] Interactive TUI interface
- [ ] Automated memory dump for flagged PIDs

## ● License

Distributed under the MIT License. See [LICENSE](./LICENSE) for details.

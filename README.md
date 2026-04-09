# 🐧 K-Scanner

Lightweight Linux memory auditing tool focused on RWX detection and forensic triage.

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![Language-C99](https://img.shields.io/badge/Language-C99-A8B9CC?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00FF41?style=flat-square)](#-roadmap)
[![Tested-on](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square&logo=arch-linux)](https://security.archlinux.org/)
[![Domain](https://img.shields.io/badge/Domain-Memory%20Forensics-8A2BE2?style=flat-square)](./docs/forensic_methodology.md)

---

## ● Etymology & Origin

The name **K-Scanner** was born from the project's focus on the **Kernel** (the heart of the Linux Operating System).

The "K" symbolizes the tool's mission to dive deep into system-level configurations, permissions, and sensitive files. It acts as a sentinel, scanning the "foundations" (Kernel-space and System-space) to ensure that the base of the OS is hardened against potential threats.

---

## ● Overview

K-Scanner is a minimal forensic utility designed to audit memory protection flags of active Linux processes.

It analyzes the `/proc` virtual filesystem to identify memory regions that violate the W^X (Write XOR Execute) security principle — a condition commonly associated with:

- Shellcode injection
- JIT-compiled regions
- Packed executables
- Fileless malware techniques

The project is written in pure C (C99) with emphasis on performance, clarity, and forensic integrity.

---

## ● Why

Modern Linux systems rely heavily on memory protection mechanisms. However, visibility into runtime RWX memory regions is not centralized.

K-Scanner provides:

- Deterministic RWX detection
- System-wide process inspection
- Live forensic triage support
- Lightweight incident response tooling

It focuses strictly on observable memory metadata.

---

## ● How It Works

K-Scanner parses the virtual maps of active processes:

```bash
/proc/[PID]/maps
```

For each running process, it inspects memory segments and evaluates their permission flags. If a memory segment contains both **Write (W)** and **Execute (X)** permissions simultaneously, an RWX alert is triggered.

The scanner operates through read-only metadata inspection and does not rely on intrusive debugging mechanisms such as `ptrace`.

---

## ● Example Output

```text
+--------+----------------------------------+--------------------+--------------------+
|  PID   | PROCESS NAME                     | STATUS             | INFO / PATH        |
+--------+----------------------------------+--------------------+--------------------+
| 102109 | wireshark                        | RWX ALERT          | 01x ANON_BLOB      |
| 102174 | Discord                          | RWX ALERT          | 02x MAPPED_FILE    |
| 102388 | Discord                          | RWX ALERT          | 05x MAPPED_FILE    |
+--------+----------------------------------+--------------------+--------------------+
```

---

## ● Project in Action

![Initial Scan](./Imagens/kscanner1.png)  
*1 - Initial System Mapping. Startup of the Live Forensic Process Analysis Mode, performing real-time memory scanning of core system processes.*

![RWX Detection](./Imagens/kscanner2.png)  
*2 - Behavioral Analysis & Contextual Detection. K-Scanner categorizes suspicious regions as ANON_BLOB (common in shellcodes) or MAPPED_FILE (common in JIT engines like Firefox/Discord).*

![Forensic Summary](./Imagens/kscanner3.png)  
*3 - Forensic Workflow via Tmux. Demonstrates memory extraction, integrity verification with SHA256, and inspection via strings/hex.*

---

## ● Features

- System-wide PID scanning
- RWX memory detection engine
- SAFE / ALERT classification
- Clean terminal output
- Low memory footprint
- Designed for forensic triage scenarios

---

## ● Operational Integrity

K-Scanner is built for stability and forensic neutrality:

1. **Simplicity:** No kernel modules, no injection, no process suspension  
2. **Forensic Integrity:** Does not modify process memory or execution state  
3. **Performance:** Optimized C implementation for minimal overhead  
4. **Passive Inspection:** Uses read-only metadata via /proc  

---

## ● Build and Run

```bash
# 1. Clone & Enter the repository
git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner

# 2. Compile the project
make clean && make

# 3. Execute the scanner
sudo ./bin/kscanner
```

---

## ● Investigation Workflow

After detecting an RWX region, analysts may proceed with:

### 1. Binary Validation

```bash
sha256sum /proc/[PID]/exe
```

### 2. Advanced Memory Extraction

```bash
sudo dd if=/proc/[PID]/mem of=dump.bin bs=1 skip=<offset> count=<size>
```

### 3. Artifact Inspection

Use `strings` or `hexdump` on the generated dump to identify suspicious payloads.

---

## ● Post-Analysis of Forensic Dumps

Once **K-Scanner** identifies a suspicious **RWX** region, it automatically extracts its raw content to the `build/dumps/` directory.

### 1. Integrity Verification (Hashing)

```bash
sha256sum build/dumps/*.bin
```

### 2. Example for a specific dump

```bash
sha256sum build/dumps/pid_101554_2dace8f1b000.bin
```

### 3. String Extraction

```bash
strings build/dumps/pid_*.bin | less
```

### Targeted example

```bash
strings build/dumps/pid_101554_2dace8f1b000.bin | head -n 15
```

### 4. Hexadecimal Analysis

```bash
hexdump -C build/dumps/pid_101554_2dace8f1b000.bin | head -n 10
```

---

## ● Deployment

### Requirements

- Linux OS (Tested on Arch Linux 6.x)
- gcc & make
- sudo privileges

---

## ● Repository Structure

```text
├── bin/
├── build/
│   ├── obj/
│   └── dumps/
├── docs/
├── examples/
├── Imagens/
├── include/
├── scripts/
├── src/
│   ├── core/
│   ├── modules/
│   └── utils/
├── tests/
├── .gitignore
├── Makefile
└── README.md
```

---

## ● Tech Stack

- **Language:** C (C99)
- **Data Source:** /proc filesystem
- **Build Tool:** GNU Make
- **Target:** Linux Kernel 4.x / 5.x / 6.x

---

## ● Roadmap

- [x] Modular C Engine
- [x] Advanced Build System
- [x] Structured Output
- [x] Automated Memory Dump
- [ ] JSON/CSV Export
- [ ] Interactive TUI
- [ ] Kernel Module (LKM)

---

## ● Documentation

[![Docs-Architecture](https://img.shields.io/badge/Architecture-Design-00599C?style=flat-square&logo=linux&logoColor=white)](./docs/architecture.md)
[![Docs-Methodology](https://img.shields.io/badge/Forensic-Methodology-444444?style=flat-square&logo=gnu-bash&logoColor=white)](./docs/forensic_methodology.md)
[![Docs-ThreatModel](https://img.shields.io/badge/Threat-Model-CC0000?style=flat-square&logo=opensourceinitiative&logoColor=white)](./docs/threat_model.md)
[![Docs-Performance](https://img.shields.io/badge/Performance-Limits-8A2BE2?style=flat-square)](./docs/performance_and_limitations.md)
[![Docs-UseCases](https://img.shields.io/badge/Use-Cases-228B22?style=flat-square)](./docs/use_cases.md)

## ● License

[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=opensourceinitiative&logoColor=white)](./LICENSE)

*This project is licensed under the MIT License.*

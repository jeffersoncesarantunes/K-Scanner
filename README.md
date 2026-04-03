# 🐧 K-Scanner

Lightweight Linux memory auditing tool focused on RWX detection and forensic triage.

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![Language-C99](https://img.shields.io/badge/Language-C99-A8B9CC?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
![Version](https://img.shields.io/badge/Version-1.0.0-333333?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-00FF41?style=flat-square)

## ● Project Information

- **Project:** K-Scanner (Kernel-level Security Scanner)
- **Author:** Jefferson Cesar Antunes
- **License:** MIT
- **Version:** 1.0.0
- **Description:** Active Security Auditing & Hardening Tool for Linux Systems.

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
+--------+----------------------------------+--------------------+--------------------+
|  PID   | PROCESS NAME                     | STATUS             | INFO / PATH        |
+--------+----------------------------------+--------------------+--------------------+
| 102109 | wireshark                        | RWX ALERT          | 01x ANON_BLOB      |
| 102174 | Discord                          | RWX ALERT          | 02x MAPPED_FILE    |
| 102388 | Discord                          | RWX ALERT          | 05x MAPPED_FILE    |
+--------+----------------------------------+--------------------+--------------------+
```

## ● Project in Action

![Initial Scan](./Imagens/kscanner1.png)
*1- Initial System Mapping. Startup of the Live Forensic Process Analysis Mode, performing real-time memory scanning of core system processes.*

![RWX Detection](./Imagens/kscanner2.png)
*2- Behavioral Analysis & Contextual Detection. O K-Scanner agora categoriza regiões suspeitas como ANON_BLOB (comum em shellcodes) ou MAPPED_FILE (comum em motores JIT como Firefox/Discord).*

![Forensic Summary](./Imagens/kscanner3.png)
*3- Forensic Workflow via Tmux. Demonstração da extração de memória, verificação de integridade com SHA256 e inspeção de strings/hexadecimal para análise de payloads.*

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

## ● Post-Analysis of Forensic Dumps

Once **K-Scanner** identifies a suspicious **RWX** region, it automatically extracts its raw content to the `build/dumps/` directory. These artifacts are essential for offline forensic investigation.

#### 1. Integrity Verification (Hashing)
```bash
sha256sum dumps/*.bin
```

### 2. Example for a specific dump (as seen in screenshots)
```bash
sha256sum dumps/pid_101554_2dace8f1b000.bin
```

#### 3. String Extraction

Search for human-readable indicators such as URLs, IP addresses, or obfuscated commands:

## ● General search for all dumps
```bash
strings dumps/pid_*.bin | less
```

## ● Targeted search on the alerted process dump from the example
```bash
strings dumps/pid_101554_2dace8f1b000.bin | head -n 15
```

## ● Hexadecimal Analysis
```bash 
hexdump -C dumps/pid_101554_2dace8f1b000.bin | head -n 10
```

## ● Deployment

**Requirements:**

- Linux OS (Tested on Arch Linux 6.x)
- gcc & make
- sudo privileges

## ● Build and Run

```bash
# 1. Clone & Enter the repository
git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner

# 2. Compile the project
# This will create 'bin/' for the executable and 'build/' for objects
make clean && make

# 3. Execute the scanner
# Run the binary from the root directory as root
sudo ./bin/kscanner
```

## ● Repository Structure

```text
├── bin/                # Target binary directory (kscanner)
├── build/              # Intermediate objects and forensic dumps
│   ├── obj/            # Modular object files (.o)
│   └── dumps/          # Memory analysis snapshots (.bin)
├── docs/               # Architecture, Methodology and Threat Model
├── examples/           # Usage guides and sample scenarios
├── Imagens/            # K-Scanner screenshots and execution flow
├── include/            # Header files (.h) - Interface definitions
├── scripts/            # Automation (Build, Diagnostic and CI/CD)
├── src/                # Core implementation (.c)
│   ├── core/           # Main engine, Memory analyzer and Process hunter
│   ├── modules/        # Advanced forensic features
│   └── utils/          # Logging and memory utilities
├── tests/              # Test cases and validation logic
├── .gitignore          # Prevents leaking binaries and memory dumps
├── Makefile            # Advanced build system (Automatic directory creation)
└── README.md           # Project entry point and manual
```

## ● Tech Stack

- **Language:** C (C99)
- **Data Source:** /proc filesystem
- **Build Tool:** GNU Make
- **Target:** Linux Kernel 4.x / 5.x / 6.x

## ● Roadmap

- [x] **Modular C Engine:** RWX detection via `/proc/[pid]/maps`.
- [x] **Advanced Build System:** Optimized POSIX-compliant Makefile.
- [x] **Structured Output:** Color-coded CLI with forensic triage.
- [x] **Automated Memory Dump:** Native extraction to `.bin` files.
- [ ] **JSON/CSV Export:** Integration with SIEM/Auditing tools.
- [ ] **Interactive TUI:** Real-time monitoring via Ncurses.
- [ ] **Kernel Module:** Deep inspection and anti-rootkit (LKM).

## ● License

Distributed under the MIT License. See [LICENSE](./LICENSE) for details.

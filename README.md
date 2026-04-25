# 🐧 K-Scanner

Lightweight Linux memory auditing tool focused on RWX detection and automated forensic triage.

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![Language-C99](https://img.shields.io/badge/Language-C99-A8B9CC?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00FF41?style=flat-square)](#-roadmap)
[![Tested-on](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square&logo=arch-linux)](https://security.archlinux.org/)
[![Domain](https://img.shields.io/badge/Domain-Live%20Memory%20Forensics-8A2BE2?style=flat-square)](./docs/forensic_methodology.md)

---

## ● Etymology & Origin

The name **K-Scanner** originates from the Linux **Kernel** — the core layer responsible for process execution, memory management, and system security.

The "K" reflects the project's mission: to inspect volatile memory at runtime, identify anomalous execution permissions, and transform low-level kernel metadata into actionable forensic intelligence.

---

## ● Overview

K-Scanner is a lightweight forensic utility designed to inspect active Linux processes for memory regions that violate the **W^X (Write XOR Execute)** security principle.

Built in pure **C99**, it combines a high-performance scanning engine with an interactive **ncurses-based Brutalist TUI**, enabling real-time process navigation, RWX detection, and immediate forensic extraction.

Common RWX scenarios include:

- Shellcode injection
- Reflective payload loading
- Fileless malware execution
- JIT-compiled engines (Firefox, Python, Node.js, Discord)

---

## ● Why

Modern Linux systems generate enormous runtime activity, but visibility into executable writable memory remains fragmented.

K-Scanner centralizes this analysis by providing:

- Deterministic RWX detection
- Interactive live process inspection
- Automated forensic evidence collection
- Immediate post-dump triage artifacts
- Minimal operational overhead

It transforms raw `/proc` telemetry into incident-response-ready intelligence.

---

## ● How It Works

K-Scanner continuously parses `/proc/[PID]/maps` to identify writable and executable memory mappings.

Whenever a region exposes simultaneous **Write (W)** and **Execute (X)** permissions, the scanner raises an **RWX ALERT**.

### Understanding RWX Alerts

Not every RWX region is malicious. Context matters.

- **Expected JIT Behavior:** Browsers, Python interpreters, Node.js, and Electron applications often allocate RWX pages for Just-In-Time compilation.
- **Suspicious Activity:** Anonymous executable pages, shellcode-like blobs, or RWX mappings in non-JIT processes deserve immediate investigation.
- **Forensic Priority:** Regions marked as anonymous or unexpected should be dumped and analyzed first.

---

## ● Example Output

```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 🐧 K-Scanner | Live Forensic Process Analysis Mode                        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

 PID    PROCESS              STATUS          MAP_ADDR
 1132   python3              RWX ALERT       7fc163862000
 1135   fail2ban-server      RWX ALERT       7f59a964f000
 1426   Xorg                 SAFE            n/a

 [ENTER] ANALYZE | [Q] EXIT | ALERTS: 12
```

---

## ● Project in Action

![Live Scan](./Imagens/kscanner1.png)
*1 - **Live Forensic Mode**: Real-time process auditing on Arch Linux, identifying memory regions with RWX (Read-Write-Execute) permissions.*

![RWX Detection](./Imagens/kscanner2.png)
*2 - **Memory Triage**: Automated extraction of printable strings from suspicious memory segments for rapid artifact analysis.*

![Forensic Extraction](./Imagens/kscanner3.png)
*3 - **Evidence Preservation**: Cryptographic integrity verification using SHA-256, ensuring all memory dumps remain untampered.*

---

## ● Features

* Interactive ncurses-based TUI
* Real-time RWX memory detection
* One-key forensic extraction
* Automatic SHA256 integrity hashing
* Automatic strings report generation
* Automatic hexadecimal preview generation
* SAFE / RWX ALERT classification
* Low-overhead live analysis

---

## ● Operational Integrity

K-Scanner is designed for forensic stability and safe live-response operations:

1. **Passive Analysis:** Reads metadata directly from `/proc`
2. **No Injection:** Never modifies target processes
3. **Controlled Extraction:** Prevents unstable full-memory dumping
4. **Evidence Integrity:** Automatically hashes every extracted artifact

---

## ● Build and Run

```bash 
# Clone the repository
git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner

# Build the project
make clean && make

# Standard execution
sudo ./kscanner
```

---

## ● Investigation Workflow

After detecting an RWX region, analysts can immediately acquire volatile evidence.

### 1. Live Memory Acquisition

Select a suspicious process and press `ENTER`.

K-Scanner will automatically:

* Dump the RWX region
* Generate SHA256 checksum
* Extract printable strings
* Produce a hexadecimal preview

### 2. Integrity Verification

```bash
cd build/dumps
sha256sum -c *.sha256
```

### 3. Rapid Triage

```bash
grep -iE "http|ssh|cmd|bash|token|pass" *.strings.txt
```

### 4. Binary Inspection

```bash
head -n 20 *.hex.txt
```

---

## ● Post-Analysis of Forensic Dumps

Each extracted memory region produces a complete triage package:

* Raw binary dump (`.bin`)
* SHA256 checksum (`.sha256`)
* Extracted strings (`.strings.txt`)
* Hexadecimal preview (`.hex.txt`)

### Validate All Evidence

```bash
sha256sum -c build/dumps/*.sha256
```

### Analyze Specific Artifact

```bash
strings build/dumps/pid_*.bin | head
```

### Inspect Raw Bytes

```bash
hexdump -C build/dumps/pid_*.bin | head
```

---

## ● Deployment

### Requirements

* Linux Kernel 5.x or newer
* gcc
* make
* ncurses
* binutils
* coreutils
* UTF-8 compatible terminal
* Root privileges

---

## ● Repository Structure

```text
├── bin/
│   └── kscanner
├── build/
│   ├── dumps/
│   └── obj/
├── docs/
│   ├── architecture.md
│   ├── forensic_methodology.md
│   ├── performance_and_limitations.md
│   ├── threat_model.md
│   └── use_cases.md
├── examples/
│   └── usage.md
├── Imagens/
│   ├── kscanner1.png
│   ├── kscanner2.png
│   └── kscanner3.png
├── include/
├── scripts/
├── src/
│   ├── core/
│   ├── modules/
│   └── utils/
├── tests/
│   └── cases.md
├── LICENSE
├── Makefile
└── README.md
```

---

## ● Tech Stack

* **Language:** C99
* **Interface:** ncurses
* **Data Source:** `/proc` filesystem
* **Hashing:** SHA256
* **Build Tool:** GNU Make
* **Target:** Linux Kernel 5.x / 6.x

---

## ● Roadmap

* [x] Modular C Engine
* [x] Interactive ncurses TUI
* [x] Automated Memory Dump
* [x] SHA256 Integrity Validation
* [x] Automated Strings/Hex Triage
* [x] JSON/CSV Export
* [ ] Live Regex Memory Hunting
* [ ] eBPF Telemetry Integration

---

## ● Documentation

[![Docs-Architecture](https://img.shields.io/badge/Architecture-Design-00599C?style=flat-square&logo=linux&logoColor=white)](./docs/architecture.md)
[![Docs-Methodology](https://img.shields.io/badge/Forensic-Methodology-444444?style=flat-square&logo=gnu-bash&logoColor=white)](./docs/forensic_methodology.md)
[![Docs-ThreatModel](https://img.shields.io/badge/Threat-Model-CC0000?style=flat-square&logo=opensourceinitiative&logoColor=white)](./docs/threat_model.md)
[![Docs-Performance](https://img.shields.io/badge/Performance-Limits-8A2BE2?style=flat-square)](./docs/performance_and_limitations.md)
[![Docs-UseCases](https://img.shields.io/badge/Use-Cases-228B22?style=flat-square)](./docs/use_cases.md)

---

## ● License

[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=opensourceinitiative&logoColor=white)](./LICENSE)

*This project is licensed under the MIT License.*

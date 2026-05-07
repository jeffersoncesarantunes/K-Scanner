# 🐧 K-Scanner

Lightweight Linux memory auditing tool focused on RWX detection and automated forensic triage.

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![Language-C99](https://img.shields.io/badge/Language-C99-A8B9CC?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00FF41?style=flat-square)](#-roadmap)
[![Tested-on](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square&logo=arch-linux)](https://security.archlinux.org/)
[![Domain](https://img.shields.io/badge/Domain-Live%20Memory%20Forensics-8A2BE2?style=flat-square)](./docs/forensic_methodology.md)

---

## ● Overview

K-Scanner is a lightweight forensic utility designed to inspect active Linux processes for memory regions that violate the **W^X (Write XOR Execute)** security principle.

Built in pure **C99**, it combines a high-performance scanning engine with an interactive **ncurses-based Brutalist TUI**, enabling real-time process navigation, RWX detection, and immediate forensic extraction.

Common RWX scenarios include:

* Shellcode injection
* Reflective payload loading
* Fileless malware execution
* JIT-compiled engines (Firefox, Python, Node.js, Discord)

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

## ● Example Output

```text id="kex2m1"
 PID    PROCESS              STATUS          MAP_ADDR
 1132   python3              RWX ALERT       7fc163862000
 1135   fail2ban-server      RWX ALERT       7f59a964f000
 1426   Xorg                 SAFE            n/a

 [ENTER] ANALYZE | [Q] EXIT | ALERTS: 12
```

---

## ● How It Works

K-Scanner continuously parses `/proc/[PID]/maps` to identify memory regions and their permission flags.

Audit flow:

1. Parse `/proc/[PID]/maps`
2. Identify memory permissions (R / W / X)
3. Detect RWX violations (W^X policy breach)
4. Classify process behavior
5. Trigger forensic extraction pipeline

### Understanding RWX Alerts

Not every RWX region is malicious. Context matters.

* **Expected JIT Behavior:** Browsers, Python, Node.js, and Electron apps may allocate RWX memory for JIT compilation
* **Suspicious Activity:** Anonymous executable pages or RWX regions in non-JIT processes
* **Forensic Priority:** Unexpected mappings should be dumped and analyzed first

---

## ● Build and Run

```bash id="p2k91a"
# Clone the repository
git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner

# Build the project
make clean && make

# Standard execution
sudo ./kscanner
```

---

## ● Investigation & Post-Analysis Workflow

After detecting an RWX region, analysts can immediately acquire and validate volatile evidence.

### 1. Live Memory Acquisition

Select a suspicious process and press `ENTER`.

K-Scanner will automatically:

* Dump the RWX region
* Generate SHA256 checksum
* Extract printable strings
* Produce a hexadecimal preview

### 2. Integrity Verification

```bash id="x91akl"
cd build/dumps
sha256sum -c *.sha256
```

### 3. Rapid Triage

```bash id="9as21x"
grep -iE "http|ssh|cmd|bash|token|pass" *.strings.txt
```

### 4. Binary Inspection

```bash id="zx12qw"
head -n 20 *.hex.txt
```

### 5. Full Artifact Set

Each memory extraction generates:

* Raw binary dump (`.bin`)
* SHA256 checksum (`.sha256`)
* Extracted strings (`.strings.txt`)
* Hexadecimal preview (`.hex.txt`)

---

## ● Why

Detecting executable writable memory in Linux is still a fragmented and manual process.

K-Scanner centralizes this capability by providing:

* Deterministic RWX detection
* Interactive live process inspection
* Automated forensic evidence collection
* Immediate triage-ready artifacts
* Minimal operational overhead

It transforms raw `/proc` telemetry into incident-response-ready intelligence.

---

## ● Project in Action

![Live Scan](./Imagens/kscanner1.png)
*1 - Live forensic mode identifying RWX memory regions in real-time.*

![RWX Detection](./Imagens/kscanner2.png)
*2 - Memory triage with automatic extraction of relevant strings.*

![Forensic Extraction](./Imagens/kscanner3.png)
*3 - Evidence preservation with SHA-256 integrity validation.*

---

## ● Operational Integrity

K-Scanner is designed for safe live-response environments:

* Passive / read-only analysis
* No process injection
* Controlled memory dumping
* Automatic evidence integrity validation

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
* **Data Source:** `/proc`
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

[![Docs-Architecture](https://img.shields.io/badge/Architecture-Design-00599C?style=flat-square\&logo=linux\&logoColor=white)](./docs/architecture.md)
[![Docs-Methodology](https://img.shields.io/badge/Forensic-Methodology-444444?style=flat-square\&logo=gnu-bash\&logoColor=white)](./docs/forensic_methodology.md)
[![Docs-ThreatModel](https://img.shields.io/badge/Threat-Model-CC0000?style=flat-square\&logo=opensourceinitiative\&logoColor=white)](./docs/threat_model.md)
[![Docs-Performance](https://img.shields.io/badge/Performance-Limits-8A2BE2?style=flat-square)](./docs/performance_and_limitations.md)
[![Docs-UseCases](https://img.shields.io/badge/Use-Cases-228B22?style=flat-square)](./docs/use_cases.md)

---

## ● Etymology & Origin

The name **K-Scanner** originates from the Linux **Kernel**, reflecting its role in inspecting runtime memory behavior and exposing anomalous execution patterns.

---

## ● License

[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square\&logo=opensourceinitiative\&logoColor=white)](./LICENSE)

*This project is licensed under the MIT License.*

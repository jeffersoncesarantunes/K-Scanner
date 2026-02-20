# 📡 K-Scanner | Live Forensic Process Analysis Studio

Real-time memory integrity audit. Identify code injections. Detect fileless malware.
**Everything running locally on your machine, zero system interruption.**

![License](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-Linux-lightgrey) ![Language](https://img.shields.io/badge/language-C-blue)

---

## 🔍 What is K-Scanner?

K-Scanner is a high-performance forensic triage tool for Linux systems, designed to identify RAM-based attack vectors. Think of it as an "X-ray" for your processes: it maps **RWX (Read, Write, Execute)** memory segments—regions frequently exploited for shellcode injection and hidden payloads.

Unlike intrusive tools that risk system stability, K-Scanner focuses on:

* **Complete Privacy** — All analysis is performed via `/proc` metadata; no data leaves your machine.
* **Production Stability** — Zero-Freeze Policy through Passive Metadata Analysis.
* **Forensic Integrity** — Read-only operations ensure original evidence remains untainted.
* **Native Performance** — Built in pure C for low CPU overhead and zero latency.

---

## 📸 Project in Action

![Initial Scan](./Imagens/kscanner1.png)
*Figure 1: Automated scan validating core system integrity and kernel threads.*

![Threat Detection](./Imagens/kscanner2.png)
*Figure 2: Real-time Alert: Identifying multiple RWX segments in application subprocesses.*

![Forensic Deep Dive](./Imagens/kscanner3.png)
*Figure 3: Forensic correlation using Tmux, Hexdump, and SHA256 validation.*

---

## ✨ Key Features

### Real-Time Memory Auditing
Based on the **W^X** (Write XOR Execute) security policy, the scanner audits every active process:
* **🟢 STATUS SAFE:** Process strictly adheres to security policies.
* **🔴 RWX ALERT:** Identifies dangerous memory capable of simultaneous writing and execution.

### Guaranteed Stability (Zero-Freeze)
Engineered for environments where uptime is critical:
* **Passive Analysis:** Does not attach debuggers (ptrace), preventing Kernel Panics.
* **⚠️ ACTION REQUIRED:** When encountering locked regions, selecting **Option 3 (Ignore)** ensures the system remains responsive and prevents freezes.

### Post-Detection Methodology
K-Scanner integrates seamlessly with industry-standard forensic tools:
1.  **Strings:** Extract C2 IPs or malicious commands: `sudo strings /proc/[PID]/mem | grep -i "http"`
2.  **SHA256:** Verify the integrity of the running binary: `sha256sum /proc/[PID]/exe`
3.  **Hexdump:** Inspect bytes to identify injected ELF headers: `sudo dd if=/proc/[PID]/mem bs=1 skip=[ADDR] count=512 | hexdump -C`

---

## 🚀 Quick Start

### Prerequisites
* Linux System (Extensively tested on **Arch Linux**)
* `gcc` compiler and `make` utility

### Installation
```bash
# Clone the repository
git clone [https://github.com/jeffersoncesarantunes/K-Scanner.git](https://github.com/jeffersoncesarantunes/K-Scanner.git)
cd K-Scanner

# Compile and Run
make clean && make
sudo ./build/kscanner
```

---

## 🛠️ Tech Stack

| Layer | Technology |
| :--- | :--- |
| **Language** | C (C99) |
| **Analysis Engine** | /proc Virtual Filesystem |
| **Build System** | GNU Make |
| **Forensics** | Memory Map Metadata Audit |
| **Tested On** | Arch Linux |

---

## 🗺️ Roadmap

- [x] RWX segment detection logic
- [x] Integration with external forensic tools
- [ ] JSON logging export for SIEM integration
- [ ] Ncurses-based Terminal User Interface (TUI)
- [ ] Containerized process analysis (Docker/K8s support)

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](./LICENSE) file for details.

---
*Developed for security analysts who demand speed without sacrificing system uptime.*

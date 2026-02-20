# 📡 K-Scanner | Advanced Linux Forensic Memory Auditor

High-speed triage tool for detecting **RWX** memory anomalies and fileless threats in real-time. Engineered for surgical precision in live forensic environments.

![License](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-Linux-lightgrey) ![Language](https://img.shields.io/badge/language-C-blue)

---

## 🔍 Overview

**K-Scanner** is a lightweight, specialized forensic tool designed to audit the memory integrity of active processes. By analyzing the `/proc` virtual filesystem, it identifies memory regions that violate the **W^X (Write XOR Execute)** security principle—a hallmark of shellcode injection, packers, and modern fileless malware.

### 🛡️ Core Pillars
* **Stealth & Non-Intrusive:** Operates without attaching debuggers (no `ptrace`), making it undetectable by most anti-forensic techniques.
* **Forensic Fidelity:** Read-only metadata analysis ensures the system state and process memory remain untainted for later investigation.
* **Architecture:** Optimized C code for minimal resource footprint during high-stress incident response.

---

## 📸 Project in Action

![Initial Scan](./Imagens/kscanner1.png)
*Figure 1: Automated system-wide integrity validation sequence.*

![Threat Detection](./Imagens/kscanner2.png)
*Figure 2: Active RWX Alert: Pinpointing suspicious memory pages in real-time.*

![Forensic Analysis](./Imagens/kscanner3.png)
*Figure 3: Multi-pane forensic workflow: Validating process integrity via SHA256 and Hexdump.*

---

## ✨ Key Capabilities

### 🛡️ Live Memory Auditing
Continuous monitoring of memory protection flags across all PIDs:
* **🟢 STATUS SAFE:** Memory pages adhere to standard security permissions.
* **🔴 RWX ALERT:** Immediate detection of simultaneous Write and Execute permissions (High Risk).

### ⚙️ Operational Reliability
K-Scanner is built for production environments where stability is paramount:
* **Passive Metadata Mapping:** Bypasses the need for process suspension, ensuring zero downtime.
* **Tactical Resilience:** Designed to handle sensitive kernel threads and locked pages gracefully—users can simply skip inaccessible regions to maintain scan momentum.

### 🛠️ Post-Detection Toolkit
Seamlessly transition from detection to deep analysis using built-in Linux forensic standards:
* **Binary Hash:** `sha256sum /proc/[PID]/exe` (Verifies if the disk image matches the running process).
* **Memory Carving:** `sudo dd if=/proc/[PID]/mem ...` (Extracts suspicious shellcode for reverse engineering).
* **String Analysis:** Scans for C2 URLs or obfuscated commands within process RAM.

---

## 🚀 Deployment

### Prerequisites
* **OS:** Linux (Tested on Arch Linux)
* **Tools:** `gcc`, `make`, `sudo` privileges

### Build & Run
```bash
# Clone the repository
git clone [https://github.com/jeffersoncesarantunes/K-Scanner.git](https://github.com/jeffersoncesarantunes/K-Scanner.git)
cd K-Scanner

# Compile and execute triage
make clean && make
sudo ./build/kscanner
```

---

## 🛠️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Language** | C (C99) |
| **Data Source** | /proc Filesystem (Metadata Audit) |
| **Build Tool** | GNU Make |
| **Target** | Linux Kernel 4.x/5.x/6.x |

---

## 🗺️ Roadmap

- [x] High-speed RWX detection engine
- [x] External forensic tool integration guide
- [ ] Structured JSON output for SIEM ingestion
- [ ] Interactive TUI (Terminal User Interface)
- [ ] Memory dump automation for flagged PIDs

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---
*Built for analysts who need visibility where traditional tools remain blind.*
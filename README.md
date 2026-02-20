# 📡 K-Scanner | Live Forensic Process Analysis Mode

K-Scanner is a high-performance forensic triage tool for Linux systems. Its specialization is detecting **RWX (Read, Write, Execute)** permissions—a primary indicator of code injection and fileless malware.

## 🎯 Objective
Provide a rapid, non-invasive diagnostic of process integrity without compromising system stability.

## 🚀 How to Run
```bash
make clean && make
sudo ./build/kscanner
```

## 🔍 Core Analysis Logic
* **🟢 STATUS SAFE:** Process adheres to W^X policies.
* **🔴 RWX ALERT:** Memory is simultaneously writable and executable.

---

## 📸 Project in Action

![Initial Scan](Imagens/kscanner1.png)
*Figure 1: Initial automated scan validating core system integrity.*

![Threat Detection](Imagens/kscanner2.png)
*Figure 2: Real-time identification of RWX alerts.*

![Forensic Analysis](Imagens/kscanner3.png)
*Figure 3: Multi-pane forensic analysis using Tmux.*

---

## 🛡️ Stability & Forensic Reliability
* **Zero-Freeze Policy:** Passive Metadata Analysis prevents system freezes or Kernel Panics.
* **Forensic Soundness:** Read-only operations on metadata.

## 🛠️ Post-Detection Methodology
1. **Strings:** `sudo strings /proc/[PID]/mem | less` 
2. **SHA256:** `sha256sum /proc/[PID]/exe` 
3. **Hexdump:** `sudo dd if=/proc/[PID]/mem bs=1 skip=[ADDR] count=512 | hexdump -C` 

---
*Developed for security analysts who need speed and precision.*

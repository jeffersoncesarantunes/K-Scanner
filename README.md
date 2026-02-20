# 📡 K-Scanner | Live Forensic Process Analysis Mode

K-Scanner is a forensic triage tool for Linux systems, designed to identify RAM-based attack vectors in real-time. It focuses on detecting **RWX (Read, Write, Execute)** segments, which are frequently used for code injection, shellcode, and fileless malware execution.

## 🎯 Objective
The goal of K-Scanner is to provide a fast, non-invasive diagnostic of running process integrity, serving as the first line of defense and forensic investigation in the Linux ecosystem.

## 🚀 How to Run
```bash
make clean && make
sudo ./build/kscanner
```

## 🔍 What does K-Scanner analyze?
The scanner iterates through all active processes on the system and analyzes their memory maps via the `/proc` virtual filesystem.

* **STATUS SAFE:** The process has no memory regions with simultaneous write and execute permissions, adhering to the **W^X** security policy.
* **RWX ALERT:** Identifies processes with dangerous permissions. This indicates that the process may be executing injected code, obfuscated payloads, or utilizing Just-In-Time (JIT) compilation techniques—which are common targets for exploitation.

## 🛡️ Stability and Performance
Unlike intrusive scanners, this version utilizes **Passive Metadata Analysis**, ensuring:

* **Operational Safety:** The scanner does not attempt to access Kernel-protected memory addresses or those mapped directly to hardware. This **eliminates the risk of system freezes** or Kernel Panics.
* **High Performance:** Optimized scanning with low CPU impact and zero heavy memory allocation (Heap) during execution.
* **Forensic Integrity:** Performs only read operations on metadata, ensuring the original state of the analyzed processes remains unaltered.

## 🛠️ Post-Detection Forensic Methodology
K-Scanner acts as a primary signaling tool. Once an **RWX ALERT** is identified, the analyst should proceed with external standard tools for deep investigation:

1. **Content Extraction (Strings):** Search for C2 IPs or malicious commands:
   `sudo strings /proc/[PID]/mem | less`

2. **Integrity Verification (SHA256):** Check if the running binary has been tampered with:
   `sha256sum /proc/[PID]/exe`

3. **Byte Analysis (Hexdump):** Inspect headers to identify injected ELF files:
   `sudo hexdump -C /proc/[PID]/mem | head -n 50`

---

**Project Architecture:**
* `src/core`: Detection core (Process Hunter and Memory Analyzer).
* `src/utils`: Forensic logging system and system utilities.
* `docs/`: Detailed technical documentation on architecture, API, and methodology.

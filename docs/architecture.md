## ● K-Scanner Architecture & API Reference

## 1. Overview
K-Scanner is a high-performance live forensic tool designed to analyze running processes via the `/proc` virtual filesystem. It is built to be non-intrusive, prioritizing system stability while maintaining deep visibility into process memory permissions.

---

## 2. System Components
- **Process Hunter (core/process_hunter.c)**: Responsible for enumerating active PIDs and filtering kernel threads from userspace processes.
- **Memory Analyzer (core/mem_analyzer.c)**: The detection engine that parses memory maps to identify RWX (Read-Write-Execute) permission patterns.
- **K-Scanner Core (core/kscanner.c)**: Orchestrates the scanning lifecycle and manages the real-time Terminal UI (Live Dashboard).
- **Logger & Utils (utils/)**: Handles forensic-grade output formatting and memory-safe string operations.

---

## 3. Data Flow
1. **Enumeration**: The Hunter scans `/proc` for active Process IDs.
2. **Parsing**: The Analyzer reads the specific memory maps (`/proc/[PID]/maps`) for each target.
3. **Detection**: The engine flags any 'rwxp' (Read, Write, Execute, Private) memory segments.
4. **Presentation**: The live dashboard updates the UI, highlighting alerts and summarizing the forensic integrity of the system.

---

## 4. Core Forensic Functions (API)

These functions represent the internal logic used to perform forensic operations:

- `forensic_has_rwx_memory(pid_t pid)`: Primary analysis function. Scans the memory segments of a given PID and returns 1 if RWX permissions are detected.
- `hunter_get_processes()`: Scans the system for active PIDs and returns a collection of process contexts for analysis.
- `scanner_start_live_mode()`: Initiates the main execution loop, handling real-time updates and dashboard refreshing.

### 4.1 Data Structures
- `ScannerConfig`: Global configuration object (e.g., scan delays, verbosity levels).
- `ProcessAlert`: Data structure used to store detected threats, including PID, process name, and the suspicious memory offset.

### 4.2 Utility Functions
- `log_forensic_alert()`: Standardized logging for critical findings.
- `memory_to_hex_string()`: Helper to format raw memory addresses for the dashboard display.

---
*K-Scanner: Engineering transparency and memory integrity.*

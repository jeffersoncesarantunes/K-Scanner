## ● K-Scanner Architecture

##  Overview
K-Scanner is a high-performance live forensic tool designed to analyze running processes via the `/proc` virtual filesystem. It is built to be non-intrusive, prioritizing system stability while maintaining deep visibility into process memory permissions.

##  Components
- **Process Hunter (core/process_hunter.c)**: Responsible for enumerating active PIDs and filtering kernel threads from userspace processes.
- **Memory Analyzer (core/mem_analyzer.c)**: The detection engine that parses memory maps to identify RWX (Read-Write-Execute) permission patterns.
- **K-Scanner Core (core/kscanner.c)**: Orchestrates the scanning lifecycle and manages the real-time Terminal UI (Live Dashboard).
- **Logger & Utils (utils/)**: Handles forensic-grade output formatting and memory-safe string operations.

##  Data Flow
1. **Enumeration**: The Hunter scans `/proc` for active Process IDs.
2. **Parsing**: The Analyzer reads the specific memory maps (`/proc/[PID]/maps`) for each target.
3. **Detection**: The engine flags any 'rwxp' (Read, Write, Execute, Private) memory segments.
4. **Presentation**: The live dashboard updates the UI, highlighting alerts and summarizing the forensic integrity of the system.

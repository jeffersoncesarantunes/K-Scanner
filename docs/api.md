# K-Scanner API Reference

## Core Forensic Functions
- `forensic_has_rwx_memory(pid_t pid)`: Primary analysis function. Scans the memory segments of a given PID and returns 1 if RWX permissions are detected.
- `hunter_get_processes()`: Scans the system for active PIDs and returns a collection of process contexts for analysis.
- `scanner_start_live_mode()`: Initiates the main execution loop, handling real-time updates and dashboard refreshing.

## Data Structures
- `ScannerConfig`: Global configuration object (e.g., scan delays, verbosity levels).
- `ProcessAlert`: Data structure used to store detected threats, including PID, process name, and the suspicious memory offset.

## Utility Functions
- `log_forensic_alert()`: Standardized logging for critical findings.
- `memory_to_hex_string()`: Helper to format raw memory addresses for the dashboard display.

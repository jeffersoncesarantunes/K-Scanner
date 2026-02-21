# K-Scanner
A lightweight Linux memory auditing tool focused on RWX detection.

## Overview

K-Scanner is a minimal forensic utility designed to audit memory protection flags of active Linux processes.

It analyzes the /proc virtual filesystem to identify memory regions that violate the W^X (Write XOR Execute) security principle — a condition commonly associated with:

- Shellcode injection
- JIT-compiled regions
- Packed executables
- Fileless malware techniques

The project is written in pure C with emphasis on performance, clarity, and forensic integrity.

## How It Works

K-Scanner parses:

/proc/[PID]/maps

For each running process, it inspects memory segments and evaluates their permission flags.

If a memory region simultaneously contains:

- W (Write)
- X (Execute)

an RWX alert is triggered, since this combination weakens modern memory protection strategies.

The scanner operates through read-only metadata inspection and does not rely on intrusive debugging mechanisms such as ptrace.

## Design Philosophy

K-Scanner was built around three principles:

1. Simplicity  
   No kernel modules, no injection, no process suspension.

2. Forensic Integrity  
   The scanner does not modify process memory or alter execution state.

3. Performance  
   Implemented in optimized C (C99) for minimal overhead during live system analysis.

## Limitations

- RWX detection alone does NOT confirm malicious activity.
- Some legitimate applications (e.g., JIT engines) may legitimately allocate RWX regions.
- Elevated privileges may be required to inspect certain processes.
- Tested primarily on Arch Linux (Kernel 6.x).
- Does not perform full memory content inspection by default.

## Project in Action

Figure 1 — System-wide memory audit  
Displays scanning across all active PIDs.

Figure 2 — RWX Detection Alert  
Highlights suspicious memory regions.

Figure 3 — Forensic Follow-up  
Workflow combining:
- SHA256 binary validation
- Memory extraction
- String analysis

Screenshots are available in the /Imagens directory.

## Features

- System-wide PID scanning
- RWX memory detection engine
- SAFE / ALERT classification
- Clean terminal output
- Low memory footprint
- Designed for forensic triage scenarios

## Operational Integrity

K-Scanner is designed for stability in live environments:

- Handles inaccessible /proc entries gracefully
- Skips restricted kernel threads without crashing
- Maintains scan continuity under permission errors

The focus is reliability during incident response and live investigations.

## Investigation Workflow

After detecting an RWX region, analysts may proceed with:

Binary validation:
sha256sum /proc/[PID]/exe

Memory extraction (advanced):
sudo dd if=/proc/[PID]/mem of=dump.bin bs=1 skip=<offset> count=<size>

String inspection:
Search for suspicious domains, encoded commands, or unusual artifacts in memory dumps.

## Deployment

Requirements:
- Linux OS
- gcc
- make
- sudo privileges

Build and execute:

git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner

make clean && make
sudo ./build/kscanner

## Tech Stack

Language: C (C99)  
Data Source: /proc Filesystem  
Build Tool: GNU Make  
Target: Linux Kernel 4.x / 5.x / 6.x  

## Roadmap

- RWX detection engine (Completed)
- Structured output format (Completed)
- JSON export for SIEM integration
- Interactive TUI interface
- Automated memory dump for flagged PIDs
- Multi-threaded scan optimization
- Kernel telemetry research

## License

Distributed under the MIT License.  
See LICENSE file for more information.

Developed as a practical exploration of Linux memory internals and live forensic analysis techniques.


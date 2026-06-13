# K-Scanner Architecture Reference

## 1. Overview

K-Scanner is a live forensic tool that inspects running processes through the `/proc` virtual filesystem. Everything is read-only — no processes get stopped, nothing gets `ptrace`d. The goal is to stay out of the way while still giving you meaningful visibility into memory permissions.

---

## 2. Module Map

```
src/
├── main.c                     Entry point, CLI dispatch
├── core/
│   ├── kscanner.c             Scan orchestrator, TUI loop, memory dump
│   ├── mem_analyzer.c         RWX region detection + lifecycle API
│   └── process_hunter.c       Process enumeration + metadata lookup
├── modules/
│   ├── tui_engine.c           ncurses dashboard rendering
│   ├── export_engine.c        JSON / CSV / terminal structured output
│   ├── regex_engine.c         In-memory regex search (/proc/[PID]/mem)
│   ├── bpf_telemetry.c        eBPF real-time RWX monitor (libbpf)
│   └── advanced_features.c    Container detection, risk scoring
└── utils/
    └── logger.c               Table-formatted terminal output
```

### 2.1 Entry Point — `src/main.c`

Parses CLI flags (`--json`, `--csv`, `--live`, `--bpf`, `--help`), decides whether to run the TUI or headless mode, then hands off to the scan orchestrator.

### 2.2 Scan Orchestrator — `src/core/kscanner.c`

- `run_scan_formatted()` — walks through `/proc`, calls `check_mem_rwx()` on each PID, then renders the TUI dashboard or writes structured output.
- `run_scan_formatted_bpf()` — same loop but also polls the eBPF perf ring between TUI refreshes, displaying live RWX events as they come in.
- `dump_memory_region()` — triggered by ENTER in the TUI. Reads the suspicious memory region from `/proc/[PID]/mem`, writes a `.bin` dump, and spawns `sha256sum`, `strings`, and `hexdump` into `build/dumps/`.

### 2.3 Detection Engine — `src/core/mem_analyzer.c`

- `forensic_has_rwx_memory()` — scans `/proc/[PID]/maps` for `rwxp` permission entries. Returns 1 if any RWX region is found.
- `forensic_init()` — checks that `/proc` is accessible.
- `forensic_cleanup()` — no persistent resources to clean up in the current design.

### 2.4 Process Hunter — `src/core/process_hunter.c`

- `forensic_get_process_info()` — reads PID, name, exe path, RWX status, and container/sandbox flags into a `forensic_process_t` struct.
- `forensic_scan_all()` — counts all numeric entries under `/proc`.
- `forensic_analyze_pid()` — checks whether `/proc/[PID]/maps` is readable.

### 2.5 TUI Engine — `src/modules/tui_engine.c`

Straightforward ncurses rendering:

- `init_tui()` / `stop_tui()` — lifecycle management.
- `update_dashboard()` — draws the process table with color-coded rows (red for `RWX ALERT`, green for `SAFE`), supports scrolling.
- `handle_input()` — wraps `getch()`.

### 2.6 Export Engine — `src/modules/export_engine.c`

Serializes `ForensicRecord[]` into three formats:

- `EXPORT_TERMINAL` — aligned table for stdout.
- `EXPORT_JSON` — array of objects with pid/process/status/info/addr.
- `EXPORT_CSV` — header row plus comma-separated values.

### 2.7 Regex Engine — `src/modules/regex_engine.c`

- `start_live_regex_hunting()` — opens `/proc/[PID]/mem`, iterates over readable memory regions from `/proc/[PID]/maps`, runs a POSIX extended regex on each region, and calls `dispatch_regex_match()` on every hit.
- Invoked via `kscanner --live <PID> '<pattern>'`.

### 2.8 eBPF Telemetry — `src/modules/bpf_telemetry.c`

- Hooks `raw_tp/sys_enter` to catch `mmap(2)` / `mprotect(2)` calls with `PROT_WRITE | PROT_EXEC`.
- Pushes events through a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` up to userspace.
- `bpf_telemetry_init()`, `bpf_telemetry_poll()`, `bpf_telemetry_shutdown()` handle the libbpf lifecycle.
- Events drain into a fixed-size ring buffer that the TUI loop or headless code path can consume.

### 2.9 Advanced Features — `src/modules/advanced_features.c`

- `is_containerized()` — checks `/proc/[PID]/cgroup` for docker/lxc/kubepods.
- `print_advanced_report()` — combines RWX status with container info and assigns a risk level (LOW / MEDIUM / HIGH / CRITICAL).
- `run_live_regex_scan()` — CLI entry point wrapping the regex engine.

---

## 3. Data Flow

```
CLI arguments
     │
     ▼
  main.c  ────┬─── --live → regex_engine (standalone)
              │
              ├─── --bpf  → bpf_telemetry (monitor in background)
              │
              └─── default → kscanner.c
                               │
                               ▼
                         /proc enumeration
                               │
                               ▼
                    check_mem_rwx() per PID
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
                 TUI mode             headless mode
              update_dashboard()    export_engine (JSON/CSV)
                    │
              [ENTER] → dump_memory_region()
                         ├── .bin (raw dump)
                         ├── .sha256
                         ├── .strings.txt
                         └── .hex.txt
```

## 4. Core Data Structures

```c
typedef struct {
    int pid;
    char process_name[256];
    char status[64];       // "RWX ALERT" | "SAFE"
    char info_path[512];   // region count + context tag
    char mem_addr[64];     // first RWX address
} ForensicRecord;

typedef struct {
    pid_t pid;
    char  name[256];
    char  exe_path[4096];
    uint64_t memory_rwx;
    int is_sandboxed;
    int is_container;
} forensic_process_t;
```

## 5. Build & Dependencies

| Component           | Dependency          | Optional |
|---------------------|---------------------|----------|
| Core scanner        | glibc, Linux `/proc`| no       |
| TUI                 | ncurses             | no       |
| eBPF telemetry      | libbpf, kernel BTF  | yes      |
| Regex engine        | POSIX regex (glibc) | no       |

`make bpf` compiles the BPF object; `make` links it in if libbpf is detected. Run `make install` to deploy both the binary and the BPF object.

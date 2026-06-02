#  ● K-Scanner Architecture Reference

## 1. Overview

K-Scanner is a high-performance live forensic tool that analyzes running
processes via the `/proc` virtual filesystem.  It is non-intrusive — all
inspection is read-only, no process is stopped or `ptrace`d.

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
    ├── logger.c               Table-formatted terminal output
    └── memory_utils.c         /proc/[PID]/maps RWX test
```

### 2.1 Entry Point — `src/main.c`

Parses CLI flags (`--json`, `--csv`, `--live`, `--bpf`, `--help`), selects
TUI or headless mode, and invokes the scan orchestrator.

### 2.2 Scan Orchestrator — `src/core/kscanner.c`

- `run_scan_formatted()` — enumerates `/proc`, calls `check_mem_rwx()` per
  PID, renders the TUI dashboard or writes structured output.
- `run_scan_formatted_bpf()` — same loop but polls the eBPF perf ring
  between TUI refreshes and displays live RWX events.
- `dump_memory_region()` — triggered by ENTER in the TUI; reads the
  suspicious memory region from `/proc/[PID]/mem`, writes a `.bin` dump,
  and spawns `sha256sum`, `strings`, `hexdump` in `build/dumps/`.

### 2.3 Detection Engine — `src/core/mem_analyzer.c`

- `forensic_has_rwx_memory()` — scans `/proc/[PID]/maps` for `rwxp`
  permission entries.  Returns 1 if any RWX region is found.
- `forensic_init()` — verifies `/proc` is accessible.
- `forensic_cleanup()` — no persistent resources in the current design.

### 2.4 Process Hunter — `src/core/process_hunter.c`

- `forensic_get_process_info()` — reads PID, name, exe path, RWX status,
  container/sandbox flags into a `forensic_process_t` struct.
- `forensic_scan_all()` — counts all numeric entries under `/proc`.
- `forensic_analyze_pid()` — checks whether `/proc/[PID]/maps` is readable.

### 2.5 TUI Engine — `src/modules/tui_engine.c`

Raw ncurses rendering:
- `init_tui()` / `stop_tui()` — lifecycle.
- `update_dashboard()` — paints the process table with colour-coded rows
  (red = `RWX ALERT`, green = `SAFE`), supports scrolling.
- `handle_input()` — wraps `getch()`.

### 2.6 Export Engine — `src/modules/export_engine.c`

Serializes `ForensicRecord[]` to three formats:
- `EXPORT_TERMINAL` — aligned table for stdout.
- `EXPORT_JSON` — array of objects with pid/process/status/info/addr.
- `EXPORT_CSV` — header row + comma-separated values.

### 2.7 Regex Engine — `src/modules/regex_engine.c`

- `start_live_regex_hunting()` — opens `/proc/[PID]/mem`, iterates over
  readable memory regions from `/proc/[PID]/maps`, runs a POSIX extended
  regex on each region, and calls `dispatch_regex_match()` for every hit.
- Invoked via `kscanner --live <PID> '<pattern>'`.

### 2.8 eBPF Telemetry — `src/modules/bpf_telemetry.c`

- Hooks `raw_tp/sys_enter` to intercept `mmap(2)` / `mprotect(2)` calls
  with `PROT_WRITE | PROT_EXEC`.
- Pushes events through a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` to userspace.
- `bpf_telemetry_init()`, `bpf_telemetry_poll()`, `bpf_telemetry_shutdown()`
  manage the libbpf lifecycle.
- Events are drained into a fixed-size ring buffer and consumed by the
  TUI loop or the headless code path.

### 2.9 Advanced Features — `src/modules/advanced_features.c`

- `is_containerized()` — inspects `/proc/[PID]/cgroup` for docker/lxc/kubepods.
- `print_advanced_report()` — combines RWX + container info into a risk
  level (LOW / MEDIUM / HIGH / CRITICAL).
- `run_live_regex_scan()` — CLI entry point that wraps the regex engine.

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

`make bpf` compiles the BPF object; `make` links it in if libbpf is
detected.  Run `make install` to deploy the binary + BPF object.

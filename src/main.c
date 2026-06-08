#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../include/kscanner.h"
#include "../include/scanner_core.h"
#include "../include/colors.h"
#include "../include/export_engine.h"
#include "../include/tui_engine.h"
#include "../include/bpf_telemetry.h"

static void print_main_usage(void) {
    printf("Usage: kscanner [OPTIONS]\n");
    printf("Options:\n");
    printf("  --json                Export results in JSON format\n");
    printf("  --csv                 Export results in CSV format\n");
    printf("  --live <pid> <rgx>    Search for regex pattern in process memory\n");
    printf("  --bpf                 Enable eBPF real-time RWX telemetry (requires root)\n");
    printf("  --silent-jit          Suppress JIT engine RWX from alert count (reduce FP)\n");
    printf("  --watch               Continuous headless monitoring (2s cycles, Ctrl+C to exit)\n");
    printf("  --yara <rule.yara>    Scan forensic dumps with YARA rules (requires yara)\n");
    printf("  --help                Show this help message\n");
}

static int handle_bpf_flag(BpfTelemetryState *bpf_state) {
    int ret = bpf_telemetry_init(bpf_state);
    if (ret != 0) {
        fprintf(stderr, "%s[!] eBPF telemetry unavailable: %s%s\n",
                CLR_YELLOW, bpf_state->error_msg, CLR_RESET);
        fprintf(stderr, "    Either the BPF object is missing (re-build with 'make bpf')\n");
        fprintf(stderr, "    or the kernel does not support BPF / you lack CAP_BPF.\n");
        return -1;
    }
    fprintf(stderr, "%s[+] eBPF telemetry active — monitoring RWX allocations in real time%s\n",
            CLR_GREEN, CLR_RESET);
    return 0;
}

int main(int argc, char *argv[]) {
    ExportFormat selected_format = EXPORT_TERMINAL;
    int use_tui = 1;
    int use_bpf = 0;
    int silent_jit = 0;
    int use_watch = 0;
    const char *yara_rule = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--live") == 0) {
            if (i + 2 < argc) {
                char *end;
                long pid = strtol(argv[i+1], &end, 10);
                if (*end != '\0' || pid <= 0) {
                    fprintf(stderr, "Error: --live requires a valid PID > 0\n");
                    return 1;
                }
                const char *pattern = argv[i+2];
                run_live_regex_scan((int)pid, pattern);
                return 0;
            } else {
                fprintf(stderr, "Error: --live requires PID and PATTERN\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--json") == 0) {
            selected_format = EXPORT_JSON;
            use_tui = 0;
        } else if (strcmp(argv[i], "--csv") == 0) {
            selected_format = EXPORT_CSV;
            use_tui = 0;
        } else if (strcmp(argv[i], "--bpf") == 0) {
            use_bpf = 1;
        } else if (strcmp(argv[i], "--watch") == 0) {
            use_watch = 1;
            use_tui = 0;
        } else if (strcmp(argv[i], "--silent-jit") == 0) {
            silent_jit = 1;
        } else if (strcmp(argv[i], "--yara") == 0) {
            if (i + 1 < argc) {
                yara_rule = argv[++i];
                if (access(yara_rule, R_OK) != 0) {
                    fprintf(stderr, "Error: --yara rule file not readable: %s\n", yara_rule);
                    return 1;
                }
            } else {
                fprintf(stderr, "Error: --yara requires a rule file path\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
            print_main_usage();
            return 0;
        }
    }

    BpfTelemetryState bpf_state;
    if (use_bpf) {
        if (handle_bpf_flag(&bpf_state) != 0) {
            return 1;
        }
    }

    if (yara_rule) set_yara_rule_path(yara_rule);

    if (use_watch) {
        run_watch_loop(selected_format, silent_jit);
        if (use_bpf) bpf_telemetry_shutdown(&bpf_state);
        return 0;
    }

    if (use_tui) {
        init_tui();
        run_scan_formatted_bpf(selected_format, use_bpf ? &bpf_state : NULL, silent_jit);
        stop_tui();
    } else {
        if (run_scan_formatted(selected_format, silent_jit) != 0) {
            fprintf(stderr, "%s[!] Critical error during scan%s\n", CLR_RED, CLR_RESET);
            return 1;
        }
        if (use_bpf) {
            BpfRwxEvent bpf_ev;
            int n = bpf_telemetry_drain_ring(&bpf_state, &bpf_ev, 1);
            if (n > 0) {
                const char *sname = "?";
                switch (bpf_ev.syscall_nr) {
                    case 9:  sname = "mmap"; break;
                    case 10: sname = "mprotect"; break;
                    case 30: sname = "shmat"; break;
                    case 59: sname = "execve"; break;
                }
                printf("%s[BPF] %s — PID %d (%s) @ %s%s\n",
                       CLR_RED, sname, bpf_ev.pid, bpf_ev.comm, bpf_ev.addr, CLR_RESET);
            }
        }
    }

    if (use_bpf) {
        bpf_telemetry_shutdown(&bpf_state);
    }

    return 0;
}

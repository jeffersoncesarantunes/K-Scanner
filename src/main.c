#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../include/kscanner.h"
#include "../include/scanner_core.h"
#include "../include/colors.h"
#include "../include/export_engine.h"
#include "../include/tui_engine.h"
#include "../include/bpf_telemetry.h"

static int resolve_binary_path(const char *name, char **out) {
    const char *path_env = getenv("PATH");
    if (!path_env) return -1;

    char *path_copy = strdup(path_env);
    if (!path_copy) return -1;

    char *dir;
    char full[4096];
    int found = -1;

    dir = strtok(path_copy, ":");
    while (dir) {
        snprintf(full, sizeof(full), "%s/%s", dir, name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH))) {
            *out = strdup(full);
            if (!*out) { free(path_copy); return -1; }
            found = 0;
            break;
        }
        dir = strtok(NULL, ":");
    }

    free(path_copy);
    return found;
}

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
    fprintf(stderr, "%s[+] eBPF telemetry active -- monitoring RWX allocations in real time%s\n",
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
                int rule_fd = open(yara_rule, O_RDONLY);
                if (rule_fd == -1) {
                    fprintf(stderr, "Error: --yara rule file not readable: %s\n", yara_rule);
                    return 1;
                }
                close(rule_fd);
                char *yara_bin = NULL;
                if (resolve_binary_path("yara", &yara_bin) != 0) {
                    fprintf(stderr, "Error: 'yara' binary not found in PATH\n");
                    return 1;
                }
                set_yara_binary_path(yara_bin);
                free(yara_bin);
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
        run_scan_formatted(selected_format, use_bpf ? &bpf_state : NULL, silent_jit);
        stop_tui();
    } else {
        if (run_scan_formatted(selected_format, use_bpf ? &bpf_state : NULL, silent_jit) != 0) {
            fprintf(stderr, "%s[!] Critical error during scan%s\n", CLR_RED, CLR_RESET);
            if (use_bpf) bpf_telemetry_shutdown(&bpf_state);
            return 1;
        }
    }

    if (use_bpf) {
        bpf_telemetry_shutdown(&bpf_state);
    }

    return 0;
}

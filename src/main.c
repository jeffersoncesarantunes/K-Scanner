#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/kscanner.h"
#include "../include/scanner_core.h"
#include "../include/colors.h"
#include "../include/export_engine.h"
#include "../include/tui_engine.h"

void print_main_usage(void) {
    printf("Usage: kscanner [OPTIONS]\n");
    printf("Options:\n");
    printf("  --json             Export results in JSON format\n");
    printf("  --csv              Export results in CSV format\n");
    printf("  --live <pid> <rgx> Search for regex pattern in process memory\n");
    printf("  --help             Show this help message\n");
}

int main(int argc, char *argv[]) {
    ExportFormat selected_format = EXPORT_TERMINAL;
    int use_tui = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--live") == 0) {
            if (i + 2 < argc) {
                int pid = atoi(argv[i+1]);
                const char *pattern = argv[i+2];
                run_live_regex_scan(pid, pattern);
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
        } else if (strcmp(argv[i], "--help") == 0) {
            print_main_usage();
            return 0;
        }
    }

    if (use_tui) {
        init_tui();
        run_scan_formatted(selected_format);
        stop_tui();
    } else {
        if (run_scan_formatted(selected_format) != 0) {
            fprintf(stderr, "%s[!] Critical error during scan%s\n", CLR_RED, CLR_RESET);
            return 1;
        }
    }

    return 0;
}

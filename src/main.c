#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kscanner.h"
#include "colors.h"
#include "export_engine.h"
#include "tui_engine.h"

void print_banner(void) {
    printf("%s", CLR_BOLD);
    printf("+-------------------------------------------------------------------------------------+\n");
    printf("|                                       K-Scanner                                     |\n");
    printf("|                          Live Forensic Process Analysis Mode                        |\n");
    printf("+-------------------------------------------------------------------------------------+\n");
    printf("%s", CLR_RESET);
}

int main(int argc, char *argv[]) {
    ExportFormat selected_format = EXPORT_TERMINAL;
    int use_tui = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            selected_format = EXPORT_JSON;
            use_tui = 0;
        } else if (strcmp(argv[i], "--csv") == 0) {
            selected_format = EXPORT_CSV;
            use_tui = 0;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        }
    }

    if (use_tui) {
        init_tui();
        run_scan_formatted(selected_format);
        stop_tui();
    } else {
        export_header(selected_format);
        if (run_scan_formatted(selected_format) != 0) {
            fprintf(stderr, "%s[!] Critical error during scan%s\n", CLR_RED, CLR_RESET);
            return 1;
        }
        export_footer(selected_format);
    }

    return 0;
}

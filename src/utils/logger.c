#include "colors.h"
#include "forensic_core.h"
#include "logger.h"
#include <stdio.h>

void print_table_header(void) {
    printf("+--------+----------------------------------+--------------------+--------------------+\n");
    printf("| PID    | PROCESS NAME                     | STATUS             | INFO / PATH        |\n");
    printf("+--------+----------------------------------+--------------------+--------------------+\n");
}

void print_process_row(forensic_process_t *proc) {
    const char *status_color = (proc->memory_rwx > 0) ? CLR_RED : CLR_GREEN;
    const char *status_text = (proc->memory_rwx > 0) ? "RWX ALERT" : "SAFE";

    printf("| %-6d | %-32s | ", proc->pid, proc->name);
    printf("%s%-18s%s | ", status_color, status_text, CLR_RESET);
    printf("%-18.18s |\n", (proc->memory_rwx > 0) ? proc->exe_path : "STABLE");
}

void print_table_footer(void) {
    printf("+--------+----------------------------------+--------------------+--------------------+\n");
}

void print_scan_summary(int total, int rwx, int safe) {
    print_table_footer();
    printf("\n%s📊 Total: %d processes | 🔴 RWX: %d | 🟢 SAFE: %d%s\n", 
           CLR_BOLD, total, rwx, safe, CLR_RESET);
    printf("[+] Scan completed successfully.\n");
}

#include <stdio.h>
#include <string.h>
#include "../../include/scanner_core.h"
#include "../../include/colors.h"

int is_containerized(int pid) {
    char path[256];
    char buf[256];
    
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    while (fgets(buf, sizeof(buf), f)) {
        if (strstr(buf, "docker") || strstr(buf, "lxc") || strstr(buf, "kubepods")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

void print_advanced_report(int pid, char* name, int has_rwx) {
    int container = is_containerized(pid);
    const char* risk = "LOW";
    
    if (has_rwx && container) risk = "CRITICAL";
    else if (has_rwx) risk = "HIGH";
    else if (container) risk = "MEDIUM";
    
    printf("PID: %d | Name: %s | Risk: %s | Container: %s\n", 
           pid, name, risk, container ? "YES" : "NO");
}

void run_advanced_scan(void) {
    printf("%s[+] Running advanced container detection scan%s\n", 
           CLR_CYAN, CLR_RESET);
}

void run_live_regex_scan(int pid, const char *pattern) {
    printf("%s[+] Initializing Live Regex Hunting for PID %d%s\n", 
           CLR_YELLOW, pid, CLR_RESET);
    
    if (start_live_regex_hunting(pid, pattern) != 0) {
        printf("%s[-] Regex Hunting failed for PID %d%s\n", 
               CLR_RED, pid, CLR_RESET);
    }
}

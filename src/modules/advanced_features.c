#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "kscanner.h"
#include "colors.h"

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

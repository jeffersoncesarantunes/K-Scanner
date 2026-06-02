#include "forensic_core.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>

int forensic_get_process_info(pid_t pid, forensic_process_t *proc) {
    char path[512];
    FILE *f;

    proc->pid = pid;
    proc->memory_rwx = forensic_has_rwx_memory(pid);
    proc->is_sandboxed = 0;
    proc->is_container = 0;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    f = fopen(path, "r");
    if (f) {
        if (fgets(proc->name, sizeof(proc->name), f)) {
            proc->name[strcspn(proc->name, "\n")] = 0;
        }
        fclose(f);
    } else {
        return -1;
    }

    snprintf(proc->exe_path, sizeof(proc->exe_path), "/proc/%d/exe", pid);
    return 0;
}

int forensic_scan_all(void) {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;

    struct dirent *entry;
    int scanned = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;
        scanned++;
    }
    closedir(dir);
    return scanned;
}

int forensic_analyze_pid(pid_t pid) {
    if (pid <= 0) return -1;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    fclose(f);
    return 0;
}

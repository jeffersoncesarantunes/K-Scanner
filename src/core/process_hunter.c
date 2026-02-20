#include "forensic_core.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int forensic_get_process_info(pid_t pid, forensic_process_t *proc) {
    char path[512];
    FILE *f;

    proc->pid = pid;
    proc->memory_rwx = forensic_has_rwx_memory(pid);

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

    return 0;
}

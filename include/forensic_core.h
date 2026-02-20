#ifndef FORENSIC_CORE_H
#define FORENSIC_CORE_H

#include <sys/types.h>
#include <stdint.h>

typedef struct {
    pid_t pid;
    char name[256];
    char exe_path[4096];
    uint64_t memory_rwx;
    int is_sandboxed;
    int is_container;
} forensic_process_t;

int forensic_init(void);
int forensic_scan_all(void);
int forensic_analyze_pid(pid_t pid);
int forensic_get_process_info(pid_t pid, forensic_process_t *proc);
int forensic_has_rwx_memory(pid_t pid);
void forensic_cleanup(void);

#endif

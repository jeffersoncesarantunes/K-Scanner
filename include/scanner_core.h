#ifndef SCANNER_CORE_H
#define SCANNER_CORE_H

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

typedef struct {
    pid_t pid;
    char name[256];
    char threat_level[20];
    char context[20];
} process_info_t;

void scan_processes(void);
int analyze_process_risk(int pid, const char *name);
int analyze_process_safety(int pid, const char* reported_name);
int is_sandboxed(int pid);
void print_process_table(process_info_t *processes, int count);

#endif

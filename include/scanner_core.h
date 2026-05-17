#ifndef SCANNER_CORE_H
#define SCANNER_CORE_H

#include <sys/types.h>
#include <unistd.h>
#include <regex.h>

typedef struct {
    pid_t pid;
    unsigned long long address_start;
    char context_preview[512];
} regex_match_t;

int start_live_regex_hunting(pid_t pid, const char *pattern);
void dispatch_regex_match(regex_match_t *match);
void run_live_regex_scan(int pid, const char *pattern);

#endif

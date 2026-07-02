#include "../../include/scanner_core.h"
#include "../../include/colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int start_live_regex_hunting(pid_t pid, const char *pattern) {
    char maps_path[64], mem_path[64], line[1024];
    FILE *maps_file;
    int mem_fd;
    regex_t regex;
    regmatch_t pmatch[1];
    int found_count = 0;

    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) return -1;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        regfree(&regex);
        return -1;
    }

    mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fclose(maps_file);
        regfree(&regex);
        return -1;
    }

    while (fgets(line, sizeof(line), maps_file)) {
        unsigned long long start, end;
        char perms[5];
        
        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) != 3) continue;

        if (perms[0] != 'r' || strstr(line, "/usr/share/fonts")) continue;

        size_t region_size = end - start;
        if (region_size > 100 * 1024 * 1024) continue; 

        char *buffer = malloc(region_size);
        if (!buffer) {
            fprintf(stderr, "[!] OOM: pid %d, region 0x%llx-0x%llx (%zu bytes)\n",
                    pid, start, end, region_size);
            continue;
        }

        ssize_t bytes_read = pread(mem_fd, buffer, region_size, start);
        
        if (bytes_read > 0) {
            char *current_pos = buffer;
            size_t remaining = (size_t)bytes_read;

            while (remaining > 0 && regexec(&regex, current_pos, 1, pmatch, 0) == 0) {
                regex_match_t match;
                match.pid = pid;
                match.address_start = start + (unsigned long long)(current_pos - buffer) + (unsigned long long)pmatch[0].rm_so;
                
                memset(match.context_preview, 0, sizeof(match.context_preview));
                size_t match_offset = (size_t)pmatch[0].rm_so;
                size_t preview_start = (match_offset > 10) ? match_offset - 10 : match_offset;
                
                size_t copy_len = (remaining - preview_start > 60) ? 60 : (remaining - preview_start);
                memcpy(match.context_preview, current_pos + preview_start, copy_len);

                dispatch_regex_match(&match);
                
                found_count++;
                size_t move = (size_t)pmatch[0].rm_eo;
                if (move == 0) move = 1;
                
                if (move > remaining) break;
                current_pos += move;
                remaining -= move;
            }
        }
        free(buffer);
    }

    close(mem_fd);
    fclose(maps_file);
    regfree(&regex);
    return (found_count > 0) ? 0 : -2;
}

void dispatch_regex_match(regex_match_t *match) {
    printf("\n--- AUDIT DETECTION ---\n");
    printf("Address: 0x%llx | PID: %d\n", match->address_start, match->pid);
    printf("Context: %s\n", match->context_preview);
}

void run_live_regex_scan(int pid, const char *pattern) {
    printf("%s[+] Initializing Live Regex Hunting for PID %d%s\n",
           CLR_YELLOW, pid, CLR_RESET);
    if (start_live_regex_hunting(pid, pattern) != 0) {
        printf("%s[-] Regex Hunting failed for PID %d%s\n",
               CLR_RED, pid, CLR_RESET);
    }
}

#include "forensic_core.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int forensic_has_rwx_memory(pid_t pid) {
    char path[64];
    char line[512];
    FILE *fp;
    int found_rwx = 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    fp = fopen(path, "r");
    
    if (!fp) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "rwxp")) {
            found_rwx = 1;
            break;
        }
    }

    fclose(fp);
    return found_rwx;
}

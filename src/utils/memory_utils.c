#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "kscanner.h"

int analyze_process_memory(int pid, char* reported_name) {
    (void)reported_name;
    
    char path[256];
    char line[512];
    FILE *fp;
    
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    fp = fopen(path, "r");
    if (!fp) return 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "rwx")) {
            fclose(fp);
            return 1;
        }
    }
    
    fclose(fp);
    return 0;
}

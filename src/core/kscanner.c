#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "colors.h"
#include "kscanner.h"
#include "forensic_core.h"
#include "logger.h"

static const char* map_context_tag(const char* path, int* is_suspicious) {
    *is_suspicious = 0;
    if (path == NULL || strlen(path) == 0 || strcmp(path, "[Anonymous/Heap]") == 0) {
        *is_suspicious = 1;
        return "ANON_BLOB";
    }
    if (strstr(path, "js-executable")) return "JIT_ENGINE";
    if (strstr(path, "heap") || strstr(path, "[heap]")) return "DYNAMIC_MEM";
    if (strstr(path, "stack") || strstr(path, "[stack]")) {
        *is_suspicious = 1;
        return "PROC_STACK";
    }
    if (strstr(path, "/usr/lib") || strstr(path, ".so")) return "SYSTEM_LIB";
    if (strstr(path, "/tmp") || strstr(path, "/dev/shm")) {
        *is_suspicious = 1;
        return "VOLATILE_FS";
    }
    
    return "MAPPED_FILE";
}

static void dump_memory_region(int pid, char *addr_str) {
    char mem_path[256], out_path[256], line[512];
    unsigned long start, end;

    snprintf(mem_path, sizeof(mem_path), "/proc/%d/maps", pid);
    FILE *f = fopen(mem_path, "r");
    if (!f) return;

    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "rwxp") && strstr(line, addr_str)) {
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                found = 1;
                break;
            }
        }
    }
    fclose(f);

    if (!found) return;

    size_t size = end - start;
    void *buffer = malloc(size);
    if (!buffer) return;

    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int fd = open(mem_path, O_RDONLY);
    if (fd == -1) {
        free(buffer);
        return;
    }

    if (pread(fd, buffer, size, (off_t)start) == (ssize_t)size) {
        mkdir("build/dumps", 0755);
        snprintf(out_path, sizeof(out_path), "build/dumps/pid_%d_%lx.bin", pid, start);
        int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out_fd != -1) {
            write(out_fd, buffer, size);
            close(out_fd);
        }
    }

    close(fd);
    free(buffer);
}

static int check_mem_rwx(int pid, char *out_info) {
    char path[256], line[512];
    char addr[64], perms[8], pathname[256];
    int found_count = 0;
    char raw_origin[256] = "";

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "rwxp")) {
            pathname[0] = '\0';
            sscanf(line, "%63s %7s %*s %*s %*s %255s", addr, perms, pathname);
            
            if (found_count == 0) {
                strncpy(raw_origin, pathname, sizeof(raw_origin));
                char start_addr_hex[18];
                sscanf(addr, "%17[^ -]", start_addr_hex);
                dump_memory_region(pid, start_addr_hex);
            }
            found_count++;
        }
    }
    fclose(f);

    if (found_count > 0) {
        int is_suspicious = 0;
        const char* tag = map_context_tag(raw_origin, &is_suspicious);
        snprintf(out_info, 128, "%02dx %s", found_count, tag);
    } else {
        strcpy(out_info, "STABLE");
    }

    return found_count;
}

static void get_process_name(int pid, char *out_name) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(out_name, 33, f)) {
            out_name[strcspn(out_name, "\n")] = 0;
        }
        fclose(f);
    } else {
        strncpy(out_name, "unknown", 33);
    }
}

int run_scan(void) {
    DIR *dir;
    struct dirent *entry;
    int total_processes = 0;
    int rwx_alerts = 0;
    int current_page_count = 0;

    printf("\n%s[+] Initializing real-time forensic memory scan...%s\n\n", CLR_GREEN, CLR_RESET);
    
    print_table_header();

    dir = opendir("/proc");
    if (!dir) {
        perror("Failed to open /proc");
        return 1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;

        int pid = atoi(entry->d_name);
        forensic_process_t proc;
        
        proc.pid = pid;
        get_process_name(pid, proc.name);
        
        char rwx_details[128];
        int violations = check_mem_rwx(pid, rwx_details);
        proc.memory_rwx = violations;
        snprintf(proc.exe_path, sizeof(proc.exe_path), "%s", rwx_details);

        total_processes++;
        current_page_count++;

        if (violations > 0) {
            rwx_alerts++;
        }

        print_process_row(&proc);

        if (current_page_count >= 20) {
            print_table_footer();
            printf("%s-- Press ENTER to continue scanning... --%s", CLR_YELLOW, CLR_RESET);
            
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF);
            
            print_table_header();
            current_page_count = 0;
        }
    }
    closedir(dir);

    print_scan_summary(total_processes, rwx_alerts, total_processes - rwx_alerts);
    
    return 0;
}

void print_usage(void) {
    printf("\n%sK-Scanner Forensic Tool%s\n", CLR_BOLD, CLR_RESET);
    printf("Usage: sudo ./kscanner [OPTIONS]\n\n");
    printf("Options:\n");
    printf("  --help    Show this diagnostic information\n\n");
    printf("Note: Root privileges are required to access process memory maps.\n");
}

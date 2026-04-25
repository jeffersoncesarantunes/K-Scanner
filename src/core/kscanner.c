#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ncurses.h>
#include "colors.h"
#include "kscanner.h"
#include "forensic_core.h"
#include "logger.h"
#include "export_engine.h"
#include "tui_engine.h"

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
    char mem_path[256], out_path[256], line[512], cmd[2048];
    char file_name[128];
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
        mkdir("build", 0755);
        mkdir("build/dumps", 0755);
        snprintf(file_name, sizeof(file_name), "pid_%d_%lx.bin", pid, start);
        snprintf(out_path, sizeof(out_path), "build/dumps/%s", file_name);
        int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out_fd != -1) {
            write(out_fd, buffer, size);
            close(out_fd);
            snprintf(cmd, sizeof(cmd), 
                "cd build/dumps && "
                "sha256sum %s > %s.sha256 && "
                "strings -n 6 %s > %s.strings.txt && "
                "hexdump -C %s | head -n 256 > %s.hex.txt",
                file_name, file_name, file_name, file_name, file_name, file_name);
            system(cmd);
        }
    }
    close(fd);
    free(buffer);
}

static int check_mem_rwx(int pid, char *out_info, char *out_addr) {
    char path[256], line[512], addr[64], perms[8], pathname[256];
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
                strncpy(out_addr, start_addr_hex, 64);
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
        strcpy(out_addr, "n/a");
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

int run_scan_formatted(ExportFormat format) {
    DIR *dir;
    struct dirent *entry;
    char temp_name[256];
    ForensicRecord *records = malloc(sizeof(ForensicRecord) * 1024);
    int count = 0;
    int rwx_total = 0;
    dir = opendir("/proc");
    if (!dir) {
        free(records);
        return 1;
    }
    while ((entry = readdir(dir)) != NULL && count < 1024) {
        if (!isdigit(entry->d_name[0])) continue;
        int pid = atoi(entry->d_name);
        records[count].pid = pid;
        get_process_name(pid, temp_name);
        strncpy(records[count].process_name, temp_name, 256);
        char rwx_details[128], rwx_addr[64];
        int violations = check_mem_rwx(pid, rwx_details, rwx_addr);
        strncpy(records[count].status, (violations > 0) ? "RWX ALERT" : "SAFE", 64);
        strncpy(records[count].info_path, rwx_details, 512);
        strncpy(records[count].mem_addr, rwx_addr, 64);
        if (violations > 0) rwx_total++;
        count++;
    }
    closedir(dir);
    if (format == EXPORT_TERMINAL) {
        int selected = 0;
        int running = 1;
        while (running) {
            update_dashboard(records, count, selected);
            attron(COLOR_PAIR(3) | A_BOLD);
            mvprintw(LINES - 1, 0, " [ENTER] ANALYZE | [Q] EXIT | ALERTS: %02d | TARGET: %-15.15s (PID: %-6d)", 
                     rwx_total, records[selected].process_name, records[selected].pid);
            for (int i = getcurx(stdscr); i < COLS; i++) printw(" ");
            attroff(COLOR_PAIR(3) | A_BOLD);
            refresh();
            int ch = handle_input();
            switch (ch) {
                case KEY_UP:
                    if (selected > 0) selected--;
                    break;
                case KEY_DOWN:
                    if (selected < count - 1) selected++;
                    break;
                case 'q':
                case 'Q':
                    running = 0;
                    break;
                case 10: 
                    if (strcmp(records[selected].mem_addr, "n/a") != 0) {
                        attron(COLOR_PAIR(2) | A_BOLD | A_REVERSE);
                        mvprintw(LINES - 1, 0, " [!] ACTION: PERFORMING DEEP MEMORY SCAN ON PID %d... ", records[selected].pid);
                        for (int i = getcurx(stdscr); i < COLS; i++) printw(" ");
                        refresh();
                        dump_memory_region(records[selected].pid, records[selected].mem_addr);
                        attron(COLOR_PAIR(1) | A_BOLD | A_REVERSE);
                        mvprintw(LINES - 1, 0, " [V] FORENSIC REPORT GENERATED SUCCESSFULLY IN: build/dumps/ ");
                        for (int i = getcurx(stdscr); i < COLS; i++) printw(" ");
                        refresh();
                        sleep(2);
                    } else {
                        attron(COLOR_PAIR(5) | A_BOLD | A_REVERSE);
                        mvprintw(LINES - 1, 0, " [X] SECURITY BYPASS: PROCESS IS STABLE - NO VOLATILE RWX REGIONS DETECTED ");
                        for (int i = getcurx(stdscr); i < COLS; i++) printw(" ");
                        refresh();
                        beep();
                        sleep(2);
                        attroff(COLOR_PAIR(5) | A_BOLD | A_REVERSE);
                    }
                    break;
            }
        }
    } else {
        export_header(format);
        for (int i = 0; i < count; i++) {
            export_record(&records[i], format);
        }
        export_footer(format);
    }
    free(records);
    return 0;
}

void print_usage(void) {
    printf("\n%sK-Scanner Forensic Tool%s\n", CLR_BOLD, CLR_RESET);
    printf("Usage: sudo ./kscanner [OPTIONS]\n\n");
    printf("Options:\n");
    printf("  --help    Show this diagnostic information\n");
    printf("  --json    Output in JSON format\n");
    printf("  --csv     Output in CSV format\n\n");
    printf("Note: Root privileges are required to access process memory maps.\n");
}

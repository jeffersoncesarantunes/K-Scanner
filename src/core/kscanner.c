#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ncurses.h>
#include "kscanner.h"
#include "export_engine.h"
#include "tui_engine.h"
#include "bpf_telemetry.h"

static void write_hex_dump(const char *in_path, const char *out_path, size_t max_lines) {
    FILE *in = fopen(in_path, "rb");
    if (!in) return;
    FILE *out = fopen(out_path, "w");
    if (!out) { fclose(in); return; }
    unsigned char buf[16];
    size_t offset = 0, lines = 0, n;
    while ((n = fread(buf, 1, 16, in)) > 0 && lines < max_lines) {
        fprintf(out, "%08zx  ", offset);
        for (size_t i = 0; i < 16; i++) {
            if (i < n) fprintf(out, "%02x ", buf[i]);
            else fprintf(out, "   ");
            if (i == 7) fputc(' ', out);
        }
        fputs(" |", out);
        for (size_t i = 0; i < n; i++)
            fputc((buf[i] >= 32 && buf[i] < 127) ? buf[i] : '.', out);
        fputs("|\n", out);
        offset += n;
        lines++;
    }
    fclose(in);
    fclose(out);
}

static ConfidenceLevel map_context_tag(const char* path, char *out_tag, size_t tag_size) {
    if (path == NULL || path[0] == '\0' || strcmp(path, "[Anonymous/Heap]") == 0) {
        snprintf(out_tag, tag_size, "ANON_BLOB");
        return CONFIDENCE_CRITICAL;
    }
    if (strstr(path, "js-executable") ||
        strstr(path, "libv8") ||
        strstr(path, "libnode") ||
        strstr(path, "libmozjs") ||
        strstr(path, "libjavascriptcore") ||
        strstr(path, "libluajit") ||
        strstr(path, "libmono") ||
        strstr(path, "libcoreclr") ||
        strstr(path, "libjvm") ||
        strstr(path, "libpypy") ||
        strstr(path, "libdart")) {
        snprintf(out_tag, tag_size, "JIT_ENGINE");
        return CONFIDENCE_LOW;
    }
    if (strstr(path, "ld-")) {
        snprintf(out_tag, tag_size, "DYN_LINKER");
        return CONFIDENCE_LOW;
    }
    if (strstr(path, "heap") || strstr(path, "[heap]")) {
        snprintf(out_tag, tag_size, "DYNAMIC_MEM");
        return CONFIDENCE_CRITICAL;
    }
    if (strstr(path, "stack") || strstr(path, "[stack]")) {
        snprintf(out_tag, tag_size, "PROC_STACK");
        return CONFIDENCE_SUSPICIOUS;
    }
    if (strstr(path, "/usr/lib") || strstr(path, ".so") ||
        strstr(path, "[vdso]") || strstr(path, "[vvar]")) {
        snprintf(out_tag, tag_size, "SYSTEM_LIB");
        return CONFIDENCE_SUSPICIOUS;
    }
    if (strstr(path, "/tmp") || strstr(path, "/dev/shm")) {
        snprintf(out_tag, tag_size, "VOLATILE_FS");
        return CONFIDENCE_SUSPICIOUS;
    }
    snprintf(out_tag, tag_size, "MAPPED_FILE");
    return CONFIDENCE_CRITICAL;
}

static void dump_memory_region(int pid, char *addr_str) {
    char mem_path[256], out_path[256], line[512];
    char file_name[128], fpath[512];
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
            snprintf(fpath, sizeof(fpath), "build/dumps/%s", file_name);
            int child, st;
            child = fork();
            if (child == 0) {
                snprintf(out_path, sizeof(out_path), "build/dumps/%s.sha256", file_name);
                int ofd = open(out_path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
                if (ofd == -1) _exit(1);
                dup2(ofd, STDOUT_FILENO);
                close(ofd);
                execlp("sha256sum", "sha256sum", fpath, NULL);
                _exit(1);
            }
            waitpid(child, &st, 0);
            child = fork();
            if (child == 0) {
                snprintf(out_path, sizeof(out_path), "build/dumps/%s.strings.txt", file_name);
                int ofd = open(out_path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
                if (ofd == -1) _exit(1);
                dup2(ofd, STDOUT_FILENO);
                close(ofd);
                execlp("strings", "strings", "-n", "6", fpath, NULL);
                _exit(1);
            }
            waitpid(child, &st, 0);
            snprintf(out_path, sizeof(out_path), "build/dumps/%s.hex.txt", file_name);
            write_hex_dump(fpath, out_path, 256);
        }
    }
    close(fd);
    free(buffer);
}

static int check_mem_rwx(int pid, char *out_info, char *out_addr, ConfidenceLevel *out_conf) {
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
        char tag[32];
        *out_conf = map_context_tag(raw_origin, tag, sizeof(tag));
        snprintf(out_info, 128, "%02dx %s", found_count, tag);
    } else {
        *out_conf = CONFIDENCE_SAFE;
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

int run_scan_formatted(ExportFormat format, int silent_jit) {
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
        ConfidenceLevel conf;
        int violations = check_mem_rwx(pid, rwx_details, rwx_addr, &conf);
        records[count].confidence = conf;
        strncpy(records[count].status, (violations > 0) ? "RWX ALERT" : "SAFE", 64);
        strncpy(records[count].info_path, rwx_details, 512);
        strncpy(records[count].mem_addr, rwx_addr, 64);
        if (violations > 0 && !(silent_jit && conf == CONFIDENCE_LOW)) rwx_total++;
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
                        attrset(A_NORMAL);
                        attron(COLOR_PAIR(1) | A_BOLD | A_REVERSE);
                        mvprintw(LINES - 1, 0, " [V] FORENSIC REPORT GENERATED SUCCESSFULLY IN: build/dumps/ ");
                        for (int i = getcurx(stdscr); i < COLS; i++) printw(" ");
                        refresh();
                        sleep(2);
                        attrset(A_NORMAL);
                    } else {
                        attron(COLOR_PAIR(5) | A_BOLD | A_REVERSE);
                        mvprintw(LINES - 1, 0, " [X] SECURITY BYPASS: PROCESS IS STABLE - NO VOLATILE RWX REGIONS DETECTED ");
                        for (int i = getcurx(stdscr); i < COLS; i++) printw(" ");
                        refresh();
                        beep();
                        sleep(2);
                        attrset(A_NORMAL);
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

int run_scan_formatted_bpf(ExportFormat format, BpfTelemetryState *bpf, int silent_jit)
{
    (void)format;
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
        ConfidenceLevel conf;
        int violations = check_mem_rwx(pid, rwx_details, rwx_addr, &conf);
        records[count].confidence = conf;
        strncpy(records[count].status, (violations > 0) ? "RWX ALERT" : "SAFE", 64);
        strncpy(records[count].info_path, rwx_details, 512);
        strncpy(records[count].mem_addr, rwx_addr, 64);
        if (violations > 0 && !(silent_jit && conf == CONFIDENCE_LOW)) rwx_total++;
        count++;
    }
    closedir(dir);

    int selected = 0;
    int running = 1;
    while (running) {
        if (bpf && bpf->active) {
            bpf_telemetry_poll(bpf);
        }
        update_dashboard(records, count, selected);

        if (bpf && bpf->active && bpf->ring_head != bpf->ring_tail) {
            BpfRwxEvent bpf_ev;
            if (bpf_telemetry_drain_ring(bpf, &bpf_ev, 1) > 0) {
                attron(COLOR_PAIR(2) | A_BOLD);
                mvprintw(LINES - 2, 2, " [BPF] RWX by PID %d (%-8s) @ %s       ",
                         bpf_ev.pid, bpf_ev.comm, bpf_ev.addr);
                attroff(COLOR_PAIR(2) | A_BOLD);
            }
        }

        attron(COLOR_PAIR(3) | A_BOLD);
        mvprintw(LINES - 1, 0, " [ENTER] ANALYZE | [Q] EXIT | ALERTS: %02d | BPF: %s | TARGET: %-15.15s (PID: %-6d)",
                 rwx_total,
                 (bpf && bpf->active) ? "ON " : "OFF",
                 records[selected].process_name, records[selected].pid);
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
                    attrset(A_NORMAL);
                    attron(COLOR_PAIR(1) | A_BOLD | A_REVERSE);
                    mvprintw(LINES - 1, 0, " [V] FORENSIC REPORT GENERATED SUCCESSFULLY IN: build/dumps/ ");
                    for (int i = getcurx(stdscr); i < COLS; i++) printw(" ");
                    refresh();
                    sleep(2);
                    attrset(A_NORMAL);
                } else {
                    attron(COLOR_PAIR(5) | A_BOLD | A_REVERSE);
                    mvprintw(LINES - 1, 0, " [X] SECURITY BYPASS: PROCESS IS STABLE - NO VOLATILE RWX REGIONS DETECTED ");
                    for (int i = getcurx(stdscr); i < COLS; i++) printw(" ");
                    refresh();
                    beep();
                    sleep(2);
                    attrset(A_NORMAL);
                }
                break;
        }
    }

    free(records);
    return 0;
}



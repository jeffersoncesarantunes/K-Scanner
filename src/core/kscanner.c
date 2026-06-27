#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <ncurses.h>
#include "kscanner.h"
#include "export_engine.h"
#include "tui_engine.h"
#include "bpf_telemetry.h"

static const char *g_yara_rule = NULL;
static char *g_yara_binary = NULL;

void set_yara_rule_path(const char *path) {
    g_yara_rule = path;
}

void set_yara_binary_path(const char *path) {
    if (g_yara_binary) free(g_yara_binary);
    g_yara_binary = strdup(path);
}

static void get_container_id(int pid, char *out, size_t out_size) {
    char path[256], line[256];
    char *p;
    size_t l;
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *f = fopen(path, "r");
    if (!f) { out[0] = '\0'; return; }
    out[0] = '\0';
    while (fgets(line, sizeof(line), f)) {
        if ((p = strstr(line, "docker-"))) {
            p += 7;
            char *end = strchr(p, '.');
            if (end) {
                l = (size_t)(end - p);
                if (l >= out_size) l = out_size - 1;
                memcpy(out, p, l); out[l] = '\0'; break;
            }
        }
        if ((p = strstr(line, "docker/"))) {
            p += 7;
            l = strcspn(p, "\n");
            if (l >= out_size) l = out_size - 1;
            memcpy(out, p, l); out[l] = '\0'; break;
        }
        if ((p = strstr(line, "kubepods"))) {
            char *ls = NULL;
            for (char *c = p; *c && *c != '\n'; c++) { if (*c == '/') ls = c; }
            if (ls && ls[1]) {
                l = strcspn(ls + 1, "\n");
                if (l >= out_size) l = out_size - 1;
                memcpy(out, ls + 1, l); out[l] = '\0'; break;
            }
        }
        if ((p = strstr(line, "/lxc/"))) {
            p += 5;
            l = strcspn(p, "\n");
            if (l >= out_size) l = out_size - 1;
            memcpy(out, p, l); out[l] = '\0'; break;
        }
    }
    fclose(f);
}

static void close_inherited_fds(void) {
    int max_fd = (int)sysconf(_SC_OPEN_MAX);
    if (max_fd < 0) max_fd = 4096;
    for (int i = STDERR_FILENO + 1; i < max_fd; i++) close(i);
}

static void scan_with_yara(const char *dump_path, const char *rule_path, const char *out_path) {
    if (access(rule_path, R_OK) != 0) {
        fprintf(stderr, "[!] YARA rule file no longer readable: %s\n", rule_path);
        return;
    }
    pid_t child = fork();
    if (child == 0) {
        close_inherited_fds();
        int fd = open(out_path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
        if (fd == -1) _exit(1);
        if (dup2(fd, STDOUT_FILENO) == -1) _exit(1);
        close(fd);
        execv(g_yara_binary, (char *[]){ "yara", "-w", (char *)rule_path, (char *)dump_path, NULL });
        _exit(1);
    }
    int st;
    waitpid(child, &st, 0);
}

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

static void scan_shellcode_patterns(const void *buf, size_t size, const char *out_path) {
    FILE *out = fopen(out_path, "w");
    if (!out) return;
    const unsigned char *p = (const unsigned char *)buf;
    size_t scan = (size > 4096) ? 4096 : size;
    int found = 0;

    int nop_count = 0, nop_max = 0;
    for (size_t i = 0; i < scan; i++) {
        if (p[i] == 0x90) {
            int run = 1;
            while (i + run < scan && p[i + run] == 0x90) run++;
            if (run >= 8) { nop_count++; if (run > nop_max) nop_max = run; }
            i += run - 1;
        }
    }
    if (nop_count > 0) {
        fprintf(out, "NOP_SLED %dx longest=%d\n", nop_count, nop_max);
        found = 1;
    }

    int sc = 0, i80 = 0;
    for (size_t i = 0; i < scan - 1; i++) {
        if (p[i] == 0x0f && p[i+1] == 0x05) sc++;
        if (p[i] == 0xcd && p[i+1] == 0x80) i80++;
    }
    if (sc > 0) { fprintf(out, "SYSCALL_x64 %dx\n", sc); found = 1; }
    if (i80 > 0) { fprintf(out, "INT_0x80 %dx\n", i80); found = 1; }

    int jr = 0, js = 0, jd = 0;
    for (size_t i = 0; i < scan - 1; i++) {
        if (p[i] == 0xff) {
            if (p[i+1] == 0xe0) jr++;
            if (p[i+1] == 0xe4) js++;
            if (p[i+1] == 0xe7) jd++;
        }
    }
    if (jr > 0) { fprintf(out, "JMP_RAX %dx\n", jr); found = 1; }
    if (js > 0) { fprintf(out, "JMP_RSP %dx\n", js); found = 1; }
    if (jd > 0) { fprintf(out, "JMP_RDI %dx\n", jd); found = 1; }

    int pr = 0;
    for (size_t i = 0; i < scan - 2; i++) {
        if (p[i+1] == 0xc3 && (p[i] == 0x5f || p[i] == 0x5e || p[i] == 0x5a || p[i] == 0x58))
            pr++;
    }
    if (pr > 0) { fprintf(out, "POP_RET_ROPGADGET %dx\n", pr); found = 1; }

    int bs = 0;
    for (size_t i = 0; i < scan - 7; i++)
        if (p[i] == '/' && memcmp(p + i, "/bin/sh", 7) == 0) bs++;
    if (bs > 0) { fprintf(out, "BINSH_STRING %dx\n", bs); found = 1; }

    if (!found) fprintf(out, "NO_SUSPICIOUS_PATTERNS\n");
    fclose(out);
}

static void write_disassembly_file(const void *buf, size_t size, const char *out_path, unsigned long start_addr) {
    size_t trunc = (size > 4096) ? 4096 : size;
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", out_path);
    FILE *tmp = fopen(tmp_path, "wb");
    if (!tmp) return;
    fwrite(buf, 1, trunc, tmp);
    fclose(tmp);

    char addr_opt[64];
    snprintf(addr_opt, sizeof(addr_opt), "x86-64,addr=0x%lx", start_addr);

    pid_t child = fork();
    if (child == 0) {
        close_inherited_fds();
        int fd = open(out_path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
        if (fd == -1) _exit(1);
        if (dup2(fd, STDOUT_FILENO) == -1) _exit(1);
        close(fd);
        execvp("objdump", (char *[]){ "objdump", "-D", "-b", "binary", "-m", "i386", "-M", addr_opt, tmp_path, NULL });
        _exit(1);
    }
    int st;
    waitpid(child, &st, 0);
    unlink(tmp_path);
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
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int fd = open(mem_path, O_RDONLY);
    if (fd == -1) return;
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/maps", pid);
    FILE *f = fopen(mem_path, "r");
    if (!f) { close(fd); return; }
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
    if (!found) { close(fd); return; }
    if (end <= start) { close(fd); return; }
    size_t size = end - start;
    if (size > 256 * 1024 * 1024) { close(fd); return; }
    void *buffer = malloc(size);
    if (!buffer) { close(fd); return; }
    if (pread(fd, buffer, size, (off_t)start) == (ssize_t)size) {
        mkdir("build", 0750);
        mkdir("build/dumps", 0750);
        snprintf(file_name, sizeof(file_name), "pid_%d_%lx.bin", pid, start);
        snprintf(out_path, sizeof(out_path), "build/dumps/%s", file_name);
        int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (out_fd != -1) {
            if (write(out_fd, buffer, size) == -1) { close(out_fd); close(fd); free(buffer); return; }
            close(out_fd);
            snprintf(fpath, sizeof(fpath), "build/dumps/%s", file_name);
            int child, st;
            child = fork();
            if (child == 0) {
                close_inherited_fds();
                snprintf(out_path, sizeof(out_path), "build/dumps/%s.sha256", file_name);
                int ofd = open(out_path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
                if (ofd == -1) _exit(1);
                if (dup2(ofd, STDOUT_FILENO) == -1) _exit(1);
                close(ofd);
                execvp("sha256sum", (char *[]){ "sha256sum", fpath, NULL });
                _exit(1);
            }
            waitpid(child, &st, 0);
            child = fork();
            if (child == 0) {
                close_inherited_fds();
                snprintf(out_path, sizeof(out_path), "build/dumps/%s.strings.txt", file_name);
                int ofd = open(out_path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
                if (ofd == -1) _exit(1);
                if (dup2(ofd, STDOUT_FILENO) == -1) _exit(1);
                close(ofd);
                execvp("strings", (char *[]){ "strings", "-n", "6", fpath, NULL });
                _exit(1);
            }
            waitpid(child, &st, 0);
            snprintf(out_path, sizeof(out_path), "build/dumps/%s.hex.txt", file_name);
            write_hex_dump(fpath, out_path, 256);
            snprintf(out_path, sizeof(out_path), "build/dumps/%s.disasm.txt", file_name);
            write_disassembly_file(buffer, size, out_path, start);
            snprintf(out_path, sizeof(out_path), "build/dumps/%s.shellcode.txt", file_name);
            scan_shellcode_patterns(buffer, size, out_path);
            if (g_yara_rule) {
                snprintf(out_path, sizeof(out_path), "build/dumps/%s.yara.txt", file_name);
                scan_with_yara(fpath, g_yara_rule, out_path);
            }
        }
    }
    close(fd);
    free(buffer);
}

static int check_mem_rwx(int pid, char *out_info, char *out_addr, ConfidenceLevel *out_conf) {
    char path[256], line[512], addr[64], perms[8], pathname[256];
    int found_count = 0;
    char raw_origin[256] = "";
    int mem_fd;
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    mem_fd = open(path, O_RDONLY);
    if (mem_fd == -1) return 0;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { close(mem_fd); return 0; }
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "rwxp")) {
            pathname[0] = '\0';
            sscanf(line, "%63s %7s %*s %*s %*s %255s", addr, perms, pathname);
            if (found_count == 0) {
                snprintf(raw_origin, sizeof(raw_origin), "%s", pathname);
                char start_addr_hex[18];
                sscanf(addr, "%17[^ -]", start_addr_hex);
                snprintf(out_addr, 64, "%s", start_addr_hex);
            }
            found_count++;
        }
    }
    if (found_count == 0) {
        pathname[0] = '\0';
    }
    fclose(f);
    close(mem_fd);
    if (found_count > 0) {
        char tag[32];
        *out_conf = map_context_tag(raw_origin, tag, sizeof(tag));
        snprintf(out_info, 128, "%02dx %s", found_count, tag);
    } else {
        *out_conf = CONFIDENCE_SAFE;
        snprintf(out_info, 128, "%s", "STABLE");
        snprintf(out_addr, 64, "%s", "n/a");
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
        snprintf(out_name, 33, "%s", "unknown");
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
        int pid = (int)strtol(entry->d_name, NULL, 10);
        records[count].pid = (int)pid;
        get_process_name((int)pid, temp_name);
        snprintf(records[count].process_name, 256, "%s", temp_name);
        char rwx_details[128], rwx_addr[64];
        ConfidenceLevel conf;
        int violations = check_mem_rwx((int)pid, rwx_details, rwx_addr, &conf);
        records[count].confidence = conf;
        snprintf(records[count].status, 64, "%s", (violations > 0) ? "RWX ALERT" : "SAFE");
        snprintf(records[count].info_path, 512, "%s", rwx_details);
        snprintf(records[count].mem_addr, 64, "%s", rwx_addr);
        get_container_id((int)pid, records[count].container_id, sizeof(records[count].container_id));
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
            char cnt_info[32] = "";
            if (records[selected].container_id[0])
                snprintf(cnt_info, sizeof(cnt_info), " | CTN:%.12s", records[selected].container_id);
            mvprintw(LINES - 1, 0, " [ENTER] ANALYZE | [Q] EXIT | ALERTS: %02d | TARGET: %-15.15s (PID: %-6d)%s", 
                     rwx_total, records[selected].process_name, records[selected].pid, cnt_info);
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
        int pid = (int)strtol(entry->d_name, NULL, 10);
        records[count].pid = pid;
        get_process_name(pid, temp_name);
        snprintf(records[count].process_name, 256, "%s", temp_name);
        char rwx_details[128], rwx_addr[64];
        ConfidenceLevel conf;
        int violations = check_mem_rwx(pid, rwx_details, rwx_addr, &conf);
        records[count].confidence = conf;
        snprintf(records[count].status, 64, "%s", (violations > 0) ? "RWX ALERT" : "SAFE");
        snprintf(records[count].info_path, 512, "%s", rwx_details);
        snprintf(records[count].mem_addr, 64, "%s", rwx_addr);
        get_container_id(pid, records[count].container_id, sizeof(records[count].container_id));
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
                const char *sname = "?";
                switch (bpf_ev.syscall_nr) {
                    case 9:  sname = "mmap"; break;
                    case 10: sname = "mprotect"; break;
                    case 30: sname = "shmat"; break;
                    case 59: sname = "execve"; break;
                }
                attron(COLOR_PAIR(2) | A_BOLD);
                if (bpf_ev.syscall_nr == 59)
                    mvprintw(LINES - 2, 2, " [BPF] EXEC PID %d (%-8s)                    ",
                             bpf_ev.pid, bpf_ev.comm);
                else
                    mvprintw(LINES - 2, 2, " [BPF] %s PID %d (%-8s) @ %s       ",
                             sname, bpf_ev.pid, bpf_ev.comm, bpf_ev.addr);
                attroff(COLOR_PAIR(2) | A_BOLD);
            }
        }

        attron(COLOR_PAIR(3) | A_BOLD);
        char cnt_info[32] = "";
        if (records[selected].container_id[0])
            snprintf(cnt_info, sizeof(cnt_info), " | CTN:%.12s", records[selected].container_id);
        mvprintw(LINES - 1, 0, " [ENTER] ANALYZE | [Q] EXIT | ALERTS: %02d | BPF: %s | TARGET: %-15.15s (PID: %-6d)%s",
                 rwx_total,
                 (bpf && bpf->active) ? "ON " : "OFF",
                 records[selected].process_name, records[selected].pid, cnt_info);
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

int run_watch_loop(ExportFormat format, int silent_jit) {
    int cycle = 0;
    int max_proc = 4096;
    char ts[64];

    while (1) {
        if (feof(stdout) || ferror(stdout)) break;
        cycle++;

        time_t t = time(NULL);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));

        ForensicRecord *records = malloc(sizeof(ForensicRecord) * max_proc);
        if (!records) break;
        int count = 0, rwx_total = 0;

        DIR *dir = opendir("/proc");
        if (!dir) { free(records); break; }
        struct dirent *entry;
        while ((entry = readdir(dir)) && count < max_proc) {
            if (!isdigit(entry->d_name[0])) continue;
            pid_t pid = (pid_t)strtol(entry->d_name, NULL, 10);
            char pname[256], rwx_info[128], rwx_addr[64];
            ConfidenceLevel conf;
            get_process_name((int)pid, pname);
            int v = check_mem_rwx((int)pid, rwx_info, rwx_addr, &conf);
            records[count].pid = (int)pid;
            records[count].confidence = conf;
            snprintf(records[count].process_name, 256, "%s", pname);
            snprintf(records[count].status, 64, "%s", v ? "RWX ALERT" : "SAFE");
            snprintf(records[count].info_path, 512, "%s", rwx_info);
            snprintf(records[count].mem_addr, 64, "%s", rwx_addr);
            get_container_id(pid, records[count].container_id, sizeof(records[count].container_id));
            if (v && !(silent_jit && conf == CONFIDENCE_LOW)) rwx_total++;
            count++;
        }
        closedir(dir);

        if (format == EXPORT_TERMINAL) {
            printf("\n=== CYCLE %d @ %s ===\n", cycle, ts);
            printf("%-8s %-20s %-12s %-10s %s\n",
                   "PID", "PROCESS", "STATUS", "CONFIDENCE", "INFO");
            for (int i = 0; i < count; i++) {
                if (strcmp(records[i].status, "RWX ALERT") != 0) continue;
                char cl[12];
                switch (records[i].confidence) {
                    case 0: snprintf(cl, sizeof(cl), "%s", "SAFE"); break;
                    case 1: snprintf(cl, sizeof(cl), "%s", "LOW"); break;
                    case 2: snprintf(cl, sizeof(cl), "%s", "MEDIUM"); break;
                    case 3: snprintf(cl, sizeof(cl), "%s", "CRITICAL"); break;
                    default: snprintf(cl, sizeof(cl), "%s", "?"); break;
                }
                printf("%-8d %-20.20s %-12s %-10s %s\n",
                       records[i].pid, records[i].process_name,
                       records[i].status, cl, records[i].info_path);
            }
            printf("--- ALERTS: %d / SCANNED: %d ---\n", rwx_total, count);
        } else {
            export_header(format);
            for (int i = 0; i < count; i++)
                export_record(&records[i], format);
            export_footer(format);
        }

        free(records);
        fflush(stdout);
        sleep(2);
    }
    return 0;
}

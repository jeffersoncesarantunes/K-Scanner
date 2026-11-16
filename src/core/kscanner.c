#include "kscanner.h"
#include "bpf_telemetry.h"
#include "colors.h"
#include "export_engine.h"
#include "scanner_pure.h"
#include "tui_engine.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <ncurses.h>
#include <openssl/sha.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *g_yara_rule = NULL;
static char *g_yara_binary = NULL;
static char g_dump_dir[PATH_MAX] = "build/dumps";
volatile sig_atomic_t g_terminate = 0;

void set_dump_dir(const char *path)
{
    if (!path || !*path)
        return;
    snprintf(g_dump_dir, sizeof(g_dump_dir), "%s", path);
}

static const char *dump_dir(void)
{
    const char *env = getenv("KSCANNER_DUMP_DIR");
    if (env && *env)
        return env;
    return g_dump_dir;
}

static void handle_sigterm(int sig)
{
    (void)sig;
    g_terminate = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigterm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) != 0) return -1;
    if (sigaction(SIGTERM, &sa, NULL) != 0) return -1;
    return 0;
}

static int validate_dump_dir(const char *dir)
{
    if (!dir || !*dir)
        return -1;
    char resolved[PATH_MAX];
    if (realpath(dir, resolved) == NULL)
        return -1;
    if (strstr(resolved, "/..") != NULL)
        return -1;
    struct stat st;
    if (lstat(resolved, &st) != 0)
        return -1;
    if (S_ISLNK(st.st_mode))
        return -1;
    return 0;
}

static int ensure_dump_dir(void)
{
    const char *dir = dump_dir();
    if (validate_dump_dir(dir) != 0)
        return -1;
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp);
    if (len == 0 || len >= sizeof(tmp))
        return -1;
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        struct stat st;
        if (lstat(tmp, &st) == 0 && S_ISLNK(st.st_mode))
            return -1;
        if (mkdir(tmp, 0750) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    struct stat st;
    if (lstat(tmp, &st) == 0 && S_ISLNK(st.st_mode))
        return -1;
    if (mkdir(tmp, 0750) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

void set_yara_rule_path(const char *path)
{
    g_yara_rule = path;
}

void set_yara_binary_path(const char *path)
{
    if (g_yara_binary)
        free(g_yara_binary);
    g_yara_binary = strdup(path);
}

static void close_inherited_fds(void)
{
    int max_fd = (int) sysconf(_SC_OPEN_MAX);
    if (max_fd < 0)
        max_fd = 4096;
    for (int i = STDERR_FILENO + 1; i < max_fd; i++)
        close(i);
}

static void scan_with_yara(const char *dump_path, const char *rule_path, const char *out_path)
{
    if (!g_yara_binary)
        return;
    pid_t child = fork();
    if (child == 0) {
        close_inherited_fds();
        int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd == -1)
            _exit(1);
        if (dup2(fd, STDOUT_FILENO) == -1)
            _exit(1);
        close(fd);
        execv(g_yara_binary,
              (char *[]){"yara", "-w", (char *) rule_path, (char *) dump_path, NULL});
        _exit(127);
    }
    if (child < 0) {
        fprintf(stderr, "[!] YARA fork failed: %s\n", strerror(errno));
        return;
    }
    int st = 0;
    if (waitpid(child, &st, 0) != child || !WIFEXITED(st) || WEXITSTATUS(st) != 0)
        fprintf(stderr, "[!] YARA scan failed: %s\n", rule_path);
}

static int pid_still_same(pid_t pid)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return st.st_ino != 0;
}

static void dump_memory_region(int pid, char *addr_str)
{
    char mem_path[PATH_MAX], out_path[PATH_MAX * 2], line[512];
    char file_name[128], fpath[PATH_MAX * 2];
    unsigned long start, end;
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/maps", pid);
    FILE *f = fopen(mem_path, "r");
    if (!f)
        return;
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
    if (!found)
        return;
    if (end <= start)
        return;
    if (!pid_still_same(pid))
        return;
    size_t size = end - start;
    if (size > 256 * 1024 * 1024)
        return;
    void *buffer = malloc(size);
    if (!buffer)
        return;
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int fd = open(mem_path, O_RDONLY);
    if (fd == -1) {
        free(buffer);
        return;
    }
    if (!pid_still_same(pid)) {
        close(fd);
        free(buffer);
        return;
    }
    ssize_t got = 0;
    while ((size_t) got < size) {
        ssize_t n = pread(fd, (char *) buffer + got, size - (size_t) got, (off_t) start + got);
        if (n <= 0)
            break;
        got += n;
    }
    if ((size_t) got == size && ensure_dump_dir() == 0) {
        snprintf(file_name, sizeof(file_name), "pid_%d_%lx.bin", pid, start);
        snprintf(out_path, sizeof(out_path), "%s/%s", dump_dir(), file_name);
        int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (out_fd != -1) {
            size_t written = 0;
            int write_ok = 1;
            while (written < size) {
                ssize_t n = write(out_fd, (char *) buffer + written, size - written);
                if (n <= 0) {
                    write_ok = 0;
                    break;
                }
                written += (size_t) n;
            }
            close(out_fd);
            if (!write_ok || written != size) {
                unlink(out_path);
                close(fd);
                free(buffer);
                return;
            }
            snprintf(fpath, sizeof(fpath), "%s/%s", dump_dir(), file_name);
            int child;
            child = fork();
            if (child == 0) {
                close_inherited_fds();
                snprintf(out_path, sizeof(out_path), "%s/%s.sha256", dump_dir(), file_name);
                int ofd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
                if (ofd == -1)
                    _exit(1);
                if (dup2(ofd, STDOUT_FILENO) == -1)
                    _exit(1);
                close(ofd);
                const char *sha_bin = "/usr/bin/sha256sum";
                struct stat st;
                if (stat(sha_bin, &st) != 0)
                    sha_bin = "sha256sum";
                execl(sha_bin, "sha256sum", fpath, NULL);
                _exit(1);
            }
            int st = 0;
            if (child < 0 || waitpid(child, &st, 0) != child || !WIFEXITED(st) ||
                WEXITSTATUS(st) != 0)
                fprintf(stderr, "[!] sha256sum unavailable or failed\n");
            child = fork();
            if (child == 0) {
                close_inherited_fds();
                snprintf(out_path, sizeof(out_path), "%s/%s.strings.txt", dump_dir(), file_name);
                int ofd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
                if (ofd == -1)
                    _exit(1);
                if (dup2(ofd, STDOUT_FILENO) == -1)
                    _exit(1);
                close(ofd);
                const char *str_bin = "/usr/bin/strings";
                struct stat st2;
                if (stat(str_bin, &st2) != 0)
                    str_bin = "strings";
                execl(str_bin, "strings", "-n", "6", fpath, NULL);
                _exit(1);
            }
            st = 0;
            if (child < 0 || waitpid(child, &st, 0) != child || !WIFEXITED(st) ||
                WEXITSTATUS(st) != 0)
                fprintf(stderr, "[!] strings unavailable or failed\n");
            snprintf(out_path, sizeof(out_path), "%s/%s.hex.txt", dump_dir(), file_name);
            write_hex_dump(fpath, out_path, 256);
            snprintf(out_path, sizeof(out_path), "%s/%s.shellcode.txt", dump_dir(), file_name);
            scan_shellcode_patterns(buffer, size, out_path);
            if (g_yara_rule) {
                snprintf(out_path, sizeof(out_path), "%s/%s.yara.txt", dump_dir(), file_name);
                scan_with_yara(fpath, g_yara_rule, out_path);
            }
        }
    }
    close(fd);
    free(buffer);
}

static int verify_pid_still_valid(int pid)
{
    char path[256], line[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    int found_pid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "Pid:\t%d", &found_pid) == 1 && found_pid == pid) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static int check_mem_rwx(int pid, char *out_info, char *out_addr, ConfidenceLevel *out_conf)
{
    char path[256], line[512], addr[64], perms[8], pathname[256];
    int found_count = 0;
    char raw_origin[256] = "";
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    if (!verify_pid_still_valid(pid)) {
        fclose(f);
        return 0;
    }
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
    fclose(f);
    if (!verify_pid_still_valid(pid))
        return 0;
    if (found_count == 0) {
        pathname[0] = '\0';
    }
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

static void get_process_name(int pid, char *out_name)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (!fgets(out_name, 33, f))
            snprintf(out_name, 33, "%s", "unknown");
        else
            out_name[strcspn(out_name, "\n")] = 0;
        fclose(f);
    } else {
        snprintf(out_name, 33, "%s", "unknown");
    }
}

static void print_bpf_event(BpfRwxEvent *ev)
{
    const char *sname = "?";
    switch (ev->syscall_nr) {
    case 9:
        sname = "mmap";
        break;
    case 10:
        sname = "mprotect";
        break;
    case 30:
        sname = "shmat";
        break;
    case 59:
        sname = "execve";
        break;
    }
    printf("%s[BPF] %s -- PID %d (%s) @ %s%s\n", CLR_RED, sname, ev->pid, ev->comm, ev->addr,
           CLR_RESET);
}

static void bpf_drain_and_print(BpfTelemetryState *bpf)
{
    BpfRwxEvent bpf_ev;
    while (bpf_telemetry_drain_ring(bpf, &bpf_ev, 1) > 0) {
        print_bpf_event(&bpf_ev);
    }
}

static int scan_processes(ForensicRecord *records, int max_records, int silent_jit,
                          int *out_rwx_total)
{
    DIR *dir = opendir("/proc");
    if (!dir)
        return -1;
    struct dirent *entry;
    int count = 0;
    int rwx_total = 0;
    while ((entry = readdir(dir)) != NULL && count < max_records && !g_terminate) {
        if (!isdigit(entry->d_name[0]))
            continue;
        pid_t pid = (pid_t) strtol(entry->d_name, NULL, 10);
        char temp_name[256], rwx_details[128], rwx_addr[64];
        ConfidenceLevel conf;
        get_process_name((int) pid, temp_name);
        int violations = check_mem_rwx((int) pid, rwx_details, rwx_addr, &conf);
        records[count].pid = (int) pid;
        records[count].confidence = conf;
        snprintf(records[count].process_name, 256, "%s", temp_name);
        snprintf(records[count].status, 64, "%s", (violations > 0) ? "RWX ALERT" : "SAFE");
        snprintf(records[count].info_path, 512, "%s", rwx_details);
        snprintf(records[count].mem_addr, 64, "%s", rwx_addr);
        get_container_id((int) pid, records[count].container_id,
                         sizeof(records[count].container_id));
        if (violations > 0 && !(silent_jit && conf == CONFIDENCE_LOW))
            rwx_total++;
        count++;
    }
    closedir(dir);
    if (out_rwx_total)
        *out_rwx_total = rwx_total;
    return count;
}

int run_scan_formatted(ExportFormat format, BpfTelemetryState *bpf, int silent_jit)
{
    ForensicRecord *records = malloc(sizeof(ForensicRecord) * 1024);
    if (!records)
        return 1;
    int rwx_total = 0;
    int count = scan_processes(records, 1024, silent_jit, &rwx_total);

    if (format == EXPORT_TERMINAL) {
        int selected = 0;
        int running = 1;
        while (running && !g_terminate) {
            if (bpf && bpf->active) {
                bpf_telemetry_poll(bpf);
            }
            update_dashboard(records, count, selected);

            if (bpf && bpf->active && bpf->ring_head != bpf->ring_tail) {
                BpfRwxEvent bpf_ev;
                if (bpf_telemetry_drain_ring(bpf, &bpf_ev, 1) > 0) {
                    const char *sname = "?";
                    switch (bpf_ev.syscall_nr) {
                    case 9:
                        sname = "mmap";
                        break;
                    case 10:
                        sname = "mprotect";
                        break;
                    case 30:
                        sname = "shmat";
                        break;
                    case 59:
                        sname = "execve";
                        break;
                    }
                    attron(COLOR_PAIR(2) | A_BOLD);
                    if (bpf_ev.syscall_nr == 59)
                        mvprintw(LINES - 2, 2, " [BPF] EXEC PID %d (%-8s)                    ",
                                 bpf_ev.pid, bpf_ev.comm);
                    else
                        mvprintw(LINES - 2, 2, " [BPF] %s PID %d (%-8s) @ %s       ", sname,
                                 bpf_ev.pid, bpf_ev.comm, bpf_ev.addr);
                    attroff(COLOR_PAIR(2) | A_BOLD);
                }
            }

            attron(COLOR_PAIR(3) | A_BOLD);
            char cnt_info[32] = "";
            int valid = (count > 0 && selected >= 0 && selected < count);
            if (valid && records[selected].container_id[0])
                snprintf(cnt_info, sizeof(cnt_info), " | CTN:%.12s",
                         records[selected].container_id);
            if (valid)
                mvprintw(LINES - 1, 0,
                         " [ENTER] ANALYZE | [Q] EXIT | ALERTS: %02d | BPF: %s | TARGET: %-15.15s "
                         "(PID: %-6d)%s",
                         rwx_total, (bpf && bpf->active) ? "ON " : "OFF",
                         records[selected].process_name, records[selected].pid, cnt_info);
            else
                mvprintw(LINES - 1, 0, " [Q] EXIT | ALERTS: %02d | BPF: %s | No processes found",
                         rwx_total, (bpf && bpf->active) ? "ON " : "OFF");
            for (int i = getcurx(stdscr); i < COLS; i++)
                printw(" ");
            attroff(COLOR_PAIR(3) | A_BOLD);
            refresh();

            int ch = handle_input();
            switch (ch) {
            case KEY_UP:
                if (selected > 0)
                    selected--;
                break;
            case KEY_DOWN:
                if (selected < count - 1)
                    selected++;
                break;
            case 'q':
            case 'Q':
                running = 0;
                break;
            case 10:
                if (!valid)
                    break;
                if (strcmp(records[selected].mem_addr, "n/a") != 0) {
                    attron(COLOR_PAIR(2) | A_BOLD | A_REVERSE);
                    mvprintw(LINES - 1, 0, " [!] ACTION: PERFORMING DEEP MEMORY SCAN ON PID %d... ",
                             records[selected].pid);
                    for (int i = getcurx(stdscr); i < COLS; i++)
                        printw(" ");
                    refresh();
                    dump_memory_region(records[selected].pid, records[selected].mem_addr);
                    attrset(A_NORMAL);
                    attron(COLOR_PAIR(1) | A_BOLD | A_REVERSE);
                    mvprintw(LINES - 1, 0,
                             " [V] FORENSIC REPORT GENERATED SUCCESSFULLY IN: build/dumps/ ");
                    for (int i = getcurx(stdscr); i < COLS; i++)
                        printw(" ");
                    refresh();
                    attrset(A_NORMAL);
                } else {
                    attron(COLOR_PAIR(5) | A_BOLD | A_REVERSE);
                    mvprintw(LINES - 1, 0,
                             " [X] SECURITY BYPASS: PROCESS IS STABLE - NO VOLATILE RWX REGIONS "
                             "DETECTED ");
                    for (int i = getcurx(stdscr); i < COLS; i++)
                        printw(" ");
                    refresh();
                    beep();
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
        if (bpf && bpf->active) {
            bpf_telemetry_poll(bpf);
            if (format == EXPORT_TERMINAL)
                bpf_drain_and_print(bpf);
        }
    }

    free(records);
    return 0;
}

int run_watch_loop(ExportFormat format, int silent_jit)
{
    int cycle = 0;
    int max_proc = 4096;
    char ts[64];
    install_signal_handlers();

    ForensicRecord *records = malloc(sizeof(ForensicRecord) * max_proc);
    if (!records)
        return 1;

    while (!g_terminate) {
        if (feof(stdout) || ferror(stdout))
            break;
        cycle++;

        time_t t = time(NULL);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));

        int rwx_total = 0;
        int count = scan_processes(records, max_proc, silent_jit, &rwx_total);

        if (format == EXPORT_TERMINAL) {
            printf("\n=== CYCLE %d @ %s ===\n", cycle, ts);
            printf("%-8s %-20s %-12s %-10s %s\n", "PID", "PROCESS", "STATUS", "CONFIDENCE", "INFO");
            for (int i = 0; i < count; i++) {
                if (strcmp(records[i].status, "RWX ALERT") != 0)
                    continue;
                char cl[12];
                switch (records[i].confidence) {
                case 0:
                    snprintf(cl, sizeof(cl), "%s", "SAFE");
                    break;
                case 1:
                    snprintf(cl, sizeof(cl), "%s", "LOW");
                    break;
                case 2:
                    snprintf(cl, sizeof(cl), "%s", "MEDIUM");
                    break;
                case 3:
                    snprintf(cl, sizeof(cl), "%s", "CRITICAL");
                    break;
                default:
                    snprintf(cl, sizeof(cl), "%s", "?");
                    break;
                }
                printf("%-8d %-20.20s %-12s %-10s %s\n", records[i].pid, records[i].process_name,
                       records[i].status, cl, records[i].info_path);
            }
            printf("--- ALERTS: %d / SCANNED: %d ---\n", rwx_total, count);
        } else if (format == EXPORT_JSON) {
            for (int i = 0; i < count; i++)
                export_record_jsonl(&records[i]);
        } else {
            if (cycle == 1)
                export_header(format);
            for (int i = 0; i < count; i++)
                export_record(&records[i], format);
        }

        fflush(stdout);
        sleep(2);
    }

    free(records);
    return 0;
}


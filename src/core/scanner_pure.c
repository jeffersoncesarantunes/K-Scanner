#include "scanner_pure.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * scanner_pure.c
 *
 * Pure, side-effect-free (except where noted) helpers extracted from
 * kscanner.c so they can be unit-tested without root access or a live
 * /proc filesystem.
 */

ConfidenceLevel map_context_tag(const char *path, char *out_tag, size_t tag_size)
{
    if (path == NULL || path[0] == '\0' || strcmp(path, "[Anonymous/Heap]") == 0) {
        snprintf(out_tag, tag_size, "ANON_BLOB");
        return CONFIDENCE_CRITICAL;
    }
    if (strstr(path, "js-executable") || strstr(path, "libv8") || strstr(path, "libnode") ||
        strstr(path, "libmozjs") || strstr(path, "libjavascriptcore") ||
        strstr(path, "libluajit") || strstr(path, "libmono") || strstr(path, "libcoreclr") ||
        strstr(path, "libjvm") || strstr(path, "libpypy") || strstr(path, "libdart")) {
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
    if (strstr(path, "/usr/lib") || strstr(path, ".so") || strstr(path, "[vdso]") ||
        strstr(path, "[vvar]")) {
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

int scan_shellcode_patterns(const void *buf, size_t size, const char *out_path)
{
    FILE *out = fopen(out_path, "w");
    if (!out)
        return -1;
    const unsigned char *p = (const unsigned char *) buf;
    size_t scan = (size > 4096) ? 4096 : size;
    int found = 0;
    if (scan < 8) {
        fprintf(out, "NO_SUSPICIOUS_PATTERNS\n");
        fclose(out);
        return 0;
    }

    int nop_count = 0, nop_max = 0;
    for (size_t i = 0; i < scan; i++) {
        if (p[i] == 0x90) {
            int run = 1;
            while (i + run < scan && p[i + run] == 0x90)
                run++;
            if (run >= 8) {
                nop_count++;
                if (run > nop_max)
                    nop_max = run;
            }
            i += run - 1;
        }
    }
    if (nop_count > 0) {
        fprintf(out, "NOP_SLED %dx longest=%d\n", nop_count, nop_max);
        found = 1;
    }

    int sc = 0, i80 = 0;
    for (size_t i = 0; i + 1 < scan; i++) {
        if (p[i] == 0x0f && p[i + 1] == 0x05)
            sc++;
        if (p[i] == 0xcd && p[i + 1] == 0x80)
            i80++;
    }
    if (sc > 0) {
        fprintf(out, "SYSCALL_x64 %dx\n", sc);
        found = 1;
    }
    if (i80 > 0) {
        fprintf(out, "INT_0x80 %dx\n", i80);
        found = 1;
    }

    int jr = 0, js = 0, jd = 0;
    for (size_t i = 0; i + 1 < scan; i++) {
        if (p[i] == 0xff) {
            if (p[i + 1] == 0xe0)
                jr++;
            if (p[i + 1] == 0xe4)
                js++;
            if (p[i + 1] == 0xe7)
                jd++;
        }
    }
    if (jr > 0) {
        fprintf(out, "JMP_RAX %dx\n", jr);
        found = 1;
    }
    if (js > 0) {
        fprintf(out, "JMP_RSP %dx\n", js);
        found = 1;
    }
    if (jd > 0) {
        fprintf(out, "JMP_RDI %dx\n", jd);
        found = 1;
    }

    int pr = 0;
    for (size_t i = 0; i + 2 < scan; i++) {
        if (p[i + 1] == 0xc3 && (p[i] == 0x5f || p[i] == 0x5e || p[i] == 0x5a || p[i] == 0x58))
            pr++;
    }
    if (pr > 0) {
        fprintf(out, "POP_RET_ROPGADGET %dx\n", pr);
        found = 1;
    }

    int bs = 0;
    for (size_t i = 0; i + 7 < scan; i++)
        if (p[i] == '/' && memcmp(p + i, "/bin/sh", 7) == 0)
            bs++;
    if (bs > 0) {
        fprintf(out, "BINSH_STRING %dx\n", bs);
        found = 1;
    }

    if (!found)
        fprintf(out, "NO_SUSPICIOUS_PATTERNS\n");
    fclose(out);
    return 0;
}

int write_hex_dump(const char *in_path, const char *out_path, size_t max_lines)
{
    FILE *in = fopen(in_path, "rb");
    if (!in)
        return -1;
    FILE *out = fopen(out_path, "w");
    if (!out) {
        fclose(in);
        return -1;
    }
    unsigned char buf[16];
    size_t offset = 0, lines = 0, n;
    while ((n = fread(buf, 1, 16, in)) > 0 && lines < max_lines) {
        fprintf(out, "%08zx  ", offset);
        for (size_t i = 0; i < 16; i++) {
            if (i < n)
                fprintf(out, "%02x ", buf[i]);
            else
                fprintf(out, "   ");
            if (i == 7)
                fputc(' ', out);
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
    return 0;
}

int get_container_id(int pid, char *out, size_t out_size)
{
    char path[256], line[256];
    char *p;
    size_t l;
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        out[0] = '\0';
        return -1;
    }
    out[0] = '\0';
    while (fgets(line, sizeof(line), f)) {
        if ((p = strstr(line, "docker-"))) {
            p += 7;
            char *end = strchr(p, '.');
            if (end) {
                l = (size_t) (end - p);
                if (l >= out_size)
                    l = out_size - 1;
                memcpy(out, p, l);
                out[l] = '\0';
                break;
            }
        }
        if ((p = strstr(line, "docker/"))) {
            p += 7;
            l = strcspn(p, "\n");
            if (l >= out_size)
                l = out_size - 1;
            memcpy(out, p, l);
            out[l] = '\0';
            break;
        }
        if ((p = strstr(line, "kubepods"))) {
            char *ls = NULL;
            for (char *c = p; *c && *c != '\n'; c++) {
                if (*c == '/')
                    ls = c;
            }
            if (ls && ls[1]) {
                l = strcspn(ls + 1, "\n");
                if (l >= out_size)
                    l = out_size - 1;
                memcpy(out, ls + 1, l);
                out[l] = '\0';
                break;
            }
        }
        if ((p = strstr(line, "/lxc/"))) {
            p += 5;
            l = strcspn(p, "\n");
            if (l >= out_size)
                l = out_size - 1;
            memcpy(out, p, l);
            out[l] = '\0';
            break;
        }
    }
    fclose(f);
    if (out[0] == '\0')
        return -1;
    return 0;
}

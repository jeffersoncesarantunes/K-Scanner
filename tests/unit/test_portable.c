#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "scanner_pure.h"
#include "export_engine.h"

static int failures = 0;

#define CHECK(cond, fmt, ...) do { \
    if (!(cond)) { \
        failures++; \
        printf("  [FAIL] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } else { \
        printf("  [PASS] " fmt "\n", ##__VA_ARGS__); \
    } \
} while (0)

static void test_map_context_tag(void)
{
    char tag[64];
    ConfidenceLevel c;

    c = map_context_tag("", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_CRITICAL && strcmp(tag, "ANON_BLOB") == 0,
          "empty path -> ANON_BLOB / CRITICAL");

    c = map_context_tag("[Anonymous/Heap]", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_CRITICAL && strcmp(tag, "ANON_BLOB") == 0,
          "anon heap -> ANON_BLOB / CRITICAL");

    c = map_context_tag("/usr/lib/libv8.so", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_LOW && strcmp(tag, "JIT_ENGINE") == 0,
          "libv8 -> JIT_ENGINE / LOW");

    c = map_context_tag("/usr/lib/libnode.so.72", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_LOW && strcmp(tag, "JIT_ENGINE") == 0,
          "libnode -> JIT_ENGINE / LOW");

    c = map_context_tag("/usr/lib/libmozjs.so", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_LOW && strcmp(tag, "JIT_ENGINE") == 0,
          "libmozjs -> JIT_ENGINE / LOW");

    c = map_context_tag("/usr/lib/libluajit.so.5.1", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_LOW && strcmp(tag, "JIT_ENGINE") == 0,
          "libluajit -> JIT_ENGINE / LOW");

    c = map_context_tag("/usr/lib/libjvm.so", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_LOW && strcmp(tag, "JIT_ENGINE") == 0,
          "libjvm -> JIT_ENGINE / LOW");

    c = map_context_tag("/usr/lib/ld-linux-x86-64.so.2", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_LOW && strcmp(tag, "DYN_LINKER") == 0,
          "ld- -> DYN_LINKER / LOW");

    c = map_context_tag("/usr/lib/libc.so.6", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_SAFE && strcmp(tag, "SYSTEM_LIB") == 0,
          ".so in /usr/lib -> SYSTEM_LIB / SAFE");

    c = map_context_tag("[vdso]", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_SAFE && strcmp(tag, "SYSTEM_LIB") == 0,
          "[vdso] -> SYSTEM_LIB / SAFE");

    c = map_context_tag("[heap]", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_CRITICAL && strcmp(tag, "DYNAMIC_MEM") == 0,
          "[heap] -> DYNAMIC_MEM / CRITICAL");

    c = map_context_tag("/tmp/foo", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_SUSPICIOUS && strcmp(tag, "VOLATILE_FS") == 0,
          "/tmp -> VOLATILE_FS / SUSPICIOUS");

    c = map_context_tag("/dev/shm/foo", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_SUSPICIOUS && strcmp(tag, "VOLATILE_FS") == 0,
          "/dev/shm -> VOLATILE_FS / SUSPICIOUS");

    c = map_context_tag("[stack]", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_SUSPICIOUS && strcmp(tag, "PROC_STACK") == 0,
          "[stack] -> PROC_STACK / SUSPICIOUS");

    c = map_context_tag("/bin/bash", tag, sizeof(tag));
    CHECK(c == CONFIDENCE_CRITICAL && strcmp(tag, "MAPPED_FILE") == 0,
          "generic mapped file -> MAPPED_FILE / CRITICAL");

    c = map_context_tag(NULL, tag, sizeof(tag));
    CHECK(c == CONFIDENCE_CRITICAL && strcmp(tag, "ANON_BLOB") == 0,
          "NULL path -> ANON_BLOB / CRITICAL");
}

static void write_tmp(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

static char *read_tmp(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char *buf = malloc(4096);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, 4095, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static void test_scan_shellcode_patterns(void)
{
    const char *tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    char out_path[512];
    snprintf(out_path, sizeof(out_path), "%s/kscanner_test_shellcode.out", tmpdir);

    /* NOP sled */
    unsigned char nop_buf[64];
    memset(nop_buf, 0x90, sizeof(nop_buf));
    CHECK(scan_shellcode_patterns(nop_buf, sizeof(nop_buf), out_path) == 0,
          "scan nop sled returns 0");
    char *out = read_tmp(out_path);
    CHECK(out && strstr(out, "NOP_SLED") != NULL, "nop sled detected");
    free(out);

    /* x64 syscall (pad to >= 8 bytes) */
    unsigned char sc_buf[] = { 0x0f, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    snprintf(out_path, sizeof(out_path), "%s/kscanner_test_syscall.out", tmpdir);
    CHECK(scan_shellcode_patterns(sc_buf, sizeof(sc_buf), out_path) == 0,
          "scan syscall returns 0");
    out = read_tmp(out_path);
    CHECK(out && strstr(out, "SYSCALL_x64") != NULL, "syscall detected");
    free(out);

    /* int 0x80 (pad to >= 8 bytes) */
    unsigned char i80_buf[] = { 0xcd, 0x80, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    snprintf(out_path, sizeof(out_path), "%s/kscanner_test_i80.out", tmpdir);
    CHECK(scan_shellcode_patterns(i80_buf, sizeof(i80_buf), out_path) == 0,
          "scan int 0x80 returns 0");
    out = read_tmp(out_path);
    CHECK(out && strstr(out, "INT_0x80") != NULL, "int 0x80 detected");
    free(out);

    /* /bin/sh string (8 bytes) */
    unsigned char binsh_buf[] = { '/', 'b', 'i', 'n', '/', 's', 'h', 0x00 };
    snprintf(out_path, sizeof(out_path), "%s/kscanner_test_binsh.out", tmpdir);
    CHECK(scan_shellcode_patterns(binsh_buf, sizeof(binsh_buf), out_path) == 0,
          "scan binsh returns 0");
    out = read_tmp(out_path);
    CHECK(out && strstr(out, "BINSH_STRING") != NULL, "binsh detected");
    free(out);

    /* JMP RAX gadget (pad to >= 8 bytes) */
    unsigned char jmp_buf[] = { 0xff, 0xe0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    snprintf(out_path, sizeof(out_path), "%s/kscanner_test_jmp.out", tmpdir);
    CHECK(scan_shellcode_patterns(jmp_buf, sizeof(jmp_buf), out_path) == 0,
          "scan jmp rax returns 0");
    out = read_tmp(out_path);
    CHECK(out && strstr(out, "JMP_RAX") != NULL, "jmp rax detected");
    free(out);

    /* Clean data -> no patterns */
    unsigned char clean_buf[64];
    memset(clean_buf, 0x41, sizeof(clean_buf));
    snprintf(out_path, sizeof(out_path), "%s/kscanner_test_clean.out", tmpdir);
    CHECK(scan_shellcode_patterns(clean_buf, sizeof(clean_buf), out_path) == 0,
          "scan clean returns 0");
    out = read_tmp(out_path);
    CHECK(out && strstr(out, "NO_SUSPICIOUS_PATTERNS") != NULL,
          "clean data reports no patterns");
    free(out);

    /* Empty/small buffer */
    snprintf(out_path, sizeof(out_path), "%s/kscanner_test_small.out", tmpdir);
    CHECK(scan_shellcode_patterns(NULL, 0, out_path) == 0,
          "scan empty buffer returns 0");
    out = read_tmp(out_path);
    CHECK(out && strstr(out, "NO_SUSPICIOUS_PATTERNS") != NULL,
          "empty buffer reports no patterns");
    free(out);

    /* Invalid output path */
    CHECK(scan_shellcode_patterns(clean_buf, sizeof(clean_buf), "/nonexistent_dir/file.out") == -1,
          "scan to invalid path returns -1");
}

static void test_write_hex_dump(void)
{
    const char *tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    char in_path[512], out_path[512];
    snprintf(in_path, sizeof(in_path), "%s/kscanner_test_hex_in.bin", tmpdir);
    snprintf(out_path, sizeof(out_path), "%s/kscanner_test_hex_out.txt", tmpdir);

    write_tmp(in_path, "Hello, World!\x00\x01\x02ff");

    CHECK(write_hex_dump(in_path, out_path, 10) == 0, "write_hex_dump returns 0");
    char *out = read_tmp(out_path);
    CHECK(out != NULL, "hex output file created");
    if (out) {
        CHECK(strstr(out, "48 65 6c 6c 6f") != NULL, "hex dump contains 'Hello'");
        CHECK(strstr(out, "|Hello, World!|") != NULL ||
              strstr(out, "Hello, World!") != NULL,
              "hex dump contains ASCII side");
        free(out);
    }

    /* Invalid input */
    CHECK(write_hex_dump("/nonexistent/file.bin", out_path, 10) == -1,
          "write_hex_dump invalid input returns -1");
}

static void test_get_container_id(void)
{
    char out[64];

    /* PID 1 should exist on any Linux and have a cgroup file */
    int rc = get_container_id(1, out, sizeof(out));
    if (rc == 0) {
        CHECK(out[0] != '\0', "get_container_id(1) returns non-empty id: %s", out);
    } else {
        /* In containers without cgroup info, empty is acceptable */
        CHECK(out[0] == '\0', "get_container_id(1) returns empty (no cgroup info)");
    }

    /* Non-existent PID */
    snprintf(out, sizeof(out), "sentinel");
    rc = get_container_id(99999999, out, sizeof(out));
    CHECK(rc == -1 && out[0] == '\0', "get_container_id(invalid pid) returns -1");
}

int main(void)
{
    printf("K-Scanner Portable Unit Test Suite\n");
    printf("===================================\n\n");

    test_map_context_tag();
    test_scan_shellcode_patterns();
    test_write_hex_dump();
    test_get_container_id();

    printf("\n");
    if (failures == 0) {
        printf("All tests passed.\n");
        return 0;
    }
    printf("%d test(s) FAILED.\n", failures);
    return 1;
}

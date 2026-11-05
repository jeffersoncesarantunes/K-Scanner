#ifndef SCANNER_PURE_H
#define SCANNER_PURE_H

#include "export_engine.h"
#include <stddef.h>

/*
 * scanner_pure.c
 *
 * Pure, side-effect-free (except where noted) helpers extracted from
 * kscanner.c so they can be unit-tested without root access or a live
 * /proc filesystem. These functions operate on in-memory buffers and
 * strings only.
 */

/*
 * Classify a memory mapping origin path into a confidence tag.
 *
 * Returns the ConfidenceLevel and writes a human-readable tag into out_tag.
 */
ConfidenceLevel map_context_tag(const char *path, char *out_tag, size_t tag_size);

/*
 * Scan a memory buffer for suspicious shellcode patterns and write a
 * human-readable report to out_path.
 *
 * Returns 0 on success, -1 on failure.
 */
int scan_shellcode_patterns(const void *buf, size_t size, const char *out_path);

/*
 * Write a hexadecimal dump of in_path to out_path, limited to max_lines.
 *
 * Returns 0 on success, -1 on failure.
 */
int write_hex_dump(const char *in_path, const char *out_path, size_t max_lines);

/*
 * Extract a container identifier from /proc/<pid>/cgroup contents.
 *
 * Reads the cgroup file at /proc/<pid>/cgroup and writes a shortened
 * container id into out. Returns 0 on success, -1 if the file cannot
 * be read or no container marker is found.
 */
int get_container_id(int pid, char *out, size_t out_size);

#endif /* SCANNER_PURE_H */

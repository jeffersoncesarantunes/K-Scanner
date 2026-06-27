#ifndef KSCANNER_H
#define KSCANNER_H

#include "export_engine.h"
#include "bpf_telemetry.h"

int run_scan_formatted(ExportFormat format, int silent_jit);
int run_scan_formatted_bpf(ExportFormat format, BpfTelemetryState *bpf, int silent_jit);
int run_watch_loop(ExportFormat format, int silent_jit);
void set_yara_rule_path(const char *path);
void set_yara_binary_path(const char *path);

#endif

#ifndef KSCANNER_H
#define KSCANNER_H

#include "export_engine.h"
#include "bpf_telemetry.h"

int run_scan_formatted(ExportFormat format, int silent_jit);
int run_scan_formatted_bpf(ExportFormat format, BpfTelemetryState *bpf, int silent_jit);

#endif

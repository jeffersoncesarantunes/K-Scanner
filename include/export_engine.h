#ifndef EXPORT_ENGINE_H
#define EXPORT_ENGINE_H

#include <stdio.h>

typedef enum {
    CONFIDENCE_SAFE = 0,
    CONFIDENCE_LOW = 1,
    CONFIDENCE_SUSPICIOUS = 2,
    CONFIDENCE_CRITICAL = 3
} ConfidenceLevel;

typedef enum {
    EXPORT_TERMINAL,
    EXPORT_JSON,
    EXPORT_CSV
} ExportFormat;

typedef struct {
    int pid;
    char process_name[256];
    char status[64];
    char info_path[512];
    char mem_addr[64];
    ConfidenceLevel confidence;
} ForensicRecord;

void export_header(ExportFormat format);
void export_record(const ForensicRecord *record, ExportFormat format);
void export_footer(ExportFormat format);

#endif

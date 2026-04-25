#ifndef EXPORT_ENGINE_H
#define EXPORT_ENGINE_H

#include <stdio.h>

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
} ForensicRecord;

void export_header(ExportFormat format);
void export_record(const ForensicRecord *record, ExportFormat format);
void export_footer(ExportFormat format);

#endif

#include "export_engine.h"
#include <stdio.h>

static int export_first_json = 1;

static const char* conf_level_str(ConfidenceLevel c) {
    switch (c) {
        case CONFIDENCE_SAFE:       return "SAFE";
        case CONFIDENCE_LOW:        return "LOW";
        case CONFIDENCE_SUSPICIOUS: return "MEDIUM";
        case CONFIDENCE_CRITICAL:   return "CRITICAL";
        default:                    return "UNKNOWN";
    }
}

void export_header(ExportFormat format) {
    if (format == EXPORT_JSON) {
        export_first_json = 1;
        printf("[\n");
    } else if (format == EXPORT_CSV) {
        printf("PID,PROCESS_NAME,STATUS,CONFIDENCE,INFO_PATH,MEM_ADDR\n");
    }
}

void export_record(const ForensicRecord *record, ExportFormat format) {
    switch (format) {
        case EXPORT_JSON:
            if (!export_first_json) printf(",\n");
            printf("  {\n");
            printf("    \"pid\": %d,\n", record->pid);
            printf("    \"process\": \"%s\",\n", record->process_name);
            printf("    \"status\": \"%s\",\n", record->status);
            printf("    \"confidence\": \"%s\",\n", conf_level_str(record->confidence));
            printf("    \"info\": \"%s\",\n", record->info_path);
            printf("    \"addr\": \"%s\"\n", record->mem_addr);
            printf("  }");
            export_first_json = 0;
            break;

        case EXPORT_CSV:
            printf("%d,%s,%s,%s,%s,%s\n", 
                   record->pid, record->process_name, 
                   record->status, conf_level_str(record->confidence),
                   record->info_path, record->mem_addr);
            break;

        case EXPORT_TERMINAL:
            printf("| %-6d | %-20s | %-12s | %-10s | %-18s |\n", 
                   record->pid, record->process_name, 
                   record->status, conf_level_str(record->confidence),
                   record->info_path);
            break;
    }
}

void export_footer(ExportFormat format) {
    if (format == EXPORT_JSON) {
        printf("\n]\n");
        export_first_json = 1;
    }
}

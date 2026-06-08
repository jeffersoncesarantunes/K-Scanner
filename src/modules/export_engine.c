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

static void json_escape(FILE *f, const char *s) {
    fputc('"', f);
    while (*s) {
        switch (*s) {
            case '"':  fprintf(f, "\\\""); break;
            case '\\': fprintf(f, "\\\\"); break;
            case '\n': fprintf(f, "\\n");  break;
            case '\r': fprintf(f, "\\r");  break;
            case '\t': fprintf(f, "\\t");  break;
            default:   fputc(*s, f);       break;
        }
        s++;
    }
    fputc('"', f);
}

static void csv_field(FILE *f, const char *s) {
    int needs_quote = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
            needs_quote = 1;
            break;
        }
    }
    if (needs_quote) {
        fputc('"', f);
        while (*s) {
            if (*s == '"') fprintf(f, "\"\"");
            else fputc(*s, f);
            s++;
        }
        fputc('"', f);
    } else {
        fprintf(f, "%s", s);
    }
}

void export_header(ExportFormat format) {
    if (format == EXPORT_JSON) {
        export_first_json = 1;
        printf("[\n");
    } else if (format == EXPORT_CSV) {
        printf("PID,PROCESS_NAME,STATUS,CONFIDENCE,INFO_PATH,MEM_ADDR,CONTAINER_ID\n");
    }
}

void export_record(const ForensicRecord *record, ExportFormat format) {
    switch (format) {
        case EXPORT_JSON:
            if (!export_first_json) printf(",\n");
            printf("  {\n");
            printf("    \"pid\": %d,\n", record->pid);
            printf("    \"process\": ");
            json_escape(stdout, record->process_name);
            printf(",\n");
            printf("    \"status\": ");
            json_escape(stdout, record->status);
            printf(",\n");
            printf("    \"confidence\": \"%s\",\n", conf_level_str(record->confidence));
            printf("    \"info\": ");
            json_escape(stdout, record->info_path);
            printf(",\n");
            printf("    \"addr\": ");
            json_escape(stdout, record->mem_addr);
            printf(",\n");
            printf("    \"container\": ");
            json_escape(stdout, record->container_id);
            printf("\n");
            printf("  }");
            export_first_json = 0;
            break;

        case EXPORT_CSV:
            printf("%d,", record->pid);
            csv_field(stdout, record->process_name);
            printf(",");
            csv_field(stdout, record->status);
            printf(",%s,", conf_level_str(record->confidence));
            csv_field(stdout, record->info_path);
            printf(",");
            csv_field(stdout, record->mem_addr);
            printf(",");
            csv_field(stdout, record->container_id);
            printf("\n");
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

#ifndef LOGGER_H
#define LOGGER_H

#include "forensic_core.h"

void print_table_header(void);
void print_process_row(forensic_process_t *proc);
void print_table_footer(void);
void print_scan_summary(int total, int rwx, int safe);

#endif

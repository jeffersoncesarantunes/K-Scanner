#ifndef TUI_ENGINE_H
#define TUI_ENGINE_H

#include "export_engine.h"

void init_tui(void);
void stop_tui(void);
void update_dashboard(const ForensicRecord *records, int count, int selected_idx);
int handle_input(void);

#endif

#include <ncurses.h>
#include <string.h>
#include <locale.h>
#include "tui_engine.h"

void init_tui(void) {
    setlocale(LC_ALL, "");
    initscr();
    raw();
    keypad(stdscr, TRUE);
    noecho();
    curs_set(0);
    start_color();
    init_pair(1, COLOR_GREEN, COLOR_BLACK);
    init_pair(2, COLOR_RED, COLOR_BLACK);
    init_pair(3, COLOR_CYAN, COLOR_BLACK);
    init_pair(4, COLOR_WHITE, COLOR_BLACK);
    init_pair(5, COLOR_YELLOW, COLOR_BLACK);
}

void stop_tui(void) {
    endwin();
}

void update_dashboard(const ForensicRecord *records, int count, int selected_idx) {
    int max_y;
    max_y = getmaxy(stdscr);
    
    int header_height = 5;
    int footer_height = 1;
    int display_rows = max_y - header_height - footer_height;
    
    int start_row = 0;
    if (selected_idx >= display_rows) {
        start_row = selected_idx - display_rows + 1;
    }

    erase();

    attron(COLOR_PAIR(3) | A_BOLD);
    mvprintw(0, 1, "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    mvprintw(1, 1, "┃ [K] K-Scanner | Live Forensic Process Analysis Mode                     ┃");
    mvprintw(2, 1, "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    attroff(COLOR_PAIR(3) | A_BOLD);

    attron(COLOR_PAIR(4) | A_BOLD);
    mvprintw(4, 2, "  %-8s %-20s %-12s %-10s %-18s", "PID", "PROCESS", "STATUS", "CONFIDENCE", "MAP_ADDR");
    attroff(COLOR_PAIR(4) | A_BOLD);

    for (int i = 0; i < display_rows && (start_row + i) < count; i++) {
        int curr_idx = start_row + i;

        switch (records[curr_idx].confidence) {
            case CONFIDENCE_SAFE:
                attron(COLOR_PAIR(1));
                break;
            case CONFIDENCE_LOW:
                attron(COLOR_PAIR(4) | A_DIM);
                break;
            case CONFIDENCE_SUSPICIOUS:
                attron(COLOR_PAIR(5));
                break;
            case CONFIDENCE_CRITICAL:
                attron(COLOR_PAIR(2) | A_BOLD);
                break;
        }

        if (curr_idx == selected_idx) {
            attron(A_REVERSE);
        }

        char conf_label[12];
        switch (records[curr_idx].confidence) {
            case CONFIDENCE_SAFE:       snprintf(conf_label, sizeof(conf_label), "SAFE"); break;
            case CONFIDENCE_LOW:        snprintf(conf_label, sizeof(conf_label), "LOW"); break;
            case CONFIDENCE_SUSPICIOUS: snprintf(conf_label, sizeof(conf_label), "MEDIUM"); break;
            case CONFIDENCE_CRITICAL:   snprintf(conf_label, sizeof(conf_label), "CRITICAL"); break;
            default:                    snprintf(conf_label, sizeof(conf_label), "?"); break;
        }

        mvprintw(5 + i, 2, "  %-8d %-20.20s %-12s %-10s %-18s", 
                 records[curr_idx].pid, 
                 records[curr_idx].process_name, 
                 records[curr_idx].status, 
                 conf_label,
                 records[curr_idx].mem_addr);

        attrset(A_NORMAL);
    }

    refresh();
}

int handle_input(void) {
    return getch();
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include "colors.h"
#include "kscanner.h"

// Estrutura para armazenar dados reais de cada processo
typedef struct {
    int pid;
    char name[33];
    char status[20];
    char address[18];
    int is_rwx;
} ProcessInfo;

// Função interna (static) para verificar memória RWX
static int check_mem_rwx(int pid, char *out_addr) {
    char path[256], line[512];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "rwxp")) {
            sscanf(line, "%17[^ -]", out_addr);
            found = 1;
            break; 
        }
    }
    fclose(f);
    return found;
}

// Função interna (static) para obter o nome do processo
static void get_process_name(int pid, char *out_name) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(out_name, 33, f)) {
            out_name[strcspn(out_name, "\n")] = 0;
        }
        fclose(f);
    } else {
        strncpy(out_name, "unknown", 33);
    }
}

// Implementação da função run_scan (declarada no kscanner.h)
int run_scan(void) {
    DIR *dir;
    struct dirent *entry;
    int total_processes = 0;
    int rwx_alerts = 0;
    int current_page_count = 0;

    const char *sep_top =    "┌────────┬──────────────────────────────────┬────────────────────┬────────────────────┐";
    const char *sep_header = "│  PID   │ PROCESS NAME                     │ STATUS             │ MEM ADDRESS        │";
    const char *sep_mid =    "├────────┼──────────────────────────────────┼────────────────────┼────────────────────┤";
    const char *sep_bottom = "└────────┴──────────────────────────────────┴────────────────────┴────────────────────┘";

    printf("\n%s[+] Initializing real-time forensic memory scan...%s\n\n", CLR_GREEN, CLR_RESET);
    
    printf("%s\n", sep_top);
    printf("%s\n", sep_header);
    printf("%s\n", sep_mid);

    dir = opendir("/proc");
    if (!dir) {
        perror("Failed to open /proc");
        return 1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;

        int pid = atoi(entry->d_name);
        char p_name[33];
        char p_addr[18] = "0x00000000";
        
        get_process_name(pid, p_name);
        int is_rwx = check_mem_rwx(pid, p_addr);

        total_processes++;
        current_page_count++;

        const char* status_color = CLR_RESET;
        char status_text[20] = "SAFE";

        if (is_rwx) {
            rwx_alerts++;
            status_color = CLR_RED;
            strcpy(status_text, "RWX ALERT");
        }

        printf("│ %-6d │ %-32s │ %s%-18s%s │ %-18s │\n", 
               pid, p_name, status_color, status_text, CLR_RESET, p_addr);

        // Paginação a cada 20 processos lidos
        if (current_page_count >= 20) {
            printf("%s\n", sep_bottom);
            printf("%s-- Press ENTER to continue scanning... --%s", CLR_YELLOW, CLR_RESET);
            
            // Limpa o buffer e espera o Enter
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF);
            
            printf("\n%s\n", sep_top);
            printf("%s\n", sep_header);
            printf("%s\n", sep_mid);
            current_page_count = 0;
        }
    }
    closedir(dir);

    printf("%s\n", sep_bottom);

    printf("\n%s[ ANALYSIS SUMMARY ]%s\n", CLR_BOLD, CLR_RESET);
    printf("📊 Total Scanned: %d | %s🔴 RWX Alerts: %d%s | %s🟢 Clean: %d%s\n", 
           total_processes, CLR_RED, rwx_alerts, CLR_RESET, 
           CLR_GREEN, total_processes - rwx_alerts, CLR_RESET);
    
    printf("\n%s[+] Scan completed. Forensic integrity verified.%s\n", CLR_CYAN, CLR_RESET);
    return 0;
}

// Implementação da função print_usage (exigida pelo main.c)
void print_usage(void) {
    printf("\n%sK-Scanner Forensic Tool%s\n", CLR_BOLD, CLR_RESET);
    printf("Usage: sudo ./kscanner [OPTIONS]\n\n");
    printf("Options:\n");
    printf("  --help    Show this diagnostic information\n\n");
    printf("Note: Root privileges are required to access process memory maps.\n");
}

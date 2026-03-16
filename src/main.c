#include <stdio.h>
#include <string.h>
#include "kscanner.h"
#include "colors.h"

void print_banner(void) {
    printf("%s", CLR_BOLD);
    printf("=======================================================================================\n");
    printf("                                      K-Scanner                                        \n");
    printf("                          Live Forensic Process Analysis Mode                          \n");
    printf("=======================================================================================\n");
    printf("%s", CLR_RESET);
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        print_usage();
        return 0;
    }

    print_banner();
    
    if (run_scan() != 0) {
        fprintf(stderr, "%s[!] Critical error during scan%s\n", CLR_RED, CLR_RESET);
        return 1;
    }

    return 0;
}

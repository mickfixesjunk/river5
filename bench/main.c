#include "hashes.h"

#include <stdio.h>
#include <string.h>

int run_micro(int argc, char **argv);
int run_file(int argc, char **argv);

static int usage(void)
{
    puts("river5-bench — benchmark harness for the river5 deduper hash.");
    puts("");
    puts("usage:");
    puts("  river5-bench list");
    puts("  river5-bench micro [--csv] [--seconds N] [--hash NAME]");
    puts("  river5-bench file  [--csv] [--hash NAME] [--threads N] <path>");
    puts("");
    puts("Registered hashes:");
    for (size_t i = 0; i < g_hashes_count; ++i) {
        printf("  - %s (%d bits)\n", g_hashes[i]->name, g_hashes[i]->output_bits);
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage();

    if (strcmp(argv[1], "list") == 0) {
        for (size_t i = 0; i < g_hashes_count; ++i) {
            printf("%s\t%d\n", g_hashes[i]->name, g_hashes[i]->output_bits);
        }
        return 0;
    }
    if (strcmp(argv[1], "micro") == 0) return run_micro(argc - 2, argv + 2);
    if (strcmp(argv[1], "file")  == 0) return run_file (argc - 2, argv + 2);
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }
    return usage();
}

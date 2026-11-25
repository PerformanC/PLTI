/* A stand-in for a library with full RELRO: every call goes through its read-only GOT. The table
   sits in the same read-only mapping, so the test can tell whether its content survives a hook. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((visibility("default"))) int victim_getpid(void) { return getpid(); }

__attribute__((visibility("default"))) size_t victim_strlen(const char *s) { return strlen(s); }

__attribute__((visibility("default"))) int victim_printf(const char *s) { return printf("%s", s); }

__attribute__((visibility("default"))) void victim_free(void *p) { free(p); }

static void *const big_table[8192] = {
    (void *)getpid, (void *)strlen,    (void *)printf, (void *)free,    (void *)malloc, (void *)puts,
    (void *)abort,  (void *)getppid,
};

/* Exported, so the table cannot be optimized away. */
__attribute__((visibility("default"))) void *victim_table_entry(size_t i) { return big_table[i & 8191]; }

/* An address inside the read-only mapping, for the test to look its mapping up. */
__attribute__((visibility("default"))) const void *victim_table_slot(size_t i) { return &big_table[i & 8191]; }

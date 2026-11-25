/* Hooks a library while other threads keep reading its GOT, which is what a hook installed in a
   running process has to survive. With "unhook" as the only argument, the hook is removed again
   and the mapping of the GOT has to be the one of the linker again.

   VICTIM is the library to load, by name or as a path ("<archive>!<entry>" for a library inside an
   APK). PLTI_GOT_RACE_THREADS is how many threads read the GOT meanwhile. With
   PLTI_GOT_RACE_UNLINK set, the file is deleted after being loaded, so PLTI cannot read it back.
   PLTI_GOT_RACE_DEBUG prints the mapping of the GOT at each step. */
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define THREADS 8

static atomic_int stop;
static atomic_long calls;

static int (*victim_getpid)(void);
static size_t (*victim_strlen)(const char *);
static int (*victim_printf)(const char *);
static void (*victim_free)(void *);
static void *(*victim_table_entry)(size_t);

static void *hammer(void *arg) {
  long n = 0;
  size_t i = (size_t)(uintptr_t)arg;
  while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
    /* Every line goes through a read-only GOT entry of the library. */
    n += victim_getpid();
    n += (long)victim_strlen("payload");
    victim_printf("");
    i = (i + 1) & 8191;
    void *p = malloc(16);
    if (p) victim_free(p);
    n += (long)(uintptr_t)victim_table_entry(i) & 1;
  }
  atomic_fetch_add(&calls, n);
  return NULL;
}

/* Returns 0 when the mapping that covers "addr" is read-only, and backed by a file exactly when
   "file_backed" is set. */
static int check_mapping(uintptr_t addr, int file_backed, const char *step, int debug) {
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps) return -1;

  char line[512];
  char *found = NULL;
  while (fgets(line, sizeof(line), maps)) {
    uintptr_t start = (uintptr_t)strtoull(line, NULL, 16);
    char *dash = strchr(line, '-');
    if (!dash || addr < start || addr >= (uintptr_t)strtoull(dash + 1, NULL, 16)) continue;

    found = line;
    break;
  }
  fclose(maps);

  if (!found) {
    fprintf(stderr, "%s: no mapping covers the GOT\n", step);
    return -1;
  }

  if (debug) fprintf(stderr, "%s: %s", step, found);
  /* An anonymous mapping has no path in its line. */
  if (!strstr(found, "r--p") || (strchr(found, '/') != NULL) != file_backed) {
    fprintf(stderr, "%s: the mapping of the GOT is not as expected: %s", step, found);
    return -1;
  }

  return 0;
}

static void *table_before[8192];

/* Returns 0 when the entries of the table of the library, from "first" on, are still what they
   were before the hook. The first one is the GOT slot of getpid(2) itself. */
static int check_table(size_t first) {
  for (size_t i = first; i < 8192; i++) {
    if (victim_table_entry(i) == table_before[i]) continue;

    fprintf(stderr, "entry %zu of the table changed\n", i);
    return -1;
  }

  return 0;
}

int main(int argc, char **argv) {
  int unhook = argc > 1 && strcmp(argv[1], "unhook") == 0;
  int debug = getenv("PLTI_GOT_RACE_DEBUG") != NULL;
  int keep_file = getenv("PLTI_GOT_RACE_UNLINK") == NULL;
  int thread_count = THREADS;
  if (getenv("PLTI_GOT_RACE_THREADS")) thread_count = atoi(getenv("PLTI_GOT_RACE_THREADS"));
  const char *victim_path = getenv("VICTIM");
  if (!victim_path) victim_path = "libvictim.so";

  void *victim = dlopen(victim_path, RTLD_NOW | RTLD_LOCAL);
  if (!victim) {
    fprintf(stderr, "dlopen %s: %s\n", victim_path, dlerror());
    return 2;
  }
  victim_getpid = (int (*)(void))dlsym(victim, "victim_getpid");
  victim_strlen = (size_t (*)(const char *))dlsym(victim, "victim_strlen");
  victim_printf = (int (*)(const char *))dlsym(victim, "victim_printf");
  victim_free = (void (*)(void *))dlsym(victim, "victim_free");
  victim_table_entry = (void *(*)(size_t))dlsym(victim, "victim_table_entry");
  const void *(*table_slot)(size_t) = (const void *(*)(size_t))dlsym(victim, "victim_table_slot");
  if (!victim_getpid || !victim_strlen || !victim_printf || !victim_free || !victim_table_entry || !table_slot) {
    fprintf(stderr, "dlsym: %s\n", dlerror());
    return 2;
  }

  if (!keep_file && unlink(victim_path) != 0) {
    fprintf(stderr, "unlink %s: %s\n", victim_path, strerror(errno));
    return 2;
  }

  /* The table sits in the read-only data of the library, next to its GOT. */
  uintptr_t data = (uintptr_t)table_slot(0);
  for (size_t i = 0; i < 8192; i++) table_before[i] = victim_table_entry(i);
  if (check_mapping(data, 1, "before", debug)) return 5;

  pthread_t threads[THREADS];
  for (size_t i = 0; i < THREADS && (int)i < thread_count; i++) pthread_create(&threads[i], NULL, hammer, (void *)(uintptr_t)(i * 997));
  usleep(50000);

  void *hook = dlopen("libhook.so", RTLD_NOW | RTLD_LOCAL);
  if (!hook) {
    fprintf(stderr, "dlopen libhook.so: %s\n", dlerror());
    return 2;
  }
  int (*is_installed)(void) = (int (*)(void))dlsym(hook, "hook_is_installed");
  int (*remove)(void) = (int (*)(void))dlsym(hook, "hook_remove");
  if (!is_installed || !is_installed()) {
    fprintf(stderr, "hook was not installed\n");
    return 3;
  }

  usleep(50000);

  /* While the hook is in place, the GOT is an anonymous mapping that reads as the original. */
  if (check_mapping(data, 0, "hooked", debug) || check_table(1)) return 5;

  if (unhook) {
    if (remove() != 0) {
      fprintf(stderr, "hook was not removed\n");
      return 4;
    }
    usleep(50000);

    /* The entry reaches getpid(2) again, and without the file the mapping can only stay anonymous. */
    if (victim_getpid() != getpid()) {
      fprintf(stderr, "victim_getpid does not reach getpid(2) after the hook was removed\n");
      return 6;
    }
    if (check_mapping(data, keep_file, "unhooked", debug) || check_table(0)) return 5;
  }

  atomic_store(&stop, 1);
  for (size_t i = 0; i < THREADS && (int)i < thread_count; i++) pthread_join(threads[i], NULL);
  printf("%ld\n", atomic_load(&calls));
  return 0;
}

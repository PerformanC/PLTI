/* Loaded into the target while its other threads are running, like an injected library. */
#include <stdlib.h>

#include "plti.h"

static struct plti ctx;
static int (*original_getpid)(void);

static int hooked_getpid(void) { return original_getpid(); }

__attribute__((constructor)) static void install(void) {
  plti_init(&ctx);
  if (!plti_add_lib(&ctx, "libvictim.so")) abort();
  if (!plti_add_hook(&ctx, "libvictim.so", "getpid", (void *)hooked_getpid, (void **)&original_getpid)) abort();
}

__attribute__((visibility("default"))) int hook_is_installed(void) {
  return original_getpid != NULL;
}

__attribute__((visibility("default"))) int hook_remove(void) {
  return plti_remove_hook(&ctx, "libvictim.so", "getpid", (void **)&original_getpid) ? 0 : -1;
}

#include "plti.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <link.h>

#include <unistd.h>

#include "elf_util.h"
#include "logging.h"

struct elf_info {
  struct elf_image elf;
  /* WARN: Dynamic allocation */
  const char *path;
};

bool plti_init(struct plti *ctx) {
  /* INFO: Noop */
  memset(ctx, 0, sizeof(*ctx));

  return true;
}

struct plti_phdr_cb_info {
  struct plti *ctx;
  const char *lib_name;
};

bool plti_add_manual_lib(struct plti *ctx, const char *lib_path, uintptr_t base_addr) {
  struct elf_image image;
  if (!elfutil_init(&image, (uintptr_t)base_addr)) {
    LOGE("Failed to initialize ELF image for library: %s", lib_path);

    return false;
  }

  struct elf_info *new_infos = (struct elf_info *)realloc(ctx->elf_infos, (ctx->elf_image_count + 1) * sizeof(struct elf_info));
  if (!new_infos) {
    LOGE("Failed to allocate memory for ELF infos");

    return false;
  }
  ctx->elf_infos = new_infos;

  ctx->elf_infos[ctx->elf_image_count].elf = image;
  ctx->elf_infos[ctx->elf_image_count].path = strdup(lib_path);
  if (!ctx->elf_infos[ctx->elf_image_count].path) {
    LOGE("Failed to duplicate ELF path for library: %s", lib_path);

    return false;
  }
  ctx->elf_image_count++;

  LOGD("Added library: %s (inode: %lu, device: %lu)", lib_path, (unsigned long)image.header_->e_shnum, (unsigned long)image.header_->e_shentsize);

  return true;
}

static int elfutil_phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
  (void) size;

  struct plti_phdr_cb_info *cb_info = (struct plti_phdr_cb_info *)data;
  /* TODO: Not use strstr, only check the basename (tho not use that function, as it is unavailable starting from SDK 24) */
  if (!info->dlpi_name || !strstr(info->dlpi_name, cb_info->lib_name)) return 0;

  /* INFO: When the p_vaddr is different from 0, the ELF header is located
             at dlpi_addr + p_vaddr of the first PT_LOAD segment with p_offset == 0.
             Otherwise, the ELF header is located at dlpi_addr. */
  uintptr_t ehdr_addr = (uintptr_t)info->dlpi_addr;
  for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
    if (info->dlpi_phdr[i].p_type != PT_LOAD || info->dlpi_phdr[i].p_offset != 0) continue;

    ehdr_addr += (uintptr_t)info->dlpi_phdr[i].p_vaddr;

    break;
  }

  if (!plti_add_manual_lib(cb_info->ctx, info->dlpi_name, ehdr_addr)) {
    LOGE("Failed to add library from dl_iterate_phdr callback: %s", info->dlpi_name);

    return -1;
  }

  /* INFO: Stop iterating, we only want the first match */
  return 1;
}

bool plti_add_lib(struct plti *ctx, const char *lib_name) {
  struct plti_phdr_cb_info cb_info = {
    .ctx = ctx,
    .lib_name = lib_name,
  };
  if (dl_iterate_phdr(elfutil_phdr_callback, &cb_info) != 1) {
    LOGE("Failed to find ELF image for library: %s", lib_name);

    return false;
  }

  LOGD("Added library: %s (inode: %lu, device: %lu)", lib_name, (unsigned long)ctx->elf_infos[ctx->elf_image_count - 1].elf.header_->e_shnum, (unsigned long)ctx->elf_infos[ctx->elf_image_count - 1].elf.header_->e_shentsize);

  return true;
}

static void *page_start(uintptr_t addr) {
  return (void *)(addr & ~(getpagesize() - 1));
}

static bool plti_internal_set_got_entry(struct elf_image *elf, uintptr_t got_addr, void *new_val) {
  int restore_prot = 0;
  if (!elfutil_get_addr_protection(elf, got_addr, &restore_prot)) {
    LOGE("Failed to infer memory protection for GOT entry at 0x%" PRIxPTR, got_addr);

    return false;
  }

  if (mprotect(page_start(got_addr), getpagesize(), restore_prot | PROT_WRITE) == -1) {
    LOGE("Failed to change memory protection for GOT entry at 0x%" PRIxPTR, got_addr);

    return false;
  }

  *((uintptr_t *)got_addr) = (uintptr_t)new_val;

  if (mprotect(page_start(got_addr), getpagesize(), restore_prot) == -1) {
    LOGE("Failed to restore memory protection for GOT entry at 0x%" PRIxPTR, got_addr);

    return false;
  }

  return true;
}

static bool plti_internal_add_hook(struct plti *ctx, const char *lib_name, const char *name, bool by_prefix, void *new_callback, void **backup) {
  /* TODO: Replace uintptr_t for void * in ELF utils */
  struct elf_image *target_image = NULL;
  for (size_t i = 0; i < ctx->elf_image_count; i++) {
    if (!strstr(ctx->elf_infos[i].path, lib_name)) continue;

    target_image = &ctx->elf_infos[i].elf;

    break;
  }

  if (!target_image) {
    LOGE("Failed to find ELF image for library for hook %s: %s", name, lib_name);

    return false;
  }

  uintptr_t *plt_addrs = NULL;
  size_t plt_addr_count = 0;
  if (by_prefix) {
    plt_addr_count = elfutil_find_plt_addr_by_prefix(target_image, name, &plt_addrs);
  } else {
    plt_addr_count = elfutil_find_plt_addr(target_image, name, &plt_addrs);
  }
  if (plt_addr_count == 0) {
    LOGE("Failed to find PLT address for hook %s in library %s", name, lib_name);

    return false;
  }

  /* INFO: Early check, so that if it fails, we will be clean (hookless) */
  struct plti_hook *new_hooks = (struct plti_hook *)realloc(ctx->hooks, (ctx->hook_count + plt_addr_count) * sizeof(struct plti_hook));
  if (!new_hooks) {
    LOGE("Failed to reallocate hooks array");

    free(plt_addrs);

    return false;
  }
  ctx->hooks = new_hooks;

  for (size_t i = 0; i < plt_addr_count; i++) {
    ctx->hooks[ctx->hook_count].lib_name = strdup(lib_name);
    if (!ctx->hooks[ctx->hook_count].lib_name) {
      LOGE("Failed to duplicate library name for hook %s in library %s", name, lib_name);

      free(plt_addrs);

      return false;
    }

    ctx->hooks[ctx->hook_count].name = strdup(name);
    if (!ctx->hooks[ctx->hook_count].name) {
      LOGE("Failed to duplicate hook name for hook %s in library %s", name, lib_name);

      free(plt_addrs);

      return false;
    }

    ctx->hooks[ctx->hook_count].address = (void *)plt_addrs[i];
    ctx->hook_count++;
  }

  for (size_t i = 0; i < plt_addr_count; i++) {
    uintptr_t plt_addr = plt_addrs[i];
    if (!plt_addr) continue;

    if (backup && *backup == NULL) {
      /* INFO: backup must keep the original target function pointer stored in the GOT/PLT slot.
                Keeping the slot address itself (previous behavior) makes callers branch into data,
                which can crash with SIGILL (ILL_ILLOPC). */
      uintptr_t original_callback = *((uintptr_t *)plt_addr);
      *backup = (void *)original_callback;
    }

    if (!plti_internal_set_got_entry(target_image, plt_addr, new_callback)) {
      LOGE("Failed to set GOT entry for PLT hook at 0x%" PRIxPTR, plt_addr);

      free(plt_addrs);

      return false;
    }
  }

  free(plt_addrs);

  return true;
}

bool plti_add_hook(struct plti *ctx, const char *lib_name, const char *name, void *new_callback, void **backup) {
  return plti_internal_add_hook(ctx, lib_name, name, false, new_callback, backup);
}

/* WARN: We should only allow one hook per symbol, considering that multiple hooks WILL lead
           to (at least) one of the original addresses being lost */
bool plti_add_hook_by_prefix(struct plti *ctx, const char *lib_name, const char *name_prefix, void *new_callback, void **backup) {
  return plti_internal_add_hook(ctx, lib_name, name_prefix, true, new_callback, backup);
}

/* TODO: Add by suffix? */

/* TODO: Perhaps: When registering hooks by prefix, add their full name to the array, and de-registering will only
           remove those targets. For now, removing any that matches so, even manual, is very acceptable. */
static bool plti_internal_remove_hook(struct plti *ctx, const char *lib_name, const char *name, void *original_callback) {
  struct elf_image *target_image = NULL;
  for (size_t i = 0; i < ctx->elf_image_count; i++) {
    if (!strstr(ctx->elf_infos[i].path, lib_name)) continue;

    target_image = &ctx->elf_infos[i].elf;

    break;
  }

  if (!target_image) {
    LOGE("Failed to find ELF image for library for removing hook %s: %s", name, lib_name);

    return false;
  }

  /* INFO: To avoid runtime memory issues to leave us in an "unclean" state, we
             do this first. Although if setting hook fails, we won't be clean if
             there's more than one hook . */
  size_t dehooked_count = 0;
  for (size_t i = 0; i < ctx->hook_count; i++) {
    if (strcmp(ctx->hooks[i].lib_name, lib_name) != 0) continue;
    if (strcmp(ctx->hooks[i].name, name) != 0) continue;

    dehooked_count++;
  }

  if (dehooked_count == 0) {
    LOGE("No matching hook found for %s in library %s", name, lib_name);

    return false;
  }

  struct plti_hook *new_hooks = NULL;
  size_t new_hook_idx = 0;

  if (dehooked_count != ctx->hook_count) {
    new_hooks = malloc((ctx->hook_count - dehooked_count) * sizeof(struct plti_hook));
    if (!new_hooks) {
      LOGE("Failed to reallocate hooks array for removing hook %s in library %s", name, lib_name);

      return false;
    }
  }

  for (size_t i = 0; i < ctx->hook_count; i++) {
    if (strcmp(ctx->hooks[i].lib_name, lib_name) != 0) goto unhook_add_hook;
    if (strcmp(ctx->hooks[i].name, name) != 0) goto unhook_add_hook;

    uintptr_t plt_addr = (uintptr_t)ctx->hooks[i].address;
    if (!plt_addr) continue;

    if (!plti_internal_set_got_entry(target_image, plt_addr, original_callback)) {
      LOGE("Failed to restore GOT entry for PLT hook at 0x%" PRIxPTR, plt_addr);

      return false;
    }

    continue;

    /* INFO: If it doesn't match, add to the new hooks array */
    unhook_add_hook:
      new_hooks[new_hook_idx].lib_name = ctx->hooks[i].lib_name;
      new_hooks[new_hook_idx].name = ctx->hooks[i].name;
      new_hooks[new_hook_idx].address = ctx->hooks[i].address;

      new_hook_idx++;
  }

  free(ctx->hooks);
  if (dehooked_count == ctx->hook_count) ctx->hooks = NULL;
  else ctx->hooks = new_hooks;

  ctx->hook_count = new_hook_idx;

  return true;
}

bool plti_remove_hook(struct plti *ctx, const char *lib_name, const char *name, void **original_callback) {
  if (!original_callback || *original_callback == NULL) {
    LOGE("Original callback pointer is NULL for hook %s in library %s", name, lib_name);

    return false;
  }

  return plti_internal_remove_hook(ctx, lib_name, name, *original_callback);
}

bool plti_remove_hook_by_prefix(struct plti *ctx, const char *lib_name, const char *name_prefix, void **original_callback) {
  return plti_internal_remove_hook(ctx, lib_name, name_prefix, *original_callback);
}

bool plti_deinit(struct plti *ctx) {
  for (size_t i = 0; i < ctx->elf_image_count; i++) {
    free((void *)ctx->elf_infos[i].path);
  }

  for (size_t i = 0; i < ctx->hook_count; i++) {
    free((void *)ctx->hooks[i].lib_name);
    free((void *)ctx->hooks[i].name);
  }

  free(ctx->elf_infos);
  ctx->elf_infos = NULL;
  ctx->elf_image_count = 0;

  return true;
}

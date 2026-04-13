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

bool plti_add_manual_lib(struct plti *ctx, const char *lib_path, void *base_addr) {
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

  if (!plti_add_manual_lib(cb_info->ctx, info->dlpi_name, (void *)ehdr_addr)) {
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

static void *page_start(void *addr) {
  return (void *)((uintptr_t)addr & ~(getpagesize() - 1));
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

  for (size_t i = 0; i < plt_addr_count; i++) {
    uintptr_t plt_addr = plt_addrs[i];
    if (!plt_addr) continue;

    /* INFO: backup must keep the original target function pointer stored in the GOT/PLT slot.
          Keeping the slot address itself (previous behavior) makes callers branch into data,
          which can crash with SIGILL (ILL_ILLOPC). */
    uintptr_t original_callback = *((uintptr_t *)plt_addr);
    if (backup && *backup == NULL) *backup = (void *)original_callback;

    /* INFO: Write new callback to PLT entry */
    int restore_prot = 0;
    if (!elfutil_get_addr_protection(target_image, plt_addr, &restore_prot)) {
      LOGE("Failed to infer memory protection for PLT entry at 0x%" PRIxPTR, plt_addr);

      free(plt_addrs);

      return false;
    }

    if (mprotect(page_start((void *)plt_addr), getpagesize(), restore_prot | PROT_WRITE) == -1) {
      LOGE("Failed to change memory protection for PLT entry at 0x%" PRIxPTR, plt_addr);

      free(plt_addrs);

      return false;
    }

    *((uintptr_t *)plt_addr) = (uintptr_t)new_callback;

    if (mprotect(page_start((void *)plt_addr), getpagesize(), restore_prot) == -1) {
      LOGE("Failed to restore memory protection for PLT entry at 0x%" PRIxPTR, plt_addr);

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

bool plti_add_hook_by_prefix(struct plti *ctx, const char *lib_name, const char *name_prefix, void *new_callback, void **backup) {
  return plti_internal_add_hook(ctx, lib_name, name_prefix, true, new_callback, backup);
}

/* TODO: Add by suffix? */

bool plti_remove_hook(struct plti *ctx, const char *lib_name, const char *name, void **backup) {
  if (!backup || *backup == NULL) {
    LOGE("Backup pointer is NULL for hook %s in library %s", name, lib_name);

    return false;
  }

  return plti_add_hook(ctx, lib_name, name, *backup, NULL);
}

bool plti_remove_hook_by_prefix(struct plti *ctx, const char *lib_name, const char *name_prefix, void **backup) {
  if (!backup || *backup == NULL) {
    LOGE("Backup pointer is NULL for hook with prefix %s in library %s", name_prefix, lib_name);

    return false;
  }

  return plti_add_hook_by_prefix(ctx, lib_name, name_prefix, *backup, NULL);
}

bool plti_deinit(struct plti *ctx) {
  for (size_t i = 0; i < ctx->elf_image_count; i++) {
    free((void *)ctx->elf_infos[i].path);
  }

  free(ctx->elf_infos);
  ctx->elf_infos = NULL;
  ctx->elf_image_count = 0;

  return true;
}

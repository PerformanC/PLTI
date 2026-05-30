#define _GNU_SOURCE
#include "plti.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <link.h>

#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "elf_util.h"
#include "fd_utils.h"
#include "logging.h"

struct stashed_vma {
  uintptr_t original_addr;
  uintptr_t backup_addr;
  size_t len;
  int original_prot;
};

struct elf_info {
  struct elf_image elf;
  /* WARN: Dynamic allocation */
  const char *path;
  struct stashed_vma *stashed_vmas;
  size_t stashed_vma_count;
};

static bool is_self_elf(struct elf_image *elf) {
  uintptr_t pc = (uintptr_t)is_self_elf;
  for (size_t i = 0; i < elf->header_->e_phnum; i++) {
    const ElfW(Phdr) *ph = &elf->program_header_[i];
    if (ph->p_type != PT_LOAD) continue;

    uintptr_t start = (uintptr_t)elf->bias_addr_ + ph->p_vaddr;
    uintptr_t end = start + ph->p_memsz;
    if (pc >= start && pc < end) return true;
  }

  return false;
}

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
  /* INFO: Prevent adding the same library twice */
  for (size_t i = 0; i < ctx->elf_image_count; i++) {
    if (ctx->elf_infos[i].elf.base_addr_ == base_addr) return true;
  }

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

  memset(&ctx->elf_infos[ctx->elf_image_count], 0, sizeof(struct elf_info));
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

/* INFO: If we allocate a VMA on a low address, we risk taking a place where the system
           would later use. This is a detection that the only fix is to use a high address. */
static void *find_high_backup_hint(size_t needed_size) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
    LOGE("Failed to create socket pair for backup hint scan");

    return NULL;
  }

  pid_t pid = fork();
  if (pid == -1) {
    LOGE("Failed to fork for backup hint scan");

    close(sockets[0]);
    close(sockets[1]);

    return NULL;
  }

  if (pid == 0) {
    close(sockets[0]);

    int maps_fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (maps_fd != -1) {
      fdutil_write_fd(sockets[1], maps_fd);
      close(maps_fd);

      char done = 0;
      read(sockets[1], &done, sizeof(done));
    }

    close(sockets[1]);
    _exit(0);
  }

  close(sockets[1]);

  int maps_fd = fdutil_read_fd(sockets[0]);
  if (maps_fd == -1) {
    LOGE("Failed to read backup hint scan fd from child");

    close(sockets[0]);
    waitpid(pid, NULL, 0);

    return NULL;
  }

  FILE *fp = fdopen(maps_fd, "r");
  if (!fp) {
    LOGE("Failed to open backup hint scan fd");

    close(maps_fd);
    close(sockets[0]);
    waitpid(pid, NULL, 0);

    return NULL;
  }

  uintptr_t pagesize = (uintptr_t)getpagesize();
  size_t size = (needed_size + pagesize - 1) & ~(pagesize - 1);

  uintptr_t prev_end = 0;
  uintptr_t best = 0;

  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    uintptr_t start, end;
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) != 2) continue;

    if (prev_end != 0 && start > prev_end && (start - prev_end) >= size)
      best = prev_end;

    if (end > prev_end) prev_end = end;
  }

  fclose(fp);

  char done = 1;
  write(sockets[0], &done, sizeof(done));
  close(sockets[0]);
  waitpid(pid, NULL, 0);

  return best != 0 ? (void *)((best + pagesize - 1) & ~(pagesize - 1)) : NULL;
}

static bool plti_internal_set_got_entry(struct elf_info *info, uintptr_t got_addr, void *new_val) {
  struct elf_image *elf = &info->elf;
  int restore_prot = 0;
  if (!elfutil_get_addr_protection(elf, got_addr, &restore_prot)) {
    LOGE("Failed to infer memory protection for GOT entry at 0x%" PRIxPTR, got_addr);

    return false;
  }

  if (is_self_elf(elf)) goto apply_hook;

  /* INFO: For writable segments (data), modify directly and exit early */
  if (restore_prot & PROT_WRITE) {
    if (mprotect(page_start(got_addr), getpagesize(), restore_prot | PROT_WRITE) == -1) {
      LOGE("Failed to make GOT entry writable at 0x%" PRIxPTR, got_addr);

      return false;
    }

    goto apply_hook;
  }

  /* INFO: For read-only segments, trying to modify directly will lead to increase in the
             library's VMA (r--p specifically) Private Dirty due to CoW being triggered. To
             avoid that, we will replace the whole VMA with an anonymous mapping,
             and stash the original VMA for later restoration.
  */
  uintptr_t vma_start = 0;
  size_t vma_len = 0;
  if (!elfutil_get_vma_boundaries(elf, got_addr, &vma_start, &vma_len)) {
    LOGE("Failed to find VMA boundaries for GOT entry at 0x%" PRIxPTR, got_addr);

    return false;
  }

  struct stashed_vma *stash = NULL;
  for (size_t i = 0; i < info->stashed_vma_count; i++) {
    if (vma_start != info->stashed_vmas[i].original_addr) continue;

    stash = &info->stashed_vmas[i];

    break;
  }

  /* INFO: Early exit if VMA is already anonymous (detected via msync failure) */
  if (!stash && (msync((void *)vma_start, vma_len, MS_ASYNC) == -1 && errno == ENOMEM))
    goto apply_hook;

  if (!stash) {
    /* INFO: Don't call LOGE -- or else it will try to access GOT while it's being modified */
    void *hint = find_high_backup_hint(vma_len);
    void *backup_addr = mmap(hint, vma_len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (backup_addr == MAP_FAILED) {
      backup_addr = mmap(NULL, vma_len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (backup_addr == MAP_FAILED) {
        LOGE("Failed to allocate backup memory for stashing VMA for library: %s", info->path);

        return false;
      }
    }

    if (mremap((void *)vma_start, vma_len, vma_len, MREMAP_FIXED | MREMAP_MAYMOVE, backup_addr) == MAP_FAILED)
      goto fail_stash_mremap;

    if (mmap((void *)vma_start, vma_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
      goto fail_stash_mmap;

    memmove((void *)vma_start, backup_addr, vma_len);

    struct stashed_vma *new_stashed = (struct stashed_vma *)realloc(info->stashed_vmas, (info->stashed_vma_count + 1) * sizeof(struct stashed_vma));
    if (!new_stashed) {
      LOGE("Failed to allocate memory for stashed VMAs for library: %s", info->path);

      goto fail_stash;
    }

    info->stashed_vmas = new_stashed;
    stash = &info->stashed_vmas[info->stashed_vma_count++];
    stash->original_addr = vma_start;
    stash->backup_addr = (uintptr_t)backup_addr;
    stash->len = vma_len;
    stash->original_prot = restore_prot;

    goto apply_hook;

    fail_stash:
      munmap((void *)vma_start, vma_len);
    fail_stash_mmap:
      mremap(backup_addr, vma_len, vma_len, MREMAP_FIXED | MREMAP_MAYMOVE, (void *)vma_start);
    fail_stash_mremap:
      munmap(backup_addr, vma_len);

      return false;
  }

  apply_hook:
    /* INFO: Always ensure page is writable before hooking, as previous hooks might have restored R permissions */
    if (mprotect(page_start(got_addr), getpagesize(), PROT_READ | PROT_WRITE) == -1) {
      LOGE("Failed to make GOT entry writable at 0x%" PRIxPTR, got_addr);

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
  struct elf_info *target_info = NULL;
  for (size_t i = 0; i < ctx->elf_image_count; i++) {
    if (!strstr(ctx->elf_infos[i].path, lib_name)) continue;

    target_info = &ctx->elf_infos[i];

    break;
  }

  if (!target_info) {
    LOGE("Failed to find ELF image for library for hook %s: %s", name, lib_name);

    return false;
  }

  uintptr_t *plt_addrs = NULL;
  size_t plt_addr_count = 0;
  if (by_prefix) {
    plt_addr_count = elfutil_find_plt_addr_by_prefix(&target_info->elf, name, &plt_addrs);
  } else {
    plt_addr_count = elfutil_find_plt_addr(&target_info->elf, name, &plt_addrs);
  }
  if (plt_addr_count == 0) {
    LOGE("Failed to find PLT address for hook %s in library %s", name, lib_name);

    return false;
  }

  for (size_t i = 0; i < plt_addr_count; i++) {
    uintptr_t plt_addr = plt_addrs[i];
    if (!plt_addr) continue;

    /* INFO: Capture original target before any modification. Each slot is independent;
               backup is only written once (first slot), which is sufficient for
               single-symbol hooks. Prefix hooks share one backup pointer. */
    uintptr_t original_callback = *((uintptr_t *)plt_addr);
    if (backup && *backup == NULL) {
      *backup = (void *)original_callback;
    }

    /* INFO: Modify GOT first. If this fails, no metadata is committed. */
    if (!plti_internal_set_got_entry(target_info, plt_addr, new_callback)) {
      LOGE("Failed to set GOT entry for PLT hook at 0x%" PRIxPTR, plt_addr);

      /* INFO: Rollback only the slots already hooked in this call.
                 Iterate ctx->hooks in reverse to find entries added by this call. */
      for (size_t j = ctx->hook_count; j > 0; j--) {
        struct plti_hook *h = &ctx->hooks[j - 1];
        if (strcmp(h->lib_name, lib_name) != 0) continue;
        if (strcmp(h->name, name) != 0) continue;

        uintptr_t hooked_plt = (uintptr_t)h->address;
        if (!hooked_plt) continue;

        /* NOTE: If rollback fails, state is inconsistent. This is best-effort. */
        plti_internal_set_got_entry(target_info, hooked_plt, (void *)original_callback);
      }

      free(plt_addrs);

      return false;
    }

    /* INFO: Only commit metadata after GOT modification succeeds. */
    struct plti_hook *new_hooks = (struct plti_hook *)realloc(ctx->hooks, (ctx->hook_count + 1) * sizeof(struct plti_hook));
    if (!new_hooks) {
      LOGE("Failed to reallocate hooks array");

      /* INFO: Metadata allocation failed but GOT is already hooked. Unhook to stay consistent. */
      plti_internal_set_got_entry(target_info, plt_addr, (void *)original_callback);

      free(plt_addrs);

      return false;
    }
    ctx->hooks = new_hooks;

    ctx->hooks[ctx->hook_count].lib_name = strdup(lib_name);
    if (!ctx->hooks[ctx->hook_count].lib_name) {
      LOGE("Failed to duplicate library name for hook %s in library %s", name, lib_name);

      plti_internal_set_got_entry(target_info, plt_addr, (void *)original_callback);

      free(plt_addrs);

      return false;
    }

    ctx->hooks[ctx->hook_count].name = strdup(name);
    if (!ctx->hooks[ctx->hook_count].name) {
      LOGE("Failed to duplicate hook name for hook %s in library %s", name, lib_name);

      free((void *)ctx->hooks[ctx->hook_count].lib_name);
      plti_internal_set_got_entry(target_info, plt_addr, (void *)original_callback);

      free(plt_addrs);

      return false;
    }

    ctx->hooks[ctx->hook_count].address = (void *)plt_addr;
    ctx->hook_count++;
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
  struct elf_info *target_info = NULL;
  for (size_t i = 0; i < ctx->elf_image_count; i++) {
    if (!strstr(ctx->elf_infos[i].path, lib_name)) continue;

    target_info = &ctx->elf_infos[i];

    break;
  }

  if (!target_info) {
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

    if (!plti_internal_set_got_entry(target_info, plt_addr, original_callback)) {
      LOGE("Failed to restore GOT entry for PLT hook at 0x%" PRIxPTR, plt_addr);

      if (new_hooks) free(new_hooks);

      return false;
    }

    continue;

    /* INFO: If it doesn't match, add to the new hooks array */
    unhook_add_hook:
      if (new_hooks) {
        new_hooks[new_hook_idx].lib_name = ctx->hooks[i].lib_name;
        new_hooks[new_hook_idx].name = ctx->hooks[i].name;
        new_hooks[new_hook_idx].address = ctx->hooks[i].address;

        new_hook_idx++;
      }
  }

  struct plti_hook *old_hooks = ctx->hooks;
  ctx->hooks = new_hooks;
  ctx->hook_count = new_hook_idx;

  for (size_t i = 0; i < target_info->stashed_vma_count; ) {
    struct stashed_vma *stash = &target_info->stashed_vmas[i];
    uintptr_t vma_end = stash->original_addr + stash->len;

    /* INFO: A library's VMA is shared across all hooks for that library. We can only
               restore the VMA if no other hooks are using it. */
    bool is_still_hooked = false;

    for (size_t j = 0; j < ctx->hook_count; j++) {
      uintptr_t hook_addr = (uintptr_t)ctx->hooks[j].address;
      if (hook_addr < stash->original_addr || hook_addr >= vma_end) continue;

      is_still_hooked = true;

      break;
    }

    if (is_still_hooked) {
      i++;

      continue;
    }

    if (mremap((void *)stash->backup_addr, stash->len, stash->len, MREMAP_FIXED | MREMAP_MAYMOVE, (void *)stash->original_addr) == MAP_FAILED) {
      LOGE("Failed to restore original VMA for library %s", target_info->path);

      free(old_hooks);

      return false;
    }

    if (i + 1 < target_info->stashed_vma_count)
      memmove(&target_info->stashed_vmas[i], &target_info->stashed_vmas[i + 1], (target_info->stashed_vma_count - i - 1) * sizeof(struct stashed_vma));

    target_info->stashed_vma_count--;
    if (target_info->stashed_vma_count == 0) {
      free(target_info->stashed_vmas);
      target_info->stashed_vmas = NULL;
    }
  }

  free(old_hooks);

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
  if (!original_callback || *original_callback == NULL) {
    LOGE("Original callback pointer is NULL for hook with prefix %s in library %s", name_prefix, lib_name);

    return false;
  }

  return plti_internal_remove_hook(ctx, lib_name, name_prefix, *original_callback);
}

bool plti_deinit(struct plti *ctx) {
  for (size_t i = 0; i < ctx->elf_image_count; i++) {
    struct elf_info *info = &ctx->elf_infos[i];

    free(info->stashed_vmas);
    free((void *)info->path);
  }

  for (size_t i = 0; i < ctx->hook_count; i++) {
    free((void *)ctx->hooks[i].lib_name);
    free((void *)ctx->hooks[i].name);
  }

  free(ctx->hooks);
  ctx->hooks = NULL;
  ctx->hook_count = 0;

  free(ctx->elf_infos);
  ctx->elf_infos = NULL;
  ctx->elf_image_count = 0;

  return true;
}

#ifndef PLTI_H
#define PLTI_H

#include <stdbool.h>
#include <sys/types.h>

/* INFO: Only keep ELF images saved for performance reasons */
struct plti {
  /* WARN: Dynamic allocation */
  struct elf_info *elf_infos;
  size_t elf_image_count;
};

bool plti_init(struct plti *ctx);

bool plti_add_lib(struct plti *ctx, const char *lib_name);

bool plti_add_manual_lib(struct plti *ctx, const char *lib_path, void *base_addr);

bool plti_add_hook(struct plti *ctx, const char *lib_name, const char *name, void *new_callback, void **backup);

bool plti_add_hook_by_prefix(struct plti *ctx, const char *lib_name, const char *name_prefix, void *new_callback, void **backup);

bool plti_remove_hook(struct plti *ctx, const char *lib_name, const char *name, void **backup);

bool plti_remove_hook_by_prefix(struct plti *ctx, const char *lib_name, const char *name_prefix, void **backup);

bool plti_deinit(struct plti *ctx);

#endif /* PLTI_H */
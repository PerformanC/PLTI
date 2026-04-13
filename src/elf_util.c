#include "elf_util.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

#include "logging.h"

#ifndef PT_GNU_RELRO
  #define PT_GNU_RELRO 0x6474e552
#endif

#if defined(__arm__)
  #define ELF_CLASS ELFCLASS32
  #define ELF_MACHINE EM_ARM

  #define ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT  /* INFO: .rel.plt */
  #define ELF_R_GENERIC_GLOB_DAT R_ARM_GLOB_DAT    /* INFO: .rel.dyn */
  #define ELF_R_GENERIC_ABS R_ARM_ABS32            /* INFO: .rel.dyn */
#elif defined(__aarch64__)
  #define ELF_CLASS ELFCLASS64
  #define ELF_MACHINE EM_AARCH64

  #define ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
  #define ELF_R_GENERIC_GLOB_DAT R_AARCH64_GLOB_DAT
  #define ELF_R_GENERIC_ABS R_AARCH64_ABS64
#elif defined(__i386__)
  #define ELF_CLASS ELFCLASS32
  #define ELF_MACHINE EM_386

  #define ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
  #define ELF_R_GENERIC_GLOB_DAT R_386_GLOB_DAT
  #define ELF_R_GENERIC_ABS R_386_32
#elif defined(__x86_64__)
  #define ELF_CLASS ELFCLASS64
  #define ELF_MACHINE EM_X86_64

  #define ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
  #define ELF_R_GENERIC_GLOB_DAT R_X86_64_GLOB_DAT
  #define ELF_R_GENERIC_ABS R_X86_64_64
#elif defined(__riscv)
  #define ELF_CLASS ELFCLASS64
  #define ELF_MACHINE EM_RISCV

  #define ELF_R_GENERIC_JUMP_SLOT R_RISCV_JUMP_SLOT
  #define ELF_R_GENERIC_GLOB_DAT R_RISCV_64
  #define ELF_R_GENERIC_ABS R_RISCV_64
#endif

#ifdef __LP64__
  #define ELF_R_SYM(info) ELF64_R_SYM(info)
  #define ELF_R_INFO(sym, type) ELF64_R_INFO(sym, type)
  #define ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
  #define ELF_R_SYM(info) ELF32_R_SYM(info)
  #define ELF_R_INFO(sym, type) ELF32_R_INFO(sym, type)
  #define ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

struct sleb128_decoder {
  const uint8_t *current;
  const uint8_t *end;
};

static void sleb128_decoder_init(struct sleb128_decoder *decoder, const uint8_t *buffer, size_t count) {
  decoder->current = buffer;
  decoder->end = buffer + count;
}

static int64_t sleb128_decode(struct sleb128_decoder *decoder) {
  int64_t value = 0;
  size_t shift = 0;
  uint8_t byte;
  const size_t size = sizeof(int64_t) * CHAR_BIT;

  do {
    if (decoder->current >= decoder->end)
      LOGF("Failed to decode SLEB128: buffer overrun");

    byte = *decoder->current++;
    value |= ((int64_t)(byte & 0x7F)) << shift;
    shift += 7;
  } while (byte & 0x80);

  if (shift < size && (byte & 0x40)) {
    value |= -((int64_t)1 << shift);
  }

  return value;
}


static bool set_by_offset(ElfW(Addr) *ptr, ElfW(Addr) base, ElfW(Addr) bias, ElfW(Addr) off) {
  ElfW(Addr) val = bias + off;

  if (val >= base) {
    *ptr = val;

    return true;
  }

  LOGE("Failed to set pointer: base=0x%" PRIxPTR ", bias=0x%" PRIxPTR ", off=0x%" PRIxPTR ", val=0x%" PRIxPTR, (uintptr_t)base, (uintptr_t)bias, (uintptr_t)off, (uintptr_t)val);

  *ptr = 0;

  return false;
}

bool elfutil_init(struct elf_image *elf, uintptr_t base_addr) {
  memset(elf, 0, sizeof(*elf));

  elf->header_ = (ElfW(Ehdr) *)base_addr;
  elf->base_addr_ = base_addr;

  /* INFO: check magic */
  if (0 != memcmp(elf->header_->e_ident, ELFMAG, SELFMAG)) return false;

  /* INFO: check class (64/32) */
  if (ELF_CLASS != elf->header_->e_ident[EI_CLASS]) return false;

  /* INFO: check endian (little/big) */
  if (ELFDATA2LSB != elf->header_->e_ident[EI_DATA]) return false;

  /* INFO: check version */
  if (EV_CURRENT != elf->header_->e_ident[EI_VERSION]) return false;

  /* INFO: check type */
  if (ET_EXEC != elf->header_->e_type && ET_DYN != elf->header_->e_type) return false;

  /* INFO: check machine */
  if (ELF_MACHINE != elf->header_->e_machine) return false;

  if (elf->header_->e_version != EV_CURRENT) {
    LOGE("Unsupported ELF version: %d", elf->header_->e_version);

    return false;
  }

  elf->program_header_ = (ElfW(Phdr) *)((uintptr_t)elf->header_ + elf->header_->e_phoff);

  uintptr_t ph_off = (uintptr_t)elf->program_header_;
  for (int i = 0; i < elf->header_->e_phnum; i++, ph_off += elf->header_->e_phentsize) {
    ElfW(Phdr) *program_header = (ElfW(Phdr) *)ph_off;

    if (program_header->p_type == PT_LOAD && program_header->p_offset == 0) {
      if (elf->base_addr_ < program_header->p_vaddr) continue;

      elf->bias_addr_ = elf->base_addr_ - program_header->p_vaddr;
    } else if (program_header->p_type == PT_DYNAMIC) {
      elf->dynamic_ = (ElfW(Dyn) *)program_header->p_vaddr;
      elf->dynamic_size_ = program_header->p_memsz;
    }
  }

  if (!elf->dynamic_) {
    LOGE("Failed to find dynamic section or bias address in ELF header");

    return false;
  }

  elf->dynamic_ = (ElfW(Dyn) *)(elf->bias_addr_ + (uintptr_t)elf->dynamic_);

  for (ElfW(Dyn) *dynamic = elf->dynamic_, *dynamic_end = elf->dynamic_ + (elf->dynamic_size_ / sizeof(dynamic[0])); dynamic < dynamic_end; dynamic++) {
    switch (dynamic->d_tag) {
      case DT_NULL: {
        dynamic = dynamic_end;

        break;
      }
      case DT_STRTAB: {
        if (!set_by_offset((ElfW(Addr) *)&elf->dyn_str_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return false;

        break;
      }
      case DT_SYMTAB: {
        if (!set_by_offset((ElfW(Addr) *)&elf->dyn_sym_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return false;

        break;
      }
      case DT_PLTREL: {
        elf->rel_plt_is_rela_ = dynamic->d_un.d_val == DT_RELA;

        break;
      }
      case DT_JMPREL: {
        if (!set_by_offset((ElfW(Addr) *)&elf->rel_plt_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return false;

        break;
      }
      case DT_PLTRELSZ: {
        elf->rel_plt_size_ = dynamic->d_un.d_val;

        break;
      }
      case DT_REL: {
        if (!set_by_offset((ElfW(Addr) *)&elf->rel_dyn_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return false;
        elf->rel_dyn_is_rela_ = false;

        break;
      }
      case DT_RELA: {
        if (!set_by_offset((ElfW(Addr) *)&elf->rel_dyn_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return false;
        elf->rel_dyn_is_rela_ = true;

        break;
      }
      case DT_RELSZ:
      case DT_RELASZ: {
        elf->rel_dyn_size_ = dynamic->d_un.d_val;

        break;
      }
      case DT_ANDROID_REL: {
        if (!set_by_offset((ElfW(Addr) *)&elf->rel_android_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return false;
        elf->rel_android_is_rela_ = false;

        break;
      }
      case DT_ANDROID_RELA: {
        if (!set_by_offset((ElfW(Addr) *)&elf->rel_android_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return false;
        elf->rel_android_is_rela_ = true;

        break;
      }
      case DT_ANDROID_RELSZ:
      case DT_ANDROID_RELASZ: {
        elf->rel_android_size_ = dynamic->d_un.d_val;

        break;
      }
      case DT_HASH: {
        if (elf->bloom_) continue;

        ElfW(Word) *raw = (ElfW(Word) *)(elf->bias_addr_ + dynamic->d_un.d_ptr);
        elf->bucket_count_ = raw[0];
        elf->bucket_ = raw + 2;
        elf->chain_ = elf->bucket_ + elf->bucket_count_;

        break;
      }
      case DT_GNU_HASH: {
        ElfW(Word) *raw = (ElfW(Word) *)(elf->bias_addr_ + dynamic->d_un.d_ptr);
        elf->bucket_count_ = raw[0];
        elf->sym_offset_ = raw[1];
        elf->bloom_size_ = raw[2];
        elf->bloom_shift_ = raw[3];
        elf->bloom_ = (ElfW(Addr) *)(raw + 4);
        elf->bucket_ = (uint32_t *)(elf->bloom_ + elf->bloom_size_);
        elf->chain_ = elf->bucket_ + elf->bucket_count_ - elf->sym_offset_;
        /* INFO: GNU hash is available when DT_GNU_HASH is parsed. */

        break;
      }
      default: break;
    }
  }


  if (0 != elf->rel_android_) {
    const char *rel = (const char *)elf->rel_android_;
    if (elf->rel_android_size_ < 4 || rel[0] != 'A' || rel[1] != 'P' || rel[2] != 'S' || rel[3] != '2')
      return false;

    elf->rel_android_ += 4;
    elf->rel_android_size_ -= 4;
  }

  return true;
}

bool elfutil_get_addr_protection(const struct elf_image *elf, uintptr_t addr, int *out_prot) {
  if (!elf || !out_prot || !elf->header_ || !elf->program_header_ || elf->header_->e_phnum == 0) return false;

  int prot = 0;
  bool found = false;
  uint64_t target = (uint64_t)addr;
  for (size_t i = 0; i < elf->header_->e_phnum; i++) {
    const ElfW(Phdr) *ph = &elf->program_header_[i];
    if (ph->p_type != PT_LOAD || ph->p_memsz == 0) continue;

    uint64_t seg_start = (uint64_t)elf->bias_addr_ + (uint64_t)ph->p_vaddr;
    uint64_t seg_end = seg_start + (uint64_t)ph->p_memsz;
    if (seg_end <= seg_start || target < seg_start || target >= seg_end) continue;

    if (ph->p_flags & PF_R) prot |= PROT_READ;
    if (ph->p_flags & PF_W) prot |= PROT_WRITE;
    if (ph->p_flags & PF_X) prot |= PROT_EXEC;
    found = true;

    break;
  }
  if (!found || prot == 0) return false;

  for (size_t i = 0; i < elf->header_->e_phnum; i++) {
    const ElfW(Phdr) *ph = &elf->program_header_[i];
    if (ph->p_type != PT_GNU_RELRO || ph->p_memsz == 0) continue;

    uint64_t relro_start = (uint64_t)elf->bias_addr_ + (uint64_t)ph->p_vaddr;
    uint64_t relro_end = relro_start + (uint64_t)ph->p_memsz;
    if (relro_end <= relro_start || target < relro_start || target >= relro_end) continue;

    prot &= ~PROT_WRITE;

    break;
  }

  *out_prot = prot;

  return true;
}

struct android_reloc_buffer {
  void *data;
  ElfW(Word) size;
};

/* INFO: Copyright ThePedroo 2025. CSOLoader code. Licensed under AGPL-3 */
static bool elfutil_unpack_android_relocs(const struct elf_image *elf, struct android_reloc_buffer *buffer) {
  if (!elf->rel_android_ || elf->rel_android_size_ == 0) return false;

  struct sleb128_decoder decoder;
  sleb128_decoder_init(&decoder, (const uint8_t *)elf->rel_android_, elf->rel_android_size_);

  uint64_t num_relocs = sleb128_decode(&decoder);
  if (num_relocs <= 0) return false;

  size_t out_index = 0;
  void *entries = calloc(num_relocs, elf->rel_android_is_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));
  if (!entries) {
    LOGE("Failed to allocate buffer for Android packed relocations");

    return false;
  }

  ElfW(Addr) current_offset = (ElfW(Addr))sleb128_decode(&decoder);

  for (uint64_t i = 0; i < num_relocs; ) {
    uint64_t group_size = sleb128_decode(&decoder);
    uint64_t group_flags = sleb128_decode(&decoder);

    size_t group_r_offset_delta = 0;

    const size_t RELOCATION_GROUPED_BY_INFO_FLAG = 1;
    const size_t RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
    const size_t RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
    const size_t RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;

    if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
      group_r_offset_delta = sleb128_decode(&decoder);
    }

    uint32_t sym_idx = 0;
    uint32_t type = 0;
    uint32_t r_addend = 0;

    if (group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) {
      ElfW(Addr) r_info = sleb128_decode(&decoder);
      sym_idx = ELF_R_SYM(r_info);
      type = ELF_R_TYPE(r_info);
    }

    size_t group_flags_reloc;
    if (elf->rel_android_is_rela_) {
      group_flags_reloc = group_flags & (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG);

      if (group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG) {
        /* INFO: Each relocation has an addend. This is the default situation
                    with lld's current encoder. */
      } else if (group_flags_reloc == (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG)) {
        r_addend += sleb128_decode(&decoder);
      } else {
        r_addend = 0;
      }
    } else {
      if (group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG)
        LOGF("REL relocations should not have addends, but found one in group %llu", (unsigned long long)i);
    }

    for (size_t j = 0; j < group_size; j++) {
      if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
        current_offset += group_r_offset_delta;
      } else {
        current_offset += sleb128_decode(&decoder);
      }
      if ((group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) == 0) {
        ElfW(Addr) r_info = sleb128_decode(&decoder);
        sym_idx = ELF_R_SYM(r_info);
        type = ELF_R_TYPE(r_info);
      }

      if (elf->rel_android_is_rela_ && group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG)
        r_addend += sleb128_decode(&decoder);

      if (elf->rel_android_is_rela_) {
        ElfW(Rela) *rela = (ElfW(Rela) *)entries;
        rela[out_index].r_offset = current_offset;
        rela[out_index].r_info = ELF_R_INFO(sym_idx, type);
        rela[out_index].r_addend = r_addend;
      } else {
        ElfW(Rel) *rel = (ElfW(Rel) *)entries;
        rel[out_index].r_offset = current_offset;
        rel[out_index].r_info = ELF_R_INFO(sym_idx, type);
      }
      out_index++;
    }

    i += group_size;
  }

  buffer->data = entries;
  buffer->size = out_index * (elf->rel_android_is_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));

  return true;
}

/* INFO: File-backed relocation tables used to avoid touching large in-memory
           mapped relocation areas during lookup. */
struct elfutil_file_relocs {
  uint8_t *data;
  size_t size;
  const ElfW(Sym) *dyn_sym;
  const char *dyn_str;
  ElfW(Word) dyn_str_size;
  const void *rel_plt;
  ElfW(Word) rel_plt_size;
  bool rel_plt_is_rela;
  const void *rel_dyn;
  ElfW(Word) rel_dyn_size;
  bool rel_dyn_is_rela;
  const void *rel_android;
  ElfW(Word) rel_android_size;
  bool rel_android_is_rela;
};

static void elfutil_free_file_relocs(struct elfutil_file_relocs *relocs) {
  if (!relocs) return;

  free(relocs->data);
  memset(relocs, 0, sizeof(*relocs));
}

/* INFO: Read the full ELF file into a private heap buffer for offline parsing. */
static bool elfutil_read_entire_file(const char *path, uint8_t **out_data, size_t *out_size) {
  int fd = -1;
  uint8_t *file_data = NULL;
  size_t file_size = 0;

  fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) goto fail;

  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size <= 0) goto fail;
  if ((uint64_t)st.st_size > SIZE_MAX) goto fail;

  file_size = (size_t)st.st_size;
  file_data = (uint8_t *)malloc(file_size);
  if (!file_data) goto fail;

  size_t total = 0;
  while (total < file_size) {
    ssize_t read_count = read(fd, file_data + total, file_size - total);
    if (read_count < 0) {
      if (errno == EINTR) continue;

      goto fail;
    }
    if (read_count == 0) goto fail;

    total += (size_t)read_count;
  }

  close(fd);

  *out_data = file_data;
  *out_size = file_size;

  return true;

fail:
  LOGE("Failed to read ELF file: %s", path ? path : "<null>");
  if (fd >= 0) close(fd);
  free(file_data);

  return false;
}

static const void *elfutil_file_vaddr_to_ptr(const uint8_t *file_data, size_t file_size, const ElfW(Phdr) *phdr, size_t phnum,
                                             ElfW(Addr) vaddr, size_t need_size) {
  if (!file_data || !phdr || phnum == 0 || need_size == 0) return NULL;

  for (size_t i = 0; i < phnum; i++) {
    const ElfW(Phdr) *p = &phdr[i];
    if (p->p_type != PT_LOAD || p->p_filesz == 0) continue;
    if (vaddr < p->p_vaddr) continue;

    uint64_t delta = (uint64_t)vaddr - (uint64_t)p->p_vaddr;
    if (delta > (uint64_t)p->p_filesz) continue;
    if ((uint64_t)need_size > (uint64_t)p->p_filesz - delta) continue;

    uint64_t file_off = (uint64_t)p->p_offset + delta;
    if (file_off > file_size) continue;
    if ((uint64_t)need_size > (uint64_t)file_size - file_off) continue;

    return file_data + file_off;
  }

  return NULL;
}

static void elfutil_set_file_reloc(const uint8_t *file_data, size_t file_size, const ElfW(Phdr) *phdr, size_t phnum,
                                    ElfW(Addr) dyn_ptr, size_t entry_size, const void **rel_ptr, bool *is_rela, bool rela_flag) {
  *rel_ptr = elfutil_file_vaddr_to_ptr(file_data, file_size, phdr, phnum, dyn_ptr, entry_size);
  *is_rela = rela_flag;
}

static bool elfutil_file_span_is_valid(const uint8_t *file_data, size_t file_size, const void *ptr, size_t span) {
  if (!ptr || span == 0) return false;

  uint64_t off = (uint64_t)((const uint8_t *)ptr - file_data);
  return off + span <= file_size;
}

static bool elfutil_load_file_relocs(const struct elf_image *elf, struct elfutil_file_relocs *out) {
  memset(out, 0, sizeof(*out));
  if (!elf || !elf->path_ || elf->path_[0] == '\0') return false;

  if (!elfutil_read_entire_file(elf->path_, &out->data, &out->size)) return false;
  if (out->size < sizeof(ElfW(Ehdr))) goto fail;

  const ElfW(Ehdr) *header = (const ElfW(Ehdr) *)out->data;
  if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) goto fail;

#ifdef __LP64__
  if (header->e_ident[EI_CLASS] != ELFCLASS64) goto fail;
#else
  if (header->e_ident[EI_CLASS] != ELFCLASS32) goto fail;
#endif
  if (header->e_ident[EI_DATA] != ELFDATA2LSB) goto fail;
  if (header->e_ident[EI_VERSION] != EV_CURRENT) goto fail;

  if (header->e_phoff == 0 || header->e_phnum == 0 || header->e_phentsize != sizeof(ElfW(Phdr))) goto fail;
  if ((uint64_t)header->e_phoff + ((uint64_t)header->e_phnum * sizeof(ElfW(Phdr))) > out->size) goto fail;

  const ElfW(Phdr) *phdr = (const ElfW(Phdr) *)(out->data + header->e_phoff);
  const ElfW(Dyn) *dynamic = NULL;
  size_t dynamic_count = 0;
  for (size_t i = 0; i < header->e_phnum; i++) {
    if (phdr[i].p_type != PT_DYNAMIC || phdr[i].p_filesz < sizeof(ElfW(Dyn))) continue;
    if ((uint64_t)phdr[i].p_offset + (uint64_t)phdr[i].p_filesz > out->size) continue;

    dynamic = (const ElfW(Dyn) *)(out->data + phdr[i].p_offset);
    dynamic_count = (size_t)(phdr[i].p_filesz / sizeof(ElfW(Dyn)));
    break;
  }
  if (!dynamic || dynamic_count == 0) goto fail;

  for (size_t i = 0; i < dynamic_count; i++) {
    const ElfW(Dyn) *d = &dynamic[i];
    if (d->d_tag == DT_NULL) break;

    switch (d->d_tag) {
      case DT_STRTAB: {
        out->dyn_str = (const char *)elfutil_file_vaddr_to_ptr(out->data, out->size, phdr, header->e_phnum, d->d_un.d_ptr, 1);

        break;
      }
      case DT_STRSZ: {
        out->dyn_str_size = d->d_un.d_val;

        break;
      }
      case DT_SYMTAB: {
        out->dyn_sym = (const ElfW(Sym) *)elfutil_file_vaddr_to_ptr(out->data, out->size, phdr, header->e_phnum, d->d_un.d_ptr, sizeof(ElfW(Sym)));

        break;
      }
      case DT_PLTREL: {
        out->rel_plt_is_rela = d->d_un.d_val == DT_RELA;

        break;
      }
      case DT_JMPREL: {
        out->rel_plt = elfutil_file_vaddr_to_ptr(out->data, out->size, phdr, header->e_phnum, d->d_un.d_ptr, 1);

        break;
      }
      case DT_PLTRELSZ: {
        out->rel_plt_size = d->d_un.d_val;

        break;
      }
      case DT_REL: {
        elfutil_set_file_reloc(out->data, out->size, phdr, header->e_phnum, d->d_un.d_ptr, sizeof(ElfW(Rel)), &out->rel_dyn, &out->rel_dyn_is_rela, false);

        break;
      }
      case DT_RELA: {
        elfutil_set_file_reloc(out->data, out->size, phdr, header->e_phnum, d->d_un.d_ptr, sizeof(ElfW(Rela)), &out->rel_dyn, &out->rel_dyn_is_rela, true);

        break;
      }
      case DT_RELSZ:
      case DT_RELASZ: {
        out->rel_dyn_size = d->d_un.d_val;

        break;
      }
      case DT_ANDROID_REL: {
        elfutil_set_file_reloc(out->data, out->size, phdr, header->e_phnum, d->d_un.d_ptr, 4, &out->rel_android, &out->rel_android_is_rela, false);

        break;
      }
      case DT_ANDROID_RELA: {
        elfutil_set_file_reloc(out->data, out->size, phdr, header->e_phnum, d->d_un.d_ptr, 4, &out->rel_android, &out->rel_android_is_rela, true);

        break;
      }
      case DT_ANDROID_RELSZ:
      case DT_ANDROID_RELASZ: {
        out->rel_android_size = d->d_un.d_val;

        break;
      }
      default: break;
    }
  }

  if (!elfutil_file_span_is_valid(out->data, out->size, out->rel_plt, out->rel_plt_size)) {
    out->rel_plt = NULL;
    out->rel_plt_size = 0;
  }

  if (!out->dyn_str || out->dyn_str_size == 0 || !elfutil_file_span_is_valid(out->data, out->size, out->dyn_str, out->dyn_str_size)) {
    out->dyn_str = NULL;
    out->dyn_str_size = 0;
  }

  if (!elfutil_file_span_is_valid(out->data, out->size, out->dyn_sym, sizeof(ElfW(Sym)))) {
    out->dyn_sym = NULL;
  }

  if (!elfutil_file_span_is_valid(out->data, out->size, out->rel_dyn, out->rel_dyn_size)) {
    out->rel_dyn = NULL;
    out->rel_dyn_size = 0;
  }

  if (elfutil_file_span_is_valid(out->data, out->size, out->rel_android, out->rel_android_size) &&
      out->rel_android_size >= 4 && memcmp(out->rel_android, "APS2", 4) == 0) {
    out->rel_android = (const uint8_t *)out->rel_android + 4;
    out->rel_android_size -= 4;
  } else {
    out->rel_android = NULL;
    out->rel_android_size = 0;
  }

  if (!out->rel_plt && !out->rel_dyn && !out->rel_android) goto fail;

  return true;

fail:
  LOGE("Failed to parse file-backed relocations for ELF: %s", elf && elf->path_ ? elf->path_ : "<null>");
  elfutil_free_file_relocs(out);

  return false;
}

static uint32_t elfutil_gnu_lookup(const struct elf_image *elf, const char *name) {
  static uint32_t bloom_mask_bits = sizeof(ElfW(Addr) *) * 8;
  static uint32_t initial_hash = 5381;
  static uint32_t hash_shift = 5;

  if (!elf->bucket_ || !elf->bucket_count_ || !elf->bloom_ || !elf->bloom_size_) return 0;

  uint32_t hash = initial_hash;
  for (int i = 0; name[i]; i++) {
    hash += (hash << hash_shift) + name[i];
  }

  uint32_t bloom_idx = (hash / bloom_mask_bits) % elf->bloom_size_;
  ElfW(Addr) bloom_word = elf->bloom_[bloom_idx];
  uintptr_t bit_lo = (uintptr_t)1 << (hash % bloom_mask_bits);
  uintptr_t bit_hi = (uintptr_t)1 << ((hash >> elf->bloom_shift_) % bloom_mask_bits);
  uintptr_t mask = bit_lo | bit_hi;
  if ((mask & bloom_word) != mask) return 0;

  uint32_t idx = elf->bucket_[hash % elf->bucket_count_];
  if (idx < elf->sym_offset_) return 0;

  const char *strings = elf->dyn_str_;
  while (true) {
    ElfW(Sym) *sym = elf->dyn_sym_ + idx;
    if (((elf->chain_[idx] ^ hash) >> 1) == 0 && strcmp(name, strings + sym->st_name) == 0) {
      return idx;
    }

    if (elf->chain_[idx] & 1) break;

    idx++;
  }

  return 0;
}

static uint32_t elfutil_elf_lookup(const struct elf_image *elf, const char *name) {
  static uint32_t hash_mask = 0xf0000000;
  static uint32_t hash_shift = 24;
  uint32_t hash = 0;
  uint32_t tmp;

  if (!elf->bucket_ || elf->bloom_) return 0;

  for (int i = 0; name[i]; i++) {
    hash = (hash << 4) + name[i];
    tmp = hash & hash_mask;
    hash ^= tmp;
    hash ^= tmp >> hash_shift;
  }

  const char *strings = elf->dyn_str_;
  for (int idx = elf->bucket_[hash % elf->bucket_count_]; idx != 0; idx = elf->chain_[idx]) {
    ElfW(Sym) *sym = elf->dyn_sym_ + idx;
    if (strcmp(name, strings + sym->st_name) == 0) {
      return idx;
    }
  }

  return 0;
}

static uint32_t elfutil_linear_lookup(const struct elf_image *elf, const char *name) {
  if (!elf->dyn_sym_ || !elf->sym_offset_) return 0;

  for (uint32_t idx = 0; idx < elf->sym_offset_; idx++) {
    ElfW(Sym) *sym = elf->dyn_sym_ + idx;

    if (strcmp(name, elf->dyn_str_ + sym->st_name) == 0) return idx;
  }

  return 0;
}

struct elfutil_symbol_match {
  bool is_prefix;
  uint32_t idx;
  const char *prefix;
  size_t prefix_len;
};

static bool elfutil_append_addr(uintptr_t **res, size_t *res_size, uintptr_t addr) {
  uintptr_t *new_res = (uintptr_t *)realloc(*res, (*res_size + 1) * sizeof(uintptr_t));
  if (!new_res) {
    LOGE("Failed to allocate memory for PLT addresses");

    free(*res);
    *res = NULL;
    *res_size = 0;

    return false;
  }

  *res = new_res;
  (*res)[*res_size] = addr;
  (*res_size)++;

  return true;
}

static bool elfutil_symbol_matches(const struct elf_image *elf, const struct elfutil_symbol_match *match, uint32_t r_sym) {
  if (!match->is_prefix) return r_sym == match->idx;
  if (!elf->dyn_sym_ || !elf->dyn_str_) return false;

  ElfW(Sym) *sym = elf->dyn_sym_ + r_sym;
  if (sym->st_name == 0) return false;

  return strncmp(elf->dyn_str_ + sym->st_name, match->prefix, match->prefix_len) == 0;
}

static void elfutil_collect_relocs(const struct elf_image *elf, const struct elfutil_symbol_match *match,
                                   const void *rel_ptr, const ElfW(Word) rel_size,
                                   bool is_rela, bool is_plt, bool stop_on_first_match,
                                   uintptr_t **res, size_t *res_size) {
  if (!rel_ptr || rel_size == 0) return;
  const void *rel_end = (const void *)((uintptr_t)rel_ptr + rel_size);
  size_t rel_entry_size = is_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
  for (const char *entry = (const char *)rel_ptr; entry < (const char *)rel_end; entry += rel_entry_size) {
    ElfW(Xword) r_info = is_rela ? ((const ElfW(Rela) *)entry)->r_info : ((const ElfW(Rel) *)entry)->r_info;
    ElfW(Addr) r_offset = is_rela ? ((const ElfW(Rela) *)entry)->r_offset : ((const ElfW(Rel) *)entry)->r_offset;
    uint32_t r_sym = ELF_R_SYM(r_info);
    uint32_t r_type = ELF_R_TYPE(r_info);

    if (!elfutil_symbol_matches(elf, match, r_sym)) continue;
    if (is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) continue;
    if (!is_plt && (r_type != ELF_R_GENERIC_ABS && r_type != ELF_R_GENERIC_GLOB_DAT)) continue;

    uintptr_t addr = elf->bias_addr_ + r_offset;
    if (addr <= elf->base_addr_) continue;

    if (!elfutil_append_addr(res, res_size, addr)) return;
    if (stop_on_first_match) break;
  }
}

static void elfutil_collect_android_relocs(const struct elf_image *elf, const struct elfutil_symbol_match *match,
                                           ElfW(Addr) rel_android, ElfW(Word) rel_android_size, bool rel_android_is_rela,
                                           uintptr_t **res, size_t *res_size) {
  if (!rel_android || rel_android_size == 0) return;

  struct elf_image android_elf = { 0 };
  android_elf.rel_android_ = rel_android;
  android_elf.rel_android_size_ = rel_android_size;
  android_elf.rel_android_is_rela_ = rel_android_is_rela;

  struct android_reloc_buffer android_buffer = { 0 };
  if (!elfutil_unpack_android_relocs(&android_elf, &android_buffer)) return;

  elfutil_collect_relocs(elf, match, android_buffer.data, android_buffer.size, rel_android_is_rela, false, false, res, res_size);
  free(android_buffer.data);
}

static void elfutil_collect_non_plt(const struct elf_image *elf, const struct elfutil_symbol_match *match,
                                    uintptr_t **res, size_t *res_size) {
  elfutil_collect_relocs(elf, match, (void *)elf->rel_dyn_, elf->rel_dyn_size_, elf->rel_dyn_is_rela_, false, false, res, res_size);
  elfutil_collect_android_relocs(elf, match, elf->rel_android_, elf->rel_android_size_, elf->rel_android_is_rela_, res, res_size);
}

static size_t elfutil_internal_find_plt_addr(const struct elf_image *elf, const char *name_or_prefix, bool by_prefix, uintptr_t **out_addrs) {
  *out_addrs = NULL;

  struct elfutil_symbol_match match = { 0 };
  if (by_prefix) {
    match.is_prefix = true;
    match.prefix = name_or_prefix;
    match.prefix_len = strlen(name_or_prefix);
  } else {
    uint32_t idx = elfutil_gnu_lookup(elf, name_or_prefix);
    if (!idx) idx = elfutil_elf_lookup(elf, name_or_prefix);
    if (!idx) idx = elfutil_linear_lookup(elf, name_or_prefix);
    if (!idx) return 0;

    match.is_prefix = false;
    match.idx = idx;
  }

  size_t count = 0;
  uintptr_t *res = NULL;

  struct elfutil_file_relocs file_relocs = { 0 };
  if (elfutil_load_file_relocs(elf, &file_relocs)) {
    const struct elf_image *scan_elf = elf;
    struct elf_image file_scan_elf = { 0 };
    if (by_prefix) {
      if (!file_relocs.dyn_sym || !file_relocs.dyn_str) {
        elfutil_free_file_relocs(&file_relocs);

        goto fallback;
      }

      file_scan_elf = *elf;
      file_scan_elf.dyn_sym_ = (ElfW(Sym) *)file_relocs.dyn_sym;
      file_scan_elf.dyn_str_ = file_relocs.dyn_str;
      scan_elf = &file_scan_elf;
    }

    elfutil_collect_relocs(scan_elf, &match, file_relocs.rel_plt, file_relocs.rel_plt_size, file_relocs.rel_plt_is_rela, true, !by_prefix, &res, &count);
    elfutil_collect_relocs(scan_elf, &match, file_relocs.rel_dyn, file_relocs.rel_dyn_size, file_relocs.rel_dyn_is_rela, false, false, &res, &count);
    elfutil_collect_android_relocs(scan_elf, &match, (ElfW(Addr))file_relocs.rel_android, file_relocs.rel_android_size, file_relocs.rel_android_is_rela, &res, &count);
    elfutil_free_file_relocs(&file_relocs);

    *out_addrs = res;

    return count;
  }
  elfutil_free_file_relocs(&file_relocs);

fallback:
  elfutil_collect_relocs(elf, &match, (void *)elf->rel_plt_, elf->rel_plt_size_, elf->rel_plt_is_rela_, true, !by_prefix, &res, &count);
  elfutil_collect_non_plt(elf, &match, &res, &count);

  *out_addrs = res;

  return count;
}

size_t elfutil_find_plt_addr(const struct elf_image *elf, const char *name, uintptr_t **out_addrs) {
  return elfutil_internal_find_plt_addr(elf, name, false, out_addrs);
}

size_t elfutil_find_plt_addr_by_prefix(const struct elf_image *elf, const char *name_prefix, uintptr_t **out_addrs) {
  return elfutil_internal_find_plt_addr(elf, name_prefix, true, out_addrs);
}

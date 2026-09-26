/* tests/test_elf_hardening.c -- the built daemon's ELF hardening
 * (audit 2026-08-29 finding 9).
 *
 * Both properties here are the kind that regress silently:
 *
 *   - PT_GNU_STACK: a SINGLE .asm file without a `.note.GNU-stack` section
 *     makes the linker mark the whole program's stack executable. Adding an
 *     assembly file is routine in this tree, so without a check the next one
 *     quietly re-enables it and nothing fails.
 *   - BIND_NOW: the link flag lives in the Makefile, which is not a
 *     prerequisite of the binary -- so editing it does not even force a
 *     relink. (That is not hypothetical: the first attempt at this fix
 *     reported success against a stale binary.)
 *
 * The ELF headers are parsed directly rather than shelling out to readelf, so
 * the test does not depend on binutils being installed or on its output format.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef __APPLE__
/* ---- the Mac build: the same two regressions, in Mach-O terms ----------
 *   executable stack  -> the MH_ALLOW_STACK_EXECUTION header flag must be
 *                        clear (and the image must be PIE);
 *   BIND_NOW / RELRO  -> no lazy binding (chained fixups bind every import at
 *                        load; with classic dyld info, lazy_bind_size must be
 *                        0), and the fixed-up pointers live in a __DATA_CONST
 *                        segment flagged SG_READ_ONLY, which dyld makes
 *                        read-only once fixups are done. */
#include <mach-o/loader.h>
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
int main(int argc, char** argv){
    const char* path = argc > 1 ? argv[1] : "daemon/bmcbitcoind";
    FILE* f = fopen(path, "rb");
    if (!f){ printf("  FAIL cannot open %s\n", path); return 1; }
    if (fseek(f, 0, SEEK_END)) { fclose(f); return 1; }
    long sz = ftell(f); rewind(f);
    unsigned char* b = malloc((size_t)sz);
    if (!b || fread(b, 1, (size_t)sz, f) != (size_t)sz){ printf("  FAIL read %s\n", path); fclose(f); return 1; }
    fclose(f);
    const struct mach_header_64* mh = (const struct mach_header_64*)b;
    if (sz < (long)sizeof *mh || mh->magic != MH_MAGIC_64){ printf("  FAIL %s is not a thin 64-bit Mach-O\n", path); return 1; }

    printf("== the stack is not executable ==\n");
    ck("MH_ALLOW_STACK_EXECUTION is NOT set", !(mh->flags & MH_ALLOW_STACK_EXECUTION));
    ck("  and the image is position independent (MH_PIE)", (mh->flags & MH_PIE) != 0);

    printf("== relocations are read-only and bound at load ==\n");
    int chained = 0, dyldinfo = 0, lazy = 0, dconst = 0, dconst_ro = 0;
    const unsigned char* p = b + sizeof *mh;
    for (uint32_t i = 0; i < mh->ncmds && p + sizeof(struct load_command) <= b + sz; i++){
        const struct load_command* lc = (const struct load_command*)p;
        if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) chained = 1;
        if (lc->cmd == LC_DYLD_INFO || lc->cmd == LC_DYLD_INFO_ONLY){
            dyldinfo = 1;
            if (((const struct dyld_info_command*)lc)->lazy_bind_size) lazy = 1;
        }
        if (lc->cmd == LC_SEGMENT_64){
            const struct segment_command_64* sg = (const struct segment_command_64*)lc;
            if (!strncmp(sg->segname, "__DATA_CONST", 16)){ dconst = 1; if (sg->flags & SG_READ_ONLY) dconst_ro = 1; }
        }
        if (!lc->cmdsize) break;
        p += lc->cmdsize;
    }
    ck("every import is bound at load: chained fixups, or no lazy-bind info (the BIND_NOW analogue)",
       chained || (dyldinfo && !lazy));
    ck("a __DATA_CONST segment exists", dconst);
    ck("  and is SG_READ_ONLY, read-only after fixups (the RELRO analogue)", dconst_ro);

    free(b);
    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
#else
#include <elf.h>

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

int main(int argc, char** argv){
    const char* path = argc > 1 ? argv[1] : "daemon/bmcbitcoind";
    FILE* f = fopen(path, "rb");
    if (!f){ printf("  FAIL cannot open %s\n", path); return 1; }
    if (fseek(f, 0, SEEK_END)) { fclose(f); return 1; }
    long sz = ftell(f);
    rewind(f);
    unsigned char* b = malloc((size_t)sz);
    if (!b || fread(b, 1, (size_t)sz, f) != (size_t)sz){ printf("  FAIL read %s\n", path); fclose(f); return 1; }
    fclose(f);

    if (memcmp(b, ELFMAG, SELFMAG) || b[EI_CLASS] != ELFCLASS64){
        printf("  FAIL %s is not a 64-bit ELF\n", path); return 1; }

    Elf64_Ehdr* eh = (Elf64_Ehdr*)b;
    Elf64_Phdr* ph = (Elf64_Phdr*)(b + eh->e_phoff);

    printf("== the stack is not executable ==\n");
    { int found = 0, exec = 0;
      for (int i = 0; i < eh->e_phnum; i++)
          if (ph[i].p_type == PT_GNU_STACK){ found = 1; exec = (ph[i].p_flags & PF_X) != 0; }
      ck("PT_GNU_STACK is present", found);
      ck("  and does NOT carry PF_X", found && !exec);
      if (found && exec)
          printf("        an .asm file is missing `section .note.GNU-stack`\n"); }

    printf("== relocations are read-only and bound at load ==\n");
    { int relro = 0;
      for (int i = 0; i < eh->e_phnum; i++) if (ph[i].p_type == PT_GNU_RELRO) relro = 1;
      ck("PT_GNU_RELRO is present", relro);

      /* walk the dynamic section for DT_FLAGS/DT_FLAGS_1 */
      int now = 0, have_dyn = 0;
      for (int i = 0; i < eh->e_phnum; i++){
          if (ph[i].p_type != PT_DYNAMIC) continue;
          have_dyn = 1;
          Elf64_Dyn* d = (Elf64_Dyn*)(b + ph[i].p_offset);
          for (; d->d_tag != DT_NULL; d++){
              if (d->d_tag == DT_FLAGS   && (d->d_un.d_val & DF_BIND_NOW)) now = 1;
              if (d->d_tag == DT_FLAGS_1 && (d->d_un.d_val & DF_1_NOW))    now = 1;
              if (d->d_tag == DT_BIND_NOW) now = 1;
          }
      }
      ck("the binary has a dynamic section", have_dyn);
      ck("  and is marked BIND_NOW (full RELRO)", now);
      if (have_dyn && !now)
          printf("        HARDENFLAGS did not reach the link -- note the Makefile is\n"
                 "        not a prerequisite, so a stale binary can mask this\n"); }

    free(b);
    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
#endif

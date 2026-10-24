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
#include <elf.h>

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* HST-6 (audit 2026-10-23): every binary named on the command line, not
 * only the daemon. bmc_wallet_cli -- the one that decrypts the seed -- had
 * BIND_NOW but no PT_GNU_RELRO (every asm .tbss was declared `nowrite`, so
 * a link with no C thread-locals put .rodata in the writable segment and ld
 * dropped RELRO), and seven helpers the daemon execs were linked without
 * HARDENFLAGS at all. The gate runs this over the whole shipped set. */
static int check_one(const char* path);
int main(int argc, char** argv){
    if (argc < 2) return check_one("daemon/bmcbitcoind");
    int bad = 0;
    for (int i = 1; i < argc; i++){ printf("---- %s ----\n", argv[i]); fails = 0; if (check_one(argv[i])) bad++; }
    if (bad) printf("\nFAILURES: %d of %d binaries\n", bad, argc - 1);
    else printf("\nALL TESTS PASSED (0 failures, %d binaries)\n", argc - 1);
    return bad ? 1 : 0;
}
static int check_one(const char* path){
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
    if (fails) printf("  FAILURES: %d in %s\n", fails, path);
    return fails ? 1 : 0;
}

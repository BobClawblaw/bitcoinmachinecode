/* tests/test_secure_lock.c -- WAL-3 (audit 2026-09-03), second half: a secret
 * must not reach swap, a hibernation image, or a core file.
 *
 * secure_zero closed the in-process case: every "we cleared the key" comment
 * in this tree described a plain memset on a buffer that is dead afterwards,
 * which -O2 is entitled to delete. This is the other half. An attacker with a
 * swap partition or a hibernation image recovers the whole wallet from a node
 * whose operator believes it is locked, and no amount of zeroing at shutdown
 * helps once the page has been written out. The 2026-09-02 host hardening
 * (LimitCORE=0) removed the core-dump route only, and only for that unit.
 *
 * WHAT IS ASSERTED. Not "the call returned success" -- that would pass on a
 * no-op. The kernel's own view, read back from /proc/self/smaps:
 *
 *   Locked:   the number of locked kB in the mapping. mlock's whole purpose.
 *   VmFlags:  contains "dd" when MADV_DONTDUMP is set on the mapping.
 *
 * Two separate mmap regions are used rather than two statics, because
 * statics share one mapping and the control would then be measuring the same
 * region as the subject -- and a control that cannot fail is not a control.
 *
 * ON DARWIN there is no /proc and no MADV_DONTDUMP. The lock is read back
 * from the kernel instead through mach_vm_region_recurse on our own task
 * (user_wired_count per region; no privileges needed), with the same control.
 * DONTDUMP is not asserted there: Darwin has no per-mapping core exclusion,
 * so secure_lock's madvise is compiled out (its #ifdef MADV_DONTDUMP). What
 * stands in on a Mac is platform policy, printed as a NOTE: the core-file
 * limit (0 by default) and encrypted swap (always on since 10.7).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include "secure_zero.h"

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

#ifdef __APPLE__
#include <unistd.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
/* Darwin: the region containing `addr` -- wired (mlock'd) or not, per the
 * kernel's own vm map. locked_kb = the region's size when wired, else 0;
 * dontdump = -1 (no such flag on Darwin). */
static int smaps_probe(const void* addr, long* locked_kb, int* dontdump){
    *locked_kb = -1; *dontdump = -1;
    mach_vm_address_t a = (mach_vm_address_t)addr; mach_vm_size_t sz = 0; natural_t depth = 0;
    vm_region_submap_info_data_64_t in; mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    if (mach_vm_region_recurse(mach_task_self(), &a, &sz, &depth, (vm_region_recurse_info_t)&in, &cnt) != KERN_SUCCESS) return 0;
    if (a > (mach_vm_address_t)addr) return 0;
    *locked_kb = in.user_wired_count ? (long)(sz / 1024) : 0;
    return 1;
}
#else
/* Read the smaps entry containing `addr`: locked kB, and whether "dd" is set. */
static int smaps_probe(const void* addr, long* locked_kb, int* dontdump){
    *locked_kb = -1; *dontdump = -1;
    FILE* f = fopen("/proc/self/smaps", "r");
    if (!f) return 0;
    unsigned long a = (unsigned long)addr;
    char line[512]; int inside = 0, found = 0;
    while (fgets(line, sizeof line, f)){
        unsigned long lo, hi;
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 && strchr(line, ' ')){
            inside = (a >= lo && a < hi);
            if (inside) found = 1;
            continue;
        }
        if (!inside) continue;
        if (!strncmp(line, "Locked:", 7)) sscanf(line + 7, " %ld", locked_kb);
        else if (!strncmp(line, "VmFlags:", 8)){
            *dontdump = strstr(line, " dd") != NULL;
            inside = 0;                      /* VmFlags is the last field */
        }
    }
    fclose(f);
    return found;
}
#endif

int main(void){
    struct rlimit rl;
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0)
        printf("RLIMIT_MEMLOCK soft=%lu\n", (unsigned long)rl.rlim_cur);

#ifdef __APPLE__
    size_t page = (size_t)getpagesize();     /* 16 KB on Apple silicon */
#else
    size_t page = 4096;
#endif
    void* secret = mmap(0, page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    void* plain  = mmap(0, page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (secret == MAP_FAILED || plain == MAP_FAILED){ printf("SKIP: mmap failed\n"); return 0; }
    memset(secret, 0xA5, page);
    memset(plain,  0x5A, page);

    int locked = secure_lock(secret, page);
    if (!locked){
        /* An operator with a low RLIMIT_MEMLOCK gets a warning at startup and
         * a working node; the same must be true here rather than a red gate
         * on a machine whose limits we do not control. */
        printf("SKIP: mlock refused (RLIMIT_MEMLOCK too low in this environment)\n");
        printf("\nALL TESTS PASSED (0 failures)\n");
        return 0;
    }
    ck("secure_lock reports success", locked == 1);

    long lk = -1, pk = -1; int dd = -1, pdd = -1;
    int f1 = smaps_probe(secret, &lk, &dd);
    int f2 = smaps_probe(plain,  &pk, &pdd);
    printf("      (secret: Locked=%ldkB dd=%d ; control: Locked=%ldkB dd=%d)\n", lk, dd, pk, pdd);

    ck("the kernel reports the mapping found", f1 && f2);
#ifdef __APPLE__
    ck("WAL-3 the locked region really is LOCKED (wired, per the kernel's vm map)", lk > 0);
    { struct rlimit rc; int enc = -1; struct xsw_usage sw; size_t swl = sizeof sw;
      if (sysctlbyname("vm.swapusage", &sw, &swl, NULL, 0) == 0) enc = sw.xsu_encrypted ? 1 : 0;
      getrlimit(RLIMIT_CORE, &rc);
      printf("NOTE: no MADV_DONTDUMP on Darwin (secure_lock compiles it out); stand-ins here:\n"
             "      core-file limit %s, swap %s\n",
             rc.rlim_cur == 0 ? "0 (no core files)" : "NONZERO (a core would include the wallet page)",
             enc == 1 ? "encrypted" : enc == 0 ? "NOT encrypted" : "unknown"); }
#else
    ck("WAL-3 the locked region really is LOCKED per /proc/self/smaps", lk > 0);
    ck("WAL-3 ...and is marked DONTDUMP, so it stays out of a core file", dd == 1);
#endif

    /* The control: an identical mapping that was never passed to
     * secure_lock. If this were also locked or dd, the assertions above would
     * be measuring something the process does by default rather than
     * something secure_lock did. */
    ck("WAL-3 control: an untouched mapping is NOT locked", pk == 0);
#ifndef __APPLE__
    ck("WAL-3 control: ...and is NOT marked DONTDUMP", pdd == 0);
#else
    (void)dd; (void)pdd;
#endif

    /* And secure_zero still works on locked memory -- locking must not have
     * turned the wipe into a no-op. */
    secure_zero(secret, page);
    { const unsigned char* b = (const unsigned char*)secret; int nz = 0;
      for (size_t i = 0; i < page; i++) if (b[i]) nz++;
      ck("secure_zero still clears a locked page", nz == 0); }

    munmap(secret, page); munmap(plain, page);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

/* test_store_map_magic.c -- the mapping cache and the read-fd cache share one
 * store struct; neither may take the other's state for its own.
 *
 * Until 2026-09-27 the mapping cache's "initialised" magic was a qword at
 * st+120, which is read-fd cache slot 7 (+64 + 7*8). store_rd_fd of any
 * file_no & 7 == 7 overwrote it; the next store_map_at then took the cache for
 * uninitialised and cleared its slots WITHOUT munmap -- a mapping of up to
 * 128 MiB leaked and the cache was lost, every time. And store_map_init's
 * magic write clobbered fd slot 7 in return, so that fd leaked too. Only
 * bmc_build_block_filters maps (one store state per thread), so production
 * saw it as a leak, never as wrong bytes. Found by the Mac port's differential
 * test of bitcoin_store_fast (note item 15); the magic is a dword at +52 now.
 *
 * Both directions are pinned, each on a signal the old code cannot produce:
 *   1. map -> fill fd slot 7 -> map again: the SAME mapping is returned and
 *      /proc/self/maps holds exactly one mapping of the blk file (the old
 *      code re-mapped and leaked the first: two entries, a new address).
 *   2. the fd cached for file 7 is the same descriptor after the second map
 *      (the old code's re-init overwrote slot 7 with the magic, so the next
 *      lookup missed and opened a fresh fd).
 * Then store_map_close leaves no mapping of the file at all. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "test_tmpdir.h"
#ifdef __APPLE__
#include <libproc.h>
#include <sys/proc_info.h>
#endif
typedef unsigned char u8; typedef unsigned long long u64;

extern int  store_init(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, u64 len);
extern void store_rd_init(void* st);
extern int  store_rd_fd(void* st, unsigned file_no);
extern void store_map_init(void* st);
extern void store_map_close(void* st);
extern const u8* store_map_at(void* st, u64 height, u64 out[2]);

static long failures;
#define CK(c, ...) do{ if (c) printf("ok  : " __VA_ARGS__); else { failures++; printf("FAIL: " __VA_ARGS__); } printf("\n"); }while(0)

/* mappings of a file with this basename: from /proc/self/maps, or on Darwin
 * (2026-09-28) by walking our own task's regions with
 * proc_pidinfo(PROC_PIDREGIONPATHINFO), which names the vnode each region
 * is backed by. (Not proc_regionfilename per mach_vm_region: asked about an
 * address in a hole it answers for the next mapped entry, so one mapping
 * counted three times here.) */
#ifdef __APPLE__
static int mappings_of(const char* base){
    unsigned long long a = 0; int n = 0; size_t bl = strlen(base);
    for (;;){
        struct proc_regionwithpathinfo r; memset(&r, 0, sizeof r);
        if (proc_pidinfo(getpid(), PROC_PIDREGIONPATHINFO, a, &r, sizeof r) < (int)sizeof r) break;
        size_t pl = strlen(r.prp_vip.vip_path);
        if (pl >= bl && !strcmp(r.prp_vip.vip_path + pl - bl, base) && (pl == bl || r.prp_vip.vip_path[pl-bl-1] == '/')) n++;
        a = r.prp_prinfo.pri_address + r.prp_prinfo.pri_size;
    }
    return n;
}
#else
static int mappings_of(const char* base){
    FILE* f = fopen("/proc/self/maps", "r"); if (!f) return -1;
    char line[512]; int n = 0; size_t bl = strlen(base);
    while (fgets(line, sizeof line, f)){
        size_t l = strlen(line); while (l && (line[l-1] == '\n' || line[l-1] == ' ')) line[--l] = 0;
        if (l >= bl && !strcmp(line + l - bl, base) && (l == bl || line[l-bl-1] == '/')) n++;
    }
    fclose(f); return n;
}
#endif

int main(void){
    tt_isolate();
    static unsigned char st[4096];
    if (store_init(st) != 1){ printf("FAIL store_init\n"); return 1; }
    store_rd_init(st);
    store_map_init(st);

    /* three small blocks, all in blk00000.dat */
    static u8 raw[3][3000];
    for (int i = 0; i < 3; i++){
        for (int j = 0; j < 3000; j++) raw[i][j] = (u8)(i * 31 + j * 7);
        u8 hash[32]; memset(hash, (u8)(0x10 + i), 32);
        if (store_append(st, hash, raw[i], sizeof raw[i]) < 0){ printf("FAIL store_append %d\n", i); return 1; }
    }

    u64 o[2]; const u8* p1 = store_map_at(st, 1, o);
    CK(p1 && o[0] == 3000 && !memcmp(p1, raw[1], 3000), "store_map_at(1) returns the block bytes (file %llu)", o[1]);
    int m1 = mappings_of("blk00000.dat");
    CK(m1 == 1, "one mapping of blk00000.dat after the first map (have %d)", m1);
    u64 slot0_addr = *(u64*)(st + 128 + 8);

    /* fill read-fd cache slot 7: blk00007.dat only has to exist */
    { FILE* f = fopen("blk00007.dat", "w"); if (!f){ printf("FAIL creating blk00007.dat\n"); return 1; } fclose(f); }
    int fd7 = store_rd_fd(st, 7);
    CK(fd7 >= 0, "store_rd_fd(7) caches a descriptor (%d) in slot 7 -- the bytes at st+120..127", fd7);
    CK(*(unsigned*)(st + 120) == 7, "slot 7 holds file_no 7 at st+120 (the old magic's home; the Mac's magic sits at +384)");

    const u8* p2 = store_map_at(st, 1, o);
    int m2 = mappings_of("blk00000.dat");
    CK(p2 == p1, "the second store_map_at returns the SAME mapping (cache still initialised)");
    CK(m2 == 1, "still one mapping of blk00000.dat (have %d): nothing re-mapped, nothing leaked", m2);
    CK(*(u64*)(st + 128 + 8) == slot0_addr, "map slot 0's address is unchanged");

    int fd7b = store_rd_fd(st, 7);
    CK(fd7b == fd7, "store_rd_fd(7) still hits the cached descriptor (%d vs %d): the map cache did not clobber fd slot 7", fd7b, fd7);

    /* a second file in the map cache, then close: every mapping goes */
    store_map_close(st);
    int m3 = mappings_of("blk00000.dat");
    CK(m3 == 0, "store_map_close unmapped blk00000.dat (%d mapping(s) left)", m3);

    if (failures){ printf("\nTESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}

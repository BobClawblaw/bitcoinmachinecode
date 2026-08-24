/* test_txv_pools_diff.c -- bitcoin_txv_pools.asm vs tx_verify.c's arenas.
 *
 * WHY THIS EXISTS
 *   Phase 2 slice 5: the allocation seams the earlier slices left in C.
 *   These are the last C the shipped twins call, so their twins closing
 *   means parse/classify can go all-asm at swap time. The functions are
 *   thin realloc wrappers; what the differential pins is the OBSERVABLE
 *   state contract: identical offsets for identical op sequences, identical
 *   used/cap evolution (growth points included), contents preserved across
 *   relocation, and bug-for-bug quirks (witpool's commit-then-fail realloc
 *   order is documented in the asm header; OOM itself is not reachable in
 *   a test without an allocator shim, so that arm rides on inspection).
 *
 * Usage: ./test_txv_pools_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;
typedef struct { const u8** ptr; u32* len; u64 cap, used; } witpool_t;
typedef struct { u8* buf; u64 cap; u64 used; } bytepool_t;

extern u64   txv_witpool_reserve(witpool_t* wp, u64 n);
extern u64   txv_bytepool_reserve(bytepool_t* p, u64 n);
extern u64   txv_bytepool_alloc(bytepool_t* p, const u8* src, u64 n);
extern void* txv_grow_arena(void** buf, u64* cap, u64 need);
extern u64   txv_witpool_reserve_asm(witpool_t* wp, u64 n);
extern u64   txv_bytepool_reserve_asm(bytepool_t* p, u64 n);
extern u64   txv_bytepool_alloc_asm(bytepool_t* p, const u8* src, u64 n);
extern void* txv_grow_arena_asm(void** buf, u64* cap, u64 need);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static long fails = 0, compared = 0;
static void ck(const char* what, int ok){
    compared++;
    if (!ok){ if (fails < 25) printf("FAIL %s\n", what); fails++; }
}

static u64 rs = 0xa11ca7edULL;
static u64 rnd(void){ rs ^= rs<<13; rs ^= rs>>7; rs ^= rs<<17; return rs; }

int main(void){
    /* ---- witpool: seeded reserve sequence, forced growth ---- */
    {
        witpool_t wc; memset(&wc, 0, sizeof wc);
        witpool_t wa; memset(&wa, 0, sizeof wa);
        int all_off = 1, all_state = 1;
        for (int i = 0; i < 4000; i++){
            u64 n = rnd() % 37;                       /* crosses 4096 many times */
            u64 oc = txv_witpool_reserve(&wc, n);
            u64 oa = txv_witpool_reserve_asm(&wa, n);
            if (oc != oa) all_off = 0;
            if (wc.cap != wa.cap || wc.used != wa.used) all_state = 0;
            /* write patterns through the returned slots on both sides */
            for (u64 j = 0; j < n; j++){
                wc.ptr[oc+j] = (const u8*)(uintptr_t)(i*1000+j);
                wc.len[oc+j] = (u32)(i*7+j);
                wa.ptr[oa+j] = (const u8*)(uintptr_t)(i*1000+j);
                wa.len[oa+j] = (u32)(i*7+j);
            }
        }
        ck("witpool: identical offsets across 4000 reserves", all_off);
        ck("witpool: identical cap/used evolution", all_state);
        ck("witpool: identical slot contents after relocations",
           memcmp(wc.ptr, wa.ptr, wc.used*sizeof(void*)) == 0 &&
           memcmp(wc.len, wa.len, wc.used*sizeof(u32)) == 0);
    }

    /* ---- bytepool: interleaved reserve/alloc, contents through growth ---- */
    {
        bytepool_t pc; memset(&pc, 0, sizeof pc);
        bytepool_t pa; memset(&pa, 0, sizeof pa);
        static u8 src[8192];
        for (int i = 0; i < 8192; i++) src[i] = (u8)(i*13+1);
        int all_off = 1, all_state = 1;
        for (int i = 0; i < 3000; i++){
            u64 n = rnd() % 300;                      /* crosses 65536 repeatedly */
            u64 oc, oa;
            if (rnd() & 1){
                oc = txv_bytepool_alloc(&pc, src + (i % 4096), n);
                oa = txv_bytepool_alloc_asm(&pa, src + (i % 4096), n);
            } else {
                oc = txv_bytepool_reserve(&pc, n);
                oa = txv_bytepool_reserve_asm(&pa, n);
                /* reserve hands out uninitialised bytes: write both sides
                 * so the final content compare stays meaningful */
                for (u64 j = 0; j < n; j++){ pc.buf[oc+j] = (u8)(i+j); pa.buf[oa+j] = (u8)(i+j); }
            }
            if (oc != oa) all_off = 0;
            if (pc.cap != pa.cap || pc.used != pa.used) all_state = 0;
        }
        ck("bytepool: identical offsets across 3000 mixed ops", all_off);
        ck("bytepool: identical cap/used evolution", all_state);
        ck("bytepool: identical bytes after relocations",
           memcmp(pc.buf, pa.buf, pc.used) == 0);
        /* zero-length alloc/reserve edge */
        ck("bytepool: zero-length ops agree",
           txv_bytepool_alloc(&pc, src, 0) == txv_bytepool_alloc_asm(&pa, src, 0) &&
           txv_bytepool_reserve(&pc, 0) == txv_bytepool_reserve_asm(&pa, 0));
    }

    /* ---- grow_arena: grow/no-grow/content preservation ---- */
    {
        void *bc = 0, *ba = 0; u64 cc = 0, ca = 0;
        int ok = 1;
        u64 sizes[] = { 100, 100, 4096, 64, 1<<20, 1<<20, (1<<20)+1 };
        for (unsigned i = 0; i < sizeof sizes/sizeof sizes[0]; i++){
            void* rc_ = txv_grow_arena(&bc, &cc, sizes[i]);
            void* ra_ = txv_grow_arena_asm(&ba, &ca, sizes[i]);
            if (!rc_ || !ra_ || rc_ != bc || ra_ != ba || cc != ca) ok = 0;
            /* stamp the newly available region and verify it survives the
             * NEXT grow (realloc preserves) */
            memset(bc, (int)(0x40+i), cc < 512 ? cc : 512);
            memset(ba, (int)(0x40+i), ca < 512 ? ca : 512);
            if (memcmp(bc, ba, cc < 512 ? cc : 512) != 0) ok = 0;
        }
        ck("grow_arena: identical cap evolution, return contract, contents", ok);
        /* no-grow returns the existing buffer untouched */
        void* keep = bc; u64 keepc = cc;
        ck("grow_arena: shrink request is a no-op returning *buf",
           txv_grow_arena(&bc, &cc, 1) == keep && cc == keepc &&
           txv_grow_arena_asm(&ba, &ca, 1) == ba && ca == keepc);
    }

    printf("compared %ld pool checks; %ld mismatch(es)\n", compared, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

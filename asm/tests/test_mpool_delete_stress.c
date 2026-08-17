/* Randomized property-based stress test for mpool_put/mpool_get/mpool_del's
 * open-addressing correctness under deletion -- same shape as
 * test_utxo_delete_stress.c, since bitcoin_mempool.asm has the identical
 * lazy-delete-with-no-tombstone bug bitcoin_utxo.asm had (mpool_del used to
 * just mark its slot "empty", breaking mpool_get for any other key that
 * collided past the deleted slot). Fixed with the same backward-shift
 * deletion algorithm; this test drives a small (heavily collision-prone)
 * real mempool and a trivial reference array through a long random
 * put/del/get sequence and asserts they agree after every step. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned long u64;

extern long mpool_struct_size(unsigned long slots);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long cap);
extern long mpool_count(void* mp);
extern long mpool_put(void* mp, const u8 txid[32], const u8* tx, u64 txlen);
extern const u8* mpool_get(void* mp, const u8 txid[32], u64* out_len);
extern long mpool_del(void* mp, const u8 txid[32]);

#define MAX_KEYS 64
typedef struct { u8 txid[32]; int live; u8 tx[8]; u64 txlen; } refent_t;
static refent_t g_ref[MAX_KEYS];

static void make_key(int id, u8 txid[32]){
    /* globally unique per id -- see test_utxo_delete_stress.c for why this
     * matters (no aliasing across ids in the reference bookkeeping). */
    memset(txid, 0, 32);
    txid[0] = (u8)(id & 0xFF);
    txid[1] = (u8)((id >> 8) & 0xFF);
}

static long ref_find(const u8 txid[32]){
    for (int i=0;i<MAX_KEYS;i++)
        if (g_ref[i].live && memcmp(g_ref[i].txid, txid, 32)==0)
            return i;
    return -1;
}

static int run_trial(unsigned seed, long slots){
    srand(seed);
    long sz = mpool_struct_size(slots);
    void* mp = malloc((size_t)sz);
    static u8 blob[1<<20];
    mpool_init(mp, slots, blob, sizeof blob);
    memset(g_ref, 0, sizeof g_ref);
    long live_count = 0;

    const int OPS = 20000;
    for (int op=0; op<OPS; op++){
        int id = rand() % MAX_KEYS;
        u8 txid[32]; make_key(id, txid);
        int action = rand() % 3; /* 0=put 1=del 2=get-check-all */

        if (action == 0){
            u8 tx[4] = {(u8)id, (u8)(id>>8), 0xBB, 0xCC};
            long r = mpool_put(mp, txid, tx, 4);
            long ridx = ref_find(txid);
            if (ridx >= 0){
                if (r != 0){
                    printf("FAIL seed=%u op=%d: put on existing key (id=%d) returned %ld, expected 0 (dup)\n", seed, op, id, r);
                    return 1;
                }
            } else if (live_count >= slots){
                /* mpool_put has a bounded probe count (unlike utxo_put), so
                 * a legitimately full table cleanly returns 2 here rather
                 * than looping -- not a bug. */
                if (r != 2){
                    printf("FAIL seed=%u op=%d: put on new key (id=%d) at live_count=%ld/slots=%ld returned %ld, expected 2 (full)\n", seed, op, id, live_count, slots, r);
                    return 1;
                }
            } else {
                if (r != 1){
                    printf("FAIL seed=%u op=%d: put on new key (id=%d) returned %ld, expected 1\n", seed, op, id, r);
                    return 1;
                }
                g_ref[id].live = 1;
                memcpy(g_ref[id].txid, txid, 32);
                memcpy(g_ref[id].tx, tx, 4);
                g_ref[id].txlen = 4;
                live_count++;
            }
        } else if (action == 1){
            long r = mpool_del(mp, txid);
            long ridx = ref_find(txid);
            int expect = (ridx >= 0) ? 1 : 0;
            if (r != expect){
                printf("FAIL seed=%u op=%d: del (id=%d) returned %ld, expected %d\n", seed, op, id, r, expect);
                return 1;
            }
            if (ridx >= 0) live_count--;
            if (ridx >= 0) g_ref[id].live = 0;
        } else {
            for (int i=0;i<MAX_KEYS;i++){
                u8 kt[32]; make_key(i, kt);
                u64 out_len = 0xDEADBEEF;
                const u8* p = mpool_get(mp, kt, &out_len);
                int expect = g_ref[i].live ? 1 : 0;
                int got = (p != 0) ? 1 : 0;
                if (got != expect){
                    printf("FAIL seed=%u op=%d: get(id=%d) found=%d, expected %d (live-check)\n", seed, op, i, got, expect);
                    return 1;
                }
                if (expect){
                    if (out_len != g_ref[i].txlen || memcmp(p, g_ref[i].tx, (size_t)out_len)!=0){
                        printf("FAIL seed=%u op=%d: get(id=%d) tx bytes/len mismatch\n", seed, op, i);
                        return 1;
                    }
                }
            }
        }
    }

    long final_live = 0;
    for (int i=0;i<MAX_KEYS;i++){
        u8 kt[32]; make_key(i, kt);
        u64 out_len = 0xDEADBEEF;
        const u8* p = mpool_get(mp, kt, &out_len);
        int expect = g_ref[i].live ? 1 : 0;
        int got = (p != 0) ? 1 : 0;
        if (got != expect){
            printf("FAIL seed=%u final: get(id=%d) found=%d, expected %d\n", seed, i, got, expect);
            return 1;
        }
        if (expect) final_live++;
    }
    long tc = mpool_count(mp);
    if (tc != final_live){
        printf("FAIL seed=%u final: mpool_count=%ld, expected %ld\n", seed, tc, final_live);
        return 1;
    }

    free(mp);
    return 0;
}

int main(void){
    long slot_options[] = {8, 16, 32, 64};
    int failures = 0, trials = 0;
    for (int s=0; s<4; s++){
        for (unsigned seed=1; seed<=25; seed++){
            trials++;
            if (run_trial(seed, slot_options[s])) failures++;
        }
    }
    printf("trials=%d failures=%d\n", trials, failures);
    if (failures==0) printf("ALL TESTS PASSED\n");
    return failures ? 1 : 0;
}

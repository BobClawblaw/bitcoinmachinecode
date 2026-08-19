/* Randomized property-based stress test for utxo_put/utxo_get/utxo_del's
 * open-addressing correctness under deletion. Drives a small (heavily
 * collision-prone) real utxo table and a trivial reference implementation
 * (an array, linear-scanned) through the same long random sequence of
 * put/del/get operations and asserts they agree after every step.
 *
 * This exists because utxo_del used to just mark its slot "empty" with no
 * tombstone, which breaks linear-probing lookups for any OTHER key that
 * collided past the deleted slot -- fixed with backward-shift deletion.
 * Small tables + many distinct keys forces exactly this collision pattern.
 *
 * max_keys is kept at slots/2 (never all the way to slots) deliberately:
 * utxo_put's probe loop has no bounded-probe fallback the way mpool_put
 * does (cmp r10,slot_count; jae .full) -- it only terminates by finding a
 * truly empty slot, so driving live_count all the way to slots would risk
 * an infinite loop in utxo_put itself on a legitimately full table, which
 * is a separate, real gap from the deletion bug this test targets.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int u32;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_count(void* u);
extern long utxo_put(void* u, const u8 txid[32], u64 index, u64 value, u64 height, u64 is_coinbase, const u8* script, u64 slen);
extern long utxo_get(void* u, const u8 txid[32], u64 index, u64* value, u64* height, u64* is_coinbase, const u8** script, u64* slen);
extern long utxo_del(void* u, const u8 txid[32], u64 index);

#define MAX_KEYS 64
typedef struct { u8 txid[32]; u32 index; int live; u64 value; } refent_t;
static refent_t g_ref[MAX_KEYS];

static void make_key(int id, u8 txid[32], u32* index){
    /* Each id maps to a GLOBALLY UNIQUE (txid,index) pair -- no aliasing,
     * so the reference array's per-id bookkeeping stays valid. */
    memset(txid, 0, 32);
    txid[0] = (u8)(id & 0xFF);
    txid[1] = (u8)((id >> 8) & 0xFF);
    *index = (u32)(id % 4);
}

static long ref_find(const u8 txid[32], u32 index){
    for (int i=0;i<MAX_KEYS;i++)
        if (g_ref[i].live && memcmp(g_ref[i].txid, txid, 32)==0 && g_ref[i].index==index)
            return i;
    return -1;
}

static int run_trial(unsigned seed, long slots){
    srand(seed);
    long sz = utxo_struct_size(slots);
    void* u = malloc((size_t)sz);
    static u8 blob[1<<20];
    utxo_init(u, slots, blob, sizeof blob);
    memset(g_ref, 0, sizeof g_ref);
    long live_count = 0;
    int max_keys = (int)(slots/2);
    if (max_keys > MAX_KEYS) max_keys = MAX_KEYS;
    if (max_keys < 2) max_keys = 2;

    const int OPS = 20000;
    for (int op=0; op<OPS; op++){
        int id = rand() % max_keys;
        u8 txid[32]; u32 index;
        make_key(id, txid, &index);
        int action = rand() % 3; /* 0=put 1=del 2=get-check-all */

        if (action == 0){
            u8 script[3] = {(u8)id, (u8)(id>>8), 0xAA};
            long r = utxo_put(u, txid, index, 1000+id, 0, 0, script, 3);
            long ridx = ref_find(txid, index);
            if (ridx >= 0){
                if (r != 0){
                    printf("FAIL seed=%u op=%d: put on existing key (id=%d) returned %ld, expected 0 (dup)\n", seed, op, id, r);
                    return 1;
                }
            } else {
                if (r != 1){
                    printf("FAIL seed=%u op=%d: put on new key (id=%d) at live_count=%ld/slots=%ld returned %ld, expected 1\n", seed, op, id, live_count, slots, r);
                    return 1;
                }
                g_ref[id].live = 1;
                memcpy(g_ref[id].txid, txid, 32);
                g_ref[id].index = index;
                g_ref[id].value = 1000+id;
                live_count++;
            }
        } else if (action == 1){
            long r = utxo_del(u, txid, index);
            long ridx = ref_find(txid, index);
            int expect = (ridx >= 0) ? 1 : 0;
            if (r != expect){
                printf("FAIL seed=%u op=%d: del (id=%d) returned %ld, expected %d\n", seed, op, id, r, expect);
                return 1;
            }
            if (ridx >= 0) { g_ref[id].live = 0; live_count--; }
        } else {
            /* verify EVERY live reference key is still found, and a sample
             * of dead/never-inserted keys correctly miss */
            for (int i=0;i<max_keys;i++){
                u8 kt[32]; u32 ki;
                make_key(i, kt, &ki);
                u64 val; const u8* sp; u64 sl, h_unused, cb_unused;
                long r = utxo_get(u, kt, ki, &val, &h_unused, &cb_unused, &sp, &sl);
                int expect = g_ref[i].live ? 1 : 0;
                if (r != expect){
                    printf("FAIL seed=%u op=%d: get(id=%d) returned %ld, expected %d (live-check)\n", seed, op, i, r, expect);
                    return 1;
                }
                if (expect && val != g_ref[i].value){
                    printf("FAIL seed=%u op=%d: get(id=%d) value=%lu expected %lu\n", seed, op, i, val, g_ref[i].value);
                    return 1;
                }
            }
        }
    }

    /* final exhaustive check */
    long final_live = 0;
    for (int i=0;i<max_keys;i++){
        u8 kt[32]; u32 ki;
        make_key(i, kt, &ki);
        u64 val; const u8* sp; u64 sl, h_unused, cb_unused;
        long r = utxo_get(u, kt, ki, &val, &h_unused, &cb_unused, &sp, &sl);
        int expect = g_ref[i].live ? 1 : 0;
        if (r != expect){
            printf("FAIL seed=%u final: get(id=%d) returned %ld, expected %d\n", seed, i, r, expect);
            return 1;
        }
        if (expect) final_live++;
    }
    long tc = utxo_count(u);
    if (tc != final_live){
        printf("FAIL seed=%u final: utxo_count=%ld, expected %ld\n", seed, tc, final_live);
        return 1;
    }

    free(u);
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

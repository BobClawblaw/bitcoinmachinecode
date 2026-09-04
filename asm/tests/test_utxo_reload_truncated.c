/* tests/test_utxo_reload_truncated.c -- UTX-2 (audit 2026-09-03): a WAL
 * reload that does not fit the memtable must be FATAL, not "success".
 *
 * THE BUG. utxo_store_reload returns -2 when the replay hits utxo_put == 2
 * (memtable full). It stops there, holding only the records up to the fill
 * point. utxo_lsm_reload propagates the -2 unchanged. daemon/utxo_live.c's
 * acceptance test was `r != -1`, so -2 counted as SUCCESS and was logged as a
 * plausible "live=N".
 *
 * What made it permanent rather than merely wrong: the memtable is now at or
 * above fill_threshold, so the very next utxo_lsm_put -- the first block's
 * coinbase -- runs mac_flush immediately, which writes the TRUNCATED memtable
 * to a run, publishes the manifest, and ftruncates the WAL. Every record past
 * the fill point is gone from the only place it existed. Blocks spending
 * those outputs are then rejected as "missing UTXO" forever, classified as a
 * consensus reject and retried from the checkpoint, never halted.
 *
 * The window is real: a bulk catch-up (2^22 slots) killed by OOM or power
 * leaves a WAL that a steady-state boot (2^16 slots) cannot hold.
 *
 * WHAT IS ASSERTED. This works at the LSM layer, which is where the -2 is
 * produced and propagated:
 *   1. an oversized WAL tail really does produce a negative reload -- if it
 *      returned a count the test would be vacuous, so this is checked;
 *   2. it is specifically -2, the "table full" code, not a generic error;
 *   3. `r != -1` -- the OLD acceptance test -- would have called it success,
 *      which is the defect stated as an executable claim;
 *   4. `r >= 0` -- the NEW test -- rejects it.
 * Points 3 and 4 are what a reader needs to see: the same value passing one
 * gate and failing the other.
 *
 * Usage: ./test_utxo_reload_truncated
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

typedef unsigned long long u64;
typedef unsigned char u8;

struct lsm_state { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; };

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8* txid, unsigned index, u64 value,
                         unsigned long height, unsigned long cb, const u8* script, unsigned slen);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_count(void* lst);
extern void utxo_lsm_close(void* lst);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("ok  : %s\n", l); else { printf("FAIL: %s\n", l); fails++; } }
static void mk(u8* t, unsigned i){ for (int j=0;j<32;j++) t[j]=(u8)(0x30+j); t[0]=(u8)i; t[1]=(u8)(i>>8); t[2]=(u8)(i>>16); }

static void state_init(struct lsm_state* lst, unsigned long slots, unsigned long tombs){
    memset(lst, 0, sizeof *lst);
    lst->op_threshold   = 100000000ULL;      /* never flush on op count */
    lst->fill_threshold = slots;             /* never flush on fill     */
    lst->tomb_buf = malloc(tombs * 36); lst->tomb_cap = tombs;
    lst->manifest_buf = malloc(512 * 16);   lst->manifest_cap = 512;
    lst->scratch_cap = (u64)(slots + tombs) * 128 + 8ULL * 1024 * 1024 + 65536;
    lst->scratch_buf = malloc(lst->scratch_cap);
}

int main(void){
    char tmpl[] = "/tmp/utxrlXXXXXX"; char* dir = mkdtemp(tmpl);
    if (!dir || chdir(dir) != 0){ printf("FAIL: tmpdir\n"); return 1; }

    /* ---- phase 1: write a WAL far larger than the small memtable ------- */
    enum { BIG_SLOTS = 8192, SMALL_SLOTS = 64, NREC = 3000 };
    {
        void* blob = malloc(16u<<20);
        void* u = malloc(utxo_struct_size(BIG_SLOTS));
        utxo_init(u, BIG_SLOTS, blob, 16u<<20);
        struct lsm_state lst; state_init(&lst, BIG_SLOTS, 4096);
        ck("bulk-sized init", utxo_lsm_init(&lst) == 1);
        u8 script[32]; for (int j=0;j<32;j++) script[j]=(u8)(0x90+j);
        int wrote = 1;
        for (unsigned i = 0; i < NREC; i++){
            u8 t[32]; mk(t, i);
            if (utxo_lsm_put(&lst, u, t, i & 3, 1000ULL+i, 100+i, 0, script, 24) != 1){ wrote = 0; break; }
        }
        ck("wrote a large WAL with no flush (bulk sizing)", wrote);
        utxo_lsm_close(&lst);
        free(u); free(blob);
    }

    /* ---- phase 2: reload it into a steady-state-sized memtable --------- */
    {
        void* blob = malloc(1u<<20);
        void* u = malloc(utxo_struct_size(SMALL_SLOTS));
        utxo_init(u, SMALL_SLOTS, blob, 1u<<20);
        struct lsm_state lst; state_init(&lst, SMALL_SLOTS, 128);
        long r = utxo_lsm_reload(&lst, u);
        long n = utxo_lsm_count(&lst);
        printf("      reload returned %ld, count %ld (wrote %d records)\n", r, n, NREC);

        ck("the oversized tail really does fail to fit (reload < 0)", r < 0);
        ck("UTX-2 the failure is -2 (memtable full), not a generic -1", r == -2);
        ck("UTX-2 the OLD acceptance test `r != -1` would have called this success",
           (r != -1));
        ck("UTX-2 the NEW acceptance test `r >= 0` rejects it", !(r >= 0));
        ck("UTX-2 and the reload really was short of the WAL", n < NREC);

        utxo_lsm_close(&lst);
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

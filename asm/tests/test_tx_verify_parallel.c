/* test_tx_verify_parallel.c -- 2026-08-19: the fork-based parallel path in
 * daemon/tx_verify.c's txv_verify_all (used once a tx has >= TXV_PARALLEL_MIN
 * non-taproot inputs) against the pre-existing sequential path.
 *
 * A single genuinely-signed 10-input P2WPKH transaction (validation/
 * gen_modern_vectors.py's own proven BIP143 oracle, never hand-rolled
 * crypto -- see tests/multi_p2wpkh_vec.h / /tmp .../gen_multi_p2wpkh.py),
 * well above TXV_PARALLEL_MIN=8, so this genuinely exercises the forked
 * workers, not the small-tx sequential fallback every other test in this
 * suite happens to take.
 *
 *   1. all 10 signatures genuine -> tx_verify_block_connect must accept.
 *   2. input 5 (of 10) has a deliberately corrupted signature -> must
 *      reject, with the reason naming that shape's real failure ("p2wpkh
 *      signature invalid"), not a crash, hang, or false accept.
 *   3. repeated 20x -- fork/wait/shared-mmap-result plumbing has no
 *      inherent nondeterminism, but this is exactly the class of bug (see
 *      today's own dl_catchup use-after-unmap) that can pass once and fail
 *      under different scheduling, so prove it doesn't.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int u32;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, u64 value, u64 height, u64 is_coinbase, const u8* script, u32 slen);
extern void utxo_lsm_close(void* lst);

/* This test only exercises tx_verify.c's ORIGINAL single-tx
 * tx_verify_block_connect path -- it never calls the newer, block-wide
 * tx_verify_block_connect_all, which is what actually calls bidx_get (the
 * real definition lives in daemon/utxo_live.c, not linked into this test
 * binary). Still needed at link time since both live in the same
 * translation unit (daemon/tx_verify.c). Always "not found in-block" is the
 * correct, safe behavior for a test that never builds an in-block index. */
long bidx_get(void* bx, u32 caller_tx_index, const u8 txid[32], u32 index,
              u64* value, u64* height, u64* is_coinbase, const u8** script, unsigned long* slen){
    (void)bx; (void)caller_tx_index; (void)txid; (void)index;
    (void)value; (void)height; (void)is_coinbase; (void)script; (void)slen;
    return 0;
}

struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask; /* LSM-owned, see bitcoin_utxo_lsm.asm */
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

extern int tx_verify_block_connect(const u8* tx, u64 txlen, long height, const u8 block_hash32[32],
                                   void* lst, void* u, const char** reason);

/* bitcoin_txval_modern.c (linked in for its per-shape witness primitives)
 * references this extern in code this test never calls -- satisfy the
 * linker with a stub that would abort loudly if it were ever actually
 * reached, rather than pull in daemon/tx_accept.c's real definition and
 * its own dependency chain just for a dead reference. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_tx_verify_parallel: unexpected call to mempool_resolve_confirmed_utxo\n");
    abort();
}

#include "multi_p2wpkh_vec.h"
#include "test_tmpdir.h"

static int g_fails = 0, g_checks = 0;
static void ck(const char* name, int cond){
    g_checks++;
    if (cond) printf("  ok  %s\n", name);
    else { g_fails++; printf("  FAIL %s\n", name); }
}

static int hex2bin(const char* h, u8* out, int cap){
    int n = 0;
    while (h[2*n] && h[2*n+1]) {
        if (n >= cap) return -1;
        unsigned v; sscanf(h + 2*n, "%2x", &v);
        out[n] = (u8)v;
        n++;
    }
    return n;
}

static void* g_table;
static struct lsm_state g_lst;

static void seed_utxos(void){
    unsigned long slots = 1UL<<12;
    long ustruct = utxo_struct_size(slots);
    g_table = malloc((size_t)ustruct);
    void* blob = malloc(4UL<<20);
    utxo_init(g_table, slots, blob, 4UL<<20);
    memset(&g_lst, 0, sizeof g_lst);
    u64 op_th = slots*2, fill_th = slots*3/4, tomb_cap = op_th, desc_cap = slots*3;
    u64 scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    g_lst.op_threshold = op_th; g_lst.fill_threshold = fill_th;
    g_lst.tomb_buf = malloc(tomb_cap*36); g_lst.tomb_cap = tomb_cap;
    g_lst.manifest_buf = malloc(256*16); g_lst.manifest_cap = 256;
    g_lst.scratch_buf = malloc(scratch_cap); g_lst.scratch_cap = scratch_cap;
    if (utxo_lsm_init(&g_lst) != 1) { fprintf(stderr, "seed: utxo_lsm_init failed\n"); exit(1); }

    for (int i=0;i<MPV_N_INPUTS;i++){
        u8 txid[32]; hex2bin(MPV_PREVOUTS[i].txid_hex, txid, 32);
        u8 spk[64]; int spklen = hex2bin(MPV_PREVOUTS[i].spk_hex, spk, sizeof spk);
        long r = utxo_lsm_put(&g_lst, g_table, txid, MPV_PREVOUTS[i].index,
                              MPV_PREVOUTS[i].value, 0, 0, spk, (u32)spklen);
        if (r != 1) { fprintf(stderr, "seed: utxo_lsm_put(%d) returned %ld\n", i, r); exit(1); }
    }
}


/* ---- -par: Core's script-verification thread count (2026-09-06) -----------
 * Core (node/chainstatemanager_args.cpp): `-par` is the TOTAL number of
 * threads doing script checks, the calling thread included -- 0 = every core,
 * -n = leave n cores free, 1 = the caller alone.
 *
 * This node parsed `par`, printed it at boot, and then used it for the
 * DOWNLOAD chunk-worker count, while the pools in this very file sized
 * themselves from sysconf() and never read it: par=8 gave a node that still
 * verified on every core AND halved its download parallelism. The download
 * count is bmc.catchupworkers now. These checks assert the READER -- naming a
 * writer without a reader is exactly how it hid. */
extern void par_set(int par);
extern int  par_get(void);
extern int  par_script_threads(void);
static int par_checks(void){
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN); if (ncpu < 1) ncpu = 1;
    int bad = 0;
    #define PAR_OK(c,m) do{ printf("  %s %s\n", (c)?"ok  :":"FAIL:", m); if(!(c)) bad++; }while(0)
    printf("== -par is the script-verification thread count (this box: %ld cores) ==\n", ncpu);
    par_set(0);  PAR_OK(par_get()==0, "the configured value is kept verbatim");
                 PAR_OK(par_script_threads()==(int)ncpu, "par=0 -> every core, as Core's autodetect does");
    par_set(8);  PAR_OK(par_script_threads()==8, "par=8 -> exactly 8 threads, whatever the box has");
    par_set(1);  PAR_OK(par_script_threads()==1, "par=1 -> single-threaded (the caller alone)");
    par_set(-1); PAR_OK(par_script_threads()==(int)ncpu-1, "par=-1 -> one core left free");
    par_set(-4); PAR_OK(par_script_threads()==(int)ncpu-4, "par=-4 -> four cores left free");
    par_set((int)-ncpu);       PAR_OK(par_script_threads()==1, "par=-<cores> cannot go below one thread");
    par_set((int)-ncpu-100);   PAR_OK(par_script_threads()==1, "an absurd negative still leaves one thread");
    { par_set(2); int a=par_script_threads(); par_set(0); int b=par_script_threads();
      PAR_OK(a==2 && b==(int)ncpu && a!=b, "par=2 and par=0 differ on a multi-core box -- the setting is READ"); }
    par_set(0);                      /* leave the default for the rest of this test */
    #undef PAR_OK
    return bad;
}

int main(void){
    int par_bad = par_checks();
    tt_isolate();
    seed_utxos();

    static u8 tx[8192];
    int txlen = hex2bin(MPV_GOOD_TX_HEX, tx, sizeof tx);
    printf("good tx: %d bytes, %d inputs (MPV_N_INPUTS=%d, >= TXV_PARALLEL_MIN)\n",
           txlen, MPV_N_INPUTS, MPV_N_INPUTS);

    u8 blockhash[32]; memset(blockhash, 0, 32);
    const char* reason = "?";
    long r = tx_verify_block_connect(tx, (u64)txlen, 600000, blockhash, &g_lst, g_table, &reason);
    ck("all-genuine 10-input P2WPKH tx: ACCEPTED", r == 1);
    if (r != 1) printf("    reason: %s\n", reason);

    static u8 badtx[8192];
    int badlen = hex2bin(MPV_BAD_TX_HEX, badtx, sizeof badtx);
    printf("bad tx (input %d corrupted): %d bytes\n", MPV_BAD_INDEX, badlen);

    int all_consistent = 1;
    for (int iter = 0; iter < 20; iter++){
        const char* r2 = "?";
        long rr = tx_verify_block_connect(badtx, (u64)badlen, 600000, blockhash, &g_lst, g_table, &r2);
        if (rr != 0 || strcmp(r2, "p2wpkh signature invalid") != 0) {
            all_consistent = 0;
            printf("    iter %d: got r=%ld reason=%s (expected r=0 reason=\"p2wpkh signature invalid\")\n",
                   iter, rr, r2);
        }
    }
    ck("corrupted-input tx: REJECTED with the right reason, 20/20 consistent runs", all_consistent);
    /* assumevalid (2026-09-01): with script evaluation switched off the same
     * corrupted signature passes block connection (every structural and UTXO
     * check still ran); switched back on it is rejected again. */
    { extern void tx_verify_set_script_checks(int on);
      const char* r3 = "?"; tx_verify_set_script_checks(0);
      long r0 = tx_verify_block_connect(badtx, (u64)badlen, 600000, blockhash, &g_lst, g_table, &r3);
      ck("script checks OFF: the bad signature is not evaluated -> accepted", r0 == 1);
      tx_verify_set_script_checks(1);
      r3 = "?"; long r1 = tx_verify_block_connect(badtx, (u64)badlen, 600000, blockhash, &g_lst, g_table, &r3);
      ck("script checks ON again: rejected with the right reason", r1 == 0 && !strcmp(r3, "p2wpkh signature invalid")); }

    utxo_lsm_close(&g_lst);
    printf("\n%s (%d checks, %d failures)\n", g_fails==0 ? "ALL PASS" : "SOME FAILED", g_checks, g_fails);
    return (g_fails ? 1 : 0) || par_bad ? 1 : 0;

}

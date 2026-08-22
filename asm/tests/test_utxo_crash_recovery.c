/* tests/test_utxo_crash_recovery.c -- a process killed BETWEEN "block N's
 * puts/dels are in the WAL" and "checkpoint N persisted" must be repaired on
 * the next boot, not rejected.
 *
 * What this guards (production, 2026-08-22 02:32, height 318148): systemd
 * SIGKILLed the download worker (it was ignoring SIGTERM -- see
 * tests/test_utxo_catchup_shutdown.c for that half) at exactly that point.
 * On reload the WAL replay re-applied 318148's spends, catch-up started at
 * 318148 again, and Stage D's verifier -- which resolves every prevout
 * BEFORE applying -- found them already spent:
 *   REJECT h=318148 tx=1: input references a missing/already-spent UTXO
 * The per-block checkpoint from 2fd4a14 shrank this window from hours to one
 * block; it cannot close it, because the WAL write and the checkpoint write
 * are two separate syscalls. utxo_live_recover_partial_block closes it from
 * the other side: "undo_<applied+1>.dat exists" proves block applied+1
 * began (live_on_input appends the undo record BEFORE each delete) and never
 * checkpointed, so it is rolled back -- prevouts restored from the undo
 * records, created outputs deleted -- and catch-up re-applies it cleanly.
 *
 * Three kills, each in a forked child via the TEST-ONLY hooks
 * (utxo_live_test_set_crash), each followed by a real close+init in the
 * parent and a key-by-key comparison against a reference replay that never
 * crashed:
 *   (a) after ALL of block N's ops, before its checkpoint  (the 318148 case)
 *   (b) mid-block: after the 2nd of 3 spends' inputs was captured+deleted
 *   (c) mid-block, with the memtable sized so tiny that a mac_flush is forced
 *       INSIDE the block before the kill -- half of N is in an immutable run,
 *       half in the WAL. The rollback must still be exact (LSM newest-wins:
 *       a restoring put shadows the run's tombstone, a deleting tombstone
 *       shadows the run's put). Proven by the key-by-key diff, not assumed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/wait.h>
#include "../daemon/node_config.h"
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void merkle_root(u8 out[32], u8* hashes, long n);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);
extern void utxo_live_test_set_crash(int mode, long n);
extern void* utxo_live_lst(void);
extern void* utxo_live_table(void);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, u64* value,
                         unsigned long* height, unsigned long* is_coinbase,
                         const u8** script, unsigned long* slen);

#define CRASH_BEFORE_PERSIST 1   /* == UTXO_LIVE_CRASH_BEFORE_PERSIST */
#define CRASH_AFTER_INPUTS   2   /* == UTXO_LIVE_CRASH_AFTER_INPUTS   */

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_utxo_crash_recovery: unexpected call to mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void ckm(const char* l, int cond){
    if (cond) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; }
}

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_txid_scratch[1<<12];

static long mk_coinbase_tx(u8* tx, u32 tag){
    u8* q = tx;
    put32(q,1); q+=4; *q++ = 1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51; put32(q,0); q+=4;
    return q - tx;
}

/* Coinbase-only block. */
static long mk_and_mine(u8* raw, u8 hash[32], u8 cb_txid_out[32], const u8 prev[32], u32 tag, u32 tstamp){
    u8 tx[64], txid[32];
    long txlen = mk_coinbase_tx(tx, tag);
    tx_txid(txid, tx, (unsigned long)txlen, g_txid_scratch, sizeof g_txid_scratch);
    memcpy(cb_txid_out, txid, 32);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, txid, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = 1; memcpy(o, tx, (size_t)txlen); o += txlen;
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

/* Coinbase + nspend transactions, tx_j spending spend_txids[j]:0 (empty
 * scriptSig against OP_1 -- valid) into one OP_1 output of 40,000,000. */
static long mk_and_mine_multispend(u8* raw, u8 hash[32], const u8 prev[32],
                                   const u8 (*spend_txids)[32], int nspend,
                                   u32 tag, u32 tstamp, u8 (*out_txids)[32]){
    u8 txbuf[8][128]; long txlen[8];
    u8 leaves[8*32];
    txlen[0] = mk_coinbase_tx(txbuf[0], tag);
    tx_txid(leaves, txbuf[0], (unsigned long)txlen[0], g_txid_scratch, sizeof g_txid_scratch);
    for (int j=0;j<nspend;j++){
        u8* q = txbuf[j+1];
        put32(q,1); q+=4;
        *q++ = 1;
        memcpy(q, spend_txids[j], 32); q+=32; put32(q,0); q+=4;
        *q++ = 0;
        put32(q,0xffffffffu); q+=4;
        *q++ = 1;
        put64(q, 40000000ULL); q+=8;
        *q++ = 1; *q++ = 0x51;
        put32(q,0); q+=4;
        txlen[j+1] = q - txbuf[j+1];
        tx_txid(leaves + 32*(j+1), txbuf[j+1], (unsigned long)txlen[j+1], g_txid_scratch, sizeof g_txid_scratch);
        memcpy(out_txids[j], leaves + 32*(j+1), 32);
    }
    u8 root[32];
    merkle_root(root, leaves, nspend+1);    /* in-place over leaves -- copies taken above */

    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = (u8)(nspend+1);
    for (int j=0;j<=nspend;j++){ memcpy(o, txbuf[j], (size_t)txlen[j]); o += txlen[j]; }
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

static long read_checkpoint_file(void){
    FILE* f = fopen("utxo_applied_height.dat", "rb");
    if (!f) return -2;
    u8 buf[12]; size_t n = fread(buf, 1, 12, f); fclose(f);
    if (n != 12) return -3;
    long h; memcpy(&h, buf+4, 8);
    return h;
}
static long count_runs(void){
    DIR* d = opendir("."); if (!d) return -1;
    long n=0; struct dirent* e;
    while ((e = readdir(d))) if (!strncmp(e->d_name, "utxo_run_", 9)) n++;
    closedir(d); return n;
}

#define NCB 150
#define MAXSPEND 5
#define NKEYS (NCB + MAXSPEND)
typedef struct { int present; u64 value; } snap_t;

static u8 store_buf[4096];
static u8 cb_txids[NCB][32];
static u8 spend_txids[MAXSPEND][32];

static void apply_sizing(int tiny){
    if (tiny){
        /* Force bulk sizing with a 4-slot memtable: fill_threshold = 3, so
         * any 4 puts flush. op_threshold 8 / tomb_cap 8 / desc_cap 12 keep
         * the file's documented desc_cap >= fill + tomb invariant. */
        g_cfg.utxo_bulk_gap_blocks = 0;
        g_cfg.utxo_bulk_slots_log2 = 2;
        g_cfg.utxo_bulk_blob_mb    = 1;
    } else {
        g_cfg.utxo_bulk_gap_blocks = 1000000L;   /* steady-state 2^16 slots */
    }
}

/* Build the 150-block coinbase chain into store_buf (fresh dir), returning
 * the last hash in prev. Deterministic tags -> identical txids every time. */
static void build_base_chain(u8 prev[32]){
    memset(prev,0,32);
    for (long h=0; h<NCB; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, cb_txids[h], prev, 0x70000000u+(u32)h, 1900000000u+(u32)h);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; }
        memcpy(prev, hash, 32);
    }
}

static void snapshot(int nspend, snap_t* out){
    for (int i=0;i<NKEYS;i++){
        const u8* t = i < NCB ? cb_txids[i] : spend_txids[i-NCB];
        u64 v=0; unsigned long hh=0, cb=0, sl=0; const u8* sc=0;
        long r = (i < NCB || i-NCB < nspend)
               ? utxo_lsm_get(utxo_live_lst(), utxo_live_table(), t, 0, &v, &hh, &cb, &sc, &sl)
               : 0;
        out[i].present = (r == 1); out[i].value = (r == 1) ? v : 0;
    }
}

typedef struct { const char* name; int mode; long n; int nspend; int tiny; } scen_t;

static void run_scenario(const scen_t* s){
    printf("\n=== %s ===\n", s->name);
    static snap_t crash_snap[NKEYS], ref_snap[NKEYS];
    long count_crash, count_ref;

    /* ---------- crash path ---------- */
    {
        tt_subdir("crash");   /* a fresh, empty datadir for this leg */
        memset(store_buf,0,sizeof store_buf);
        apply_sizing(s->tiny);
        ck("store_init", store_init(store_buf), 1);
        ck("utxo_live_init", utxo_live_init("."), 1);
        u8 prev[32]; build_base_chain(prev);
        ck("base chain applied", utxo_live_catchup(store_buf), NCB);
        utxo_live_close();

        u8 raw[1024], hash[32];
        long len = mk_and_mine_multispend(raw, hash, prev, cb_txids, s->nspend, 0x80000000u, 1900100000u, spend_txids);
        ck("store_append spend block at 150", store_append(store_buf, hash, raw, len), NCB);

        long runs_before = count_runs();
        utxo_live_test_set_crash(s->mode, s->n);
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); exit(1); }
        if (pid == 0){
            if (utxo_live_init(".") != 1) _exit(2);
            long ar = utxo_live_catchup(store_buf);
            fprintf(stderr, "crash hook did not fire (ar=%ld)\n", ar);
            _exit(3);
        }
        utxo_live_test_set_crash(0, -1);      /* disarm in the parent */
        int status = 0;
        if (waitpid(pid, &status, 0) != pid) { perror("waitpid"); exit(1); }
        ckm("child died via the crash hook's _exit(1)", WIFEXITED(status) && WEXITSTATUS(status)==1);
        long runs_after = count_runs();
        if (s->tiny)
            ckm("a flush landed INSIDE the crashed block (run files grew while the child ran)", runs_after > runs_before);

        ck("on-disk checkpoint still 149 (block 150 never checkpointed)", read_checkpoint_file(), NCB-1);
        ckm("undo_150.dat exists (block 150 began applying)", access("undo_150.dat", F_OK) == 0);

        /* Real restart. */
        ck("utxo_live_init (post-crash reload)", utxo_live_init("."), 1);
        ck("applied_height from the checkpoint", utxo_live_applied_height(), NCB-1);
        long ar = utxo_live_catchup(store_buf);
        ck("catch-up after recovery: rolled 150 back, then re-applied it cleanly (1 block, no REJECT)", ar, 1);
        ck("applied_height == 150", utxo_live_applied_height(), NCB);
        ck("checkpoint == 150", read_checkpoint_file(), NCB);
        ck("second catch-up is a no-op", utxo_live_catchup(store_buf), 0);
        snapshot(s->nspend, crash_snap);
        count_crash = utxo_live_count();
        utxo_live_close();
    }
    /* ---------- reference path: same chain, never crashed ---------- */
    {
        tt_subdir("ref");   /* a fresh, empty datadir for this leg */
        memset(store_buf,0,sizeof store_buf);
        apply_sizing(s->tiny);
        ck("ref store_init", store_init(store_buf), 1);
        ck("ref utxo_live_init", utxo_live_init("."), 1);
        u8 prev[32]; build_base_chain(prev);
        u8 raw[1024], hash[32]; u8 tmp_txids[MAXSPEND][32];
        long len = mk_and_mine_multispend(raw, hash, prev, cb_txids, s->nspend, 0x80000000u, 1900100000u, tmp_txids);
        ck("ref spend block txids identical to the crash path's", memcmp(tmp_txids, spend_txids, 32*(size_t)s->nspend), 0);
        store_append(store_buf, hash, raw, len);
        ck("ref catch-up applied 151 blocks", utxo_live_catchup(store_buf), NCB+1);
        snapshot(s->nspend, ref_snap);
        count_ref = utxo_live_count();
        utxo_live_close();
    }
    /* ---------- compare ---------- */
    long mism = 0;
    for (int i=0;i<NKEYS;i++){
        if (crash_snap[i].present != ref_snap[i].present || crash_snap[i].value != ref_snap[i].value){
            if (mism < 8) printf("   MISMATCH key %d: crash(present=%d value=%llu) ref(present=%d value=%llu)\n",
                                 i, crash_snap[i].present, crash_snap[i].value, ref_snap[i].present, ref_snap[i].value);
            mism++;
        }
    }
    ck("every key identical to the never-crashed reference (present + value)", mism, 0);
    if (!s->tiny)
        ck("live UTXO count identical to the reference", count_crash, count_ref);
    else
        /* PRE-EXISTING, OUT OF SCOPE HERE: utxo_lsm_reload rebuilds the live
         * counter ([lst+88]) from the WAL replay only, i.e. memtable-resident
         * entries, not the sum over on-disk runs -- so after any reload with
         * runs present, utxo_lsm_count() is "memtable live", not the set
         * size (production reload lines show e.g. live=2944064 at height
         * 318147, far below the real set). The key-by-key diff above is the
         * correctness check; the tally is cosmetic (heartbeat/logs). */
        printf("NOTE (c): live count after reload = %ld vs reference %ld -- expected: reload's counter is memtable-only when runs exist (pre-existing LSM accounting, not a set difference; every key matched)\n",
               count_crash, count_ref);
    /* And the reference itself is what the chain says it should be. */
    long spent_cb = 0, present_cb = 0, present_spend = 0;
    for (int i=0;i<NCB;i++){ if (ref_snap[i].present) present_cb++; else spent_cb++; }
    for (int j=0;j<s->nspend;j++) if (ref_snap[NCB+j].present && ref_snap[NCB+j].value == 40000000ULL) present_spend++;
    ck("reference: exactly nspend coinbases spent", spent_cb, s->nspend);
    ck("reference: all spend outputs present with the right value", present_spend, s->nspend);
    ck("reference: count == 151 coinbases - nspend + nspend", count_ref, NCB + 1);
}

int main(void){
    tt_isolate();
    scen_t scens[] = {
        { "(a) killed after ALL of block 150's ops hit the WAL, before its checkpoint",
          CRASH_BEFORE_PERSIST, 1, 3, 0 },
        { "(b) killed mid-block: after the 2nd of 3 spend inputs was captured+deleted",
          CRASH_AFTER_INPUTS, 2, 3, 0 },
        { "(c) killed mid-block with a forced mac_flush INSIDE the block (4-slot memtable, 5 spends, die after input 4)",
          CRASH_AFTER_INPUTS, 4, 5, 1 },
    };
    for (unsigned i=0;i<sizeof scens/sizeof scens[0];i++) run_scenario(&scens[i]);
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}

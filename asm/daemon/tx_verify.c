/* daemon/tx_verify.c -- Stage D: per-transaction script verification for
 * block connection (called from apply_block_inner in utxo_live.c). One
 * function per non-coinbase tx: resolves each input's confirmed prevout
 * from the live LSM UTXO set (which, by construction, already reflects
 * every EARLIER tx in the same block -- apply_block_inner walks tx-by-tx in
 * order) and dispatches by the prevout scriptPubKey's shape:
 *   - a legacy shape (anything that is NOT one of the three witness-program
 *     shapes below) goes to sv_verify_script (bitcoin_scriptverify.c) --
 *     P2PK/P2PKH/P2SH/bare-multisig, exactly Stage B's scope.
 *   - P2WPKH / P2WSH (CHECKSIG or the one 2-of-2 multisig shape) / P2TR
 *     key-path go to the witness primitives bitcoin_txval_modern.c already
 *     proved out at the mempool layer (p2wpkh_verify / p2wsh_verify_checksig
 *     / p2wsh_verify_multisig / taproot_keypath_verify).
 *
 * Deliberately NOT a call into txval_modern() itself: that function is a
 * WHOLE-TX validator that (a) hard-caps at 16 inputs and (b) REJECTS a tx
 * that mixes a legacy-shaped prevout with a witness-shaped one
 * ("unsupported prevout script type") -- both wrong for block connection,
 * which must accept every real historical transaction, including ones with
 * far more than 16 inputs and ones that spend a mix of legacy and witness
 * outputs in the same tx (both real, common mainnet shapes). This file
 * reuses txval_modern's per-shape PRIMITIVES, not its whole-tx driver.
 *
 * Also enforces the 100-block coinbase maturity rule per spent input, using
 * the height/is_coinbase fields the UTXO record format grew for exactly
 * this purpose (2026-08-19).
 *
 * KNOWN COVERAGE LIMIT -- the same one bitcoin_txval_modern.c already has:
 * any witness shape outside the three above (arbitrary P2WSH witnessScripts,
 * taproot SCRIPT-path spends, anything with more witness items than
 * TXV_MAX_WIT_ITEMS) is REJECTED -- loudly, distinctly logged as
 * "unsupported", never silently treated as valid. A full archive replay
 * under this file will not reach chain tip until that coverage is extended;
 * see PLAN_SCRIPT_VERIFY.md's Stage D note.
 *
 * PARALLEL VERIFICATION (2026-08-19, revised 2026-08-19). Signature
 * verification (ECDSA/Schnorr) is the dominant cost of block connection and
 * was, until now, entirely single-threaded -- a from-scratch archive replay
 * measured at ~1 core of this box's 32 in active use. This file resolves
 * every input's prevout SEQUENTIALLY first (exactly as before -- this is
 * cheap, and is what preserves correctness: same-tx input order and the
 * surrounding apply_block_inner's per-tx interleaving of verify-then-apply
 * are what make same-block spends resolve correctly, and none of that
 * changes here), then fans the expensive per-input crypto checks out across
 * worker THREADS and collects pass/fail before deciding whether to apply
 * the transaction. Ordering between transactions and between blocks is
 * completely unchanged: only the (already provably independent, once each
 * input's prevout is resolved) crypto work for ONE transaction's OWN inputs
 * runs concurrently. Taproot inputs, needing the BIP341 aggregate sighash
 * built from every input's prevout, stay on the existing sequential pass 2
 * -- rarer in practice, and keeping it simple keeps the parallel path's
 * correctness argument simple.
 *
 * Originally fork()-based (the same pattern dl_catchup uses for parallel
 * block downloading), and disabled during bulk UTXO catch-up because
 * fork()'s copy-on-write page-table setup cost scales with the PARENT's
 * resident size -- during a from-scratch replay the parent IS the growing
 * multi-GB UTXO memtable, so every fork() got progressively more expensive
 * over the course of the run (confirmed via production stack sampling: every
 * sample landed inside fork() itself, not inside any verify routine).
 * Rewritten to use pthreads instead, which share the process's address
 * space rather than copying its page tables, and so have no such cost --
 * this is what makes it safe to run during bulk mode too now. That in turn
 * required making sv_verify_script's legacy-path scratch state genuinely
 * thread-safe (bitcoin_scriptverify.c/bitcoin_interp.asm/
 * bitcoin_sighash.asm/bitcoin_scriptcodec.asm, real ELF TLS, see those
 * files' own header notes and tests/test_scriptverify_thread_stress.c) --
 * P2WPKH/P2WSH's dedicated fast paths already had no such state and needed
 * no changes.
 */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;

/* ---- legacy verifier (bitcoin_scriptverify.c) ---- */
extern int sv_verify_script(const unsigned char* scriptSig, unsigned long ssl,
                            const unsigned char* scriptPubKey, unsigned long spl,
                            unsigned long long flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);

/* ---- activation-height flag schedule (bitcoin_script_flags.asm) ---- */
extern unsigned long long script_flags_for_block(unsigned long long height, const u8 hash32[32]);

/* ---- witness primitives (bitcoin_segwit.c / bitcoin_taproot_sighash.c),
 * same externs bitcoin_txval_modern.c declares ---- */
extern long strip_witness(const u8* tx, int64_t txlen, u8* out, long cap);
extern int  p2wpkh_verify(const u8* tx, int64_t txlen, int64_t n_in,
                          const u8* prev_spk, int64_t prev_spklen, uint64_t amount,
                          const u8* vchSig, uint64_t siglen,
                          const u8* vchPub, uint64_t publen);
extern int  p2wsh_verify_checksig(const u8* tx, int64_t txlen, int64_t n_in,
                                  uint64_t amount, const u8* witness_script,
                                  uint64_t wslen, const u8* vchSig, uint64_t siglen,
                                  const u8* vchPub, uint64_t publen);
extern int  p2wsh_verify_multisig(const u8* tx, int64_t txlen, int64_t n_in,
                                  uint64_t amount, const u8* witness_script,
                                  uint64_t wslen,
                                  const u8* sig1, uint64_t sig1len,
                                  const u8* sig2, uint64_t sig2len,
                                  const u8* pub1, const u8* pub2);
extern int  taproot_keypath_verify(const u8* spk, const u8* sig, int siglen,
                                   const u8* tx, int64_t txlen, int64_t n_in,
                                   const u8* prevouts, const u8* amounts,
                                   const u8* spks, int64_t num_inputs);

/* ---- confirmed UTXO set (bitcoin_utxo_lsm.asm) ---- */
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
                         u64* value, u64* height, u64* is_coinbase,
                         const u8** script, unsigned long* slen);

/* Core's COINBASE_MATURITY (consensus/consensus.h): a coinbase output
 * cannot be spent until (spending block height - creation height) >= 100. */
#define COINBASE_MATURITY 100

/* Bounds. Generous vs. any known real chain data (largest known mainnet tx
 * input counts are in the low tens of thousands) and produce a clean, loud
 * rejection rather than silent truncation if ever exceeded -- matching
 * bitcoin_txval_modern.c's own PREV_SPK_BUF_MAX philosophy.
 *
 * TXV_SPK_CAP (2026-08-20, corrected): matches bitcoin_interp.asm's own
 * MAX_SCRIPT_SIZE=10000 -- the real Bitcoin consensus cap on any script,
 * which that interpreter already enforces and is already sized to handle.
 * Previously 252, on the mistaken belief that it needed to stay under 0xfd
 * to fit the taproot aggregate sighash array's single-length-byte encoding
 * (see the "prevout script too large for taproot aggregate sighash" check
 * below) -- that check is actually a SEPARATE, independent `>= 0xfd` literal
 * comparison, not derived from this constant at all, so the two were never
 * actually coupled; the low cap just meant this file rejected any real
 * legacy prevout script over 252 bytes (e.g. a large bare multisig) with a
 * generic "prevout script too large", regardless of whether the tx had
 * anything to do with taproot. First hit live in production at height
 * 243015 during a full archive replay -- 243014 blocks of real chain data
 * had simply never carried a legacy script that large before. */
#define TXV_MAX_INPUTS    20000
#define TXV_SPK_CAP       10000
#define TXV_MAX_WIT_ITEMS    8

#define TXV_SHAPE_LEGACY  0
#define TXV_SHAPE_P2WPKH  1
#define TXV_SHAPE_P2WSH   2
#define TXV_SHAPE_P2TR    3

typedef struct {
    const u8* outpoint;             /* 36 bytes: txid(32)+index(4), in tx bytes */
    const u8* scriptSig; u32 scriptSiglen;
    const u8* wit[TXV_MAX_WIT_ITEMS]; u32 witlen[TXV_MAX_WIT_ITEMS]; u32 nwit;
    /* resolved during the sequential pass, before any forking -- self-
     * contained (a COPY, not a utxo_lsm_get pointer, which is only valid
     * until the next call) so a forked child can safely read it. */
    u64 value;
    u8  spk[TXV_SPK_CAP]; u32 spklen;
    u8  shape;
} txv_rawin_t;
static txv_rawin_t g_txv_in[TXV_MAX_INPUTS];

static u64 txv_rd_cs(const u8** p, const u8* end, int* ok){
    if (*p >= end) { *ok = 0; return 0; }
    const u8* b = *p; u8 f = b[0];
    if (f < 0xfd) { *p = b+1; return f; }
    if (f == 0xfd){ if (b+3>end){*ok=0;return 0;} u64 v=b[1]|((u64)b[2]<<8); *p=b+3; return v; }
    if (f == 0xfe){ if (b+5>end){*ok=0;return 0;} u64 v=0; for(int i=0;i<4;i++) v|=(u64)b[1+i]<<(8*i); *p=b+5; return v; }
    if (b+9>end){*ok=0;return 0;} u64 v=0; for(int i=0;i<8;i++) v|=(u64)b[1+i]<<(8*i); *p=b+9; return v;
}

/* Parses the tx's own input list (outpoint/scriptSig) and, if segwit-
 * marked, its per-input witness stacks, into g_txv_in[0..nin). Does not
 * touch outputs (irrelevant to script verification) or resolve any UTXO.
 * Returns 1 well-formed / 0 malformed-or-over-bound (reason set). */
static int txv_parse(const u8* tx, u64 txlen, u64* out_nin, const char** reason){
    const u8* p = tx; const u8* end = tx+txlen;
    int ok = 1;
    if (txlen < 10) { *reason = "tx too short"; return 0; }
    p += 4; /* version */
    int segwit = (p+2<=end && p[0]==0x00 && p[1]==0x01);
    if (segwit) p += 2;
    u64 nin = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad n_in varint"; return 0; }
    if (nin == 0 || nin > TXV_MAX_INPUTS) { *reason = "input count out of bounds"; return 0; }
    for (u64 i=0;i<nin;i++){
        if (p+36 > end) { *reason = "truncated outpoint"; return 0; }
        g_txv_in[i].outpoint = p; p += 36;
        u64 sl = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad scriptSig varint"; return 0; }
        if ((u64)(end-p) < sl+4) { *reason = "truncated scriptSig/sequence"; return 0; }
        g_txv_in[i].scriptSig = p; g_txv_in[i].scriptSiglen = (u32)sl;
        p += sl + 4;
        g_txv_in[i].nwit = 0;
    }
    u64 nout = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad n_out varint"; return 0; }
    for (u64 i=0;i<nout;i++){
        if (p+8>end){ *reason = "truncated output"; return 0; }
        p += 8;
        u64 sl = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad output script varint"; return 0; }
        if ((u64)(end-p) < sl){ *reason = "truncated output script"; return 0; }
        p += sl;
    }
    if (segwit){
        for (u64 i=0;i<nin;i++){
            u64 nitems = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad witness item-count varint"; return 0; }
            if (nitems > TXV_MAX_WIT_ITEMS) { *reason = "too many witness items"; return 0; }
            g_txv_in[i].nwit = (u32)nitems;
            for (u64 j=0;j<nitems;j++){
                u64 il = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad witness-item-len varint"; return 0; }
                if ((u64)(end-p) < il){ *reason = "truncated witness item"; return 0; }
                g_txv_in[i].wit[j] = p; g_txv_in[i].witlen[j] = (u32)il;
                p += il;
            }
        }
    }
    *out_nin = nin;
    return 1;
}

static int is_p2wpkh(const u8* spk, u32 sl){ return sl==22 && spk[0]==0x00 && spk[1]==0x14; }
static int is_p2wsh (const u8* spk, u32 sl){ return sl==34 && spk[0]==0x00 && spk[1]==0x20; }
static int is_p2tr  (const u8* spk, u32 sl){ return sl==34 && spk[0]==0x51 && spk[1]==0x20; }

/* txv_verify_one(): the actual per-input crypto check, dispatched by shape.
 * Pure function of g_txv_in[i]'s already-resolved fields plus the tx bytes
 * (both read-only by this point) -- safe to call from a forked child, which
 * has its own COW copy of everything it touches. Returns 1 valid / 0
 * invalid (reason set to a static string literal; NOT malloc'd, so it is
 * safe to read across a fork -- the string constants live in .rodata,
 * mapped identically in every child). */
static int txv_verify_one(const u8* tx, u64 txlen, u64 i, unsigned long long flags,
                          u8* sv_work, unsigned long sv_workcap, const char** reason){
    txv_rawin_t* in = &g_txv_in[i];
    switch (in->shape){
    case TXV_SHAPE_P2WPKH:
        if (!p2wpkh_verify(tx, (int64_t)txlen, (int64_t)i, in->spk, (int64_t)in->spklen, in->value,
                           in->wit[0], in->witlen[0], in->wit[1], in->witlen[1])) {
            *reason = "p2wpkh signature invalid"; return 0;
        }
        return 1;
    case TXV_SHAPE_P2WSH: {
        const u8* ws = in->wit[in->nwit-1];
        u32 wslen = in->witlen[in->nwit-1];
        if (wslen >= 34 && ws[0]==0x21 && ws[wslen-1]==0xac){
            if (!p2wsh_verify_checksig(tx, (int64_t)txlen, (int64_t)i, in->value, ws, wslen,
                                       in->wit[0], in->witlen[0], ws+1, 33)) {
                *reason = "p2wsh checksig invalid"; return 0;
            }
            return 1;
        }
        if (wslen >= 3+33+33 && ws[0]==0x52 && ws[wslen-1]==0xae && in->nwit >= 4){
            if (!p2wsh_verify_multisig(tx, (int64_t)txlen, (int64_t)i, in->value, ws, wslen,
                                       in->wit[2], in->witlen[2], in->wit[1], in->witlen[1],
                                       ws+2, ws+36)) {
                *reason = "p2wsh multisig invalid"; return 0;
            }
            return 1;
        }
        *reason = "unsupported p2wsh witnessScript shape"; return 0;
    }
    case TXV_SHAPE_LEGACY: {
        int err = sv_verify_script(in->scriptSig, in->scriptSiglen, in->spk, in->spklen,
                                   flags, (unsigned long)i, tx, txlen, sv_work, sv_workcap);
        if (err != 0) { *reason = "legacy script verification failed"; return 0; }
        return 1;
    }
    default: /* taproot: handled by pass 2, never dispatched here */
        return 1;
    }
}

/* Below this many non-taproot inputs, spawning threads costs more than it
 * saves -- pthread_create/join round-trips easily cost single-digit
 * microseconds, comparable to a handful of ECDSA verifies (~115us each per
 * the project's own bench_ecdsa measurement). Chosen conservatively; a real
 * profile could tune it, but correctness does not depend on the exact
 * value -- only throughput does. */
#define TXV_PARALLEL_MIN 8
#define TXV_MAX_WORKERS  16

/* Was: set by utxo_live.c (via txv_set_bulk_mode) to skip parallel dispatch
 * during a bulk UTXO catch-up, because fork()'s cost scaled with the
 * growing memtable (see this file's header note). Threads don't have that
 * problem -- kept as a real, callable no-op (not deleted) so utxo_live.c's
 * existing call site doesn't need touching, and so a future cost that DOES
 * scale with bulk-mode state has an obvious place to hook back in. */
void txv_set_bulk_mode(int on){ (void)on; }

typedef struct { u8 ok; char reason[64]; } txv_result_t;
static txv_result_t g_txv_results[TXV_MAX_INPUTS];

typedef struct {
    const u8* tx; u64 txlen; unsigned long long flags;
    u64 lo, hi;
} txv_worker_arg_t;

static void* txv_worker_thread(void* argp){
    txv_worker_arg_t* a = (txv_worker_arg_t*)argp;
    static __thread u8 sv_work[1<<20];   /* per-THREAD, not per-process --
                                          * threads share g_txv_results and
                                          * the process's other statics, so
                                          * this one specifically must stay
                                          * __thread or concurrent workers
                                          * would race on it (exactly the
                                          * class of bug
                                          * test_scriptverify_thread_stress.c
                                          * was built to catch). */
    for (u64 i=a->lo;i<a->hi;i++){
        if (g_txv_in[i].shape == TXV_SHAPE_P2TR) { g_txv_results[i].ok = 1; continue; }
        const char* r = 0;
        int ok = txv_verify_one(a->tx, a->txlen, i, a->flags, sv_work, sizeof sv_work, &r);
        g_txv_results[i].ok = ok ? 1 : 0;
        if (!ok) { size_t n=strlen(r); if(n>63)n=63; memcpy(g_txv_results[i].reason, r, n); g_txv_results[i].reason[n]=0; }
    }
    return 0;
}

/* txv_verify_all(): verify every non-taproot input in g_txv_in[0..nin),
 * in parallel once there's enough work to be worth it. Sequential fallback
 * below TXV_PARALLEL_MIN keeps small (the common case, historically) txs
 * exactly as fast as before with zero thread overhead.
 * Returns 1 all valid / 0 at least one invalid (reason set). */
static int txv_verify_all(const u8* tx, u64 txlen, u64 nin, unsigned long long flags,
                          const char** reason){
    u64 nverify = 0;
    for (u64 i=0;i<nin;i++) if (g_txv_in[i].shape != TXV_SHAPE_P2TR) nverify++;
    if (nverify == 0) return 1;

    static char rbuf[64];

    if (nverify < TXV_PARALLEL_MIN){
        static u8 sv_work[1<<20];
        for (u64 i=0;i<nin;i++){
            if (g_txv_in[i].shape == TXV_SHAPE_P2TR) continue;
            const char* r = 0;
            if (!txv_verify_one(tx, txlen, i, flags, sv_work, sizeof sv_work, &r)) {
                *reason = r; return 0;
            }
        }
        return 1;
    }

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN); if (ncpu < 1) ncpu = 1;
    int nworkers = (int)(nverify < (u64)ncpu ? nverify : (u64)ncpu);
    if (nworkers > TXV_MAX_WORKERS) nworkers = TXV_MAX_WORKERS;
    if (nworkers < 1) nworkers = 1;

    memset(g_txv_results, 0, sizeof(txv_result_t)*(size_t)nin);

    u64 per = (nin + (u64)nworkers - 1) / (u64)nworkers;
    pthread_t tids[TXV_MAX_WORKERS];
    txv_worker_arg_t args[TXV_MAX_WORKERS];
    int spawned = 0;
    for (int w=0; w<nworkers; w++){
        u64 lo = (u64)w*per, hi = lo+per; if (hi>nin) hi=nin;
        if (lo >= hi) break;
        args[spawned].tx = tx; args[spawned].txlen = txlen; args[spawned].flags = flags;
        args[spawned].lo = lo; args[spawned].hi = hi;
        if (pthread_create(&tids[spawned], 0, txv_worker_thread, &args[spawned]) != 0){
            /* thread creation failed partway: whatever didn't get a thread
             * (including this one) stays at its zeroed g_txv_results slot
             * and is picked up by the "finish inline" sweep below -- same
             * fallback story fork() had, just for pthread_create instead. */
            break;
        }
        spawned++;
    }
    for (int w=0; w<spawned; w++) pthread_join(tids[w], 0);

    static u8 sv_work_main[1<<20];
    int all_ok = 1;
    for (u64 i=0;i<nin;i++){
        if (g_txv_in[i].shape == TXV_SHAPE_P2TR) continue;
        if (g_txv_results[i].ok) continue;
        if (g_txv_results[i].reason[0] != 0){
            /* a real, reported failure */
            memcpy(rbuf, g_txv_results[i].reason, sizeof rbuf);
            all_ok = 0; break;
        }
        /* blank: pthread_create failure above left this index untouched --
         * verify it inline now, in this thread, so a transient resource
         * failure never silently skips a check. */
        const char* r = 0;
        if (!txv_verify_one(tx, txlen, i, flags, sv_work_main, sizeof sv_work_main, &r)) {
            memcpy(rbuf, r, strlen(r)+1 > sizeof rbuf ? sizeof rbuf : strlen(r)+1);
            all_ok = 0; break;
        }
    }
    if (!all_ok) *reason = rbuf;
    return all_ok;
}

/* tx_verify_block_connect(tx, txlen, height, block_hash32, lst, u, &reason)
 * -> 1 accept / 0 reject (reason set to a static string literal). Caller
 * must have already excluded the coinbase tx -- every input seen here is a
 * real spend, never a coinbase's null prevout. */
int tx_verify_block_connect(const u8* tx, u64 txlen, long height, const u8 block_hash32[32],
                            void* lst, void* u, const char** reason){
    u64 nin;
    if (!txv_parse(tx, txlen, &nin, reason)) return 0;

    unsigned long long flags = script_flags_for_block((unsigned long long)height, block_hash32);
    int has_taproot = 0;

    /* ---- pass 1 (sequential, unchanged in spirit from before): maturity
     * check + resolve every input's prevout from the confirmed UTXO set,
     * copying out what's needed (utxo_lsm_get's own pointer is only valid
     * until the next call) so verification -- now possibly forked out --
     * has a fully self-contained, read-only view of each input. ---- */
    for (u64 i=0;i<nin;i++){
        u32 index; memcpy(&index, g_txv_in[i].outpoint+32, 4);
        u64 value=0, uheight=0, ucb=0; const u8* spk=0; unsigned long spklen=0;
        long r = utxo_lsm_get(lst, u, g_txv_in[i].outpoint, index, &value, &uheight, &ucb, &spk, &spklen);
        if (r != 1) { *reason = "input references a missing/already-spent UTXO"; return 0; }
        if (ucb) {
            long conf = height - (long)uheight;
            if (conf < COINBASE_MATURITY) { *reason = "immature coinbase spend (100-block rule)"; return 0; }
        }

        g_txv_in[i].value = value;
        if (spklen > TXV_SPK_CAP) { *reason = "prevout script too large"; return 0; }
        memcpy(g_txv_in[i].spk, spk, spklen);
        g_txv_in[i].spklen = (u32)spklen;

        if (is_p2tr(spk, (u32)spklen)) {
            has_taproot = 1;
            g_txv_in[i].shape = TXV_SHAPE_P2TR;
            if (g_txv_in[i].scriptSiglen != 0) { *reason = "p2tr scriptSig must be empty"; return 0; }
            if (g_txv_in[i].nwit != 1) { *reason = "p2tr keypath needs exactly 1 witness item"; return 0; }
            continue;
        }
        if (is_p2wpkh(spk, (u32)spklen)) {
            g_txv_in[i].shape = TXV_SHAPE_P2WPKH;
            if (g_txv_in[i].scriptSiglen != 0) { *reason = "p2wpkh scriptSig must be empty"; return 0; }
            if (g_txv_in[i].nwit != 2) { *reason = "p2wpkh needs exactly 2 witness items"; return 0; }
            continue;
        }
        if (is_p2wsh(spk, (u32)spklen)) {
            g_txv_in[i].shape = TXV_SHAPE_P2WSH;
            if (g_txv_in[i].scriptSiglen != 0) { *reason = "p2wsh scriptSig must be empty"; return 0; }
            if (g_txv_in[i].nwit < 2) { *reason = "p2wsh needs a witnessScript"; return 0; }
            continue;
        }
        g_txv_in[i].shape = TXV_SHAPE_LEGACY;
    }

    /* ---- pass 1b: the actual (possibly parallel) crypto verification for
     * every non-taproot input just classified above. ---- */
    if (!txv_verify_all(tx, txlen, nin, flags, reason)) return 0;

    if (!has_taproot) return 1;

    /* ---- pass 2 (sequential, unchanged): taproot key-path inputs, which
     * need EVERY input's resolved prevout (amount+scriptPubKey) for BIP341's
     * aggregate sighash. Re-resolves rather than reusing pass 1's cached
     * copies purely out of caution (pass 1 already has them in g_txv_in, so
     * this could reuse that directly -- kept as a fresh utxo_lsm_get pass
     * for now to minimize the diff against the already-proven pre-parallel
     * version; taproot inputs are the rare case, so the extra lookups cost
     * little). ---- */
    static u8 po[TXV_MAX_INPUTS*36];
    static u8 am[TXV_MAX_INPUTS*8];
    static u8 sp[TXV_MAX_INPUTS*(1+TXV_SPK_CAP)];
    static u8 spk34[TXV_MAX_INPUTS][34];
    static u8 is_tap[TXV_MAX_INPUTS];
    static u8 ns[8<<20];
    u64 sp_off = 0;
    for (u64 k=0;k<nin;k++){
        memcpy(po + k*36, g_txv_in[k].outpoint, 36);
        u32 index; memcpy(&index, g_txv_in[k].outpoint+32, 4);
        u64 value=0, h=0, cb=0; const u8* spk=0; unsigned long spklen=0;
        long r = utxo_lsm_get(lst, u, g_txv_in[k].outpoint, index, &value, &h, &cb, &spk, &spklen);
        if (r != 1) { *reason = "input references a missing/already-spent UTXO (pass 2)"; return 0; }
        for (int b=0;b<8;b++) am[k*8+b] = (u8)(value>>(8*b));
        if (spklen >= 0xfd) { *reason = "prevout script too large for taproot aggregate sighash"; return 0; }
        sp[sp_off++] = (u8)spklen;
        memcpy(sp+sp_off, spk, spklen);
        sp_off += spklen;
        if (is_p2tr(spk, (u32)spklen)) { is_tap[k] = 1; memcpy(spk34[k], spk, 34); }
        else is_tap[k] = 0;
    }
    long nslen = strip_witness(tx, (int64_t)txlen, ns, sizeof ns);
    if (nslen <= 0) { *reason = "malformed witness (strip failed)"; return 0; }

    for (u64 i=0;i<nin;i++){
        if (!is_tap[i]) continue;
        if (!taproot_keypath_verify(spk34[i], g_txv_in[i].wit[0], (int)g_txv_in[i].witlen[0],
                                    ns, nslen, (int64_t)i, po, am, sp, (int64_t)nin)) {
            *reason = "p2tr keypath signature invalid"; return 0;
        }
    }
    return 1;
}

/* ============================================================================
 * CROSS-TRANSACTION PARALLEL VERIFICATION (2026-08-19).
 *
 * Everything above this point is UNCHANGED and stays exactly as it was:
 * tx_verify_block_connect() still verifies one transaction at a time using
 * its own file-scope g_txv_in/g_txv_results, still used by
 * tests/test_tx_verify_parallel.c. This section is purely additive.
 *
 * WHY: profiling the live daemon during bulk catch-up (2026-08-19) showed
 * genuine secp256k1 verification arithmetic (fe_mul alone ~29.5% of sampled
 * CPU) dominating, while the daemon used only ~1.2 of the box's ~32 cores --
 * because the pool above only ever fans out across ONE transaction's own
 * inputs (gated by TXV_PARALLEL_MIN), and most transactions in this era of
 * chain history have too few inputs each to trigger it, even though a whole
 * BLOCK has plenty of independent signature checks spread across many small
 * transactions.
 *
 * WHY INPUT GRANULARITY, NOT TRANSACTION GRANULARITY: an earlier sketch of
 * this design dispatched at transaction granularity (an outer pool where
 * each worker ran a whole tx_verify_block_connect() call). That has two real
 * bugs: (a) a worker thread verifying an >=TXV_PARALLEL_MIN-input tx would
 * itself spawn the pool above, oversubscribing badly; (b) g_txv_in/
 * g_txv_results are file-scope statics -- safe today only because exactly
 * one tx is ever in flight at a time, but silently wrong under concurrent
 * transaction-granularity dispatch (a second worker's writes would race the
 * first's, or -- if instead made __thread -- a DIFFERENT worker thread
 * spawned by an outer worker would see an empty TLS copy, never the outer
 * thread's resolved data). Dispatching at INPUT granularity across one
 * flat, heap-allocated, block-scoped array sidesteps both: Phase 1 below is
 * the array's sole writer (single-threaded, matching the resolve pass
 * above), each Phase 2 worker only ever writes the result slots it
 * dequeued (disjoint by construction, no synchronization needed beyond the
 * pthread_create/join happens-before edges that already exist), and there
 * is only ONE pool, not a nested pair.
 *
 * IN-BLOCK CHAINED SPENDS: a transaction may spend an output created by an
 * earlier transaction in the SAME block. bidx_get (exported by
 * daemon/utxo_live.c) resolves against that in-block index first, falling
 * back to the confirmed UTXO set via utxo_lsm_get -- see bidx_get's own
 * comment for why it also takes the resolving tx's own block position (an
 * input may only resolve against a STRICTLY EARLIER transaction's output,
 * matching real consensus behavior; utxo_live.c enforces this).
 *
 * IN-BLOCK DOUBLE-SPENDS: today, an in-block double-spend is rejected only
 * because the OLD code's strict verify-then-apply interleaving means the
 * second spender's utxo_lsm_get fails once the first spender's output has
 * already been deleted. Once verification for the WHOLE block runs before
 * any of it applies (the entire point of this file), that accidental
 * detection disappears -- both conflicting spends would resolve
 * successfully against the not-yet-mutated confirmed set / in-block index.
 * daemon/utxo_live.c's apply_block_inner is responsible for an EXPLICIT
 * whole-block duplicate-outpoint check (an open-addressed hash set over
 * every tx's inputs, same 36-byte-key technique as bitcoin_utxo_lsm.asm's
 * tomb_hash_buf) BEFORE ever calling into this file -- this file assumes
 * that check already ran and never sees a block containing such a
 * double-spend. This is Core's own CheckBlock design: duplicate-outpoint
 * detection is a whole-block structural check, separate from and before
 * per-tx script verification, not something this file re-derives.
 *
 * TAPROOT stays exactly as sequential/single-tx-at-a-time as the pass 2
 * above -- rare in practice, and it reuses Phase 1's already-resolved
 * prevout data (value/spk/spklen) instead of re-querying, since Phase 1 has
 * already done that work for every input, taproot included.
 * ============================================================================ */

/* bidx_get: exported by daemon/utxo_live.c -- same argument/return shape as
 * utxo_lsm_get, plus the CALLING tx's own 0-based block position. Returns
 * 1 hit / 0 miss (not resolvable in-block; caller falls back to
 * utxo_lsm_get against the confirmed set). bx may be NULL (no in-block
 * index at all, e.g. a block with no chained spends) -- callers must check
 * before calling. */
extern long bidx_get(void* bx, u32 caller_tx_index, const u8 txid[32], u32 index,
                     u64* value, u64* height, u64* is_coinbase,
                     const u8** script, unsigned long* slen);

/* Mirrors daemon/utxo_live.c's own block_tx_t exactly (same convention this
 * codebase already uses for struct lsm_state -- duplicated per file rather
 * than shared via a header). pn_in is tx_parse's own input count, reused
 * here to size the flat verify array without a second parsing pass. */
typedef struct {
    const u8* ptr;
    u64 len;
    u8  txid[32];
    u32 pn_in;
} block_tx_t;

/* realloc()s *buf up to need_bytes if it isn't already that big, tracking
 * the arena's real capacity in *cap_bytes separately from whatever the
 * CURRENT block only needs -- never shrinks. Same "allocate once, reuse"
 * arena pattern as daemon/utxo_live.c's own grow_arena (own copy here,
 * matching this codebase's convention of duplicating small file-local
 * helpers rather than sharing via a header): the original per-block
 * malloc/free of flat/res/ranges below measured ~4M minor page faults/sec
 * on the live daemon -- fresh allocations at bulk-mode block rates cost
 * more than the crypto work this file exists to parallelize. */
static void* grow_arena(void** buf, u64* cap_bytes, u64 need_bytes){
    if (need_bytes > *cap_bytes){
        void* p = realloc(*buf, need_bytes);
        if (!p) return 0;
        *buf = p; *cap_bytes = need_bytes;
    }
    return *buf;
}

#define TXVB_MAX_WORKERS 64

typedef struct {
    u64 tx_index;
    u32 local_idx;               /* 0-based position among THIS tx's own
                                   * inputs -- the sighash primitives need
                                   * this, not the flat array's global index */
    const u8* tx_ptr; u64 tx_len; /* this input's own tx -- workers no
                                   * longer receive tx/txlen as a call arg
                                   * since different flat-array entries
                                   * belong to different transactions */
    const u8* outpoint;
    const u8* scriptSig; u32 scriptSiglen;
    const u8* wit[TXV_MAX_WIT_ITEMS]; u32 witlen[TXV_MAX_WIT_ITEMS]; u32 nwit;
    u64 value;
    u8  spk[TXV_SPK_CAP]; u32 spklen;
    u8  shape;
} txvb_in_t;

typedef struct { u8 ok; char reason[64]; } txvb_result_t;
typedef struct { u64 lo, hi; } txvb_txrange_t;

/* Parses ONE tx's inputs (+ witnesses) into flat[base..base+nin), mirroring
 * txv_parse's own CompactSize decode exactly (reuses txv_rd_cs directly --
 * that low-level reader is already shared, only this per-tx driving loop is
 * duplicated), writing into a caller-supplied flat array/offset instead of
 * g_txv_in[0..). Bounds-checks base+nin against cap defensively rather than
 * trusting the caller's sizing sum. */
static int txvb_parse_tx(const u8* tx, u64 txlen, u64 tx_index,
                         txvb_in_t* flat, u64 base, u64 cap,
                         u64* out_nin, const char** reason){
    const u8* p = tx; const u8* end = tx+txlen;
    int ok = 1;
    if (txlen < 10) { *reason = "tx too short"; return 0; }
    p += 4;
    int segwit = (p+2<=end && p[0]==0x00 && p[1]==0x01);
    if (segwit) p += 2;
    u64 nin = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad n_in varint"; return 0; }
    if (nin == 0) { *reason = "input count out of bounds"; return 0; }
    if (base + nin > cap) { *reason = "block input count exceeds sizing pass"; return 0; }
    for (u64 i=0;i<nin;i++){
        txvb_in_t* e = &flat[base+i];
        e->tx_index = tx_index; e->local_idx = (u32)i;
        e->tx_ptr = tx; e->tx_len = txlen;
        if (p+36 > end) { *reason = "truncated outpoint"; return 0; }
        e->outpoint = p; p += 36;
        u64 sl = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad scriptSig varint"; return 0; }
        if ((u64)(end-p) < sl+4) { *reason = "truncated scriptSig/sequence"; return 0; }
        e->scriptSig = p; e->scriptSiglen = (u32)sl;
        p += sl + 4;
        e->nwit = 0;
    }
    u64 nout = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad n_out varint"; return 0; }
    for (u64 i=0;i<nout;i++){
        if (p+8>end){ *reason = "truncated output"; return 0; }
        p += 8;
        u64 sl = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad output script varint"; return 0; }
        if ((u64)(end-p) < sl){ *reason = "truncated output script"; return 0; }
        p += sl;
    }
    if (segwit){
        for (u64 i=0;i<nin;i++){
            txvb_in_t* e = &flat[base+i];
            u64 nitems = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad witness item-count varint"; return 0; }
            if (nitems > TXV_MAX_WIT_ITEMS) { *reason = "too many witness items"; return 0; }
            e->nwit = (u32)nitems;
            for (u64 j=0;j<nitems;j++){
                u64 il = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad witness-item-len varint"; return 0; }
                if ((u64)(end-p) < il){ *reason = "truncated witness item"; return 0; }
                e->wit[j] = p; e->witlen[j] = (u32)il;
                p += il;
            }
        }
    }
    *out_nin = nin;
    return 1;
}

/* Mirrors txv_verify_one exactly, reading a caller-supplied entry pointer
 * instead of g_txv_in[i], and in->local_idx (this input's position within
 * ITS OWN tx) instead of a bare loop index for the sighash-position
 * arguments the underlying primitives need. */
static int txvb_verify_one(const u8* tx, u64 txlen, txvb_in_t* in, unsigned long long flags,
                           u8* sv_work, unsigned long sv_workcap, const char** reason){
    switch (in->shape){
    case TXV_SHAPE_P2WPKH:
        if (!p2wpkh_verify(tx, (int64_t)txlen, (int64_t)in->local_idx, in->spk, (int64_t)in->spklen, in->value,
                           in->wit[0], in->witlen[0], in->wit[1], in->witlen[1])) {
            *reason = "p2wpkh signature invalid"; return 0;
        }
        return 1;
    case TXV_SHAPE_P2WSH: {
        const u8* ws = in->wit[in->nwit-1];
        u32 wslen = in->witlen[in->nwit-1];
        if (wslen >= 34 && ws[0]==0x21 && ws[wslen-1]==0xac){
            if (!p2wsh_verify_checksig(tx, (int64_t)txlen, (int64_t)in->local_idx, in->value, ws, wslen,
                                       in->wit[0], in->witlen[0], ws+1, 33)) {
                *reason = "p2wsh checksig invalid"; return 0;
            }
            return 1;
        }
        if (wslen >= 3+33+33 && ws[0]==0x52 && ws[wslen-1]==0xae && in->nwit >= 4){
            if (!p2wsh_verify_multisig(tx, (int64_t)txlen, (int64_t)in->local_idx, in->value, ws, wslen,
                                       in->wit[2], in->witlen[2], in->wit[1], in->witlen[1],
                                       ws+2, ws+36)) {
                *reason = "p2wsh multisig invalid"; return 0;
            }
            return 1;
        }
        *reason = "unsupported p2wsh witnessScript shape"; return 0;
    }
    case TXV_SHAPE_LEGACY: {
        int err = sv_verify_script(in->scriptSig, in->scriptSiglen, in->spk, in->spklen,
                                   flags, (unsigned long)in->local_idx, tx, txlen, sv_work, sv_workcap);
        if (err != 0) { *reason = "legacy script verification failed"; return 0; }
        return 1;
    }
    default: /* taproot: handled by the sequential taproot pass, never here */
        return 1;
    }
}

typedef struct {
    txvb_in_t* flat; txvb_result_t* res; unsigned long long flags; u64 lo, hi;
} txvb_warg_t;

static void* txvb_worker(void* argp){
    txvb_warg_t* a = (txvb_warg_t*)argp;
    static __thread u8 sv_work[1<<20];  /* per-THREAD -- see txv_worker_thread's
                                         * own comment above, identical reasoning */
    for (u64 i=a->lo;i<a->hi;i++){
        if (a->flat[i].shape == TXV_SHAPE_P2TR) { a->res[i].ok = 1; continue; }
        const char* r = 0;
        int ok = txvb_verify_one(a->flat[i].tx_ptr, a->flat[i].tx_len, &a->flat[i], a->flags, sv_work, sizeof sv_work, &r);
        a->res[i].ok = ok ? 1 : 0;
        if (!ok) { size_t n=strlen(r); if(n>63)n=63; memcpy(a->res[i].reason, r, n); a->res[i].reason[n]=0; }
    }
    return 0;
}

/* txvb_verify_all: verify every non-taproot input across the WHOLE block's
 * flat array, in parallel once there's enough work to be worth it (same
 * TXV_PARALLEL_MIN threshold and reasoning as above, just measured
 * block-wide instead of per-tx). Always fills res[] completely for every
 * non-taproot entry and returns -- no early exit on the first failure,
 * unlike txv_verify_all -- the caller (tx_verify_block_connect_all's Phase 4)
 * is the single place that scans res[] and decides accept/reject, so the
 * "earliest failing tx in block order" logic exists in exactly one place. */
static void txvb_verify_all(txvb_in_t* flat, txvb_result_t* res, u64 total, unsigned long long flags){
    u64 nverify = 0;
    for (u64 i=0;i<total;i++){
        if (flat[i].shape != TXV_SHAPE_P2TR) { nverify++; res[i].ok=0; res[i].reason[0]=0; }
        else res[i].ok = 1;
    }
    if (nverify == 0) return;

    if (nverify < TXV_PARALLEL_MIN){
        /* plain static, not __thread -- this branch only ever runs on the
         * calling thread (sequential, no pthread_create here), same as
         * txv_verify_all's own equivalent branch above. */
        static u8 sv_work[1<<20];
        for (u64 i=0;i<total;i++){
            if (flat[i].shape == TXV_SHAPE_P2TR) continue;
            const char* r = 0;
            int ok = txvb_verify_one(flat[i].tx_ptr, flat[i].tx_len, &flat[i], flags, sv_work, sizeof sv_work, &r);
            res[i].ok = ok?1:0;
            if (!ok) { size_t n=strlen(r); if(n>63)n=63; memcpy(res[i].reason,r,n); res[i].reason[n]=0; }
        }
        return;
    }

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN); if (ncpu < 1) ncpu = 1;
    int nworkers = (int)(nverify < (u64)ncpu ? nverify : (u64)ncpu);
    if (nworkers > TXVB_MAX_WORKERS) nworkers = TXVB_MAX_WORKERS;
    if (nworkers < 1) nworkers = 1;

    u64 per = (total + (u64)nworkers - 1) / (u64)nworkers;
    pthread_t tids[TXVB_MAX_WORKERS];
    txvb_warg_t args[TXVB_MAX_WORKERS];
    int spawned = 0;
    for (int w=0; w<nworkers; w++){
        u64 lo = (u64)w*per, hi = lo+per; if (hi>total) hi=total;
        if (lo >= hi) break;
        args[spawned].flat=flat; args[spawned].res=res; args[spawned].flags=flags;
        args[spawned].lo=lo; args[spawned].hi=hi;
        if (pthread_create(&tids[spawned], 0, txvb_worker, &args[spawned]) != 0){
            /* same fallback story as txv_verify_all: whatever didn't get a
             * thread stays at its zeroed res[] slot, picked up below. */
            break;
        }
        spawned++;
    }
    for (int w=0; w<spawned; w++) pthread_join(tids[w], 0);

    /* plain static, not __thread -- runs only after every worker has
     * already joined above (sequential), same as txv_verify_all's own
     * equivalent fallback sweep. */
    static u8 sv_work_main[1<<20];
    for (u64 i=0;i<total;i++){
        if (flat[i].shape == TXV_SHAPE_P2TR) continue;
        if (res[i].ok) continue;
        if (res[i].reason[0] != 0) continue;   /* a real reported failure already */
        const char* r = 0;
        int ok = txvb_verify_one(flat[i].tx_ptr, flat[i].tx_len, &flat[i], flags, sv_work_main, sizeof sv_work_main, &r);
        res[i].ok = ok ? 1 : 0;
        if (!ok) { size_t n=strlen(r); if(n>63)n=63; memcpy(res[i].reason, r, n); res[i].reason[n]=0; }
    }
}

/* tx_verify_block_connect_all(txs, ntx, height, block_hash32, lst, u, bx,
 * &fail_tx_index, &reason) -> 1 accept / 0 reject. txs[0] MUST be the
 * coinbase (skipped entirely -- matches Bitcoin's own "coinbase is always
 * the first tx" rule already relied on elsewhere in this codebase); bx is
 * the in-block index from daemon/utxo_live.c's Phase 0 (may be NULL if the
 * block has no chained spends at all -- callers may pass NULL freely, this
 * function checks before calling bidx_get). Caller (daemon/utxo_live.c) is
 * responsible for the separate whole-block duplicate-outpoint check BEFORE
 * calling this -- see this section's header comment. */
int tx_verify_block_connect_all(const block_tx_t* txs, u64 ntx, long height,
                                const u8 block_hash32[32], void* lst, void* u, void* bx,
                                u64* fail_tx_index, const char** reason){
    static char g_rbuf[64];
    unsigned long long flags = script_flags_for_block((unsigned long long)height, block_hash32);

    u64 total_nin = 0;
    for (u64 t=1; t<ntx; t++) total_nin += txs[t].pn_in;
    if (total_nin == 0) return 1;

    static txvb_in_t* g_flat = 0;        static u64 g_flat_cap = 0;
    static txvb_result_t* g_res = 0;     static u64 g_res_cap = 0;
    static txvb_txrange_t* g_ranges = 0; static u64 g_ranges_cap = 0;
    txvb_in_t* flat = grow_arena((void**)&g_flat, &g_flat_cap, total_nin * sizeof(txvb_in_t));
    txvb_result_t* res = grow_arena((void**)&g_res, &g_res_cap, total_nin * sizeof(txvb_result_t));
    txvb_txrange_t* ranges = grow_arena((void**)&g_ranges, &g_ranges_cap, ntx * sizeof(txvb_txrange_t));
    if (!flat || !res || !ranges) {
        *reason = "out of memory"; *fail_tx_index = 0;
        return 0;
    }

    /* ---- Phase 0/parse: expand every tx's inputs into the flat array. ---- */
    u64 base = 0;
    for (u64 t=1; t<ntx; t++){
        u64 nin_this;
        if (!txvb_parse_tx(txs[t].ptr, txs[t].len, t, flat, base, total_nin, &nin_this, reason)) {
            *fail_tx_index = t; return 0;
        }
        ranges[t].lo = base; ranges[t].hi = base + nin_this;
        base += nin_this;
    }
    if (base != total_nin) {
        /* tx_parse (utxo_live.c's sizing pass) and txvb_parse_tx (this
         * file's own CompactSize decode) disagree on some tx's input count
         * -- an internal consistency bug, not a malformed-block condition
         * (a genuinely malformed tx would have failed txvb_parse_tx above
         * already). */
        *reason = "internal: input count parse mismatch"; *fail_tx_index = 0;
        return 0;
    }

    /* ---- Phase 1: resolve + classify every input, sequential, block-wide
     * (in-block index first, confirmed set fallback). ---- */
    int has_taproot = 0;
    for (u64 gi=0; gi<total_nin; gi++){
        txvb_in_t* in = &flat[gi];
        u32 index; memcpy(&index, in->outpoint+32, 4);
        u64 value=0, uheight=0, ucb=0; const u8* spk=0; unsigned long spklen=0;
        long r = -1;
        if (bx) r = bidx_get(bx, (u32)in->tx_index, in->outpoint, index, &value, &uheight, &ucb, &spk, &spklen);
        if (r != 1) r = utxo_lsm_get(lst, u, in->outpoint, index, &value, &uheight, &ucb, &spk, &spklen);
        if (r != 1) { *reason = "input references a missing/already-spent UTXO"; *fail_tx_index = in->tx_index; goto fail; }
        if (ucb) {
            long conf = height - (long)uheight;
            if (conf < COINBASE_MATURITY) { *reason = "immature coinbase spend (100-block rule)"; *fail_tx_index = in->tx_index; goto fail; }
        }
        in->value = value;
        if (spklen > TXV_SPK_CAP) { *reason = "prevout script too large"; *fail_tx_index = in->tx_index; goto fail; }
        memcpy(in->spk, spk, spklen); in->spklen = (u32)spklen;

        if (is_p2tr(spk, (u32)spklen)) {
            has_taproot = 1; in->shape = TXV_SHAPE_P2TR;
            if (in->scriptSiglen != 0) { *reason = "p2tr scriptSig must be empty"; *fail_tx_index = in->tx_index; goto fail; }
            if (in->nwit != 1) { *reason = "p2tr keypath needs exactly 1 witness item"; *fail_tx_index = in->tx_index; goto fail; }
            continue;
        }
        if (is_p2wpkh(spk, (u32)spklen)) {
            in->shape = TXV_SHAPE_P2WPKH;
            if (in->scriptSiglen != 0) { *reason = "p2wpkh scriptSig must be empty"; *fail_tx_index = in->tx_index; goto fail; }
            if (in->nwit != 2) { *reason = "p2wpkh needs exactly 2 witness items"; *fail_tx_index = in->tx_index; goto fail; }
            continue;
        }
        if (is_p2wsh(spk, (u32)spklen)) {
            in->shape = TXV_SHAPE_P2WSH;
            if (in->scriptSiglen != 0) { *reason = "p2wsh scriptSig must be empty"; *fail_tx_index = in->tx_index; goto fail; }
            if (in->nwit < 2) { *reason = "p2wsh needs a witnessScript"; *fail_tx_index = in->tx_index; goto fail; }
            continue;
        }
        in->shape = TXV_SHAPE_LEGACY;
    }

    /* ---- Phase 2: the actual (parallel) crypto verification for every
     * non-taproot input in the whole block. ---- */
    txvb_verify_all(flat, res, total_nin, flags);

    /* ---- Phase 4 (before Phase 3/taproot -- see this section's header
     * comment for the accepted, documented scoping of "earliest tx" when a
     * block has BOTH a non-taproot and a taproot problem): first failing
     * non-taproot input, in block order (flat array order already matches,
     * since entries are appended tx-by-tx in order). ---- */
    for (u64 gi=0; gi<total_nin; gi++){
        if (flat[gi].shape == TXV_SHAPE_P2TR) continue;
        if (!res[gi].ok) {
            *fail_tx_index = flat[gi].tx_index;
            size_t n = strlen(res[gi].reason); if (n > sizeof(g_rbuf)-1) n = sizeof(g_rbuf)-1;
            memcpy(g_rbuf, res[gi].reason, n); g_rbuf[n] = 0;
            *reason = g_rbuf;
            goto fail;
        }
    }

    /* ---- Phase 3: taproot key-path inputs, sequential, one tx at a time,
     * exactly as tx_verify_block_connect's own pass 2 -- reuses Phase 1's
     * already-resolved value/spk/spklen instead of re-querying (safe:
     * nothing mutates UTXO state between Phase 1 and here). ---- */
    if (has_taproot) {
        static u8 ns[8<<20];
        static u8* g_po = 0;      static u64 g_po_cap = 0;
        static u8* g_am = 0;      static u64 g_am_cap = 0;
        static u8* g_sp = 0;      static u64 g_sp_cap = 0;
        static u8 (*g_spk34)[34] = 0; static u64 g_spk34_cap = 0;
        static u8* g_is_tap = 0;  static u64 g_is_tap_cap = 0;
        for (u64 t=1; t<ntx; t++){
            u64 lo = ranges[t].lo, hi = ranges[t].hi, nin_t = hi-lo;
            int tx_has_tap = 0;
            for (u64 gi=lo; gi<hi; gi++) if (flat[gi].shape == TXV_SHAPE_P2TR) { tx_has_tap = 1; break; }
            if (!tx_has_tap) continue;

            /* Persistent, grown-on-demand arenas -- see grow_arena's own
             * comment above for why (same fix as flat/res/ranges). Sized
             * per single-tx input count, not block-wide, since taproot
             * pass 3 stays sequential/single-tx-at-a-time. */
            u8* po = grow_arena((void**)&g_po, &g_po_cap, nin_t*36);
            u8* am = grow_arena((void**)&g_am, &g_am_cap, nin_t*8);
            u8* sp = grow_arena((void**)&g_sp, &g_sp_cap, nin_t*(1+TXV_SPK_CAP));
            u8 (*spk34)[34] = grow_arena((void**)&g_spk34, &g_spk34_cap, nin_t*34);
            u8* is_tap = grow_arena((void**)&g_is_tap, &g_is_tap_cap, nin_t);
            if (!po || !am || !sp || !spk34 || !is_tap) {
                *reason = "out of memory"; *fail_tx_index = t;
                goto fail;
            }
            u64 sp_off = 0;
            int tap_fail = 0;
            for (u64 k=0;k<nin_t;k++){
                txvb_in_t* in = &flat[lo+k];
                memcpy(po+k*36, in->outpoint, 36);
                for (int b=0;b<8;b++) am[k*8+b] = (u8)(in->value>>(8*b));
                if (in->spklen >= 0xfd) { *reason = "prevout script too large for taproot aggregate sighash"; *fail_tx_index = t; tap_fail = 1; break; }
                sp[sp_off++] = (u8)in->spklen;
                memcpy(sp+sp_off, in->spk, in->spklen); sp_off += in->spklen;
                if (in->shape == TXV_SHAPE_P2TR) { is_tap[k] = 1; memcpy(spk34[k], in->spk, 34); }
                else is_tap[k] = 0;
            }
            if (!tap_fail) {
                long nslen = strip_witness(txs[t].ptr, (int64_t)txs[t].len, ns, sizeof ns);
                if (nslen <= 0) { *reason = "malformed witness (strip failed)"; *fail_tx_index = t; tap_fail = 1; }
                else {
                    for (u64 k=0;k<nin_t;k++){
                        if (!is_tap[k]) continue;
                        txvb_in_t* in = &flat[lo+k];
                        if (!taproot_keypath_verify(spk34[k], in->wit[0], (int)in->witlen[0],
                                                    ns, nslen, (int64_t)k, po, am, sp, (int64_t)nin_t)) {
                            *reason = "p2tr keypath signature invalid"; *fail_tx_index = t; tap_fail = 1; break;
                        }
                    }
                }
            }
            if (tap_fail) goto fail;
        }
    }

    return 1;

fail:
    return 0;
}

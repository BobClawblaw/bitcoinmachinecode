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
 * PARALLEL VERIFICATION (2026-08-19). Signature verification (ECDSA/Schnorr)
 * is the dominant cost of block connection and was, until now, entirely
 * single-threaded -- a from-scratch archive replay measured at ~1 core of
 * this box's 32 in active use. This file now resolves every input's
 * prevout SEQUENTIALLY first (exactly as before -- this is cheap, and is
 * what preserves correctness: same-tx input order and the surrounding
 * apply_block_inner's per-tx interleaving of verify-then-apply are what
 * make same-block spends resolve correctly, and none of that changes here),
 * then fans the expensive per-input crypto checks out across forked worker
 * processes -- the same fork()+shared-mmap-results pattern dl_catchup
 * already uses for parallel block downloading -- and collects pass/fail
 * before deciding whether to apply the transaction. Ordering between
 * transactions and between blocks is completely unchanged: only the
 * (already provably independent, once each input's prevout is resolved)
 * crypto work for ONE transaction's OWN inputs runs concurrently. Taproot
 * inputs, needing the BIP341 aggregate sighash built from every input's
 * prevout, stay on the existing sequential pass 2 -- rarer in practice, and
 * keeping it simple keeps the parallel path's correctness argument simple.
 */
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

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
 * bitcoin_txval_modern.c's own PREV_SPK_BUF_MAX philosophy. TXV_SPK_CAP must
 * stay under 0xfd: the taproot aggregate below mirrors txval_modern's own
 * single-length-byte prevout-script encoding exactly (not a full CompactSize
 * varint), since that is the encoding taproot_keypath_verify's asm expects. */
#define TXV_MAX_INPUTS    20000
#define TXV_SPK_CAP         252
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

/* Below this many non-taproot inputs, forking costs more than it saves --
 * fork() plus 2 mmap/munmap round-trips easily costs tens of microseconds,
 * comparable to a handful of ECDSA verifies (~115us each per the project's
 * own bench_ecdsa measurement). Chosen conservatively; a real profile could
 * tune it, but correctness does not depend on the exact value -- only
 * throughput does. */
#define TXV_PARALLEL_MIN 8
#define TXV_MAX_WORKERS  16

/* Set by utxo_live.c (via txv_set_bulk_mode) whenever its own memtable is
 * bulk-sized -- a from-scratch or long-gap catch-up that keeps growing a
 * multi-GB in-process UTXO structure. fork()'s copy-on-write page-table
 * setup cost scales with the PARENT's resident size, so forking workers out
 * of a process that is itself the thing getting bigger every block gets
 * progressively more expensive over the course of a catch-up -- observed in
 * production as a geometric slowdown (20k-height chunks going from ~5s to
 * 3.5min as RSS climbed past ~1.5GB) that tracked fork() cost, not
 * signature-verify cost (confirmed by repeated stack samples of the running
 * process landing inside fork() every time). Steady-state serving keeps the
 * memtable small and bounded by design (see utxo_live.c's own downshift
 * comment), where forking stays cheap -- so only skip parallel dispatch
 * while bulk mode is active, not permanently. */
static int g_txv_bulk_mode = 0;
void txv_set_bulk_mode(int on){ g_txv_bulk_mode = on; }

typedef struct { u8 ok; char reason[64]; } txv_result_t;

/* txv_verify_all(): verify every non-taproot input in g_txv_in[0..nin),
 * in parallel once there's enough work to be worth it AND we're not inside
 * a bulk UTXO catch-up (g_txv_bulk_mode -- see its own comment). Sequential
 * fallback below TXV_PARALLEL_MIN keeps small (the common case,
 * historically) txs exactly as fast as before with zero fork overhead.
 * Returns 1 all valid / 0 at least one invalid (reason set). */
static int txv_verify_all(const u8* tx, u64 txlen, u64 nin, unsigned long long flags,
                          const char** reason){
    u64 nverify = 0;
    for (u64 i=0;i<nin;i++) if (g_txv_in[i].shape != TXV_SHAPE_P2TR) nverify++;
    if (nverify == 0) return 1;

    static char rbuf[64];

    if (nverify < TXV_PARALLEL_MIN || g_txv_bulk_mode){
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

    txv_result_t* results = mmap(0, sizeof(txv_result_t)*(size_t)nin, PROT_READ|PROT_WRITE,
                                 MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (results == MAP_FAILED) {
        /* fall back to sequential rather than fail the block over a
         * resource hiccup -- correctness doesn't depend on parallelism */
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
    memset(results, 0, sizeof(txv_result_t)*(size_t)nin);

    u64 per = (nin + (u64)nworkers - 1) / (u64)nworkers;
    pid_t pids[TXV_MAX_WORKERS];
    int spawned = 0;
    for (int w=0; w<nworkers; w++){
        u64 lo = (u64)w*per, hi = lo+per; if (hi>nin) hi=nin;
        if (lo >= hi) break;
        pid_t p = fork();
        if (p < 0){
            /* fork failed partway: wait for whoever's already running, then
             * finish the remaining range (including this one) inline,
             * sequentially, in THIS process -- still correct, just slower. */
            break;
        }
        if (p == 0){
            static u8 sv_work[1<<20];
            for (u64 i=lo;i<hi;i++){
                if (g_txv_in[i].shape == TXV_SHAPE_P2TR) { results[i].ok = 1; continue; }
                const char* r = 0;
                int ok = txv_verify_one(tx, txlen, i, flags, sv_work, sizeof sv_work, &r);
                results[i].ok = ok ? 1 : 0;
                if (!ok) { size_t n=strlen(r); if(n>63)n=63; memcpy(results[i].reason, r, n); results[i].reason[n]=0; }
            }
            _exit(0);
        }
        pids[spawned++] = p;
    }
    /* whatever didn't get spawned (fork() failure, or none attempted
     * because nworkers==0 somehow) -- covered by the "finish inline" pass
     * below, which re-checks every index's results[i] and fills in any
     * still-untouched (ok==0, reason[0]==0 -- distinguishable from a real
     * failure, which always sets reason) slot itself. */
    for (int w=0; w<spawned; w++){
        int status = 0;
        waitpid(pids[w], &status, 0);
        if (!(WIFEXITED(status) && WEXITSTATUS(status)==0)){
            /* a worker crashed/was killed: treat every slot it owned as
             * unverified rather than trust whatever partial writes landed --
             * the inline sweep below re-verifies anything still blank. */
        }
    }
    static u8 sv_work_main[1<<20];
    int all_ok = 1;
    for (u64 i=0;i<nin;i++){
        if (g_txv_in[i].shape == TXV_SHAPE_P2TR) continue;
        if (results[i].ok) continue;
        if (results[i].reason[0] != 0){
            /* a real, reported failure */
            memcpy(rbuf, results[i].reason, sizeof rbuf);
            all_ok = 0; break;
        }
        /* blank: either genuinely not yet covered (fork() failure above) or
         * a crashed worker's slot -- verify it inline now, in this process,
         * so a transient resource failure never silently skips a check. */
        const char* r = 0;
        if (!txv_verify_one(tx, txlen, i, flags, sv_work_main, sizeof sv_work_main, &r)) {
            memcpy(rbuf, r, strlen(r)+1 > sizeof rbuf ? sizeof rbuf : strlen(r)+1);
            all_ok = 0; break;
        }
    }
    munmap(results, sizeof(txv_result_t)*(size_t)nin);   /* only after every read above */
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

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
 * runs concurrently.
 *
 * TAPROOT USED TO BE EXCLUDED FROM THAT and verified in a sequential pass
 * afterwards, at both entry points, for two reasons: BIP341's sighash needs
 * WHOLE-TRANSACTION data (every input's outpoint/amount/scriptPubKey plus
 * the witness-stripped serialization), and secp256k1_taproot.asm's staging
 * buffers were process-global. Both are gone as of 2026-08-23. The buffers
 * are thread-local (gated by tests/test_taproot_thread_stress), and a
 * separate cheap pass now builds the aggregate data for every
 * taproot-bearing transaction in the block into one arena that is read-only
 * for the whole of verification. See the TAPROOT AGGREGATE-SIGHASH ARENA
 * comment below and PERF_SCOPE.md section 14.7 -- the profile that forced
 * this measured 32 worker threads asleep and one thread running at 67% field
 * arithmetic on an 85%-idle box.
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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "../bmc_thread.h"
#include <semaphore.h>

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
extern int  sv_classify_segwit(const u8* spk, u32 spl, const u8* ss, u32 ssl,
                               u32* version, const u8** prog, u32* proglen, int* wrapped);
extern int  sv_verify_witness_v0(const u8* prog, u32 proglen,
                                 const u8* const* wit, const u32* witlen, u32 nwit,
                                 u64 amount, unsigned long long flags, unsigned long nIn,
                                 const u8* tx, unsigned long txlen, u8* work, unsigned long workcap);
#define TXV_FLAG_WITNESS (1ULL<<11)   /* SCRIPT_VERIFY_WITNESS, Core bit */
/* SCRIPT_VERIFY_TAPROOT, Core bit 17 (script_flags_consts.inc SFC_BIT_TAPROOT).
 * script_flags_for_block() already computes this correctly, INCLUDING Core's
 * one mainnet exception block -- 692261,
 * 0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad, for which
 * Core's chainparams override the flags down to P2SH|WITNESS. That block spends
 * four real witness-v1 outputs with NO witness at all, which is invalid under
 * taproot and valid without it. The two P2TR dispatch sites below used to
 * ignore the computed flags entirely and apply taproot rules unconditionally,
 * so the replay rejected that block: a FALSE REJECT. See LOG.md incident #22. */
#define TXV_FLAG_TAPROOT (1ULL<<17)
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
/* taproot_verify_input (bitcoin_taproot_sighash.c): full BIP341/BIP342
 * dispatch for one P2TR input -- key-path (with/without annex) or
 * script-path (control-block Merkle commitment + tapscript execution via
 * the shared script_eval interpreter), replacing the old "P2TR always
 * means exactly-one-witness-item key-path" assumption below. Everything
 * else (annex/control-block classification, weight budget) lives there. */
extern int  taproot_verify_input(const u8* spk,
                                 const u8* const* wit, const u32* witlen, u32 nwit,
                                 const u8* tx, int64_t txlen, int64_t n_in,
                                 const u8* prevouts, const u8* amounts,
                                 const u8* spks, int64_t num_inputs,
                                 const char** reason);
/* IR-9: same, with the caller's script flags (policy bits reach the leaf) */
extern int taproot_verify_input_flags(const u8* spk,
                                 const u8* const* wit, const u32* witlen, u32 nwit,
                                 const u8* tx, int64_t txlen, int64_t n_in,
                                 const u8* prevouts, const u8* amounts,
                                 const u8* spks, int64_t num_inputs,
                                 const char** reason, unsigned long long flags);

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
/* Per-input witness stack item count. The history here is two incidents, and
 * the second one invalidated the first one's reasoning:
 *
 *   #15 (498787 tx 2420) raised this from 8, which had rejected an ordinary
 *   17-item P2SH-P2WSH stack. It settled on 1004, arguing that a P2WSH
 *   witness's items BECOME the initial stack, so >1001 could never satisfy
 *   MAX_STACK(1000)/cleanstack, plus tapscript's script+control+annex.
 *
 *   #26 (761249 tx 121, txid 73be398c...2a7e) proved that argument wrong on
 *   real mainnet data: ONE input with 500,003 witness items, accepted by
 *   Core, rejected here. The hole is the same one #19 found for the element
 *   SIZE limit -- Core runs the BIP342 OP_SUCCESSx scan BEFORE the stack
 *   limits ("OP_SUCCESSx processing overrides everything"), so a tapscript
 *   spend under an OP_SUCCESSx leaf is consensus-VALID with any number of
 *   stack items. #19's author flagged exactly this as a known divergence and
 *   left it; the replay then walked into it.
 *
 * There is no consensus item-count rule at all, so the only sound bound is
 * what the wire can physically express. Every item costs at least one byte
 * (its own compactsize length prefix, 0x00 for an empty item), so a
 * transaction of length L carries at most L items, and L is bounded by
 * MAX_BLOCK_SERIALIZED_SIZE = 4,000,000, which is validated before this
 * point. The pool stores ptr+len (12 B/item), so the worst case a valid
 * block can force is ~48 MB of pool -- bounded, and bounded by data the
 * block-level checks already accepted.
 *
 * This is a reject THRESHOLD, not an array dimension (items live in the
 * growable witpool below), so raising it costs nothing until the data
 * actually arrives. */
#define TXV_MAX_WIT_ITEMS    4000000

#define TXV_SHAPE_LEGACY  0
#define TXV_SHAPE_P2WPKH  1
#define TXV_SHAPE_P2WSH   2
#define TXV_SHAPE_P2TR    3
#define TXV_SHAPE_WV0     4   /* witness v0 program (native or P2SH-wrapped): general interpreter path */
#define TXV_SHAPE_WPASS   5   /* unknown witness version (1..16, not taproot): anyone-can-spend under consensus flags */

typedef struct {
    const u8* outpoint;             /* 36 bytes: txid(32)+index(4), in tx bytes */
    const u8* scriptSig; u32 scriptSiglen;
    const u8** wit; u32* witlen; u32 nwit; u32 wit_off; /* wit/witlen resolved from g_wit_pool at
                                  * (wit_off) AFTER parse stops growing the pool -- offset, not pointer,
                                  * survives the pool's realloc, same discipline as spk_off. */
    const u8* wprog; u32 wproglen; u8 wrapped;   /* TXV_SHAPE_WV0: the witness program (spk+2, or the P2SH redeemScript's program) */
    /* resolved during the sequential pass, before any forking -- self-
     * contained (a COPY, not a utxo_lsm_get pointer, which is only valid
     * until the next call) so a forked child can safely read it. */
    u64 value;
    u8  spk[TXV_SPK_CAP]; u32 spklen;
    u8  shape;
} txv_rawin_t;
static txv_rawin_t g_txv_in[TXV_MAX_INPUTS];

/* ---- VAL-10 / SER-3 (audit 2026-09-03): CANONICAL CompactSize ----
 *
 * Core's ReadCompactSize (serialize.h) throws "non-canonical
 * ReadCompactSize()" when a value is encoded in a wider form than it needs,
 * and "ReadCompactSize(): size too large" above MAX_SIZE (0x02000000). Every
 * decoder here accepted `fd 01 00` for 1, so a block containing such a
 * transaction parsed cleanly HERE and is undeserializable to every Core node
 * on the network -- and since txids are computed over the verbatim bytes, the
 * merkle root still matches, so nothing else caught it. A miner producing one
 * would split this node onto a chain no one else can follow.
 *
 * The minimum a width may encode: 0xfd for the 3-byte form, 0x10000 for the
 * 5-byte form, 0x100000000 for the 9-byte form. Nothing valid is lost --
 * a canonical encoder never emits the wider form -- and nothing already in
 * the archive can be affected, because a non-canonical transaction could
 * never have been relayed to us by a Core node in the first place. */
#define TXV_CS_MAX_SIZE 0x02000000ULL
static u64 txv_rd_cs(const u8** p, const u8* end, int* ok){
    if (*p >= end) { *ok = 0; return 0; }
    const u8* b = *p; u8 f = b[0];
    if (f < 0xfd) { *p = b+1; return f; }
    if (f == 0xfd){ if (b+3>end){*ok=0;return 0;} u64 v=b[1]|((u64)b[2]<<8);
                    if (v < 0xfdULL){*ok=0;return 0;}                       /* non-canonical */
                    *p=b+3; if (v > TXV_CS_MAX_SIZE){*ok=0;return 0;} return v; }
    if (f == 0xfe){ if (b+5>end){*ok=0;return 0;} u64 v=0; for(int i=0;i<4;i++) v|=(u64)b[1+i]<<(8*i);
                    if (v <= 0xffffULL){*ok=0;return 0;}                    /* non-canonical */
                    *p=b+5; if (v > TXV_CS_MAX_SIZE){*ok=0;return 0;} return v; }
    if (b+9>end){*ok=0;return 0;} u64 v=0; for(int i=0;i<8;i++) v|=(u64)b[1+i]<<(8*i);
    if (v <= 0xffffffffULL){*ok=0;return 0;}                                /* non-canonical */
    *p=b+9; if (v > TXV_CS_MAX_SIZE){*ok=0;return 0;} return v;
}

/* Witness-item pool: (ptr-into-tx, len) pairs for every input's stack, so an
 * input's witness is not a fixed inline array (which at TXV_MAX_INPUTS x the
 * item cap would be hundreds of MB of mostly-empty storage per block). Two
 * parallel growable arrays; inputs reference a start OFFSET and resolve to
 * ptr/len addresses only AFTER parse stops growing the pool, exactly like
 * g_spk_pool/spk_off above (a realloc during parse would otherwise dangle a
 * pointer handed to an earlier input). The item pointers themselves aim into
 * the tx bytes, which are stable for the block. Bump-reset per block/tx. */
typedef struct { const u8** ptr; u32* len; u64 cap, used; } witpool_t;
static witpool_t g_wit_pool = {0};
/* Phase 2 slice 1 seam (2026-08-24): bitcoin_txv_parse.asm's twin of
 * txv_parse keeps pool GROWTH in C -- allocation is phase 3's boundary --
 * so the reserve gets a non-static name it can call. Same function. */
u64 txv_witpool_reserve(witpool_t* wp, u64 n);
/* Reserve n contiguous slots; returns the start offset, or ~0ull on OOM. */
u64 txv_witpool_reserve(witpool_t* wp, u64 n){
    if (wp->used + n > wp->cap){
        u64 nc = wp->cap ? wp->cap : 4096;
        while (nc < wp->used + n) nc *= 2;
        const u8** np = realloc(wp->ptr, nc*sizeof(const u8*));
        u32*      nl = realloc(wp->len, nc*sizeof(u32));
        if (np) wp->ptr = np;
        if (nl) wp->len = nl;
        if (!np || !nl) return ~0ull;
        wp->cap = nc;
    }
    u64 off = wp->used; wp->used += n; return off;
}

/* ---- packed byte-pool bump allocator ------------------------------------
 * Reused across blocks like grow_arena below, but bump-reset instead of
 * grown-per-entry. Backs (a) txvb_in_t's prevout scriptPubKey copies and
 * (b) the taproot aggregate-sighash arena. Cost is proportional to the
 * block's REAL byte total, not entries x worst-case. Grows (never shrinks)
 * only when a block's total need exceeds current capacity; `used` resets to
 * 0 at the start of every call, so a reused-but-dirty pool from an earlier
 * block is safe -- every byte handed out gets freshly written, nothing is
 * ever read from an unwritten pool region.
 *
 * Both entry points return byte OFFSETS, not pointers (2026-08-20, replacing
 * an earlier pointer-returning version that was a real dangling-pointer bug:
 * a LATER call in the same block's resolve loop can realloc() and relocate
 * pool->buf, silently invalidating every pointer already handed out to
 * EARLIER entries in that same loop -- confirmed in production: height
 * 184390's tx=1 legacy input resolved a correct P2PKH scriptPubKey, then
 * failed verification against garbage bytes). An offset stays valid
 * regardless of relocation; callers must resolve it to an address
 * (pool->buf + offset) only AFTER the pool is done growing, i.e. after the
 * resolve/build phase returns -- exactly when every current reader runs. */
typedef struct { u8* buf; u64 cap; u64 used; } bytepool_t;
static bytepool_t g_spk_pool = {0};

/* Reserve n uninitialised bytes; the caller writes them itself. Returns the
 * offset, or ~0ull on OOM. Callers must finish writing the region BEFORE the
 * next reserve/alloc on the same pool (which may relocate pool->buf). */
static u64 bytepool_reserve(bytepool_t* pool, u64 n){
    if (pool->used + n > pool->cap){
        u64 newcap = pool->cap ? pool->cap : 65536;
        while (newcap < pool->used + n) newcap *= 2;
        void* p = realloc(pool->buf, newcap);
        if (!p) return ~0ull;
        pool->buf = p; pool->cap = newcap;
    }
    u64 off = pool->used;
    pool->used += n;
    return off;
}
static u64 bytepool_alloc(bytepool_t* pool, const u8* src, u64 n){
    u64 off = bytepool_reserve(pool, n);
    if (off == ~0ull) return off;
    memcpy(pool->buf + off, src, n);
    return off;
}

/* ============================================================================
 * TAPROOT AGGREGATE-SIGHASH ARENA (PERF_SCOPE.md section 14.7, 2026-08-23)
 *
 * BIP341's sighash commits to EVERY input's outpoint, amount and
 * scriptPubKey, plus the witness-stripped transaction -- so verifying one
 * taproot input needs whole-transaction data, not just that input's own.
 * Until now that was rebuilt into one reused scratch arena per transaction,
 * which forced every taproot input in the block through a single sequential
 * pass while every other shape fanned out across the worker pool. Measured
 * on the live daemon at height ~797,000: 32 worker threads asleep, one
 * thread running at 67% field arithmetic, on an 85%-idle box.
 *
 * The parallel axis is ACROSS TRANSACTIONS, not within one. Measured against
 * Bitcoin Core at heights 825,000 and 825,001: 96% / 95% of taproot-bearing
 * transactions have exactly ONE taproot input (mean 1.13 / 1.11), so fanning
 * a transaction's own taproot inputs across threads finds nothing to fan out.
 *
 * Hence the two-phase shape:
 *
 *   Phase A (tapagg_build, sequential, cheap -- memcpy + strip_witness, no
 *   signature work): for every transaction with at least one taproot input,
 *   append its four aggregate arrays to ONE per-BLOCK arena and record a
 *   descriptor of byte offsets.
 *
 *   Phase B (tapagg_verify, parallel): every taproot input in the block is
 *   an ordinary entry in the flat verify array and is dispatched to the
 *   worker pool like any other shape. The arena is READ-ONLY for the whole
 *   of phase B -- which is precisely why phase A exists as a separate pass
 *   rather than having each worker rebuild its own transaction's arrays.
 *
 * Sizing: sum over taproot-bearing transactions of
 * (44*nin + sum(1+spklen) + txlen) -- a few MB per block. The `sp` array is
 * PACKED (1+spklen per input), not the nin*(1+TXV_SPK_CAP) worst case the
 * old per-transaction arena used.
 *
 * The prerequisite for any of this was secp256k1_taproot.asm's `tagh_buf`
 * and `tap_preimg` becoming thread-local (2026-08-23, gated by
 * tests/test_taproot_thread_stress: 29,236 wrong digests of 96,000 against
 * the pre-fix globals, 0 after). Those were the only shared mutable state on
 * the taproot path; everything else it touches (bitcoin_taproot_sighash.c's
 * BMC_TLS_BUF scratch, bitcoin_interp.asm's and bitcoin_scriptcodec.asm's
 * .tbss) was already per-thread.
 * ========================================================================= */

/* One transaction's BIP341 aggregate-sighash inputs, as byte OFFSETS into a
 * bytepool -- never pointers, since the pool reallocs as later transactions
 * are appended (same discipline as spk_off). */
typedef struct {
    u64 po_off;   /* nin*36 -- outpoints, wire order                       */
    u64 am_off;   /* nin*8  -- amounts, LE64                               */
    u64 sp_off;   /* packed: per input, one length byte then the spk bytes */
    u64 ns_off;   /* the witness-stripped tx serialization                 */
    u64 nslen;
    u64 nin;
} tapagg_t;

/* Yields input k's already-resolved outpoint / amount / scriptPubKey. Two
 * tiny adapters below (one per entry point) so phase A itself exists exactly
 * once and the two entry points cannot drift apart. */
typedef void (*tapin_fn)(void* ctx, u64 k, const u8** outpoint, u64* value,
                         const u8** spk, u32* spklen);

/* Phase A for ONE transaction. Appends to *pool and fills *d. 1 ok / 0 fail. */
static int tapagg_build(bytepool_t* pool, tapagg_t* d,
                        tapin_fn get, void* ctx, u64 nin,
                        const u8* tx, u64 txlen, const char** reason){
    const u8* op; u64 v; const u8* spk; u32 sl;
    u64 splen = 0;
    for (u64 k=0;k<nin;k++){
        get(ctx, k, &op, &v, &spk, &sl);
        /* SCR-5 (audit 2026-09-03): BIP341's sha_scriptpubkeys hashes each
         * spent scriptPubKey prefixed by a CompactSize length -- Core's
         * PrecomputedTransactionData::Init uses ser_compactsize, and a
         * scriptPubKey up to MAX_SCRIPT_SIZE (10000) is consensus-spendable.
         * This run previously encoded the length in ONE byte and REJECTED any
         * co-input script >= 253 -- a false reject against the live chain
         * (a bare multisig co-input + a P2TR input = whole tx refused, block
         * rejected, node stalls on a fork Core accepts). The reader
         * (ts_agg_hashes) already walks a proper minimality-checked
         * compactsize; the writers were the drift. sl is already capped at
         * TXV_SPK_CAP = MAX_SCRIPT_SIZE < 0x10000, so 1 or 3 bytes suffice. */
        if (sl > TXV_SPK_CAP) { *reason = "prevout script too large"; return 0; }
        splen += (sl < 0xfd ? 1u : 3u) + sl;
    }
    /* strip_witness never grows a transaction (it only drops the marker/flag
     * and the witness section, and re-serializes everything else verbatim),
     * so txlen is a sound cap for the stripped copy. */
    u64 need = nin*36 + nin*8 + splen + txlen;
    u64 off = bytepool_reserve(pool, need);
    if (off == ~0ull) { *reason = "out of memory"; return 0; }
    d->po_off = off;
    d->am_off = d->po_off + nin*36;
    d->sp_off = d->am_off + nin*8;
    d->ns_off = d->sp_off + splen;
    d->nin    = nin;
    /* Safe to take addresses now and not before: the single reserve above is
     * the last thing that can relocate pool->buf until the next transaction. */
    u8* base = pool->buf;
    u8* po = base + d->po_off;
    u8* am = base + d->am_off;
    u8* sp = base + d->sp_off;
    u8* ns = base + d->ns_off;
    u64 w = 0;
    for (u64 k=0;k<nin;k++){
        get(ctx, k, &op, &v, &spk, &sl);
        /* The sizing pass above and this write pass call `get` SEPARATELY, and
         * `get` is a function pointer -- so "both passes see the same spklen"
         * is no longer a locally checkable fact. Both adapters read fields that
         * nothing writes in between, but if that ever stopped being true the
         * memcpy below would overrun `sp` INTO THE ARENA REGIONS OTHER
         * TRANSACTIONS' DESCRIPTORS POINT AT -- i.e. a corrupted sighash for an
         * unrelated transaction, silently. These three checks make the
         * invariant enforced rather than documented; they cost two compares per
         * input against a Schnorr verify. Same reasoning for `base`: a future
         * adapter that allocated would dangle po/am/sp/ns, and this catches it
         * before the first write of the iteration rather than after. */
        if (pool->buf != base) { *reason = "internal: taproot arena moved during build"; return 0; }
        { u64 csl = (sl < 0xfd ? 1u : 3u);
          if (sl > TXV_SPK_CAP || w + csl + sl > splen) { *reason = "internal: taproot arena sizing pass disagreed"; return 0; }
          memcpy(po + k*36, op, 36);
          for (int b=0;b<8;b++) am[k*8+b] = (u8)(v>>(8*b));
          if (sl < 0xfd){ sp[w++] = (u8)sl; }
          else { sp[w++] = 0xfd; sp[w++] = (u8)(sl & 0xff); sp[w++] = (u8)(sl >> 8); }
          memcpy(sp + w, spk, sl); w += sl; }
    }
    long nslen = strip_witness(tx, (int64_t)txlen, ns, (long)txlen);
    if (nslen <= 0) { *reason = "malformed witness (strip failed)"; return 0; }
    d->nslen = (u64)nslen;
    return 1;
}

/* Phase B for ONE taproot input. Pure reader of *pool and *d -- callable
 * concurrently from any number of worker threads. local_idx is the input's
 * index WITHIN ITS OWN TRANSACTION, which is what BIP341 commits to. */
static int tapagg_verify(const bytepool_t* pool, const tapagg_t* d, const u8* spk,
                         const u8* const* wit, const u32* witlen, u32 nwit,
                         u64 local_idx, unsigned long long flags, const char** reason){
    const u8* A = pool->buf;
    const char* r = "p2tr verify failed";
    /* IR-9: the WV0 and LEGACY arms forwarded `flags`; this one did not, so
     * TXV_MEMPOOL_POLICY_FLAGS never reached a tapscript leaf. */
    if (!taproot_verify_input_flags(spk, wit, witlen, nwit,
                              A + d->ns_off, (int64_t)d->nslen, (int64_t)local_idx,
                              A + d->po_off, A + d->am_off, A + d->sp_off,
                              (int64_t)d->nin, &r, flags)) { *reason = r; return 0; }
    return 1;
}

/* Parses the tx's own input list (outpoint/scriptSig) and, if segwit-
 * marked, its per-input witness stacks, into g_txv_in[0..nin). Does not
 * touch outputs (irrelevant to script verification) or resolve any UTXO.
 * Returns 1 well-formed / 0 malformed-or-over-bound (reason set). */
static int txv_parse(const u8* tx, u64 txlen, u64* out_nin, const char** reason){
    const u8* p = tx; const u8* end = tx+txlen;
    int ok = 1;
    if (txlen < 10) { *reason = "tx too short"; return 0; }
    g_wit_pool.used = 0;   /* bump-reset for this tx's witness items */
    p += 4; /* version */
    int segwit = (p+2<=end && p[0]==0x00 && p[1]==0x01);
    if (segwit) p += 2;
    u64 nin = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad n_in varint"; return 0; }
    if (nin == 0 || nin > TXV_MAX_INPUTS) { *reason = "input count out of bounds"; return 0; }
    for (u64 i=0;i<nin;i++){
        if (p+36 > end) { *reason = "truncated outpoint"; return 0; }
        g_txv_in[i].outpoint = p; p += 36;
        u64 sl = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad scriptSig varint"; return 0; }
        /* split bound: `(end-p) < sl+4` WRAPS for sl within 4 of 2^64 (an 0xff
         * compactsize can encode that), accepting a tx Core rejects and
         * truncating scriptSiglen to 0xFFFFFFFF -- incident #36. This is the
         * form bitcoin_segwit.c's swtx_parse already uses; neither side can
         * overflow. Proven by tests/test_txv_cs_maxsize.c. */
        { u64 avail=(u64)(end-p); if (avail < sl || avail - sl < 4) { *reason = "truncated scriptSig/sequence"; return 0; } }
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
            u64 woff = txv_witpool_reserve(&g_wit_pool, nitems);
            if (woff == ~0ull) { *reason = "out of memory"; return 0; }
            g_txv_in[i].wit_off = (u32)woff;
            for (u64 j=0;j<nitems;j++){
                u64 il = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad witness-item-len varint"; return 0; }
                if ((u64)(end-p) < il){ *reason = "truncated witness item"; return 0; }
                g_wit_pool.ptr[woff+j] = p; g_wit_pool.len[woff+j] = (u32)il;
                p += il;
            }
        }
    }
    /* Resolve offsets to addresses now the pool is done growing for this tx. */
    for (u64 i=0;i<nin;i++){
        if (g_txv_in[i].nwit){ g_txv_in[i].wit = g_wit_pool.ptr + g_txv_in[i].wit_off; g_txv_in[i].witlen = g_wit_pool.len + g_txv_in[i].wit_off; }
        else { g_txv_in[i].wit = 0; g_txv_in[i].witlen = 0; }
    }
    *out_nin = nin;
    return 1;
}

static int is_p2tr  (const u8* spk, u32 sl){ return sl==34 && spk[0]==0x51 && spk[1]==0x20; }

/* txv_verify_one(): the actual per-input crypto check, dispatched by shape.
 * Pure function of g_txv_in[i]'s already-resolved fields plus the tx bytes
 * (both read-only by this point) -- safe to call from a forked child, which
 * has its own COW copy of everything it touches. Returns 1 valid / 0
 * invalid (reason set to a static string literal; NOT malloc'd, so it is
 * safe to read across a fork -- the string constants live in .rodata,
 * mapped identically in every child). */
/* Legacy (pre-segwit sigversion) signature hashing must serialize the tx
 * WITHOUT witness data (Core: SERIALIZE_TRANSACTION_NO_WITNESS). Before block
 * 481824 every legacy input lived in a non-segwit tx, so tx bytes == stripped
 * bytes and this never mattered; a tx that mixes a legacy input with a segwit
 * input (first seen at 481825) is segwit-serialized, so the legacy input's
 * sighash would be computed over marker/flag/witness bytes and fail. Strip
 * once into a thread-local buffer; input order/count is unchanged, so nIn is
 * preserved. Returns the tx unchanged when it carries no witness. */
static const u8* legacy_tx_view(const u8* tx, u64 txlen, u64* out_len){
    if (txlen < 6 || !(tx[4]==0x00 && tx[5]==0x01)) { *out_len = txlen; return tx; }
    static __thread u8* stripped; BMC_TLS_BUF(stripped, 1<<20);
    long n = strip_witness(tx, (int64_t)txlen, stripped, (long)(1<<20));
    if (n <= 0) { *out_len = txlen; return tx; }   /* fall back; sv will reject on a bad hash */
    *out_len = (u64)n; return stripped;
}
/* Single-transaction entry point's taproot phase-A state: one descriptor and
 * one pool, since exactly one transaction is ever in flight here (that is the
 * whole premise of g_txv_in being a file-scope static). Separate from the
 * block path's pool so the two can never alias. */
static bytepool_t g_t1_tap_pool = {0};
static tapagg_t   g_t1_tap = {0};
static int        g_t1_tap_built = 0;

/* Adapter: input k of the single-transaction path, resolved by pass 1. */
static void t1_tapin(void* ctx, u64 k, const u8** outpoint, u64* value,
                     const u8** spk, u32* spklen){
    (void)ctx;
    *outpoint = g_txv_in[k].outpoint;
    *value    = g_txv_in[k].value;
    *spk      = g_txv_in[k].spk;
    *spklen   = g_txv_in[k].spklen;
}

/* Script evaluation switch (Core's -assumevalid, 2026-09-01): when off, every
 * structural, consensus and UTXO check still runs -- only the signature/script
 * EVALUATION of an input is skipped, exactly what Core skips for blocks below
 * its assumevalid block. Default on; utxo_live.c turns it off per block while
 * applying at or below the operator's assumevalid height, and never for a
 * submitblock dry run. Read by worker threads: a plain int is enough. */
int g_txv_script_checks = 1;
void tx_verify_set_script_checks(int on){ g_txv_script_checks = on ? 1 : 0; }
int  tx_verify_script_checks(void){ return g_txv_script_checks; }

static int txv_verify_one(const u8* tx, u64 txlen, u64 i, unsigned long long flags,
                          u8* sv_work, unsigned long sv_workcap, const char** reason){
    txv_rawin_t* in = &g_txv_in[i];
    if (!g_txv_script_checks) return 1;   /* assumevalid: below the assumed-valid block, no script evaluation */
    switch (in->shape){
    case TXV_SHAPE_P2TR: {
        /* Phase B. g_t1_tap/g_t1_tap_pool were filled by pass 1c below,
         * strictly before any worker thread was created, and are read-only
         * from here on -- so this case is safe to run concurrently. */
        if (!g_t1_tap_built) { *reason = "internal: taproot aggregate not built"; return 0; }
        return tapagg_verify(&g_t1_tap_pool, &g_t1_tap, in->spk,
                             in->wit, in->witlen, in->nwit, i, flags, reason);
    }
    case TXV_SHAPE_WV0: {
        int err = sv_verify_witness_v0(in->wprog, in->wproglen, in->wit, in->witlen, in->nwit,
                                       in->value, flags, (unsigned long)i, tx, txlen, sv_work, sv_workcap);
        if (err != 0) { *reason = in->wproglen == 20 ? "p2wpkh signature invalid" : "p2wsh script verification failed"; return 0; }
        return 1;
    }
    case TXV_SHAPE_LEGACY: {
        u64 ltxlen; const u8* ltx = legacy_tx_view(tx, txlen, &ltxlen);
        int err = sv_verify_script(in->scriptSig, in->scriptSiglen, in->spk, in->spklen,
                                   flags, (unsigned long)i, ltx, ltxlen, sv_work, sv_workcap);
        if (err != 0) { *reason = "legacy script verification failed"; return 0; }
        return 1;
    }
    default: /* TXV_SHAPE_WPASS: unknown witness version, anyone-can-spend */
        return 1;
    }
}

/* Below this many inputs, spawning threads costs more than it
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
    static __thread u8* sv_work; BMC_TLS_BUF(sv_work, 1<<20);   /* per-THREAD, not per-process --
                                          * threads share g_txv_results and
                                          * the process's other statics, so
                                          * this one specifically must stay
                                          * __thread or concurrent workers
                                          * would race on it (exactly the
                                          * class of bug
                                          * test_scriptverify_thread_stress.c
                                          * was built to catch). */
    for (u64 i=a->lo;i<a->hi;i++){
        const char* r = 0;
        int ok = txv_verify_one(a->tx, a->txlen, i, a->flags, sv_work, 1<<20, &r);
        g_txv_results[i].ok = ok ? 1 : 0;
        if (!ok) { size_t n=strlen(r); if(n>63)n=63; memcpy(g_txv_results[i].reason, r, n); g_txv_results[i].reason[n]=0; }
    }
    return 0;
}

/* txv_verify_all(): verify EVERY input in g_txv_in[0..nin) -- taproot
 * included as of 2026-08-23 (PERF_SCOPE.md section 14.7) -- in parallel once
 * there's enough work to be worth it. Sequential fallback below
 * TXV_PARALLEL_MIN keeps small (the common case, historically) txs exactly
 * as fast as before with zero thread overhead.
 * Returns 1 all valid / 0 at least one invalid (reason set). */
static int txv_verify_all(const u8* tx, u64 txlen, u64 nin, unsigned long long flags,
                          const char** reason){
    u64 nverify = nin;
    if (nverify == 0) return 1;

    static char rbuf[64];

    if (nverify < TXV_PARALLEL_MIN){
        static u8 sv_work[1<<20];
        for (u64 i=0;i<nin;i++){
            const char* r = 0;
            if (!txv_verify_one(tx, txlen, i, flags, sv_work, 1<<20, &r)) {
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
        if (bmc_pthread_create(&tids[spawned], txv_worker_thread, &args[spawned]) != 0){
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

/* Prevout resolution callback for txv_connect_body: fills value / creation
 * height / coinbase flag / script for one outpoint, returns 1 found / 0 not.
 * The returned spk pointer need only stay valid until the NEXT resolver
 * call -- the body copies it out immediately (same contract utxo_lsm_get
 * has always had here). Introduced so MEMPOOL ADMISSION can run this exact,
 * replay-proven verifier (legacy scripts, full BIP341/342 taproot,
 * everything) with its own view -- live confirmed set PLUS unconfirmed
 * mempool parents -- instead of maintaining a second, partial verifier
 * (bitcoin_txval_modern.c grew three first-contact incidents in one day
 * doing exactly that; it remains for its vector tests but is off the
 * accept path). */
typedef int (*txv_resolve_fn)(void* ctx, const u8 outpoint[36], u32 index,
                              u64* value, u64* height, u64* is_coinbase,
                              const u8** spk, unsigned long* spklen);

typedef struct { void* lst; void* u; } txv_lsm_ctx_t;
static int txv_resolve_lsm(void* ctxv, const u8 outpoint[36], u32 index,
                           u64* value, u64* height, u64* is_coinbase,
                           const u8** spk, unsigned long* spklen){
    txv_lsm_ctx_t* c = ctxv;
    return utxo_lsm_get(c->lst, c->u, outpoint, index, value, height, is_coinbase, spk, spklen) == 1;
}

static int txv_connect_body(const u8* tx, u64 txlen, long height, unsigned long long flags,
                            txv_resolve_fn rf, void* rctx, const char** reason){
    u64 nin;
    if (!txv_parse(tx, txlen, &nin, reason)) return 0;

    int has_taproot = 0;

    /* ---- pass 1 (sequential, unchanged in spirit from before): maturity
     * check + resolve every input's prevout from the confirmed UTXO set,
     * copying out what's needed (utxo_lsm_get's own pointer is only valid
     * until the next call) so verification -- now possibly forked out --
     * has a fully self-contained, read-only view of each input. ---- */
    for (u64 i=0;i<nin;i++){
        u32 index; memcpy(&index, g_txv_in[i].outpoint+32, 4);
        u64 value=0, uheight=0, ucb=0; const u8* spk=0; unsigned long spklen=0;
        if (!rf(rctx, g_txv_in[i].outpoint, index, &value, &uheight, &ucb, &spk, &spklen))
            { *reason = "input references a missing/already-spent UTXO"; return 0; }
        if (ucb) {
            long conf = height - (long)uheight;
            if (conf < COINBASE_MATURITY) { *reason = "immature coinbase spend (100-block rule)"; return 0; }
        }

        g_txv_in[i].value = value;
        if (spklen > TXV_SPK_CAP) { *reason = "prevout script too large"; return 0; }
        memcpy(g_txv_in[i].spk, spk, spklen);
        g_txv_in[i].spklen = (u32)spklen;

        if (is_p2tr(spk, (u32)spklen) && (flags & TXV_FLAG_TAPROOT)) {
            has_taproot = 1;
            g_txv_in[i].shape = TXV_SHAPE_P2TR;
            if (g_txv_in[i].scriptSiglen != 0) { *reason = "p2tr scriptSig must be empty"; return 0; }
            if (g_txv_in[i].nwit == 0) { *reason = "p2tr empty witness"; return 0; }
            continue;
        }
        if (flags & TXV_FLAG_WITNESS) {
            u32 wver=0, wplen=0; const u8* wprog=0; int wrapped=0;
            /* Classify against the STABLE per-input copy, not `spk` --
             * utxo_lsm_get's pointer is only valid until the next call, and
             * the returned wprog (stored below, read in pass 1b) would
             * otherwise aim into that transient buffer. Same bug class as
             * the block path's wprog_off (incident 482566 tx 1499). */
            int cls = sv_classify_segwit(g_txv_in[i].spk, (u32)spklen, g_txv_in[i].scriptSig, g_txv_in[i].scriptSiglen,
                                         &wver, &wprog, &wplen, &wrapped);
            if (cls < 0) { *reason = "p2sh-wrapped witness program: scriptSig must be exactly one push of the redeemScript"; return 0; }
            if (cls > 0) {
                if (!wrapped && g_txv_in[i].scriptSiglen != 0) { *reason = "witness program scriptSig must be empty"; return 0; }
                if (wver == 0) {
                    g_txv_in[i].shape = TXV_SHAPE_WV0; g_txv_in[i].wprog = wprog; g_txv_in[i].wproglen = wplen; g_txv_in[i].wrapped = (u8)wrapped;
                    if (wplen == 20 && g_txv_in[i].nwit != 2) { *reason = "p2wpkh needs exactly 2 witness items"; return 0; }
                    if (wplen == 32 && g_txv_in[i].nwit < 1) { *reason = "p2wsh needs a witnessScript"; return 0; }
                } else {
                    g_txv_in[i].shape = TXV_SHAPE_WPASS;   /* unknown version: valid under consensus flags (no DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) */
                }
                continue;
            }
            /* Core VerifyScript: a witness on an input whose script is not a
             * witness program is SCRIPT_ERR_WITNESS_UNEXPECTED. */
            if (g_txv_in[i].nwit != 0) { *reason = "unexpected witness on a non-witness script"; return 0; }
        }
        g_txv_in[i].shape = TXV_SHAPE_LEGACY;
    }

    /* ---- pass 1c (taproot phase A, sequential and cheap): build the BIP341
     * aggregate-sighash arrays for this transaction BEFORE any verification
     * thread exists, so pass 1b's workers can read them concurrently.
     *
     * Reuses pass 1's already-cached value/spk/spklen instead of re-querying
     * the UTXO set, which is what the old sequential pass 2 did. The
     * re-query was documented as "purely out of caution ... to minimize the
     * diff against the already-proven pre-parallel version"; it returned the
     * same bytes pass 1 had already copied out, and its extra failure mode
     * ("missing/already-spent UTXO (pass 2)") was unreachable, since pass 1
     * had just resolved every one of these outpoints and nothing mutates
     * UTXO state in between.
     *
     * is_tap is likewise gone: pass 1 already set shape == TXV_SHAPE_P2TR
     * for exactly the inputs the old `is_p2tr(spk, spklen)` retest would
     * have flagged. The two can only differ when the TAPROOT flag is off for
     * this block, and in that case has_taproot is 0 and neither this nor the
     * old pass 2 runs at all (that flag is per-BLOCK, so it cannot differ
     * between inputs of one transaction -- see TXV_FLAG_TAPROOT's own note
     * about Core's mainnet exception block 692261). ---- */
    /* Cleared unconditionally, not inside the `if`. It is true today that
     * has_taproot == 0 implies no TXV_SHAPE_P2TR input exists (both are set by
     * the same branch in pass 1), so a stale 1 from the previous transaction
     * could never be read -- but that is a non-local invariant guarding a
     * silent failure, and clearing it here costs nothing. */
    g_t1_tap_built = 0;
    if (has_taproot){
        g_t1_tap_pool.used = 0;
        if (!tapagg_build(&g_t1_tap_pool, &g_t1_tap, t1_tapin, 0, nin, tx, txlen, reason))
            return 0;
        g_t1_tap_built = 1;
    }

    /* ---- pass 1b (taproot phase B): the actual (possibly parallel) crypto
     * verification for EVERY input classified above, taproot included. ---- */
    if (!txv_verify_all(tx, txlen, nin, flags, reason)) return 0;
    return 1;
}

/* tx_verify_block_connect(tx, txlen, height, block_hash32, lst, u, &reason)
 * -> 1 accept / 0 reject (reason set to a static string literal). Caller
 * must have already excluded the coinbase tx -- every input seen here is a
 * real spend, never a coinbase's null prevout. Thin wrapper: the body above
 * is IDENTICAL to what this function was before the resolver seam -- same
 * flags source, same maturity rule, same reasons -- with the one
 * utxo_lsm_get call routed through txv_resolve_lsm. */
int tx_verify_block_connect(const u8* tx, u64 txlen, long height, const u8 block_hash32[32],
                            void* lst, void* u, const char** reason){
    unsigned long long flags = script_flags_for_block((unsigned long long)height, block_hash32);
    txv_lsm_ctx_t c = { lst, u };
    return txv_connect_body(tx, txlen, height, flags, txv_resolve_lsm, &c, reason);
}

/* tx_verify_mempool: the SAME verifier for mempool admission. next_height is
 * the height the tx would confirm at (tip+1): it selects the script flags
 * and anchors the coinbase-maturity check. The block-hash argument to
 * script_flags_for_block exists only for Core's one historical taproot
 * exception block, which no future height can be -- zeros are correct. */
/* SCR-9 (audit 2026-09-03): Core verifies a MEMPOOL candidate under
 * STANDARD_SCRIPT_VERIFY_FLAGS (policy/policy.h), not under the consensus set
 * a block gets. This path passed consensus flags only, so the node accepted
 * -- and RELAYED -- transactions Core calls non-standard.
 *
 * WHAT IS SET HERE, AND WHY IT IS NOT THE WHOLE STANDARD MASK.
 *
 * Core's STANDARD = MANDATORY | STRICTENC | MINIMALDATA |
 * DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK | MINIMALIF | NULLFAIL | LOW_S |
 * DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM | WITNESS_PUBKEYTYPE |
 * CONST_SCRIPTCODE | DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
 * DISCOURAGE_OP_SUCCESS | DISCOURAGE_UPGRADABLE_PUBKEYTYPE.
 *
 * Only the bits this tree's interpreter actually READS are set below. Setting
 * a bit nothing tests would make the code claim a parity it does not have,
 * which is the failure mode this audit round kept finding in the DOCS; there
 * is no reason to import it into the source. Each bit here was traced to the
 * instruction that tests it:
 *
 *   STRICTENC      (1)  bitcoin_interp.asm:2768, 2801
 *   LOW_S          (3)  bitcoin_interp.asm:2731, 2744
 *   MINIMALDATA    (6)  bitcoin_interp.asm:192 (SNUM_MAX), 561
 *   CLEANSTACK     (8)  bitcoin_scriptverify.c:389
 *   MINIMALIF     (13)  bitcoin_interp.asm:809
 *   NULLFAIL      (14)  bitcoin_interp.asm:2089, 3414
 *   CONST_SCRIPTCODE (16) bitcoin_scriptverify.c:121, 186-193
 *   DISCOURAGE_OP_SUCCESS (19) bitcoin_interp.asm:457, and the prescan in
 *                              bitcoin_taproot_sighash.c that returns before
 *                              it (IR-9: flags now reach the tapscript leaf)
 *
 * DELIBERATELY ABSENT:
 *
 *   DISCOURAGE_UPGRADABLE_NOPS (7) -- NOT an oversight. bitcoin_interp.asm:736
 *     documents that NOP1/NOP4..NOP10 must stay no-ops: real, historically
 *     mined mainnet transactions use OP_NOP1 in consensus-valid scripts, and
 *     treating the range as bad opcodes rejects them. The interpreter is
 *     shared with the block path, so there is no arm to switch on here.
 *   DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM (12), WITNESS_PUBKEYTYPE (15),
 *   DISCOURAGE_UPGRADABLE_TAPROOT_VERSION (18),
 *   DISCOURAGE_UPGRADABLE_PUBKEYTYPE (20) -- no interpreter arm exists. These
 *     are the "unknown witness versions" and "uncompressed keys in segwit"
 *     cases SCR-9 names, and they stay open; see docs/FEATURE_GAPS.md.
 *
 * CLEANSTACK is safe to set unconditionally here because Core's own note
 * ("should never be used without P2SH or WITNESS") is satisfied: P2SH has
 * been in the consensus set since height 173,805 and every mempool candidate
 * is verified at tip+1.
 */
#define TXV_MEMPOOL_POLICY_FLAGS ( (1ULL<<1)  /* STRICTENC        */ \
                                 | (1ULL<<3)  /* LOW_S            */ \
                                 | (1ULL<<6)  /* MINIMALDATA      */ \
                                 | (1ULL<<8)  /* CLEANSTACK       */ \
                                 | (1ULL<<13) /* MINIMALIF        */ \
                                 | (1ULL<<14) /* NULLFAIL         */ \
                                 | (1ULL<<16) /* CONST_SCRIPTCODE */ \
                                 | (1ULL<<19) /* DISCOURAGE_OP_SUCCESS */ )

/* Core's -acceptnonstdtxn drops back to the consensus set (its require_standard
 * is false). Injectable rather than read from g_cfg here so this translation
 * unit stays free of the daemon config -- daemon/tx_accept.c calls the setter
 * beside the mpool_policy_set_acceptnonstd it already makes. */
static int g_txv_mempool_standard = 1;
void txv_set_mempool_standard(int on){ g_txv_mempool_standard = on ? 1 : 0; }
int  txv_get_mempool_standard(void){ return g_txv_mempool_standard; }

/* tx_verify_at_height -- the CONSENSUS verifier at a given height, driven by
 * a caller-supplied resolver.
 *
 * tx_verify_block_connect does this but resolves through the LSM, so it needs
 * a live UTXO store; tx_verify_mempool takes a resolver but applies MEMPOOL
 * flags (SCR-9's policy bits on top of the consensus set). Neither shape lets
 * a test verify a historical transaction against the flags of ITS OWN block,
 * which is exactly what the mined-transaction corpus
 * (tests/test_txaccept_corpus.c) needs: a 2011 transaction has to be judged by
 * 2011's rules, and several real ones would be rejected under today's.
 *
 * Same body, same flag source, same maturity anchor as the block-connect path
 * -- only the resolver differs. The block-hash argument to
 * script_flags_for_block matters for exactly one mainnet block (Core's
 * taproot exception at 692,261); callers that care pass it, and the corpus
 * avoids that height rather than pretend zeros are right there.
 */
int tx_verify_at_height(const u8* tx, u64 txlen, long height,
                        txv_resolve_fn rf, void* rctx, const char** reason){
    static const u8 zero32[32];
    unsigned long long flags = script_flags_for_block((unsigned long long)height, zero32);
    return txv_connect_body(tx, txlen, height, flags, rf, rctx, reason);
}

int tx_verify_mempool(const u8* tx, u64 txlen, long next_height,
                      txv_resolve_fn rf, void* rctx, const char** reason){
    static const u8 zero32[32];
    unsigned long long flags = script_flags_for_block((unsigned long long)next_height, zero32);
    if (g_txv_mempool_standard) flags |= TXV_MEMPOOL_POLICY_FLAGS;
    return txv_connect_body(tx, txlen, next_height, flags, rf, rctx, reason);
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
 * TAPROOT (2026-08-23, PERF_SCOPE.md section 14.7) is now dispatched through
 * the same pool as every other shape, at the same input granularity. What
 * used to force it sequential was that BIP341's sighash needs WHOLE-
 * TRANSACTION data (every input's outpoint/amount/scriptPubKey plus the
 * witness-stripped serialization), which was rebuilt into one reused scratch
 * arena per transaction. Phase 1.5 below builds that data for every
 * taproot-bearing transaction in the block ONCE, up front, into a single
 * per-block arena that is read-only for the whole of Phase 2 -- so no worker
 * has to rebuild anything and no two workers share a writable byte. See the
 * TAPROOT AGGREGATE-SIGHASH ARENA comment near the top of this file for the
 * measurement that picked this axis (96% of taproot-bearing transactions
 * have exactly ONE taproot input, so the within-transaction axis is worth
 * approximately nothing).
 * ============================================================================ */

/* VAL-1 fees ledger (audit 2026-09-03): per-tx input sums for the LAST
 * tx_verify_block_connect_all call. File-scope like every other arena here
 * (same single-threaded Phase-1 discipline); the caller reads it through
 * txvb_last_tx_in_sums immediately after a successful call. */
static u64* g_tx_in_sums = 0;    static u64 g_tx_in_sums_cap = 0;
static u64 g_tx_in_sums_n = 0;
const u64* txvb_last_tx_in_sums(u64* n_out){
    if (n_out) *n_out = g_tx_in_sums_n;
    return g_tx_in_sums;
}

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

/* g_spk_pool / bytepool_alloc / bytepool_reserve now live near the top of
 * this file (just after witpool_reserve), because the single-transaction
 * entry point's taproot phase A needs a pool too. */

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
    const u8** wit; u32* witlen; u32 nwit; u32 wit_off; /* offset into g_wit_pool, resolved to
                                  * wit/witlen after Phase 0 -- see g_txv_in's copy. */
    const u8* wprog; u32 wproglen; u8 wrapped;   /* TXV_SHAPE_WV0: the witness program. wrapped: a pointer into the
                                  * scriptSig's redeemScript (tx bytes, stable for the whole pass).
                                  * native (!wrapped): wprog is NULL and wprog_off below is the program's
                                  * byte offset WITHIN the spk -- the raw sv_classify_segwit pointer
                                  * aimed into utxo_lsm_get's transient buffer ("only valid until the
                                  * next call"), which a later Phase-1 resolve overwrites; incident
                                  * 482566 tx 1499 read another entry's hash160 through it. Resolve as
                                  * (g_spk_pool.buf + spk_off + wprog_off), same discipline as spk_off. */
    u32 wprog_off;
    u64 value;
    u64 spk_off; u32 spklen;     /* spk_off is a byte OFFSET into g_spk_pool
                                  * (see bytepool_alloc's own comment), NOT a
                                  * pointer -- the pool can still realloc()
                                  * and relocate for a LATER entry in this
                                  * same block's resolve loop, which would
                                  * dangle a pointer captured here but leaves
                                  * an offset valid. Resolve to an address
                                  * (g_spk_pool.buf + spk_off) only after
                                  * Phase 1 is done growing the pool. Packed
                                  * (not an inline TXV_SPK_CAP-sized buffer)
                                  * for the same reason as before: an inline
                                  * array here would cost every one of
                                  * possibly thousands of entries the full
                                  * worst-case size (10000 bytes, since
                                  * TXV_SPK_CAP was raised to the real
                                  * consensus max) regardless of that
                                  * entry's actual (almost always tiny)
                                  * script. */
    u64 tap_desc;                /* TXV_SHAPE_P2TR only: index into g_tapdesc
                                  * (== this input's own tx_index) of the
                                  * BIP341 aggregate-sighash descriptor built
                                  * for its transaction by Phase 1.5. ~0ull
                                  * when not built -- checked, not assumed,
                                  * because reading a stale descriptor would
                                  * produce a WRONG SIGHASH, which is silent. */
    u8  shape;
} txvb_in_t;

typedef struct { u8 ok; char reason[64]; } txvb_result_t;
typedef struct { u64 lo, hi; } txvb_txrange_t;

/* Per-block taproot aggregate-sighash arena + one descriptor per transaction
 * (indexed by block position, so ntx entries; only taproot-bearing
 * transactions are ever filled in or read). Written by Phase 1.5 only;
 * strictly read-only from the moment Phase 2 dispatches. */
static bytepool_t       g_tap_pool = {0};
static tapagg_t*        g_tapdesc = 0;
static u64              g_tapdesc_cap = 0;

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
        /* split bound: `(end-p) < sl+4` WRAPS for sl within 4 of 2^64 (an 0xff
         * compactsize can encode that), accepting a tx Core rejects and
         * truncating scriptSiglen to 0xFFFFFFFF -- incident #36. This is the
         * form bitcoin_segwit.c's swtx_parse already uses; neither side can
         * overflow. Proven by tests/test_txv_cs_maxsize.c. */
        { u64 avail=(u64)(end-p); if (avail < sl || avail - sl < 4) { *reason = "truncated scriptSig/sequence"; return 0; } }
        e->scriptSig = p; e->scriptSiglen = (u32)sl;
        p += sl + 4;
        e->nwit = 0;
        e->tap_desc = ~0ull;   /* filled by Phase 1.5 iff this turns out to
                                * be a taproot input; a stale value from the
                                * PREVIOUS block's flat array would otherwise
                                * hand a worker the wrong transaction's
                                * aggregate sighash data -- silently */
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
            u64 woff = txv_witpool_reserve(&g_wit_pool, nitems);
            if (woff == ~0ull) { *reason = "out of memory"; return 0; }
            e->wit_off = (u32)woff;
            for (u64 j=0;j<nitems;j++){
                u64 il = txv_rd_cs(&p, end, &ok); if(!ok){ *reason = "bad witness-item-len varint"; return 0; }
                if ((u64)(end-p) < il){ *reason = "truncated witness item"; return 0; }
                g_wit_pool.ptr[woff+j] = p; g_wit_pool.len[woff+j] = (u32)il;
                p += il;
            }
        }
    }
    *out_nin = nin;
    return 1;
}

/* Adapter: input k of ONE transaction on the block path. ctx is &flat[lo],
 * i.e. that transaction's first entry in the block-wide flat array. Reads
 * only Phase 1's already-resolved fields; the scriptPubKey comes out of
 * g_spk_pool, which Phase 1 is done growing by the time this runs. */
static void txvb_tapin(void* ctx, u64 k, const u8** outpoint, u64* value,
                       const u8** spk, u32* spklen){
    const txvb_in_t* in = &((const txvb_in_t*)ctx)[k];
    *outpoint = in->outpoint;
    *value    = in->value;
    *spk      = g_spk_pool.buf + in->spk_off;
    *spklen   = in->spklen;
}

/* Mirrors txv_verify_one exactly, reading a caller-supplied entry pointer
 * instead of g_txv_in[i], and in->local_idx (this input's position within
 * ITS OWN tx) instead of a bare loop index for the sighash-position
 * arguments the underlying primitives need. */
/* Explicit-state signature (2026-08-24, phase 2 slice 8): the pools and the
 * descriptor array arrive as parameters instead of file-scope statics, so
 * bitcoin_txv_dispatch.asm's twin can be driven side by side. Every caller
 * passes the globals; behavior is byte-identical to the static version. */
static int txvb_verify_one(const u8* tx, u64 txlen, txvb_in_t* in, unsigned long long flags,
                           u8* sv_work, unsigned long sv_workcap,
                           const bytepool_t* spk_pool, const bytepool_t* tap_pool,
                           const tapagg_t* tapdesc, const char** reason){
    /* Safe here (unlike inside Phase 1's own resolve loop): every caller of
     * this function runs strictly after that loop has finished growing
     * the spk pool for this block, so pool->buf is stable for the whole
     * verification pass. */
    const u8* spk = spk_pool->buf + in->spk_off;
    if (!g_txv_script_checks) return 1;   /* assumevalid: the block-connect batch path skips evaluation too (missed on the first cut, 2026-09-01 13:10) */
    switch (in->shape){
    case TXV_SHAPE_P2TR: {
        /* Phase B. tapdesc/tap_pool were filled by Phase 1.5, strictly
         * before any worker was dispatched, and are read-only from then on
         * -- which is what makes this case safe to run concurrently across
         * transactions. `spk` is exactly the 34-byte P2TR scriptPubKey
         * (is_p2tr required spklen == 34). */
        if (in->tap_desc == ~0ull) { *reason = "internal: taproot aggregate not built"; return 0; }
        return tapagg_verify(tap_pool, &tapdesc[in->tap_desc], spk,
                             in->wit, in->witlen, in->nwit, in->local_idx, flags, reason);
    }
    case TXV_SHAPE_WV0: {
        const u8* wprog = in->wprog ? in->wprog : spk + in->wprog_off;
        int err = sv_verify_witness_v0(wprog, in->wproglen, in->wit, in->witlen, in->nwit,
                                       in->value, flags, (unsigned long)in->local_idx, tx, txlen, sv_work, sv_workcap);
        if (err != 0) { *reason = in->wproglen == 20 ? "p2wpkh signature invalid" : "p2wsh script verification failed"; return 0; }
        return 1;
    }
    case TXV_SHAPE_LEGACY: {
        u64 ltxlen; const u8* ltx = legacy_tx_view(tx, txlen, &ltxlen);
        int err = sv_verify_script(in->scriptSig, in->scriptSiglen, spk, in->spklen,
                                   flags, (unsigned long)in->local_idx, ltx, ltxlen, sv_work, sv_workcap);
        if (err != 0) { *reason = "legacy script verification failed"; return 0; }
        return 1;
    }
    default: /* TXV_SHAPE_WPASS: unknown witness version, anyone-can-spend */
        return 1;
    }
}

/* ---- persistent worker pool (2026-08-20) ---------------------------------
 * Originally pthread_create/pthread_join'd a FRESH set of workers on every
 * single call (every block whose block-wide nverify crossed
 * TXV_PARALLEL_MIN). strace on the live daemon during bulk catch-up showed
 * why that was expensive independent of pthread_create's own per-call cost
 * (already benchmarked cheap in isolation, see tx_verify.c's own header):
 * ~840 clone3 calls/sec, matched almost exactly by mmap+munmap+mprotect
 * counts -- every fresh thread needs a freshly mmap'd stack, faulted in as
 * the new thread touches it, then munmap'd on exit. At bulk-mode block
 * rates that dwarfed the crypto work being parallelized.
 *
 * Fixed the same "allocate once, reuse forever" way as every other
 * bottleneck fixed tonight, just applied to OS threads instead of memory:
 * a fixed-size (TXVB_MAX_WORKERS) pool of worker threads started lazily
 * (grown, never shrunk, via txvb_pool_ensure) and parked on their own
 * semaphore between rounds instead of exiting. The main thread posts one
 * work descriptor + wakes each worker's semaphore, then waits on a shared
 * "done" semaphore once per worker to know the round finished -- same
 * fan-out/barrier shape as before, just without tearing down and
 * recreating the OS threads themselves every time.
 *
 * NOT applied to the OLD single-tx txv_worker_thread/txv_verify_all above:
 * apply_block_inner no longer calls the single-tx tx_verify_block_connect
 * at all (only tx_verify_block_connect_all), so that path is exercised by
 * tests only, never by the live daemon -- not on the hot path this fixes. */
/* WORK CLAIMING (2026-08-23): a round used to hand each worker a fixed,
 * contiguous [lo,hi) slice of the flat array. That was defensible while
 * every entry was a single ECDSA-ish check of roughly equal cost; it stopped
 * being so once taproot joined the same round, because per-entry cost now
 * spans a key-path Schnorr verify, a tapscript execution, and a
 * zero-work TXV_SHAPE_WPASS entry, and those are not spread evenly through a
 * block. Workers now pull the next index off one shared counter instead, so
 * a slice full of expensive inputs cannot leave 31 threads idle. The counter
 * is the ONLY thing workers share besides the read-only inputs; each still
 * writes only the res[] slots it claimed, so the disjointness argument in
 * this section's header is unchanged. */
typedef struct {
    pthread_t tid;
    sem_t work_sem;
    txvb_in_t* flat; txvb_result_t* res; unsigned long long flags;
    u64* next;                 /* shared claim counter for this round */
    u64  total;                /* one past the last claimable index */
} txvb_worker_slot_t;

static txvb_worker_slot_t g_txvb_pool[TXVB_MAX_WORKERS];
static int g_txvb_pool_size = 0;
static sem_t g_txvb_done_sem;
static int g_txvb_done_sem_ready = 0;

/* Loops forever -- these workers live for the process's whole lifetime,
 * same as this codebase's convention elsewhere of never gracefully
 * joining background threads at shutdown (the daemon's SIGTERM handler
 * calls _exit(0), which tears down every thread regardless of state). */
static void* txvb_worker_loop(void* argp){
    txvb_worker_slot_t* w = (txvb_worker_slot_t*)argp;
    static __thread u8* sv_work; BMC_TLS_BUF(sv_work, 1<<20);  /* per-THREAD -- see txv_worker_thread's
                                         * own comment above, identical reasoning.
                                         * Now allocated once for this worker's
                                         * whole process-lifetime, not once per
                                         * dispatch round either. */
    for (;;){
        /* sem_wait/sem_post are the round's memory barriers: everything the
         * main thread wrote into flat[]/g_spk_pool/g_tap_pool before posting
         * work_sem is visible here, and everything written into res[] here
         * is visible to the main thread after it drains g_txvb_done_sem. */
        sem_wait(&w->work_sem);
        for (;;){
            u64 i = __atomic_fetch_add(w->next, 1, __ATOMIC_RELAXED);
            if (i >= w->total) break;
            const char* r = 0;
            int ok = txvb_verify_one(w->flat[i].tx_ptr, w->flat[i].tx_len, &w->flat[i], w->flags, sv_work, 1<<20, &g_spk_pool, &g_tap_pool, g_tapdesc, &r);
            w->res[i].ok = ok ? 1 : 0;
            if (!ok) { size_t n=strlen(r); if(n>63)n=63; memcpy(w->res[i].reason, r, n); w->res[i].reason[n]=0; }
        }
        sem_post(&g_txvb_done_sem);
    }
    return 0;   /* unreachable -- for(;;) above never exits, see this
                 * function's own header comment */
}

/* Starts new persistent workers if the pool doesn't already have `need` of
 * them -- never shuts any down once started. Returns the number of workers
 * actually available (may be less than `need` if pthread_create ever
 * fails, matching txvb_verify_all's existing "finish inline" fallback
 * story for whatever didn't get a thread). */
static int txvb_pool_ensure(int need){
    if (!g_txvb_done_sem_ready) { sem_init(&g_txvb_done_sem, 0, 0); g_txvb_done_sem_ready = 1; }
    while (g_txvb_pool_size < need){
        txvb_worker_slot_t* w = &g_txvb_pool[g_txvb_pool_size];
        sem_init(&w->work_sem, 0, 0);
        if (bmc_pthread_create(&w->tid, txvb_worker_loop, w) != 0) break;
        g_txvb_pool_size++;
    }
    return g_txvb_pool_size;
}

/* txvb_verify_all: verify EVERY input across the WHOLE block's flat array --
 * taproot included as of 2026-08-23 (PERF_SCOPE.md section 14.7) -- in
 * parallel once there's enough work to be worth it (same TXV_PARALLEL_MIN
 * threshold and reasoning as above, just measured block-wide instead of
 * per-tx). Always fills res[] completely and returns -- no early exit on the
 * first failure, unlike txv_verify_all -- the caller
 * (tx_verify_block_connect_all's Phase 4) is the single place that scans
 * res[] and decides accept/reject, so the "earliest failing tx in block
 * order" logic exists in exactly one place. */
static void txvb_verify_all(txvb_in_t* flat, txvb_result_t* res, u64 total, unsigned long long flags){
    for (u64 i=0;i<total;i++){ res[i].ok=0; res[i].reason[0]=0; }
    u64 nverify = total;
    if (nverify == 0) return;

    if (nverify < TXV_PARALLEL_MIN){
        /* plain static, not __thread -- this branch only ever runs on the
         * calling thread (sequential, no pthread_create here), same as
         * txv_verify_all's own equivalent branch above. */
        static u8 sv_work[1<<20];
        for (u64 i=0;i<total;i++){
            const char* r = 0;
            int ok = txvb_verify_one(flat[i].tx_ptr, flat[i].tx_len, &flat[i], flags, sv_work, 1<<20, &g_spk_pool, &g_tap_pool, g_tapdesc, &r);
            res[i].ok = ok?1:0;
            if (!ok) { size_t n=strlen(r); if(n>63)n=63; memcpy(res[i].reason,r,n); res[i].reason[n]=0; }
        }
        return;
    }

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN); if (ncpu < 1) ncpu = 1;
    int nworkers = (int)(nverify < (u64)ncpu ? nverify : (u64)ncpu);
    if (nworkers > TXVB_MAX_WORKERS) nworkers = TXVB_MAX_WORKERS;
    if (nworkers < 1) nworkers = 1;

    int pool_avail = txvb_pool_ensure(nworkers);
    int nspawn = nworkers < pool_avail ? nworkers : pool_avail;
    static u64 claim;            /* one round at a time; the pool is not
                                  * re-entrant and never has been */
    claim = 0;
    int spawned = 0;
    for (int w=0; w<nspawn; w++){
        txvb_worker_slot_t* slot = &g_txvb_pool[w];
        slot->flat=flat; slot->res=res; slot->flags=flags;
        slot->next=&claim; slot->total=total;
        sem_post(&slot->work_sem);
        spawned++;
    }
    for (int w=0; w<spawned; w++) sem_wait(&g_txvb_done_sem);

    /* plain static, not __thread -- runs only after every worker has
     * already joined above (sequential), same as txv_verify_all's own
     * equivalent fallback sweep. */
    static u8 sv_work_main[1<<20];
    for (u64 i=0;i<total;i++){
        if (res[i].ok) continue;
        if (res[i].reason[0] != 0) continue;   /* a real reported failure already */
        const char* r = 0;
        int ok = txvb_verify_one(flat[i].tx_ptr, flat[i].tx_len, &flat[i], flags, sv_work_main, sizeof sv_work_main, &g_spk_pool, &g_tap_pool, g_tapdesc, &r);
        res[i].ok = ok ? 1 : 0;
        if (!ok) { size_t n=strlen(r); if(n>63)n=63; memcpy(res[i].reason, r, n); res[i].reason[n]=0; }
    }
}

/* SCR-6 (audit 2026-09-03): per-tx sigop COST for the LAST
 * tx_verify_block_connect_all call -- the exact quantity Core's ConnectBlock
 * accumulates (nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
 * reject bad-blk-sigops above MAX_BLOCK_SIGOPS_COST=80,000). Same file-scope
 * single-threaded export discipline as the VAL-1 fees ledger. */
static u64* g_tx_sigops = 0;  static u64 g_tx_sigops_cap = 0;  static u64 g_tx_sigops_n = 0;
unsigned long long* txvb_last_tx_sigops(unsigned long long* n){ if(n) *n = g_tx_sigops_n; return (unsigned long long*)g_tx_sigops; }

/* VAL-4 / BIP68 (audit 2026-09-03): the per-input prevout CREATION HEIGHTS,
 * flat and in the same order as `flat`, with each input's owning transaction
 * index alongside.
 *
 * CalculateSequenceLocks needs prevHeights[] -- one height per input -- and
 * this loop is the only place that resolves them (bidx_get for a spend of an
 * output created earlier in the SAME block, utxo_lsm_get otherwise). Exporting
 * them costs one array write per input on a path that already did the lookup;
 * re-resolving them in the caller would mean duplicating the bidx/LSM
 * precedence rule, which is exactly the kind of second implementation that
 * drifts. Same seam as txvb_last_tx_sigops. */
static u64* g_in_height = 0;  static u64 g_in_height_cap = 0;  static u64 g_in_height_n = 0;
static u32* g_in_txidx  = 0;  static u64 g_in_txidx_cap  = 0;
unsigned long long* txvb_last_in_heights(unsigned long long* n, unsigned int** txidx){
    if (n) *n = g_in_height_n;
    if (txidx) *txidx = g_in_txidx;
    return (unsigned long long*)g_in_height;
}

/* The last data push of a scriptSig (Core's subscript source for both the
 * P2SH accurate sigop count and the P2SH-wrapped witness lookup). Mirrors
 * daemon/tx_accept.c's sgc_last_push: any non-push opcode (opcode > OP_16)
 * yields 0, exactly like CScript::GetSigOpCount(const CScript&). */
static int txv_sgc_last_push(const u8* sc, unsigned long sl, const u8** out, unsigned long* outl){
    const u8* p = sc; const u8* end = sc + sl;
    const u8* last = 0; unsigned long lastl = 0;
    while (p < end){
        u8 op = *p++;
        unsigned long n;
        if (op <= 0x4b) n = op;
        else if (op == 0x4c){ if (p >= end) return 0; n = *p++; }
        else if (op == 0x4d){ if (p+2 > end) return 0; n = (unsigned long)p[0] | ((unsigned long)p[1]<<8); p += 2; }
        else if (op == 0x4e){ if (p+4 > end) return 0; n = (unsigned long)p[0]|((unsigned long)p[1]<<8)|((unsigned long)p[2]<<16)|((unsigned long)p[3]<<24); p += 4; }
        else if (op <= 0x60) { last = p; lastl = 0; continue; }   /* OP_1NEGATE/OP_N */
        else return 0;                                            /* opcode > OP_16 */
        if ((unsigned long)(end - p) < n) return 0;
        last = p; lastl = n; p += n;
    }
    if (!last) return 0;
    *out = last; *outl = lastl;
    return 1;
}

extern long tx_legacy_sigops(const u8* tx, unsigned long txlen);
extern long script_sigops_accurate(const u8* script, unsigned long len);

/* Core WitnessSigOps for one witness program. */
static u64 txv_witness_sigops(int wver, unsigned long proglen, const u8* wit_last, unsigned long wit_lastl){
    if (wver != 0 || !wit_last) return 0;
    if (proglen == 20) return 1;                              /* P2WPKH */
    if (proglen == 32) return (u64)script_sigops_accurate(wit_last, wit_lastl);  /* P2WSH */
    return 0;
}

/* GetTransactionSigOpCost for ONE non-coinbase tx, from the Phase-1-resolved
 * flat entries. All reads are of data Phase 1 already bounded. */
static u64 txv_sigop_cost_tx(const u8* tx, u64 txlen, const txvb_in_t* flat,
                             u64 lo, u64 hi, u64 flags){
    u64 cost = (u64)tx_legacy_sigops(tx, (unsigned long)txlen) * 4ULL;   /* WITNESS_SCALE_FACTOR */
    for (u64 gi = lo; gi < hi; gi++){
        const txvb_in_t* in = &flat[gi];
        const u8* spk = g_spk_pool.buf + in->spk_off;
        unsigned long spkl = in->spklen;
        int is_p2sh = (spkl == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87);
        const u8* red = 0; unsigned long redl = 0;
        if (is_p2sh && (flags & (1ULL<<0)) /* SCRIPT_VERIFY_P2SH, Core bit */
            && in->scriptSiglen &&
            txv_sgc_last_push(in->scriptSig, in->scriptSiglen, &red, &redl) && red)
            cost += (u64)script_sigops_accurate(red, redl) * 4ULL;
        if (flags & TXV_FLAG_WITNESS){
            /* native witness program on the prevout spk... */
            const u8* ws = spk; unsigned long wsl = spkl;
            if (is_p2sh){ ws = red; wsl = redl; }              /* ...or P2SH-wrapped */
            if (ws && wsl >= 4 && wsl <= 42 &&
                (ws[0] == 0x00 || (ws[0] >= 0x51 && ws[0] <= 0x60)) &&
                (unsigned long)ws[1] + 2 == wsl && ws[1] >= 2 && ws[1] <= 40){
                int wver = ws[0] == 0x00 ? 0 : ws[0] - 0x50;
                const u8* wlast = in->nwit ? in->wit[in->nwit-1] : 0;
                unsigned long wlastl = in->nwit ? in->witlen[in->nwit-1] : 0;
                cost += txv_witness_sigops(wver, ws[1], wlast, wlastl);
            }
        }
    }
    return cost;
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
/* txvb_classify: the per-input consensus classification, extracted verbatim
 * from Phase 1's loop body (2026-08-24, phase 2 slice 2 of the C->asm
 * conversion) so bitcoin_txv_classify.asm can be differentially driven
 * against it. Maturity, spk copy-out (offset discipline), the taproot gate,
 * segwit classification including the wrapped/native wprog split, the
 * unexpected-witness rule, and the legacy fallthrough. Returns 1 ok /
 * 0 reject with *reason set; caller owns fail_tx_index. Pool passed
 * explicitly so twin and oracle can use separate pools. */
u64 txv_bytepool_alloc(bytepool_t* pool, const u8* src, u64 n){
    return bytepool_alloc(pool, src, n);
}
/* slice 5 seams: the remaining static arena functions, exported so
 * bitcoin_txv_pools.asm's twins can be differentially driven. */
u64 txv_bytepool_reserve(bytepool_t* pool, u64 n){
    return bytepool_reserve(pool, n);
}
void* txv_grow_arena(void** buf, u64* cap_bytes, u64 need_bytes){
    return grow_arena(buf, cap_bytes, need_bytes);
}
/* slice 7 seams: the static taproot aggregate build/verify, exported for
 * tests/test_tapagg_diff.c. */
int txv_test_tapagg_build(bytepool_t* pool, tapagg_t* d, tapin_fn get, void* ctx,
                          u64 nin, const u8* tx, u64 txlen, const char** reason){
    return tapagg_build(pool, d, get, ctx, nin, tx, txlen, reason);
}
int txv_test_tapagg_verify(const bytepool_t* pool, const tapagg_t* d, const u8* spk,
                           const u8* const* wit, const u32* witlen, u32 nwit,
                           u64 local_idx, const char** reason){
    return tapagg_verify(pool, d, spk, wit, witlen, nwit, local_idx, 0, reason);
}
/* slice 8 seam: the dispatch, explicit-state. */
int txv_test_verify_one(const u8* tx, u64 txlen, txvb_in_t* in, unsigned long long flags,
                        u8* sv_work, unsigned long sv_workcap,
                        const bytepool_t* spk_pool, const bytepool_t* tap_pool,
                        const tapagg_t* tapdesc, const char** reason){
    return txvb_verify_one(tx, txlen, in, flags, sv_work, sv_workcap,
                           spk_pool, tap_pool, tapdesc, reason);
}
int txvb_classify(txvb_in_t* in, long height, unsigned long long flags,
                  u64 value, u64 uheight, u64 ucb,
                  const u8* spk, unsigned long spklen,
                  bytepool_t* spk_pool, int* has_taproot, const char** reason){
    if (ucb) {
        long conf = height - (long)uheight;
        if (conf < COINBASE_MATURITY) { *reason = "immature coinbase spend (100-block rule)"; return 0; }
    }
    in->value = value;
    if (spklen > TXV_SPK_CAP) { *reason = "prevout script too large"; return 0; }
    in->spk_off = bytepool_alloc(spk_pool, spk, spklen);
    if (in->spk_off == ~0ull) { *reason = "out of memory"; return 0; }
    in->spklen = (u32)spklen;

    if (is_p2tr(spk, (u32)spklen) && (flags & TXV_FLAG_TAPROOT)) {
        *has_taproot = 1; in->shape = TXV_SHAPE_P2TR;
        if (in->scriptSiglen != 0) { *reason = "p2tr scriptSig must be empty"; return 0; }
        /* Exact shape (key-path vs script-path, annex or not) isn't
         * decidable from nwit alone -- taproot_verify_input classifies
         * it properly in Phase 3. Only the structural "some witness
         * must be present" rule (BIP341: an empty witness is always
         * invalid) is checked here. */
        if (in->nwit == 0) { *reason = "p2tr empty witness"; return 0; }
        return 1;
    }
    if (flags & TXV_FLAG_WITNESS) {
        u32 wver=0, wplen=0; const u8* wprog=0; int wrapped=0;
        int cls = sv_classify_segwit(spk, (u32)spklen, in->scriptSig, in->scriptSiglen,
                                     &wver, &wprog, &wplen, &wrapped);
        if (cls < 0) { *reason = "p2sh-wrapped witness program: scriptSig must be exactly one push of the redeemScript"; return 0; }
        if (cls > 0) {
            if (!wrapped && in->scriptSiglen != 0) { *reason = "witness program scriptSig must be empty"; return 0; }
            if (wver == 0) {
                in->shape = TXV_SHAPE_WV0; in->wproglen = wplen; in->wrapped = (u8)wrapped;
                if (wrapped) { in->wprog = wprog; in->wprog_off = 0; }          /* redeemScript: tx bytes, stable */
                else         { in->wprog = 0; in->wprog_off = (u32)(wprog - spk); } /* program lies inside the spk:
                              * store an offset and re-derive from the POOL copy at verify time --
                              * `spk` here is utxo_lsm_get's transient buffer (see spk_off's comment) */
                if (wplen == 20 && in->nwit != 2) { *reason = "p2wpkh needs exactly 2 witness items"; return 0; }
                if (wplen == 32 && in->nwit < 1) { *reason = "p2wsh needs a witnessScript"; return 0; }
            } else {
                in->shape = TXV_SHAPE_WPASS;
            }
            return 1;
        }
        if (in->nwit != 0) { *reason = "unexpected witness on a non-witness script"; return 0; }
    }
    in->shape = TXV_SHAPE_LEGACY;
    return 1;
}

int tx_verify_block_connect_all(const block_tx_t* txs, u64 ntx, long height,
                                const u8 block_hash32[32], void* lst, void* u, void* bx,
                                u64* fail_tx_index, const char** reason){
    static char g_rbuf[64];
    unsigned long long flags = script_flags_for_block((unsigned long long)height, block_hash32);

    /* VAL-1 fees ledger (audit 2026-09-03): per-tx input sums, exported to
     * the caller's ConnectBlock fee/subsidy check through
     * txvb_last_tx_in_sums. Sized and zeroed on EVERY call before any return
     * (the total_nin==0 early exit below must still read as "zero fees"). */
    {
        u64* p = grow_arena((void**)&g_tx_in_sums, &g_tx_in_sums_cap, ntx * sizeof(u64));
        if (!p){ *reason = "out of memory"; *fail_tx_index = 0; return 0; }
        memset(g_tx_in_sums, 0, ntx * sizeof(u64));
        g_tx_in_sums_n = ntx;
    }

    u64 total_nin = 0;
    for (u64 t=1; t<ntx; t++) total_nin += txs[t].pn_in;

    /* SCR-6 ledger sizing + the coinbase's legacy cost, BEFORE the total_nin
     * early-return, so the exported array is valid on EVERY success path (the
     * caller sums it unconditionally). With zero non-coinbase inputs no tx has
     * a P2SH/witness addend (those need resolved inputs), so the whole block's
     * cost is just the legacy per-tx scan. */
    {
        { /* VAL-4/BIP68: one slot per INPUT, sized here alongside the sigop ledger */
          u64* hp = grow_arena((void**)&g_in_height, &g_in_height_cap, total_nin * sizeof(u64));
          u32* xp = grow_arena((void**)&g_in_txidx,  &g_in_txidx_cap,  total_nin * sizeof(u32));
          /* total_nin == 0 is a coinbase-only block: grow_arena returns NULL
           * for a zero-byte request, which is not a failure. Only a genuine
           * allocation failure is. */
          if (total_nin && (!hp || !xp)){ *reason = "oom: bip68 height ledger"; return 0; }
          if (total_nin){
              memset(g_in_height, 0, total_nin * sizeof(u64));
              memset(g_in_txidx,  0, total_nin * sizeof(u32));
          }
          g_in_height_n = total_nin; }
        u64* p = grow_arena((void**)&g_tx_sigops, &g_tx_sigops_cap, ntx * sizeof(u64));
        if (!p){ *reason = "out of memory"; *fail_tx_index = 0; return 0; }
        memset(g_tx_sigops, 0, ntx * sizeof(u64));
        g_tx_sigops_n = ntx;
        g_tx_sigops[0] = (u64)tx_legacy_sigops(txs[0].ptr, (unsigned long)txs[0].len) * 4ULL;
        if (total_nin == 0){
            for (u64 t=1; t<ntx; t++)
                g_tx_sigops[t] = (u64)tx_legacy_sigops(txs[t].ptr, (unsigned long)txs[t].len) * 4ULL;
            return 1;
        }
    }

    static txvb_in_t* g_flat = 0;        static u64 g_flat_cap = 0;
    static txvb_result_t* g_res = 0;     static u64 g_res_cap = 0;
    static txvb_txrange_t* g_ranges = 0; static u64 g_ranges_cap = 0;
    /* g_spk_pool is file-scope (see its own comment, near bytepool_alloc) --
     * txvb_verify_one and the taproot pass below both need to resolve
     * spk_off against it too, not just this function. */
    txvb_in_t* flat = grow_arena((void**)&g_flat, &g_flat_cap, total_nin * sizeof(txvb_in_t));
    txvb_result_t* res = grow_arena((void**)&g_res, &g_res_cap, total_nin * sizeof(txvb_result_t));
    txvb_txrange_t* ranges = grow_arena((void**)&g_ranges, &g_ranges_cap, ntx * sizeof(txvb_txrange_t));
    if (!flat || !res || !ranges) {
        *reason = "out of memory"; *fail_tx_index = 0;
        return 0;
    }
    g_spk_pool.used = 0;   /* bump-reset: safe, every byte handed out below
                            * this call is freshly memcpy'd before any read */
    g_wit_pool.used = 0;   /* bump-reset the witness-item pool for this block */

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

    /* Resolve each input's witness offset to ptr/len addresses now the pool
     * is done growing (Phase 0 was its sole writer). Before Phase 1/2/3 read
     * in->wit[]/in->witlen[]. */
    for (u64 gi=0; gi<total_nin; gi++){
        txvb_in_t* in = &flat[gi];
        if (in->nwit){ in->wit = g_wit_pool.ptr + in->wit_off; in->witlen = g_wit_pool.len + in->wit_off; }
        else { in->wit = 0; in->witlen = 0; }
    }

    /* ---- Phase 1: resolve + classify every input, sequential, block-wide
     * (in-block index first, confirmed set fallback). Classification body
     * extracted into txvb_classify (2026-08-24, phase 2 slice 2) so the C
     * and its asm twin can be driven side by side; the resolve (bidx/LSM
     * lookup) stays here -- it is the caller's coupling to storage, not
     * classification. Behavior byte-identical to the inline version. ---- */
    int has_taproot = 0;
    for (u64 gi=0; gi<total_nin; gi++){
        txvb_in_t* in = &flat[gi];
        u32 index; memcpy(&index, in->outpoint+32, 4);
        u64 value=0, uheight=0, ucb=0; const u8* spk=0; unsigned long spklen=0;
        long r = -1;
        if (bx) r = bidx_get(bx, (u32)in->tx_index, in->outpoint, index, &value, &uheight, &ucb, &spk, &spklen);
        if (r != 1) r = utxo_lsm_get(lst, u, in->outpoint, index, &value, &uheight, &ucb, &spk, &spklen);
        if (r != 1) { *reason = "input references a missing/already-spent UTXO"; *fail_tx_index = in->tx_index; goto fail; }
        /* VAL-1 fees ledger: every non-coinbase input's resolved value lands
         * in its transaction's input sum. A u64 CAmount can never overflow
         * this accumulator (see the VAL_MAX_MONEY bound the caller applies
         * against the resulting fee). */
        if (in->tx_index < g_tx_in_sums_n) g_tx_in_sums[in->tx_index] += value;
        if (gi < g_in_height_n){ g_in_height[gi] = uheight; g_in_txidx[gi] = (u32)in->tx_index; }
        if (!txvb_classify(in, height, flags, value, uheight, ucb, spk, spklen,
                           &g_spk_pool, &has_taproot, reason)) {
            *fail_tx_index = in->tx_index; goto fail;
        }
    }

    /* ---- SCR-6 (audit 2026-09-03): finish the per-tx sigop COST ledger
     * (sized at the top of this function; the coinbase's legacy cost is
     * already in g_tx_sigops[0]). Core's ConnectBlock accumulates
     * GetTransactionSigOpCost(tx, view, flags) per tx and rejects
     * bad-blk-sigops above MAX_BLOCK_SIGOPS_COST=80,000; the gate itself
     * runs in the caller (apply_block_inner), next to the fee/subsidy check,
     * so the dry-run path (submitblock / GBT proposal) answers it too. -- */
    for (u64 t=1; t<ntx; t++)
        g_tx_sigops[t] = txv_sigop_cost_tx(txs[t].ptr, txs[t].len, flat,
                                           ranges[t].lo, ranges[t].hi, flags);

    /* ---- Phase 1.5 (taproot phase A): sequential, cheap, and the whole
     * reason Phase 2 can now take taproot. For every transaction with at
     * least one taproot input, append its BIP341 aggregate-sighash arrays
     * (outpoints, amounts, packed scriptPubKeys, witness-stripped tx) to one
     * per-BLOCK arena and point every taproot input at the descriptor. This
     * is memcpy plus strip_witness -- not signature work. The arena is
     * READ-ONLY from the moment Phase 2 dispatches, which is what lets many
     * transactions' taproot inputs verify concurrently against it. ---- */
    if (has_taproot) {
        g_tap_pool.used = 0;
        tapagg_t* td = grow_arena((void**)&g_tapdesc, &g_tapdesc_cap, ntx*sizeof(tapagg_t));
        if (!td) { *reason = "out of memory"; *fail_tx_index = 0; goto fail; }
        for (u64 t=1; t<ntx; t++){
            u64 lo = ranges[t].lo, hi = ranges[t].hi, nin_t = hi-lo;
            int tx_has_tap = 0;
            for (u64 gi=lo; gi<hi; gi++) if (flat[gi].shape == TXV_SHAPE_P2TR) { tx_has_tap = 1; break; }
            if (!tx_has_tap) continue;
            if (!tapagg_build(&g_tap_pool, &td[t], txvb_tapin, &flat[lo], nin_t,
                              txs[t].ptr, txs[t].len, reason)) {
                *fail_tx_index = t; goto fail;
            }
            for (u64 gi=lo; gi<hi; gi++)
                if (flat[gi].shape == TXV_SHAPE_P2TR) flat[gi].tap_desc = t;
        }
    }

    /* ---- Phase 2: the actual (parallel) crypto verification for EVERY
     * input in the whole block, taproot included. ---- */
    txvb_verify_all(flat, res, total_nin, flags);

    /* ---- Phase 4: first failing input, in block order (flat array order
     * already matches, since entries are appended tx-by-tx in order). Now
     * that taproot rides the same pass, this is genuinely the earliest
     * failure in the block; the previous code deliberately reported the
     * earliest NON-taproot failure ahead of any taproot one, because taproot
     * ran in a separate later pass. Both reject the same blocks -- only the
     * reported reason/tx index could differ, and only for a block with two
     * independent failures. ---- */
    for (u64 gi=0; gi<total_nin; gi++){
        if (!res[gi].ok) {
            *fail_tx_index = flat[gi].tx_index;
            size_t n = strlen(res[gi].reason); if (n > sizeof(g_rbuf)-1) n = sizeof(g_rbuf)-1;
            memcpy(g_rbuf, res[gi].reason, n); g_rbuf[n] = 0;
            *reason = g_rbuf;
            goto fail;
        }
    }

    return 1;

fail:
    return 0;
}

/* ---- phase 2 slice 1 test hooks (2026-08-24) ----------------------------
 * tests/test_txv_parse_diff.c drives the C txv_parse and the asm
 * txv_parse_asm side by side. The C one is static and writes file-scope
 * state; these expose exactly enough to compare, same pattern as
 * utxo_live's test hooks. Not used by the daemon. */
int txv_test_parse(const u8* tx, u64 txlen, u64* out_nin, const char** reason){
    return txv_parse(tx, txlen, out_nin, reason);
}
int txv_test_parse_block(const u8* tx, u64 txlen, u64 tx_index, void* flat,
                         u64 base, u64 cap, u64* out_nin, const char** reason){
    return txvb_parse_tx(tx, txlen, tx_index, (txvb_in_t*)flat, base, cap, out_nin, reason);
}
void* txv_test_in(void){ return g_txv_in; }
void* txv_test_witpool(void){ return &g_wit_pool; }

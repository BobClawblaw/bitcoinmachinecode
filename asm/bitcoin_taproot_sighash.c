#include "bmc_thread.h"
/* bitcoin_taproot_sighash.c -- BIP341 (Taproot) + BIP342 (Tapscript) signature
 * hashing and taproot spend validation.
 *
 * The cryptographic core is all in verified x86-64 ASM (sha256_full.asm,
 * secp256k1_taproot.asm tagged_hash256, secp256k1_schnorr.asm schnorr_verify).
 * This file provides the BIP341 SigMsg serialization (a thin, self-contained
 * glue layer, mirroring the project's wallet_core.c / bitcoin_mempool_policy.c
 * convention) and the key-path / script-path spend verifiers.
 *
 * The BIP341 SigMsg layout here is validated byte-for-byte against the official
 * Bitcoin Core wallet-test-vectors (bip-0341/wallet-test-vectors.json) for
 * SIGHASH_DEFAULT/ALL/NONE/SINGLE and the ANYONECANPAY variants (see
 * validation/gen_taproot_vectors.py + asm/tests/test_taproot_sighash.c).
 */
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>

extern void sha256_full(uint8_t* out, const void* msg, int64_t len);
extern void tagged_hash256(uint8_t* out, const char* tag, uint64_t taglen,
                           const uint8_t* msg, uint64_t msglen);
extern int  schnorr_verify(const uint8_t* sig, const uint8_t* pk,
                           const uint8_t* msg, int msglen);
extern long taproot_tweak_pubkey(uint8_t* out_x, const uint8_t* internal_x,
                                 const uint8_t* merkle_root);
extern long tap_leaf_hash(uint8_t out[32], uint8_t leaf_version,
                          const uint8_t* script, uint64_t slen);
extern long tap_merkle_root(uint8_t out[32], const uint8_t* leaf_hashes, uint64_t count,
                            const uint8_t* control, uint64_t clen);
extern int  stack_push(uint64_t* sp, uint8_t* elems, const uint8_t* data, uint32_t len);

#define SHA256SZ 32

/* ---------------- compact-size (varint) helpers ----------------
 * read_cs is BOUNDED and MINIMALITY-CHECKING, and both properties are new
 * (2026-08-22). It is the same reader bitcoin_segwit.c grew in fc4bd67, for
 * the same two reasons, and the two files must agree because the daemon feeds
 * both the SAME stripped transaction (daemon/tx_verify.c calls
 * strip_witness() and hands the result to taproot_verify_input()).
 *
 * BOUNDED. A compactsize is 1, 3, 5 or 9 bytes and the width is chosen by the
 * first byte, which is itself wire data. The previous reader here took no
 * `end` at all, so ANY walk that landed on the last byte of the transaction
 * read up to 8 bytes past it -- and every walk in this file could land there,
 * because tx_parse() read the length BEFORE checking that the length fit.
 * Concretely: a 10-byte buffer whose byte 4 is 0xff made tx_parse read
 * tx[5..12], three bytes past the end, before any bound was consulted. That
 * is incident #21's class exactly, one file over. tests/test_taproot_bounds_
 * fuzz.c puts the transaction against a PROT_NONE page and SIGSEGVs on the
 * pre-fix tree.
 *
 * MINIMAL. Core's ReadCompactSize() throws "non-canonical ReadCompactSize()"
 * for an 0xfd form below 253, an 0xfe form below 0x10000, or an 0xff form
 * below 0x100000000, ungated, so a transaction carrying a padded compactsize
 * cannot be deserialized by Core at all and cannot appear in a block Core
 * accepts. That rule became load-bearing the moment sha_outputs started
 * hashing each CTxOut IN PLACE instead of re-serializing it: the old
 * ser_txout() wrote put_cs(len), i.e. the canonical form, so a padded length
 * was silently rewritten before hashing, and raw bytes are not rewritten.
 * Neither answer is Core's -- Core refuses the transaction -- so this refuses
 * it too, which is what makes in-place hashing PROVABLY identical to
 * canonical re-serialization for every transaction not refused. It costs the
 * hot path nothing: the single-byte encoding returns before any width is
 * computed.
 *
 * (Same standing note as bitcoin_segwit.c: nothing else in the tree enforces
 * minimality -- bitcoin_tx.asm's readers do not -- so a peer's non-canonical
 * transaction is still mis-parsed elsewhere. Pre-existing, separate fix.) */
static uint64_t read_cs(const uint8_t** p, const uint8_t* end, int* ok){
    const uint8_t* b = *p;
    if (b >= end){ *ok = 0; *p = end; return 0; }
    uint8_t f = *b++;
    if (f < 0xfd){ *p = b; return f; }          /* hot path: one compare */
    int extra = (f == 0xfd) ? 2 : (f == 0xfe ? 4 : 8);
    if (end - b < extra){ *ok = 0; *p = end; return 0; }
    uint64_t v, min;
    if (f == 0xfd){ v = b[0] | ((uint64_t)b[1]<<8); b += 2; min = 0xfdULL; }
    else if (f == 0xfe){ v = 0; for(int i=0;i<4;i++) v |= (uint64_t)b[i]<<(8*i); b += 4; min = 0x10000ULL; }
    else              { v = 0; for(int i=0;i<8;i++) v |= (uint64_t)b[i]<<(8*i); b += 8; min = 0x100000000ULL; }
    if (v < min){ *ok = 0; *p = end; return 0; }   /* non-canonical */
    *p = b;
    return v;
}
/* Bytes still available at q. Every bound test below is a "remaining >=
 * wanted" comparison on this value, never `q + n > end`: the lengths come off
 * the wire and can be up to 2^64-1, so forming q+n first overflows the
 * pointer (undefined, and in practice wraps to a small address that PASSES
 * the test). The old tx_parse used exactly that form -- `q + (int64_t)sl + 4 >
 * t->tx + t->txlen` -- and worse, cast an unsigned wire length through
 * int64_t first, so any sl >= 2^63 went NEGATIVE and the comparison passed
 * unconditionally. Incident #21 removed the same idiom from
 * bitcoin_segwit.c. */
static uint64_t ts_avail(const uint8_t* q, const uint8_t* end){
    return (uint64_t)(end - q);
}
static int cs_size(uint64_t n){
    if (n < 0xfdUL) return 1;
    if (n <= 0xffffUL) return 3;
    if (n <= 0xffffffffUL) return 5;
    return 9;
}
static void put_cs(uint8_t* d, uint64_t n){
    if (n < 0xfdUL) { d[0]=(uint8_t)n; }
    else if (n <= 0xffffUL){ d[0]=0xfd; d[1]=(uint8_t)n; d[2]=(uint8_t)(n>>8); }
    else if (n <= 0xffffffffUL){ d[0]=0xfe; for(int i=0;i<4;i++) d[1+i]=(uint8_t)(n>>(8*i)); }
    else { d[0]=0xff; for(int i=0;i<8;i++) d[1+i]=(uint8_t)(n>>(8*i)); }
}
static void w32le(uint8_t* d, uint32_t v){ for(int i=0;i<4;i++) d[i]=(uint8_t)(v>>(8*i)); }
static void w64le(uint8_t* d, uint64_t v){ for(int i=0;i<8;i++) d[i]=(uint8_t)(v>>(8*i)); }

/* ---------------- transaction view ----------------
 * ONE bounded pass over the transaction records where every input and every
 * output starts; every accessor afterwards is an array index.
 *
 * What this replaces was O(n^3) PER TRANSACTION, the identical shape
 * PERF_SCOPE.md section 7 measured in bitcoin_segwit.c and fc4bd67 removed:
 *
 *   tx_seq(t,i) and tx_outpoint(t,i) each re-walked the input list FROM THE
 *   START to reach input i, parsing a compactsize per step. BIP341's
 *   sha_sequences calls tx_seq once per input, so building it was O(nin^2)
 *   varint reads.
 *
 *   ser_txout(t,i) re-walked the first i outputs, and ser_txout_len(t,i) did
 *   the same walk TWICE -- literally twice, the first result computed into a
 *   local and then thrown away and the loop re-run. sha_outputs called both
 *   once per output, so it was THREE O(nout^2) walks.
 *
 *   And taproot_sighash() is called once per input (once per executed
 *   OP_CHECKSIG/OP_CHECKSIGADD, via taproot_checksig_fn), while BIP341's
 *   aggregate hashes depend only on the transaction and not on which input
 *   is being signed -- so all of that was redone from scratch nin times.
 *
 * Core has never paid any of it: PrecomputedTransactionData walks the
 * transaction once.
 *
 * in_off[i] is the offset of input i's 36-byte outpoint, for i in [0, nin],
 * where in_off[nin] is one past the last input (the nout compactsize).
 * Inputs are contiguous, so input i's 4-byte nSequence ends exactly at
 * in_off[i+1] -- that is where tx_seq reads it, with no parsing at all, and
 * it is exact for the final input too.
 *
 * out_off[i] is the offset of output i's CTxOut, for i in [0, nout], with
 * out_off[nout] the end of the outputs section.
 *
 * AND THE PART WORTH STATING PLAINLY, BECAUSE BIP341 IS NOT BIP143 HERE:
 * BIP341's sha_outputs is SHA256 over "the serialization of all outputs in
 * CTxOut format", i.e. 8-byte value || compactsize(len) || scriptPubKey per
 * output -- byte for byte the transaction's OWN wire encoding, exactly as in
 * BIP143. So sha_outputs is a single sha256 over the contiguous slice
 * [out_off[0], out_off[nout]) IN PLACE, and SIGHASH_SINGLE's
 * sha_single_output is one over [out_off[n_in], out_off[n_in+1]). ser_txout
 * and ser_txout_len are deleted; no output is copied anywhere.
 *
 * BIP341 does ALSO hash amounts and scriptPubKeys separately -- sha_amounts
 * and sha_scriptpubkeys, which BIP143 has no counterpart for -- and that is
 * NOT a counterexample to the in-place property, because those two are over
 * the SPENT outputs (the UTXOs this transaction consumes), which are not in
 * this transaction at all. They arrive as the caller's own contiguous
 * prevouts/amounts/spks arrays and are handled separately below, where they
 * turn out to need no copying either. The outputs THIS transaction creates
 * are hashed in exactly one place, sha_outputs, in exactly one format. */
typedef struct {
    const uint8_t* tx;   int64_t txlen;
    const uint8_t* end;      /* tx + txlen; every walk below bounds against it */
    int      version;
    uint32_t locktime;
    int64_t  nin, nout;
    const uint32_t* in_off;  /* nin+1 offsets; see above */
    const uint32_t* out_off; /* nout+1 offsets; see above */
} txview_t;

/* Offset-table capacity, in uint32 entries, shared by in_off and out_off.
 *
 * The bound is arithmetic, not a guess, and it is the same one fc4bd67 used
 * for SW_OFF_ENTRIES so the two sighash paths refuse at the same place. On
 * the wire an input costs at least 36 (outpoint) + 1 (a zero-length
 * scriptSig's compactsize) + 4 (nSequence) = 41 bytes and an output at least
 * 8 (value) + 1 = 9, so for a transaction of txlen bytes
 *
 *      (nin + 1) + (nout + 1)  <=  txlen * (1/41 + 1/9) + 2
 *                              =   0.13550 * txlen + 2,
 *
 * and MAX_BLOCK_SERIALIZED_SIZE is 4 MiB, so no transaction a valid block can
 * carry needs more than 0.13550 * 4194304 + 2 = 568,335 entries. 600,000
 * (2.29 MiB) therefore cannot false-reject anything, while still being a
 * hard, checked ceiling on a wire-supplied count rather than an unbounded
 * allocation. Note that the transaction reaching this file is the STRIPPED
 * (no-witness) serialization, which is strictly smaller, so the bound is if
 * anything looser than it needs to be.
 *
 * Per-thread HEAP (BMC_TLS_BUF), never a stack array: incident #13 is what a
 * size-dependent fixed stack buffer does when it meets real chain data. */
#define TS_OFF_ENTRIES 600000u
/* sha_sequences gathers 4 bytes per input, so it needs 4*nin bytes. It can
 * never be the binding constraint: the offset table above already refuses
 * nin+1 > TS_OFF_ENTRIES, so nin <= 599,999 and 4*nin <= 2,399,996 -- which
 * is why this is derived from TS_OFF_ENTRIES rather than stated separately.
 * (The real bound is far smaller: a 4 MiB transaction holds at most
 * 4194304/41 = 102,300 inputs, i.e. 409,200 bytes.) */
#define TS_SEQ_CAP     (4u * TS_OFF_ENTRIES)

/* Single bounded pass. `off` is TS_OFF_ENTRIES uint32 slots owned by the
 * caller; on success t->in_off and t->out_off point into it and stay valid
 * for as long as it does. Returns 0 on malformed. */
static int tx_parse(txview_t* t, uint32_t* off){
    const uint8_t* p = t->tx;
    /* Offsets are recorded as uint32. A transaction over 4 GiB cannot exist
     * in a valid block (MAX_BLOCK_SERIALIZED_SIZE is 4 MiB), so refusing one
     * outright is a bound no real transaction can reach -- and it is what
     * makes the narrowing casts below exact. */
    if (t->txlen < 10 || (uint64_t)t->txlen > 0xffffffffu) return 0;
    const uint8_t* end = t->tx + t->txlen;
    t->end = end;
    int ok = 1;
    t->version = (int32_t)(p[0] | (p[1]<<8) | (p[2]<<16) | ((uint32_t)p[3]<<24));
    p += 4;
    t->nin = (int64_t)read_cs(&p, end, &ok);
    if (!ok || t->nin <= 0) return 0;
    /* nin comes off the wire: bound the table before indexing it. (A count
     * >= 2^63 lands negative in the int64 and is already refused above.) */
    if ((uint64_t)t->nin + 1u > (uint64_t)TS_OFF_ENTRIES) return 0;
    uint32_t* in_off = off;
    const uint8_t* q = p;
    for (int64_t i=0;i<t->nin;i++){
        in_off[i] = (uint32_t)(q - t->tx);
        if (ts_avail(q, end) < 36) return 0;
        q += 36;                         /* prevout */
        uint64_t sl = read_cs(&q, end, &ok);
        /* `avail < sl + 4` would wrap for sl within 4 of 2^64 -- read_cs can
         * return any 64-bit value the wire supplies -- and let a bogus q
         * through. Split it so neither side can overflow. */
        if (!ok || ts_avail(q, end) < sl || ts_avail(q, end) - sl < 4) return 0;
        q += sl + 4;                     /* scriptSig + nSequence */
    }
    in_off[t->nin] = (uint32_t)(q - t->tx);
    t->in_off = in_off;
    t->nout = (int64_t)read_cs(&q, end, &ok);
    if (!ok || t->nout < 0) return 0;
    if ((uint64_t)t->nin + 1u + (uint64_t)t->nout + 1u > (uint64_t)TS_OFF_ENTRIES) return 0;
    uint32_t* out_off = off + t->nin + 1;
    for (int64_t i=0;i<t->nout;i++){
        out_off[i] = (uint32_t)(q - t->tx);
        if (ts_avail(q, end) < 8) return 0;
        q += 8;                          /* value */
        uint64_t sl = read_cs(&q, end, &ok);
        if (!ok || ts_avail(q, end) < sl) return 0;
        q += sl;                         /* scriptPubKey */
    }
    out_off[t->nout] = (uint32_t)(q - t->tx);
    t->out_off = out_off;
    if (ts_avail(q, end) < 4) return 0;
    t->locktime = (uint32_t)(q[0]|(q[1]<<8)|(q[2]<<16)|((uint32_t)q[3]<<24));
    return 1;
}

/* nSequence of input i. Inputs are contiguous, so it is the last 4 bytes
 * before input i+1 begins -- and in_off[nin] is one past the last input, so
 * this is exact for the final input too. O(1), no compactsize read.
 * i must be in [0, nin). */
static uint32_t tx_seq(const txview_t* t, int64_t i){
    const uint8_t* q = t->tx + t->in_off[i+1] - 4;
    return (uint32_t)(q[0]|(q[1]<<8)|(q[2]<<16)|((uint32_t)q[3]<<24));
}

/* outpoint (36 bytes) of input i. O(1): tx_parse recorded the offset in its
 * one bounded pass and proved 36 bytes are there. i must be in [0, nin). */
static const uint8_t* tx_outpoint(const txview_t* t, int64_t i){
    return t->tx + t->in_off[i];
}

/* Outputs [lo, hi) as a contiguous in-place slice. See the header comment:
 * a CTxOut's BIP341 serialization IS its wire encoding, so there is nothing
 * to build and nothing to copy. */
static const uint8_t* tx_txout_range(const txview_t* t, int64_t lo, int64_t hi,
                                     uint64_t* len){
    *len = (uint64_t)(t->out_off[hi] - t->out_off[lo]);
    return t->tx + t->out_off[lo];
}

/* -------- context for sighash -------- */
typedef struct {
    const uint8_t* tx;   int64_t txlen;
    int64_t  n_in;
    uint8_t  hash_type;
    const uint8_t* prevouts;   /* 36 * num_inputs  (for !ACP) */
    const uint8_t* amounts;    /* 8  * num_inputs  (for !ACP) */
    const uint8_t* spks;       /* compactsize+data each, for all inputs */
    int64_t  num_inputs;
    int      ext_flag;         /* 0 keypath, 1 scriptpath(BIP342) */
    const uint8_t* tapleaf;    /* 32 bytes or NULL */
    uint32_t codesep_pos;
    const uint8_t* annex;      /* optional annex bytes (witness annex), or NULL */
    uint64_t annexlen;         /* length of annex (if annex != NULL) */
} tapctx_t;

/* Key-path budget for a reference P2TR: script is 34 bytes. */

/* SigMsg preimage buffer used by the four verifiers below (taproot_sighash
 * itself still takes the buffer from its caller, because tests drive it
 * directly). Bound, from the BIP341 layout:
 *
 *   epoch 1 + hash_type 1 + nVersion 4 + nLockTime 4
 *   + 4*32 aggregates (non-ACP only)               = 128
 *   + sha_outputs 32  OR  sha_single_output 32     =  32  (mutually exclusive)
 *   + spend_type 1
 *   + input_index 4  OR  ACP's outpoint 36 + amount 8 + cs+spk + nSequence 4
 *   + sha_annex 32
 *   + ext: tapleaf 32 + key_version 1 + codesep 4  =  37
 *
 * which is 244 bytes plus, on the ANYONECANPAY branch only, the spent
 * scriptPubKey and its compactsize. That was a `uint8_t pre[256]` stack
 * array, and 256 is enough ONLY because the spent output of a taproot input
 * is a 34-byte P2TR program -- for anything larger taproot_sighash's own cap
 * check fired and returned 0, i.e. a silent FALSE REJECT on a consensus path,
 * with the accept/reject line sitting at an undocumented ~200 bytes. Core has
 * no such limit. 64 KiB removes the latent false-reject entirely (no caller in
 * this tree can reach even 253 bytes -- daemon/tx_verify.c and
 * bitcoin_txval_modern.c both refuse a spent scriptPubKey >= 0xfd before
 * calling here) while keeping the bound hard and checked. Per-thread heap;
 * none of the four verifiers nest, so one buffer serves them all. */
#define TS_PRE_CAP (64u<<10)

/* BIP341's four aggregate hashes, plus the offset of the input being signed
 * inside the caller's spks run (the ANYONECANPAY branch needs it, and finding
 * it here costs nothing because the run has to be walked anyway).
 * Returns 0 on malformed input; the caller MUST fail closed on 0.
 *
 * WHAT USED TO BE HERE, AND WHY IT WAS BOTH SLOW AND UNSAFE.
 *
 * Every one of the four staged its input into a 4 MiB per-thread buffer and
 * hashed that. Three of the four did not need to: c->prevouts, c->amounts and
 * c->spks are ALREADY the contiguous concatenations BIP341 asks for -- the
 * old loops were copying a buffer onto itself, 36/8/n bytes at a time, and
 * then hashing the copy. They are now hashed where they lie, which removes
 * both the copies and the 4 MiB buffer.
 *
 * The bound checks on those copies were also wrong in two ways:
 *   - the scriptpubkeys loop tested `n + 600 > TS_AGG_CAP` and then copied
 *     `cs + sl` bytes, so any spent scriptPubKey longer than 600 bytes
 *     overran the destination. Consensus places no limit on a scriptPubKey's
 *     size (only relay standardness does) -- this is incident #21's shape
 *     exactly, on the heap instead of the stack;
 *   - the sequences loop had NO bound at all, and it iterated to
 *     c->num_inputs while tx_seq() indexed the TRANSACTION, which has t->nin
 *     inputs. Nothing checked that those two agree. They do agree for every
 *     caller in this tree, but "a distant function already checked this" is
 *     how #13 and #21 both happened, so it is checked here now.
 *
 * And on failure the function simply `return`ed -- leaving the remaining
 * h_* outputs UNINITIALIZED, which taproot_sighash then copied into the
 * preimage. A truncated aggregate was not refused; it was hashed. Returning
 * a status and failing closed is the entire fix for that. */
static int ts_agg_hashes(const tapctx_t* c, const txview_t* t,
                         uint8_t h_prev[32], uint8_t h_amt[32],
                         uint8_t h_spk[32], uint8_t h_seq[32],
                         const uint8_t** spk_at_nin, uint64_t* spk_at_nin_len)
{
    const int64_t n = c->num_inputs;
    /* BIP341's aggregates are over ALL of this transaction's inputs, so the
     * caller's per-input arrays must describe exactly this transaction. */
    if (n <= 0 || n != t->nin) return 0;

    /* sha_prevouts, sha_amounts: contiguous already. No copy, no buffer. */
    sha256_full(h_prev, c->prevouts, n * 36);
    sha256_full(h_amt,  c->amounts,  n * 8);

    /* sha_scriptpubkeys: also contiguous -- the run IS
     * compactsize(len)||spk repeated once per input, which is precisely what
     * BIP341 hashes. Walk it once to measure it (and to locate entry n_in),
     * then hash it in place.
     *
     * This run is NOT wire data: it is built by this codebase from resolved
     * UTXOs (daemon/tx_verify.c and bitcoin_txval_modern.c both write one
     * single-byte compactsize per entry and refuse a scriptPubKey >= 253
     * bytes outright). It therefore has no `end` to bound against, and the
     * API gives none. Rather than trust that, the walk carries its own hard
     * ceiling: TS_SPK_RUN_CAP bytes total, checked before every advance, so a
     * corrupted length cannot run away even though it cannot be proven
     * in-bounds. The real fix is an spks_len parameter; that is an ABI change
     * across ~10 call sites in two .c files and five tests, deliberately not
     * bundled into a sighash restructure. Recorded in the commit message. */
    #define TS_SPK_RUN_CAP (4u<<20)
    {
        const uint8_t* p = c->spks;
        const uint8_t* run_end = c->spks + TS_SPK_RUN_CAP;
        int ok = 1;
        for (int64_t i=0;i<n;i++){
            uint64_t sl = read_cs(&p, run_end, &ok);
            if (!ok || ts_avail(p, run_end) < sl) return 0;
            if (i == c->n_in){ *spk_at_nin = p; *spk_at_nin_len = sl; }
            p += sl;
        }
        sha256_full(h_spk, c->spks, (int64_t)(p - c->spks));
    }

    /* sha_sequences: the only one that genuinely has to be gathered, because
     * nSequences are 41+ bytes apart in the transaction rather than
     * contiguous. With in_off[] that is one indexed load per input and no
     * compactsize read at all -- it was an O(nin^2) re-walk. */
    {
        static __thread uint8_t* seqbuf; BMC_TLS_BUF(seqbuf, TS_SEQ_CAP);
        if ((uint64_t)n * 4u > (uint64_t)TS_SEQ_CAP) return 0;   /* unreachable: see TS_SEQ_CAP */
        size_t k = 0;
        for (int64_t i=0;i<n;i++){ w32le(seqbuf+k, tx_seq(t,i)); k += 4; }
        sha256_full(h_seq, seqbuf, (int64_t)k);
    }
    return 1;
}

/* Phase 2 slice 13b seams (2026-08-24): tx_parse and tx_seq are static;
 * exported so bitcoin_bip341.asm's twins use the SAME parse and the same
 * sequence accessor, isolating the serialization under test. */
int ts_tx_parse_export(void* t, uint32_t* off){ return tx_parse((txview_t*)t, off); }
uint32_t ts_tx_seq_export(const void* t, int64_t i){ return tx_seq((const txview_t*)t, i); }
int ts_agg_hashes_export(const void* c, const void* t, uint8_t hp[32], uint8_t ha[32],
                         uint8_t hs[32], uint8_t hq[32], const uint8_t** sp, uint64_t* sl){
    return ts_agg_hashes((const tapctx_t*)c, (const txview_t*)t, hp, ha, hs, hq, sp, sl);
}

/* Build the full TapSighash preimage "0x00 || SigMsg || ext" into pre (cap),
 * return its length, or 0 on error. Then compute TaggedHash("TapSighash", pre)
 * into out32. */
long taproot_sighash(uint8_t* out32, const tapctx_t* c, uint8_t* pre, long cap)
{
    /* The single-pass offset table. Per-thread heap, not a stack array
     * (incident #13), and single-owner: tx_parse fills it and every accessor
     * below indexes it before this function returns. Nothing re-enters -- the
     * only caller chain that could is script_eval -> taproot_checksig_fn ->
     * here, which is one level deep and completes each call before the next. */
    static __thread uint32_t* ts_off;
    BMC_TLS_BUF(ts_off, TS_OFF_ENTRIES * sizeof(uint32_t));

    txview_t t; t.tx = c->tx; t.txlen = c->txlen;
    if (!tx_parse(&t, ts_off)) return 0;
    if (c->n_in < 0 || c->n_in >= t.nin) return 0;
    if (c->n_in >= c->num_inputs) return 0;

    uint8_t h_prev[32], h_amt[32], h_spk[32], h_seq[32];
    const uint8_t* spk_nin = NULL; uint64_t spk_nin_len = 0;
    if (!ts_agg_hashes(c, &t, h_prev, h_amt, h_spk, h_seq, &spk_nin, &spk_nin_len))
        return 0;
    if (!spk_nin) return 0;

    uint8_t ht = c->hash_type;
    /* BIP341: "If the hash_type is not valid, fail." Core, interpreter.cpp
     * (SignatureHashSchnorr):
     *   if (!(hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83)))
     *       return false;
     * which CheckSchnorrSignature turns into SCRIPT_ERR_SCHNORR_SIG_HASHTYPE,
     * i.e. the input is INVALID.
     *
     * FOUND 2026-08-22 while building this commit's corpus proof, and
     * PRE-EXISTING -- not something the restructure introduced. Nothing here
     * validated hash_type at all, and hash_type is the last byte of a 65-byte
     * Schnorr signature, so it is entirely attacker-chosen. A spend signed
     * with hash_type 0x04 is rejected by Core and was ACCEPTED here (0x04 & 3
     * == 0, so it took the plain sha_outputs path and produced a perfectly
     * good hash for the spender to have signed). That is a FALSE ACCEPT on a
     * consensus path -- a chain split, not a false reject.
     *
     * The 64-byte/SIGHASH_DEFAULT rule and the 65-byte-with-0x00 rule are
     * already enforced by the four callers below, which is also where Core
     * puts them (CheckSchnorrSignature, before it hashes anything). */
    if (!(ht <= 0x03 || (ht >= 0x81 && ht <= 0x83))) return 0;
    uint8_t eff = (ht == 0) ? 1 : ht;
    int acp  = (eff & 0x80) != 0;
    int is_single = (eff & 0x03) == 3;
    int is_none   = (eff & 0x03) == 2;

    uint8_t* p = pre;
    uint8_t* pend = pre + cap;

    /* epoch */
    if (p + 1 > pend) return 0; *p++ = 0x00;
    /* hash_type */
    if (p + 1 > pend) return 0; *p++ = ht;
    /* nVersion (LE) */
    if (p + 4 > pend) return 0; w32le(p, (uint32_t)t.version); p += 4;
    /* nLockTime */
    if (p + 4 > pend) return 0; w32le(p, t.locktime); p += 4;
    /* pre-hashes (not ACP) */
    if (!acp){
        if (p + 4*SHA256SZ > pend) return 0;
        memcpy(p, h_prev, 32); p+=32;
        memcpy(p, h_amt,  32); p+=32;
        memcpy(p, h_spk,  32); p+=32;
        memcpy(p, h_seq,  32); p+=32;
    }
    /* sha_outputs (not NONE, not SINGLE) -- IN PLACE over the transaction's
     * own bytes. See the txview_t header comment: a CTxOut's BIP341
     * serialization is byte for byte its wire encoding, so all outputs
     * concatenated are exactly the contiguous slice [out_off[0],
     * out_off[nout]).
     *
     * What is gone: a staging buffer fed by ser_txout_len() + ser_txout()
     * once per output -- three O(nout) walks per output, i.e. three O(nout^2)
     * walks per call, and this whole block ran once per input. Also gone with
     * it: ser_txout_len()'s `int` return, which for a scriptPubKey of
     * 0x100000000 bytes truncated to 13 and let ser_txout() memcpy 4 GiB.
     * Nothing is copied now, so nothing can overrun. */
    if (!is_none && !is_single){
        uint64_t olen; const uint8_t* obytes = tx_txout_range(&t, 0, t.nout, &olen);
        uint8_t ho[32]; sha256_full(ho, obytes, (int64_t)olen);
        if (p + 32 > pend) return 0; memcpy(p, ho, 32); p += 32;
    }
    /* spend_type = ext_flag*2 | annex_present (BIP341 bit0 = annex present) */
    int annex_present = (c->annex != NULL);
    if (p + 1 > pend) return 0; *p++ = (uint8_t)(c->ext_flag * 2 + annex_present);
    if (acp){
        /* outpoint */
        const uint8_t* op = tx_outpoint(&t, c->n_in);
        if (p + 36 > pend) return 0; memcpy(p, op, 36); p += 36;
        /* amount */
        uint64_t amt; const uint8_t* a = c->amounts + c->n_in*8;
        amt = 0; for(int b=0;b<8;b++) amt |= (uint64_t)a[b]<<(8*b);
        if (p + 8 > pend) return 0; w64le(p, amt); p += 8;
        /* scriptPubKey of the spent output being signed. ts_agg_hashes
         * located it during the walk it had to do anyway; this used to be a
         * SECOND unbounded walk of the spks run, from the start, with an
         * unbounded read_cs. */
        uint64_t sl = spk_nin_len;
        if (cap < 0 || (uint64_t)(cap - (p - pre)) < (uint64_t)cs_size(sl) + sl) return 0;
        put_cs(p, sl); p += cs_size(sl);
        memcpy(p, spk_nin, sl); p += sl;
        /* nSequence */
        uint32_t seq = tx_seq(&t, c->n_in);
        if (p + 4 > pend) return 0; w32le(p, seq); p += 4;
    } else {
        /* input_index */
        if (p + 4 > pend) return 0; w32le(p, (uint32_t)c->n_in); p += 4;
    }
    /* annex (BIP341): sha256(compactsize(len) || annex) */
    if (annex_present){
        /* sha256(compactsize(len) || annex) -- Core: (HashWriter{} << annex)
         * .GetSHA256(), interpreter.cpp:1964. The annex is a witness stack
         * item, so its length is bounded by the block size; the prefix is at
         * most 9 bytes. The `> CAP - 9` form avoids the overflow that
         * `cs_size + annexlen > CAP` has for an annexlen near 2^64. */
        #define TS_ANNEX_CAP ((4u<<20) + 9u)
        static __thread uint8_t* abuf; BMC_TLS_BUF(abuf, TS_ANNEX_CAP); size_t an = 0;
        if (c->annexlen > (uint64_t)TS_ANNEX_CAP - 9u) return 0;
        put_cs(abuf, c->annexlen); an += cs_size(c->annexlen);
        memcpy(abuf+an, c->annex, (size_t)c->annexlen); an += (size_t)c->annexlen;
        uint8_t ha[32]; sha256_full(ha, abuf, (int64_t)an);
        if (p + 32 > pend) return 0; memcpy(p, ha, 32); p += 32;
    }
    /* SINGLE: sha_single_output -- in place, same property as sha_outputs,
     * over the one-output slice [out_off[n_in], out_off[n_in+1]). */
    if (is_single){
        if (c->n_in < t.nout){
            uint64_t slen1; const uint8_t* sbytes =
                tx_txout_range(&t, c->n_in, c->n_in + 1, &slen1);
            uint8_t hs[32]; sha256_full(hs, sbytes, (int64_t)slen1);
            if (p + 32 > pend) return 0; memcpy(p, hs, 32); p += 32;
        } else {
            /* Core, interpreter.cpp, in the SIGHASH_SINGLE branch:
             *     if (in_pos >= tx_to.vout.size()) return false;
             * -- there is no such thing as a taproot SIGHASH_SINGLE over a
             * non-existent output. BIP143 does substitute a zero hash in this
             * position and BIP341 deliberately does NOT, and this file had
             * carried the BIP143 behaviour over: it wrote 32 zero bytes and
             * returned a usable sighash for an input index past the end of
             * the output list.
             *
             * FOUND 2026-08-22, PRE-EXISTING, same class as the hash_type
             * check above: Core rejects the input, we accepted it, so any
             * spender willing to sign that hash could have split us off the
             * chain. 130 of the 945 vectors in the first smoke run of
             * validation/diff_bip341_corpus.py are exactly this case on real
             * mainnet transactions -- it is not a corner that needs
             * constructing. Fail closed, which is now byte-for-byte Core's
             * accept/reject boundary. */
            return 0;
        }
    }
    /* BIP342 ext (tapscript) */
    if (c->ext_flag == 1){
        if (c->tapleaf == NULL) return 0;
        if (p + 32 > pend) return 0; memcpy(p, c->tapleaf, 32); p += 32;
        if (p + 1 > pend) return 0; *p++ = 0x00;          /* key_version */
        if (p + 4 > pend) return 0; w32le(p, c->codesep_pos); p += 4;
    }
    long prelen = (long)(p - pre);
    tagged_hash256(out32, "TapSighash", 10, pre, (uint64_t)prelen);
    return prelen;
}

/* ---------------- spend validation ---------------- */

/* Key-path spend: verify a single schnorr signature over the key-path sighash
 * against the P2TR output key (32-byte x-only from scriptPubKey = OP_1 <32b>).
 *   spk: scriptPubKey (34 bytes: 0x51 0x20 <32>)
 *   sig: 64 or 65 bytes (last byte = hash_type if 65)
 *   tx, n_in, prevouts, amounts, spks, num_inputs
 * Returns 1 valid, 0 invalid. */
int taproot_keypath_verify(const uint8_t* spk, const uint8_t* sig, int siglen,
                           const uint8_t* tx, int64_t txlen, int64_t n_in,
                           const uint8_t* prevouts, const uint8_t* amounts,
                           const uint8_t* spks, int64_t num_inputs)
{
    if (siglen < 64 || siglen > 65) return 0;
    if (spk[0] != 0x51 || spk[1] != 0x20) return 0;
    uint8_t ht = (siglen == 65) ? sig[siglen-1] : 0x00;
    /* SIGHASH_DEFAULT (ht 0) requires exactly 64-byte sig; 65-byte with ht 0 invalid */
    if (siglen == 65 && ht == 0x00) return 0;

    tapctx_t c;
    c.tx = tx; c.txlen = txlen; c.n_in = n_in; c.hash_type = ht;
    c.prevouts = prevouts; c.amounts = amounts; c.spks = spks;
    c.num_inputs = num_inputs; c.ext_flag = 0; c.tapleaf = NULL; c.codesep_pos = 0xffffffff;
    c.annex = NULL; c.annexlen = 0;

    static __thread uint8_t* pre; BMC_TLS_BUF(pre, TS_PRE_CAP);
    uint8_t hash[32];
    if (taproot_sighash(hash, &c, pre, (long)TS_PRE_CAP) <= 0) return 0;
    return schnorr_verify(sig, spk+2, hash, 32);
}

/* Key-path verify aware of a witness annex (BIP341 annex rules). Annex commits
 * into the SigMsg (spend_type bit0 + sha256(compactsize(len)||annex)). Returns
 * 1 valid/0 invalid; if out_hash non-NULL the computed sighash is written there.
 */
int taproot_keypath_verify_annex(const uint8_t* spk, const uint8_t* sig, int siglen,
                                 const uint8_t* tx, int64_t txlen, int64_t n_in,
                                 const uint8_t* prevouts, const uint8_t* amounts,
                                 const uint8_t* spks, int64_t num_inputs,
                                 const uint8_t* annex, uint64_t annexlen,
                                 uint8_t* out_hash)
{
    if (siglen < 64 || siglen > 65) return 0;
    if (spk[0] != 0x51 || spk[1] != 0x20) return 0;
    uint8_t ht = (siglen == 65) ? sig[siglen-1] : 0x00;
    if (siglen == 65 && ht == 0x00) return 0;

    tapctx_t c;
    c.tx = tx; c.txlen = txlen; c.n_in = n_in; c.hash_type = ht;
    c.prevouts = prevouts; c.amounts = amounts; c.spks = spks;
    c.num_inputs = num_inputs; c.ext_flag = 0; c.tapleaf = NULL; c.codesep_pos = 0xffffffff;
    c.annex = annex; c.annexlen = annexlen;

    static __thread uint8_t* pre; BMC_TLS_BUF(pre, TS_PRE_CAP);
    uint8_t hash[32];
    if (taproot_sighash(hash, &c, pre, (long)TS_PRE_CAP) <= 0) return 0;
    if (out_hash) memcpy(out_hash, hash, 32);
    return schnorr_verify(sig, spk+2, hash, 32);
}

/* ---------------- script-path (BIP342 tapscript) signature check ----------------
 * A single OP_CHECKSIG / OP_CHECKSIGADD verification: compute the tapscript
 * sighash (SigMsg with ext_flag=1 + tapleaf/key_version/codesep) and BIP340-verify
 * the schnorr signature against an x-only pubkey. This is the checksig_fn body the
 * script interpreter drives for a tapscript spend.
 *
 * sig: 64 or 65 bytes (last byte = hash_type). Empty sig (siglen==0) => treat as
 *      a CHECKSIGADD 'no signature' (returns 0 but is a valid empty entry --
 *      caller decides). pubkey: 32-byte x-only.
 */
int tapscript_checksig_annex(const uint8_t* sig, int siglen, const uint8_t* pubkey,
                             const uint8_t* tx, int64_t txlen, int64_t n_in,
                             const uint8_t* prevouts, const uint8_t* amounts,
                             const uint8_t* spks, int64_t num_inputs,
                             const uint8_t* tapleaf /*32 bytes*/,
                             uint32_t codesep_pos,
                             const uint8_t* annex, uint64_t annexlen,
                             uint8_t* out_hash /*32 or NULL*/);
int tapscript_checksig(const uint8_t* sig, int siglen, const uint8_t* pubkey,
                       const uint8_t* tx, int64_t txlen, int64_t n_in,
                       const uint8_t* prevouts, const uint8_t* amounts,
                       const uint8_t* spks, int64_t num_inputs,
                       const uint8_t* tapleaf /*32 bytes*/,
                       uint32_t codesep_pos, uint8_t* out_hash /*32 or NULL*/)
{
    return tapscript_checksig_annex(sig, siglen, pubkey, tx, txlen, n_in,
                                    prevouts, amounts, spks, num_inputs,
                                    tapleaf, codesep_pos, NULL, 0, out_hash);
}

/* Annex-aware variant: a script-path spend's witness can carry an annex
 * (BIP341) exactly like a key-path spend can, and the annex is committed
 * into the SigMsg the same way in both cases (spend_type bit0 + sha256(
 * compactsize(len)||annex)) -- taproot_keypath_verify_annex already handles
 * this for key-path; this is the script-path counterpart, found missing
 * 2026-08-21 while wiring script-path dispatch (taproot_verify_input):
 * tapscript_checksig previously hardcoded annex=NULL unconditionally, so a
 * script-path spend with a real annex present would compute the wrong
 * sighash and any genuinely valid signature would fail to verify here (a
 * false-reject, never a false-accept -- schnorr_verify is still the final
 * gate over whatever hash got computed). */
int tapscript_checksig_annex(const uint8_t* sig, int siglen, const uint8_t* pubkey,
                             const uint8_t* tx, int64_t txlen, int64_t n_in,
                             const uint8_t* prevouts, const uint8_t* amounts,
                             const uint8_t* spks, int64_t num_inputs,
                             const uint8_t* tapleaf /*32 bytes*/,
                             uint32_t codesep_pos,
                             const uint8_t* annex, uint64_t annexlen,
                             uint8_t* out_hash /*32 or NULL*/)
{
    if (siglen == 0) return 0;                 /* null/empty signature entry */
    if (siglen < 64 || siglen > 65) return 0;
    uint8_t ht = (siglen == 65) ? sig[siglen-1] : 0x00;
    if (siglen == 65 && ht == 0x00) return 0;

    tapctx_t c;
    c.tx = tx; c.txlen = txlen; c.n_in = n_in; c.hash_type = ht;
    c.prevouts = prevouts; c.amounts = amounts; c.spks = spks;
    c.num_inputs = num_inputs; c.ext_flag = 1; c.tapleaf = tapleaf;
    c.codesep_pos = codesep_pos;
    c.annex = annex; c.annexlen = annexlen;

    static __thread uint8_t* pre; BMC_TLS_BUF(pre, TS_PRE_CAP);
    uint8_t hash[32];
    if (taproot_sighash(hash, &c, pre, (long)TS_PRE_CAP) <= 0) return 0;
    if (out_hash) memcpy(out_hash, hash, 32);
    return schnorr_verify(sig, pubkey, hash, 32);
}

/* ---------------- interpreter checksig_fn (tapscript) ----------------
 * Wires the script interpreter (bitcoin_interp.asm) OP_CHECKSIG / OP_CHECKSIGADD
 * to BIP342 taproot signature verification. The interpreter calls:
 *   uint64_t fn(void* ctx, const uint8_t* sig, size_t siglen,
 *               const uint8_t* pub, size_t publen,
 *               const struct { const uint8_t* p; size_t n; }* slice);
 * ctx points at a taproot_checksig_ctx (below). Publen is 0 for 'empty pubkey'
 * (CHECKSIGADD null entry); siglen 0 means 'no signature'.
 */
typedef struct {
    const uint8_t* tx;    int64_t txlen;
    int64_t n_in;
    const uint8_t* prevouts;
    const uint8_t* amounts;
    const uint8_t* spks;
    int64_t num_inputs;
    const uint8_t* tapleaf;   /* 32 bytes */
    uint32_t codesep_pos;
    const uint8_t* annex;     /* optional witness annex, or NULL */
    uint64_t annexlen;
    /* BIP342 sigops/witness-size validation-weight budget (Core's
     * VALIDATION_WEIGHT_PER_SIGOP_PASSED / VALIDATION_WEIGHT_OFFSET, both
     * 50, script/script.h). The caller (taproot_verify_input) initializes
     * this to ser_size(full original witness) + 50, then this function
     * decrements it by 50 on every invocation with a non-empty signature --
     * the asm interpreter's interp_checksig/interp_checksig_add already
     * gate the call itself on siglen!=0, so every actual call here is
     * exactly Core's qualifying "success = !sig.empty()" case. Going
     * negative fails the whole tapscript, matching Core's
     * EvalChecksigTapscript exactly. Mutated in place: this ctx is
     * per-verify-call, never shared/reused, so no locking needed. */
    int64_t weight_left;
} taproot_checksig_ctx;

uint64_t taproot_checksig_fn(void* cptr, const uint8_t* sig, size_t siglen,
                             const uint8_t* pub, size_t publen,
                             const void* slice)
{
    taproot_checksig_ctx* c = (taproot_checksig_ctx*)cptr;
    /* The interpreter's slice is { p, n, codesep_pos } (bitcoin_interp.asm,
     * interp_slice): p/n are the legacy scriptCode and are irrelevant here;
     * codesep_pos is BIP342's "opcode position of the last EXECUTED
     * OP_CODESEPARATOR, or 0xffffffff" that the interpreter tracks for
     * SIGVERSION_TAPSCRIPT and that SignatureHashSchnorr commits into the
     * SigMsg after key_version (Core: execdata.m_codeseparator_pos). Falls
     * back to the ctx's own value when no slice is supplied (direct callers
     * outside the interpreter). */
    const struct { const uint8_t* p; size_t n; uint64_t codesep_pos; }* sl = slice;
    uint32_t codesep_pos = sl ? (uint32_t)sl->codesep_pos : c->codesep_pos;
    if (siglen == 0) return 0;                     /* no signature provided */
    c->weight_left -= 50;
    if (c->weight_left < 0) return 0;               /* BIP342 validation-weight budget exceeded */
    if (publen != 32) return 0;                    /* x-only pubkey required */
    int r = tapscript_checksig_annex(sig, (int)siglen, pub,
                                     c->tx, c->txlen, c->n_in,
                                     c->prevouts, c->amounts, c->spks,
                                     c->num_inputs, c->tapleaf,
                                     codesep_pos, c->annex, c->annexlen, NULL);
    return (uint64_t)r;
}

/* ============================================================================
 * BIP341 witness classification + BIP342 script-path dispatch
 * (taproot_verify_input). The full P2TR entry point: given ANY witness
 * shape, decides key-path vs script-path (with or without an annex),
 * verifies the control-block Merkle commitment for script-path, and -- for
 * the known tapscript leaf version -- executes the tapscript itself
 * through the shared script_eval interpreter (bitcoin_interp.asm), the
 * same interpreter every other script type in this project uses. Mirrors
 * Bitcoin Core's VerifyWitnessProgram taproot branch (script/
 * interpreter.cpp) exactly, including the BIP342 sigops/witness-size
 * validation-weight budget.
 * ============================================================================ */
#define TAPROOT_ANNEX_TAG          0x50u
#define TAPROOT_CONTROL_BASE_SIZE  33
#define TAPROOT_CONTROL_NODE_SIZE  32
#define TAPROOT_CONTROL_MAX_NODES  128
#define TAPROOT_CONTROL_MAX_SIZE   (TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE*TAPROOT_CONTROL_MAX_NODES)
#define TAPROOT_LEAF_MASK          0xfeu
#define TAPROOT_LEAF_TAPSCRIPT     0xc0u

/* ---- private mirror of bitcoin_interp.asm's struct script_state ABI,
 * same layout bitcoin_scriptverify.c's sv_run already relies on (see that
 * file's own copy for the authoritative field-by-field commentary). Script
 * is passed by pointer, NOT copied -- script_eval only ever READS through
 * it (confirmed: no write to [r12+32] anywhere in bitcoin_interp.asm), and
 * BIP342 deliberately has NO fixed script-size cap (the interpreter's own
 * MAX_SCRIPT_SIZE check is skipped entirely for SIGVERSION_TAPSCRIPT), so
 * copying into a fixed-size scratch buffer would silently misbehave on a
 * large real tapscript (e.g. an Ordinals-style inscription reveal) where
 * the legacy/witness-v0 paths' 20000-byte scopy buffer would not. ---- */
#define TS_ELEM_SIZE      528
#define TS_MAX_STACK      1000
#define TS_MAX_ELEM       520     /* Core MAX_SCRIPT_ELEMENT_SIZE */
#define TS_SIGV_TAPSCRIPT 2
struct ts_script_state {
    uint8_t*  main_elems; uint64_t main_sp;
    uint8_t*  alt_elems;  uint64_t alt_sp;
    uint8_t*  script;     uint64_t script_len;
    int       sigversion; uint64_t flags;
    uint8_t*  work;       uint64_t work_cap;
    uint64_t* error_out;
    void*     checksig_ctx;
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t,
                            const uint8_t*, size_t, const void*);
    uint32_t  tx_locktime;
    uint32_t  in_sequence;
    uint32_t  tx_version;
};
extern int script_eval(struct ts_script_state* st);

/* The interp (bitcoin_interp.asm) gates op_cltv on bit (1<<9) and op_csv on
 * bit (1<<10) of st.flags. These are the ONLY st.flags bits the tapscript
 * evaluation branch reads meaningfully: MINIMALIF is enforced unconditionally
 * under SIGVERSION_TAPSCRIPT, CHECKMULTISIG(+NULLDUMMY) is forbidden in
 * tapscript, and MINIMALDATA / DISCOURAGE_OP_SUCCESS are mempool-policy bits
 * that are never part of Core's consensus GetBlockScriptFlags. At every height
 * where taproot is active, BIP65(CLTV) and BIP112(CSV) are already active too,
 * so this is exactly the consensus flag subset that reaches this branch --
 * mirroring how sv_run_v receives the block flag set for the v0 path. */
#define TS_SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY (1ULL<<9)
#define TS_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY (1ULL<<10)

/* ---- BIP342 IsOpSuccess (Core script/script.cpp:365) ---- */
static int ts_is_op_success(unsigned op){
    return op == 80 || op == 98 || (op >= 126 && op <= 129) ||
           (op >= 131 && op <= 134) || (op >= 137 && op <= 138) ||
           (op >= 141 && op <= 142) || (op >= 149 && op <= 153) ||
           (op >= 187 && op <= 254);
}

/* Core's tapscript OP_SUCCESSx pre-scan, hoisted OUT of the interpreter.
 *
 * script_eval (bitcoin_interp.asm) runs this same scan itself, but it runs it
 * AFTER taproot_verify_input has already built the initial stack -- and Core's
 * ExecuteWitnessScript (script/interpreter.cpp:1846-1871) is emphatic that the
 * scan comes FIRST: "OP_SUCCESSx processing overrides everything, including
 * stack element size limits". Both the >1000-element and the >520-byte checks
 * are skipped when an OP_SUCCESSx is present, so a script-path spend with a
 * 3 MB witness item and an OP_SUCCESSx leaf is consensus-VALID and mineable
 * today. Getting the order right is therefore not a stylistic point: it decides
 * whether such an input is accepted (Core) or rejected (us).
 *
 * Returns 1 if an OP_SUCCESSx is reachable by a GetOp walk. A truncated push
 * makes Core's GetOp fail -> SCRIPT_ERR_BAD_OPCODE; we return 0 and let the
 * interpreter's own walk produce that same rejection a moment later, rather
 * than duplicating the error path. */
static int ts_has_op_success(const uint8_t* s, uint64_t n){
    uint64_t i = 0;
    while (i < n){
        unsigned op = s[i++];
        if (ts_is_op_success(op)) return 1;
        if (op <= 0x4b)          { i += op; }
        else if (op == 0x4c)     { if (i + 1 > n) return 0; i += 1 + (uint64_t)s[i]; }
        else if (op == 0x4d)     { if (i + 2 > n) return 0;
                                   i += 2 + ((uint64_t)s[i] | ((uint64_t)s[i+1]<<8)); }
        else if (op == 0x4e)     { if (i + 4 > n) return 0;
                                   i += 4 + ((uint64_t)s[i] | ((uint64_t)s[i+1]<<8)
                                           | ((uint64_t)s[i+2]<<16) | ((uint64_t)s[i+3]<<24)); }
        if (i > n) return 0;     /* push runs off the end: Core's GetOp fails */
    }
    return 0;
}

/* taproot_verify_input(): full dispatch for one P2TR input's witness.
 * Returns 1 valid / 0 invalid; *reason set to a static (never NULL)
 * description, matching this project's existing per-shape error-reporting
 * convention (see e.g. daemon/tx_verify.c's "p2wpkh signature invalid").
 *
 * wit[]/witlen[]: the input's FULL witness stack, nwit items (nwit >= 1 --
 * an empty witness is rejected structurally before this is ever called).
 * spk: the 34-byte P2TR scriptPubKey (0x51 0x20 <32-byte x-only key>).
 * n_in: this input's index WITHIN ITS OWN TRANSACTION (0-based) -- matches
 * every other function in this file, NOT a block-wide flat index.
 *
 * OP_CODESEPARATOR inside a tapscript (BIP342 codesep_pos): tracked by the
 * interpreter itself -- script_eval records the opcode position of the last
 * EXECUTED OP_CODESEPARATOR (0xffffffff if none, unexecuted branches don't
 * count) and hands it to taproot_checksig_fn through interp_slice's third
 * field at every CHECKSIG/CHECKSIGADD, where it lands in the SigMsg after
 * key_version exactly as Core's SignatureHashSchnorr serializes
 * execdata.m_codeseparator_pos. (Until 2026-08-21 this was not tracked and
 * any tapscript containing a raw 0xab byte -- even inside push data, e.g.
 * a pubkey -- was refused outright; that scan is gone.) */
/* Phase 2 slice 13a seams (2026-08-24): two statics the asm twin needs.
 * tap_txctx_export mirrors the C's guarded block exactly -- it writes the
 * three fields ONLY when tx_parse succeeds and n_in is in range, leaving
 * the caller's zeros otherwise. */
int ts_has_op_success_export(const uint8_t* s, uint64_t n){ return ts_has_op_success(s, n); }
void tap_txctx_export(const uint8_t* tx, int64_t txlen, int64_t n_in,
                      uint32_t* ver, uint32_t* lt, uint32_t* seq){
    static __thread uint32_t* tv_off_x;
    BMC_TLS_BUF(tv_off_x, TS_OFF_ENTRIES * sizeof(uint32_t));
    txview_t v; v.tx = tx; v.txlen = txlen;
    if (tx_parse(&v, tv_off_x) && n_in >= 0 && n_in < v.nin) {
        *ver = (uint32_t)v.version;
        *lt  = v.locktime;
        *seq = tx_seq(&v, n_in);
    }
}

int taproot_verify_input(const uint8_t* spk,
                         const uint8_t* const* wit, const uint32_t* witlen, uint32_t nwit,
                         const uint8_t* tx, int64_t txlen, int64_t n_in,
                         const uint8_t* prevouts, const uint8_t* amounts,
                         const uint8_t* spks, int64_t num_inputs,
                         const char** reason)
{
    if (nwit == 0) { *reason = "p2tr empty witness"; return 0; }

    /* ---- BIP341 annex: present iff >=2 items and the LAST item's first
     * byte is the annex tag (0x50). Stripped before path classification;
     * committed into the sighash separately by the keypath-annex/tapscript
     * sighash paths, not treated as ordinary stack/script data. */
    int annex_present = 0;
    const uint8_t* annex = NULL; uint64_t annexlen = 0;
    if (nwit >= 2 && witlen[nwit-1] >= 1 && wit[nwit-1][0] == TAPROOT_ANNEX_TAG) {
        annex_present = 1; annex = wit[nwit-1]; annexlen = witlen[nwit-1];
    }
    uint32_t eff = nwit - (annex_present ? 1u : 0u);
    if (eff == 0) { *reason = "p2tr empty witness after annex"; return 0; }

    /* ---- key-path: effective stack size 1 (just the signature) ---- */
    if (eff == 1) {
        if (annex_present) {
            if (!taproot_keypath_verify_annex(spk, wit[0], (int)witlen[0], tx, txlen, n_in,
                                              prevouts, amounts, spks, num_inputs,
                                              annex, annexlen, NULL)) {
                *reason = "p2tr keypath (annex) signature invalid"; return 0;
            }
            return 1;
        }
        if (!taproot_keypath_verify(spk, wit[0], (int)witlen[0], tx, txlen, n_in,
                                    prevouts, amounts, spks, num_inputs)) {
            *reason = "p2tr keypath signature invalid"; return 0;
        }
        return 1;
    }

    /* ---- script-path: effective stack size >= 2 ----
     * Last effective item = control block, second-to-last = the tapscript
     * itself, everything before that = the tapscript's initial stack. */
    const uint8_t* control = wit[eff-1]; uint64_t clen = witlen[eff-1];
    const uint8_t* script  = wit[eff-2]; uint64_t slen = witlen[eff-2];

    if (clen < TAPROOT_CONTROL_BASE_SIZE || clen > TAPROOT_CONTROL_MAX_SIZE ||
        ((clen - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE) != 0) {
        *reason = "p2tr control block wrong size"; return 0;
    }

    uint8_t leaf_version = control[0] & TAPROOT_LEAF_MASK;
    const uint8_t* internal_pk = control + 1;   /* 32 bytes, x-only */

    /* Merkle commitment: this ALWAYS runs, regardless of leaf version --
     * per BIP341, it's what proves the control block genuinely commits
     * this script to this specific taproot output. Only whether the
     * SCRIPT gets executed afterward depends on the leaf version. */
    uint8_t leaf_hash[32];
    if (tap_leaf_hash(leaf_hash, leaf_version, script, slen) != 1) {
        *reason = "p2tr tapscript too large"; return 0;
    }
    uint8_t merkle_root[32];
    if (tap_merkle_root(merkle_root, leaf_hash, 1, control, clen) != 1) {
        *reason = "p2tr merkle root reconstruction failed"; return 0;
    }
    uint8_t computed_q[32];
    if (taproot_tweak_pubkey(computed_q, internal_pk, merkle_root) != 1) {
        *reason = "p2tr script-path internal pubkey invalid"; return 0;
    }
    if (memcmp(computed_q, spk + 2, 32) != 0) {
        *reason = "p2tr script-path commitment mismatch"; return 0;
    }

    /* Unknown leaf version: per BIP341, the commitment check just above is
     * ALL that's required -- validation succeeds unconditionally without
     * executing anything, reserved for future softforks to redefine script
     * semantics under an unrecognized version without a hard fork. */
    if (leaf_version != TAPROOT_LEAF_TAPSCRIPT) return 1;

    /* ---- Core ExecuteWitnessScript's tapscript prologue, IN ITS ORDER
     * (script/interpreter.cpp:1846-1871): OP_SUCCESSx scan, then the initial
     * stack's element-COUNT limit, then its element-SIZE limit. All three used
     * to be missing or mis-ordered here:
     *
     *   1. The OP_SUCCESSx scan happened only inside script_eval, i.e. AFTER
     *      the stack had been built -- see ts_has_op_success's own comment.
     *   2. The 520-byte per-element limit was NEVER APPLIED on this path at
     *      all. bitcoin_witness_v0.c:192 has it for witness-v0; the tapscript
     *      path went straight from the wire into stack_push, which bounds the
     *      stack DEPTH (MAX_STACK_SIZE) but NOT the element LENGTH
     *      (bitcoin_scriptcodec.asm:162 -- it copies `len` bytes into a
     *      528-byte record, no check). A witness item may be nearly a whole
     *      block (the largest on mainnet today is 3,938,182 B, block 774628),
     *      so a script-path spend carrying a >524-byte INITIAL-STACK item
     *      overran ts_main_e -- a 528,000-byte heap buffer -- by up to ~3.4 MB.
     *      Reachable by any peer, since a block is parsed and verified before
     *      it is known to be invalid; and legitimately mineable, since case 1
     *      means an OP_SUCCESSx leaf makes exactly this shape CONSENSUS-VALID.
     *      Sampling 47,578 real script-path inputs across 68 blocks in
     *      775,000-869,000 found a maximum initial-stack item of 79 bytes and
     *      no OP_SUCCESSx leaf at all -- so the archive replay would not have
     *      tripped this, which is precisely why it needed finding by reading
     *      the code against Core rather than by waiting for the chain.
     *   3. The element-COUNT limit was only implicit in stack_push's own
     *      MAX_STACK_SIZE failure; stated here so the reason string is honest.
     *
     * Anything that fails these checks is rejected BEFORE a single byte is
     * copied onto the stack. ---- */
    if (ts_has_op_success(script, slen)) return 1;   /* overrides everything below */
    {
        uint32_t ninit = eff - 2;                     /* eff >= 2 checked above */
        if (ninit > TS_MAX_STACK) {
            *reason = "p2tr tapscript initial stack too large"; return 0;
        }
        for (uint32_t i = 0; i < ninit; i++) {
            if (witlen[i] > TS_MAX_ELEM) {
                *reason = "p2tr tapscript witness item exceeds 520 bytes"; return 0;
            }
        }
    }

    /* BIP342 sigops/witness-size validation-weight budget: ser_size of the
     * ORIGINAL full witness (every one of the nwit items -- annex, control
     * block and script included, exactly as broadcast), not the post-pop
     * remainder. Core: GetSerializeSize(witness.stack) + VALIDATION_WEIGHT_
     * OFFSET(50); ser_size of a stack = compactsize(count) + sum over items
     * of (compactsize(len) + len). */
    int64_t weight_left = (int64_t)cs_size(nwit);
    for (uint32_t i = 0; i < nwit; i++) weight_left += cs_size(witlen[i]) + (int64_t)witlen[i];
    weight_left += 50;

    taproot_checksig_ctx ctx;
    ctx.tx = tx; ctx.txlen = txlen; ctx.n_in = n_in;
    ctx.prevouts = prevouts; ctx.amounts = amounts; ctx.spks = spks;
    ctx.num_inputs = num_inputs; ctx.tapleaf = leaf_hash; ctx.codesep_pos = 0xffffffffu;
    ctx.annex = annex; ctx.annexlen = annexlen;
    ctx.weight_left = weight_left;

    static __thread uint8_t *ts_main_e, *ts_alt_e, *ts_work;
    BMC_TLS_BUF(ts_main_e, TS_MAX_STACK*TS_ELEM_SIZE); BMC_TLS_BUF(ts_alt_e, TS_MAX_STACK*TS_ELEM_SIZE); BMC_TLS_BUF(ts_work, 1<<16);

    uint64_t sp = 0;
    for (uint32_t i = 0; i + 2 < eff; i++) {
        if (!stack_push(&sp, ts_main_e, wit[i], witlen[i])) {
            *reason = "p2tr tapscript initial stack overflow"; return 0;
        }
    }

    struct ts_script_state st;
    memset(&st, 0, sizeof st);
    st.main_elems = ts_main_e; st.main_sp = sp;
    st.alt_elems  = ts_alt_e;  st.alt_sp  = 0;
    st.script = (uint8_t*)(uintptr_t)script; st.script_len = slen;
    st.sigversion = TS_SIGV_TAPSCRIPT;
    /* incident #16: CLTV/CSV inside a tapscript were under-enforced because
     * st.flags was 0 (op_cltv/op_csv gated OFF -> silently NOP) and
     * tx_locktime/in_sequence/tx_version were left zeroed by the memset above.
     * Activate the two flags the tapscript branch reads and thread the real tx
     * context, mirroring the witness-v0 path (sv_verify_witness_v0 -> sv_run_v).
     * The tx handed to taproot_verify_input is the STRIPPED (no-witness)
     * serialization -- the same one taproot_sighash parses -- so the file's own
     * tx_parse/tx_seq read version/locktime/nSequence directly (keeping this
     * translation unit self-contained; no cross-object link dependency). */
    st.flags = TS_SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | TS_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    {
        /* Read version/locktime/nSequence out IMMEDIATELY and let the view
         * die here. taproot_sighash() owns the same per-thread offset table,
         * and script_eval() below re-enters it once per CHECKSIG -- so this
         * view must not outlive this block. It does not: all three values are
         * plain scalars copied into st before script_eval is called. */
        static __thread uint32_t* tv_off;
        BMC_TLS_BUF(tv_off, TS_OFF_ENTRIES * sizeof(uint32_t));
        txview_t tvctx; tvctx.tx = tx; tvctx.txlen = txlen;
        if (tx_parse(&tvctx, tv_off) && n_in >= 0 && n_in < tvctx.nin) {
            st.tx_version  = (uint32_t)tvctx.version;
            st.tx_locktime = tvctx.locktime;
            st.in_sequence = tx_seq(&tvctx, n_in);
        }
    }
    st.work = ts_work; st.work_cap = 1<<16;
    uint64_t err = 0; st.error_out = &err;
    st.checksig_ctx = &ctx;
    st.checksig_fn  = taproot_checksig_fn;

    if (!script_eval(&st)) { *reason = "p2tr tapscript execution failed"; return 0; }
    /* script_eval returning 1 already means the interpreter's own
     * SIGVERSION_TAPSCRIPT-specific cleanstack/empty-result rule (exactly
     * one truthy element left) passed -- nothing further to check here. */
    return 1;
}

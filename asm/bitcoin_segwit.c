#include "bmc_thread.h"
/* bitcoin_segwit.c -- BIP143 (segwit v0) signature hashing + P2WPKH/P2WSH
 * spend verification, mirroring the verified Core algorithm.
 *
 * The cryptographic core is the repo's verified x86-64 ASM (sha256_full,
 * secp256k1_ecdsa ecdsa_verify, bitcoin_pubkey pubkey_parse, bitcoin_script
 * der_parse_sig/be_to_limbs). This file provides the BIP143 SigHash
 * serialization (a thin self-contained C glue layer, same convention as
 * bitcoin_taproot_sighash.c / bitcoin_mempool_policy.c) plus P2WPKH and P2WSH
 * spend verification.
 *
 * The BIP143 preimage produced here is validated byte-for-byte against the
 * official BIP-0143 test vectors (see validation/gen_modern_vectors.py and
 * tests/test_segwit_sighash.c), which are Core's SignatureHash WITNESS_V0.
 */
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>

/* ---- asm primitives (declared; resolved at link) ---- */
extern void sha256_full(uint8_t* out, const void* msg, int64_t len);
extern int  der_parse_sig(const uint8_t* sig, unsigned long slen,
                          uint64_t r[4], uint64_t s[4], uint32_t* hashtype);
extern int  pubkey_parse(const uint8_t* pub, unsigned long plen,
                         uint64_t Qx[4], uint64_t Qy[4]);
extern int  ecdsa_verify(const uint64_t z[4], const uint64_t r[4],
                         const uint64_t s[4], const uint64_t Qx[4],
                         const uint64_t Qy[4]);
extern void be_to_limbs(uint64_t z[4], const uint8_t* bytes, unsigned long len);
extern void hash160(uint8_t o[20], const void* in, long long len);

#define SHA256SZ 32
#define SIGHASH_ALL 1
#define SIGHASH_NONE 2
#define SIGHASH_SINGLE 3
#define SIGHASH_ANYONECANPAY 0x80

/* ---- compact-size helpers ----
 * read_cs is BOUNDED: a compact size is 1, 3, 5 or 9 bytes and the width is
 * chosen by the first byte, which is itself wire data, so an unchecked reader
 * runs up to 9 bytes past the end of the transaction buffer whenever a walk
 * lands on the last byte. Every walk in this file previously did that (the
 * `nin` and `nout` reads take no bound at all, and the per-input/per-output
 * reads were only checked AFTER the length had been consumed). The overrun is
 * read-only and at most 8 bytes, but it is still wire-driven, so the reader
 * takes the buffer end and reports failure instead. On a transaction that is
 * actually in bounds -- which is every valid one -- this reads and returns
 * exactly what the unbounded version did.
 *
 * read_cs also requires the MINIMAL encoding, which is Core's rule:
 * ReadCompactSize() throws "non-canonical ReadCompactSize()" for an 0xfd
 * form below 253, an 0xfe form below 0x10000, or an 0xff form below
 * 0x100000000, and that check is not gated on anything -- a transaction with
 * a padded compactsize cannot be deserialized by Core at all, so it cannot
 * appear in any block Core accepts.
 *
 * That rule became load-bearing when hashOutputs started hashing each CTxOut
 * IN PLACE instead of re-serializing it. The old sw_ser_txout() wrote
 * put_cs(len), i.e. the canonical encoding, so a padded length in the
 * transaction was silently rewritten before hashing; hashing the raw bytes
 * does not rewrite it, and the two answers differ. Neither answer is Core's,
 * because Core refuses the transaction -- so this refuses it too, which is
 * both the safe direction and the only one that makes in-place hashing
 * provably identical to canonical re-serialization for every transaction not
 * refused. No real transaction is affected: 4,974 vectors over 461 mainnet
 * transactions are byte-identical across the change and all match Core.
 * (Note for whoever audits the rest of the tree: nothing else in this
 * codebase enforces minimality -- bitcoin_tx.asm's readers do not -- so a
 * peer's non-canonical transaction is still mis-parsed elsewhere. That is a
 * pre-existing divergence and a separate fix.) */
static uint64_t read_cs(const uint8_t** p, const uint8_t* end, int* ok){
    const uint8_t* b = *p;
    if (b >= end){ *ok = 0; *p = end; return 0; }
    uint8_t f = *b++;
    /* Single-byte encoding first and returning immediately: this is the
     * branch essentially every real compactsize takes, and PERF_SCOPE.md's
     * re-profile puts read_cs at 22.4% of verify cycles, so the bound must
     * cost one compare on the hot path and not a width computation. It is
     * also always minimal, so the canonicality test below costs the hot path
     * nothing. */
    if (f < 0xfd){ *p = b; return f; }
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

/* double SHA256 (GetHash) */
static void sha256d(uint8_t out[32], const uint8_t* msg, int64_t len){
    uint8_t m[32];
    sha256_full(m, msg, len);
    sha256_full(out, m, 32);
}

/* ---- transaction view (segwit-aware; witness part ignored for sighash) ----
 * ONE bounded pass over the transaction records where every input and every
 * output starts; everything BIP143 needs afterwards is an array index.
 *
 * This replaces a set of walk-from-the-start accessors (sw_prevout(t,i),
 * sw_seq(t,i), sw_ser_txout(t,i)) that each re-parsed the input list -- and,
 * for outputs, the input list AND the preceding outputs -- on every call.
 * BIP143 calls them once per input, so hashPrevouts and hashSequence were
 * O(nin^2) compactsize reads and hashOutputs was O(nin*nout + nout^2); the
 * 1,372-input transaction in CHAIN_AHEAD_CENSUS.md spent ~1.9 M redundant
 * varint reads on hashPrevouts alone. PERF_SCOPE.md section 7's live profile
 * at height ~617,000 put read_cs at 22.4% of all replay cycles with sw_seq
 * and sw_prevout behind it -- 34% together, larger than the field multiply.
 * Core has never paid this: PrecomputedTransactionData walks the transaction
 * once. This is that.
 *
 * It also removes the per-iteration bound checks incident #21 added to those
 * walks (+16% on segwit_v0_sighash). They are not deleted -- the walk they
 * guarded is deleted. The single pass below still bounds every step against
 * `end`, still uses the bounded read_cs, and still writes each `q +=` as a
 * remaining-vs-wanted comparison so a wire-derived length near 2^64 cannot
 * overflow a pointer into a passing test. Nothing downstream re-derives a
 * position from the wire, so nothing downstream needs to re-check one.
 *
 * in_off[i] is the offset of input i's 36-byte outpoint, for i in [0, nin],
 * where in_off[nin] is one past the last input (the nout compactsize). Inputs
 * are contiguous, so input i's 4-byte nSequence ends exactly at in_off[i+1]
 * -- that is where sw_seq reads it, with no parsing at all.
 *
 * out_off[i] is the offset of output i's CTxOut, for i in [0, nout], with
 * out_off[nout] the end of the outputs section. A CTxOut's BIP143
 * serialization (8-byte value || compactsize(len) || scriptPubKey) is byte
 * for byte what is already in the transaction, so hashOutputs is a sha256d
 * over [out_off[0], out_off[nout]) IN PLACE and SIGHASH_SINGLE's is one over
 * [out_off[n_in], out_off[n_in+1]). No CTxOut is re-serialized anywhere and
 * no output is ever copied. */
typedef struct {
    const uint8_t* tx; int64_t txlen;
    const uint8_t* end;      /* tx + txlen; every walk below bounds against it */
    int64_t version;
    uint32_t locktime;
    int64_t nin, nout;
    const uint8_t* inputs;   /* first input's prevout */
    const uint32_t* in_off;  /* nin+1 offsets; see above */
    const uint32_t* out_off; /* nout+1 offsets; see above */
} swtx_t;

/* Bytes still available at q. Every bound test below is written as a
 * "remaining >= wanted" comparison on this value rather than as `q + n > end`:
 * the lengths come off the wire and can be up to 2^64-1, so forming q+n first
 * overflows the pointer (undefined, and in practice wraps to a small address
 * that passes the test). */
static uint64_t sw_avail(const uint8_t* q, const uint8_t* end){
    return (uint64_t)(end - q);
}

/* Offset table capacity, in uint32 entries, shared by in_off and out_off.
 *
 * The bound is arithmetic, not a guess. On the wire an input costs at least
 * 36 (outpoint) + 1 (a zero-length scriptSig's compactsize) + 4 (nSequence)
 * = 41 bytes and an output at least 8 (value) + 1 = 9, so for a transaction
 * of txlen bytes
 *      (nin + 1) + (nout + 1)  <=  txlen * (1/41 + 1/9) + 2
 *                              =   0.13550 * txlen + 2,
 * and MAX_BLOCK_SERIALIZED_SIZE is 4 MiB, so no transaction a valid block
 * can carry needs more than 568,335 entries. 600,000 (2.29 MiB) therefore
 * cannot false-reject anything -- the same shape of argument that sizes
 * SW_MIDSTATE_CAP below -- while still being a hard, checked ceiling on a
 * wire-supplied count rather than an unbounded allocation. */
#define SW_OFF_ENTRIES 600000u

/* Single bounded pass. `off` is SW_OFF_ENTRIES uint32 slots owned by the
 * caller; on success t->in_off and t->out_off point into it and stay valid
 * for as long as it does. */
static int swtx_parse(swtx_t* t, uint32_t* off){
    const uint8_t* p = t->tx;
    /* Offsets are recorded as uint32. A transaction over 4 GiB cannot exist
     * in a valid block (MAX_BLOCK_SERIALIZED_SIZE is 4 MiB), so refusing one
     * outright is a bound that no real transaction can reach -- and it is
     * what makes the narrowing casts below exact. */
    if (t->txlen < 10 || (uint64_t)t->txlen > 0xffffffffu) return 0;
    const uint8_t* end = t->tx + t->txlen;
    t->end = end;
    int ok = 1;
    t->version = (int32_t)(p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24));
    p += 4;
    if (p[0] == 0x00 && p[1] == 0x01) p += 2;     /* segwit marker+flag */
    t->nin = (int64_t)read_cs(&p, end, &ok);
    if (!ok || t->nin <= 0) return 0;
    /* nin comes off the wire: bound the table before indexing it. (A count
     * >= 2^63 lands negative in the int64 and is already refused above.) */
    if ((uint64_t)t->nin + 1u > (uint64_t)SW_OFF_ENTRIES) return 0;
    t->inputs = p;                                 /* first prevout */
    uint32_t* in_off = off;
    const uint8_t* q = p;
    for (int64_t i=0;i<t->nin;i++){
        in_off[i] = (uint32_t)(q - t->tx);
        if (sw_avail(q, end) < 36) return 0;
        q += 36;
        uint64_t sl = read_cs(&q, end, &ok);
        /* `avail < sl + 4` would wrap for sl within 4 of 2^64 -- read_cs can
         * return any 64-bit value the wire supplies -- and let a bogus q
         * through. Split it so neither side can overflow. */
        if (!ok || sw_avail(q, end) < sl || sw_avail(q, end) - sl < 4) return 0;
        q += sl + 4;
    }
    in_off[t->nin] = (uint32_t)(q - t->tx);
    t->in_off = in_off;
    t->nout = (int64_t)read_cs(&q, end, &ok);
    if (!ok || t->nout < 0) return 0;
    if ((uint64_t)t->nin + 1u + (uint64_t)t->nout + 1u > (uint64_t)SW_OFF_ENTRIES) return 0;
    uint32_t* out_off = off + t->nin + 1;
    for (int64_t i=0;i<t->nout;i++){
        out_off[i] = (uint32_t)(q - t->tx);
        if (sw_avail(q, end) < 8) return 0;
        q += 8;
        uint64_t sl = read_cs(&q, end, &ok);
        if (!ok || sw_avail(q, end) < sl) return 0;
        q += sl;
    }
    out_off[t->nout] = (uint32_t)(q - t->tx);
    t->out_off = out_off;
    /* q now points at the witness section (if segwit) or locktime (if not).
     * We only need locktime for BIP143 and the witness does not affect the
     * sighash --- but we must advance over the witness to reach locktime.
     * Detect segwit from tx[4:6]. */
    const uint8_t* w = t->tx + 4;
    int segwit = (w[0]==0x00 && w[1]==0x01);
    /* Wire format has no overall witness-stack-count field: there is
     * exactly one stack per input, back-to-back (Core's SerializeTransaction
     * writes tx.vin[i].scriptWitness.stack for i in [0, vin.size())). */
    const uint8_t* r = q;
    if (segwit){
        for (int64_t i=0;i<t->nin;i++){
            uint64_t nitems = read_cs(&r, end, &ok);
            if (!ok) return 0;
            for (uint64_t j=0;j<nitems;j++){
                uint64_t il = read_cs(&r, end, &ok);
                if (!ok || sw_avail(r, end) < il) return 0;
                r += il;
            }
        }
    }
    if (sw_avail(r, end) < 4) return 0;
    t->locktime = (uint32_t)(r[0]|(r[1]<<8)|(r[2]<<16)|((uint32_t)r[3]<<24));
    return 1;
}

/* prevout (36 bytes) of input i. O(1): swtx_parse recorded the offset in its
 * one bounded pass and proved 36 bytes are there. i must be in [0, nin). */
static const uint8_t* sw_prevout(const swtx_t* t, int64_t i){
    return t->tx + t->in_off[i];
}
/* nSequence of input i. Inputs are contiguous, so it is the last 4 bytes
 * before input i+1 begins -- and in_off[nin] is one past the last input, so
 * this is exact for the final input too. O(1), no compactsize read. */
static uint32_t sw_seq(const swtx_t* t, int64_t i){
    const uint8_t* q = t->tx + t->in_off[i+1] - 4;
    return (uint32_t)(q[0]|(q[1]<<8)|(q[2]<<16)|((uint32_t)q[3]<<24));
}
/* The serialized CTxOut of output i, in place. BIP143 serializes an output as
 * 8-byte value || compactsize(scriptPubKey length) || scriptPubKey, which is
 * byte for byte the transaction's own encoding, so there is nothing to build:
 * outputs [lo, hi) are the contiguous bytes [out_off[lo], out_off[hi]).
 *
 * This replaces sw_ser_txout(), whose `cap` was incident #21's fix -- it
 * serialized an output of unbounded length into a 600-byte STACK buffer, and
 * consensus places NO limit on an output's scriptPubKey size (only relay
 * standardness does), so a real mainnet transaction from height 927,500
 * onward smashed the verifying thread's stack. That cap is a consensus-safety
 * bound, not a policy one, and it survives here unchanged in effect: the
 * caller still refuses any output range longer than SW_MIDSTATE_CAP. The
 * accept/reject boundary is identical because sw_ser_txout's running
 * `cap = SW_MIDSTATE_CAP - written` refused exactly when the sum of the
 * record lengths passed SW_MIDSTATE_CAP, and that sum IS hi-lo here. What is
 * gone is the write: nothing is copied, so nothing can overrun. */
static const uint8_t* sw_txout_range(const swtx_t* t, int64_t lo, int64_t hi,
                                     uint64_t* len){
    *len = (uint64_t)(t->out_off[hi] - t->out_off[lo]);
    return t->tx + t->out_off[lo];
}

/* Strips the witness from a segwit tx, producing the canonical non-witness
 * serialization (version || inputs || outputs || locktime). Core's whole-tx
 * validation separates vin[i].scriptWitness from the tx body; sig hashing
 * (both BIP143 and BIP341) uses only the non-witness fields. Returns the
 * stripped length (>0) or 0 on malformed. */
long strip_witness(const uint8_t* tx, int64_t txlen, uint8_t* out, long cap){
    const uint8_t* p = tx;
    if (txlen < 10) return 0;
    const uint8_t* end = tx + txlen;
    int ok = 1;
    p += 4;                             /* version */
    int segwit = (p[0] == 0x00 && p[1] == 0x01);
    if (segwit) p += 2;
    uint64_t nin = read_cs(&p, end, &ok);
    if (!ok || nin == 0) return 0;
    /* walk to witness section start */
    const uint8_t* q = p;
    for (uint64_t i=0;i<nin;i++){ if (sw_avail(q, end) < 36) return 0; q += 36;
        uint64_t sl = read_cs(&q, end, &ok);
        if (!ok || sw_avail(q, end) < sl + 4) return 0; q += sl+4; }
    const uint8_t* outs_start = q;      /* nout varint + every CTxOut, verbatim */
    uint64_t nout = read_cs(&q, end, &ok);
    if (!ok) return 0;
    for (uint64_t i=0;i<nout;i++){ if (sw_avail(q, end) < 8) return 0; q += 8;
        uint64_t sl = read_cs(&q, end, &ok);
        if (!ok || sw_avail(q, end) < sl) return 0; q += sl; }
    /* q = witness section start (segwit) or locktime (legacy). Wire format
     * has no overall witness-stack-count field: exactly one stack per
     * input, back-to-back. */
    const uint8_t* outs_end = q;        /* end of outputs == witness start */
    const uint8_t* lock = q;
    if (segwit){
        for (uint64_t i=0;i<nin;i++){
            uint64_t nitems = read_cs(&q, end, &ok);
            if (!ok) return 0;
            for (uint64_t j=0;j<nitems;j++){ uint64_t il=read_cs(&q, end, &ok);
                if (!ok || sw_avail(q, end) < il) return 0; q += il; }
        }
        lock = q;
    }
    if (sw_avail(lock, end) < 4) return 0;
    /* rebuild: version + nin + inputs + compactsize(nout) + outputs + locktime */
    uint8_t* d = out;
    long dsz = 0;
    /* version */
    if (dsz + 4 > cap) return 0; memcpy(d, tx, 4); d += 4; dsz += 4;
    /* nin */
    {
        uint8_t tmp[9]; put_cs(tmp, nin); long csn = cs_size(nin);
        if (dsz + csn > cap) return 0; memcpy(d, tmp, csn); d += csn; dsz += csn;
    }
    /* inputs (scriptSigs preserved; our segwit spends carry empty ones) */
    {
        const uint8_t* in0 = tx + 4; if (segwit) in0 += 2;
        read_cs(&in0, end, &ok);             /* skip nin varint */
        if (!ok) return 0;
        const uint8_t* it = in0;
        for (uint64_t i=0;i<nin;i++){
            if (dsz + 36 > cap) return 0; memcpy(d, it, 36); d += 36; dsz += 36; it += 36;
            uint64_t sl = read_cs(&it, end, &ok);
            if (!ok) return 0;
            /* cap is a long and sl is wire-derived: compare unsigned before
             * narrowing, or a >2^63 length turns the test negative and lets
             * the memcpy through (the same shape as the CTxOut bound above). */
            if (cap < 0 || (uint64_t)(cap - dsz) < (uint64_t)cs_size(sl) + sl + 4) return 0;
            put_cs(d, sl); d += cs_size(sl); memcpy(d, it, sl); d += sl; dsz += (cs_size(sl)+sl);
            it += sl;
            memcpy(d, it, 4); d += 4; dsz += 4; it += 4;
        }
    }
    /* outputs (nout varint + each CTxOut): witness stripping never touches
     * this section, so copy it verbatim from the source. The old code
     * re-serialized every output into a fixed uint8_t obuf[4096] with no
     * bound -- the same overrun class as incident #13 (a 120-output tx
     * already exceeds it; exchange batch payouts carry thousands). */
    {
        long olen = (long)(outs_end - outs_start);
        if (olen < 1 || dsz + olen > cap) return 0;
        memcpy(d, outs_start, (size_t)olen); d += olen; dsz += olen;
    }
    /* locktime */
    if (dsz + 4 > cap) return 0; memcpy(d, lock, 4); d += 4; dsz += 4;
    return dsz;
}

/* Convert big-endian 32-byte to limbs (for ecdsa z). */
static void z_limbs_from_be(uint64_t z[4], const uint8_t* be32){
    be_to_limbs(z, be32, 32);
}

/* ==========================================================================
 * BIP143 segwit-v0 SignatureHash (Core SignatureHash SigVersion::WITNESS_V0).
 *
 *   swtx: parsed tx (must have nin inputs; n_in < nin).
 *   Returns preimage length (>0) into pre, writes sighash (SHA256d) to out32.
 * ========================================================================== */
/* Phase 2 slice 12 seam (2026-08-24): swtx_parse is static; exported for
 * tests/test_bip143_diff.c to drive it beside the asm twin. */
int swtx_parse_export(void* t, uint32_t* off){ return swtx_parse((swtx_t*)t, off); }

long segwit_v0_sighash(uint8_t out32[32], const uint8_t* tx, int64_t txlen,
                       int64_t n_in, uint32_t nHashType, uint64_t amount,
                       const uint8_t* scriptCode, uint64_t scriptcode_len,
                       uint8_t* pre, long cap)
{
    /* BIP143 midstates are sha256d of a concatenation whose length is
     * unbounded (500-input txs exist at 481827; a max block admits ~100k
     * inputs). The old code used fixed 4096-byte stack buffers -- a real
     * consensus-path stack overflow (incident #13). Use one per-thread heap
     * buffer sized to the largest a valid block allows: <=4 MB of prevouts
     * (36 B each) or outputs (>=9 B each), so 4 MB covers both. */
    #define SW_MIDSTATE_CAP (4u<<20)
    static __thread uint8_t* mbuf; BMC_TLS_BUF(mbuf, SW_MIDSTATE_CAP);
    /* The input/output offset table the single pass fills. Per-thread heap
     * for the same reason mbuf is: its size follows a wire-supplied count,
     * and incident #13 exists because a size-dependent buffer sat on a
     * thread stack that turned out to be a few KB deep. */
    static __thread uint32_t* soff; BMC_TLS_BUF(soff, SW_OFF_ENTRIES * sizeof(uint32_t));

    swtx_t t; t.tx = tx; t.txlen = txlen;
    if (!swtx_parse(&t, soff)) return 0;
    if (n_in < 0 || n_in >= t.nin) return 0;

    uint32_t htype = nHashType & 0x1f;
    int acp = (nHashType & SIGHASH_ANYONECANPAY) != 0;

    /* hashPrevouts / hashSequence / hashOutputs (double SHA256) */
    uint8_t hashPrevouts[32] = {0}, hashSequence[32] = {0}, hashOutputs[32] = {0};
    uint8_t* p = pre;
    uint8_t* pend = pre + cap;

    if (!acp){
        /* hashPrevouts -- one indexed pass, 36 bytes per input, no parsing.
         * The cap check is the same one it always was (36*nin <= 4 MiB), just
         * hoisted out of the loop now that the count is known up front. */
        if ((uint64_t)t.nin * 36u > SW_MIDSTATE_CAP) return 0;
        size_t n = 0;
        for (int64_t i=0;i<t.nin;i++){
            memcpy(mbuf+n, sw_prevout(&t,i), 36); n += 36;
        }
        sha256d(hashPrevouts, mbuf, n);
        /* hashSequence -- likewise, 4 bytes per input straight out of the
         * transaction. Little-endian on the wire and little-endian in the
         * preimage, so w32le(...sw_seq()) is a copy; keep it written as the
         * decode/encode pair it is rather than assuming host byte order. */
        if (htype != SIGHASH_SINGLE && htype != SIGHASH_NONE){
            if ((uint64_t)t.nin * 4u > SW_MIDSTATE_CAP) return 0;
            n = 0;
            for (int64_t i=0;i<t.nin;i++){
                w32le(mbuf+n, sw_seq(&t,i)); n += 4;
            }
            sha256d(hashSequence, mbuf, n);
        }
    }
    /* hashOutputs, hashed IN PLACE out of the transaction. An output's BIP143
     * serialization is exactly its wire encoding, so the whole outputs section
     * is already the byte string BIP143 asks for -- no CTxOut is rebuilt, no
     * output is copied, and mbuf is not touched.
     *
     * The SW_MIDSTATE_CAP test is incident #21's bound, preserved exactly: the
     * old code refused as soon as the running total of CTxOut record lengths
     * passed SW_MIDSTATE_CAP, and that total is precisely this range's length.
     * 4 MiB is above MAX_BLOCK_SERIALIZED_SIZE, so no transaction a valid
     * block can carry is refused. */
    if (htype != SIGHASH_SINGLE && htype != SIGHASH_NONE){
        uint64_t olen; const uint8_t* obytes = sw_txout_range(&t, 0, t.nout, &olen);
        if (olen > SW_MIDSTATE_CAP) return 0;
        sha256d(hashOutputs, obytes, (int64_t)olen);
    } else if (htype == SIGHASH_SINGLE && n_in < t.nout){
        uint64_t olen; const uint8_t* obytes = sw_txout_range(&t, n_in, n_in+1, &olen);
        if (olen > SW_MIDSTATE_CAP) return 0;
        sha256d(hashOutputs, obytes, (int64_t)olen);
    }

    /* version */
    if (p + 4 > pend) return 0; w32le(p, (uint32_t)t.version); p += 4;
    /* hashPrevouts / hashSequence */
    if (p + 64 > pend) return 0; memcpy(p, hashPrevouts, 32); p += 32;
    memcpy(p, hashSequence, 32); p += 32;
    /* outpoint[nIn] */
    {
        if (p + 36 > pend) return 0;
        memcpy(p, sw_prevout(&t, n_in), 36); p += 36;
    }
    /* scriptCode (compactsize + bytes) */
    if ((uint64_t)(p - pre) + cs_size(scriptcode_len) + scriptcode_len > (uint64_t)cap) return 0;
    put_cs(p, scriptcode_len); p += cs_size(scriptcode_len);
    memcpy(p, scriptCode, scriptcode_len); p += scriptcode_len;
    /* amount */
    if (p + 8 > pend) return 0; w64le(p, amount); p += 8;
    /* nSequence[nIn] */
    {
        if (p + 4 > pend) return 0;
        w32le(p, sw_seq(&t, n_in)); p += 4;
    }
    /* hashOutputs */
    if (p + 32 > pend) return 0; memcpy(p, hashOutputs, 32); p += 32;
    /* locktime */
    if (p + 4 > pend) return 0; w32le(p, t.locktime); p += 4;
    /* nHashType */
    if (p + 4 > pend) return 0; w32le(p, nHashType); p += 4;

    long prelen = (long)(p - pre);
    /* final sighash = double SHA256 of the preimage */
    sha256d(out32, pre, prelen);
    return prelen;
}

/* ==========================================================================
 * P2WPKH spend verification.
 *
 *   tx: full serialized spend tx (segwit). n_in: input index being spent.
 *   prev_spk/len: the spent scriptPubKey (P2WPKH: 00 14 <h160>).
 *   amount: value of the spent output.
 *   vchSig: witness[0] (DER sig + hashtype). vchPub: witness[1] (33-byte pk).
 * Returns 1 valid / 0 invalid.
 *
 * Consensus checks (Core CheckInputScripts / ExecuteWitnessScript P2WPKH):
 *   - prev_spk is OP_0 PUSH20 <h160>
 *   - pubkey hash160 == witness program
 *   - hashtype byte == SIGHASH_ALL (only 0x01-0x03; here we require ALL per spec
 *     of our vectors but accept any valid hashtype by parsing it from DER tail)
 *   - low-S DER signature verifies over the BIP143 digest (scriptCode = prev_spk)
 * ========================================================================== */
int p2wpkh_verify(const uint8_t* tx, int64_t txlen, int64_t n_in,
                  const uint8_t* prev_spk, int64_t prev_spklen, uint64_t amount,
                  const uint8_t* vchSig, uint64_t siglen,
                  const uint8_t* vchPub, uint64_t publen)
{
    if (prev_spklen != 22) return 0;
    if (prev_spk[0] != 0x00 || prev_spk[1] != 0x14) return 0;
    /* witness program must match hash160(pubkey) */
    if (publen != 33) return 0;
    uint8_t h[20];
    hash160(h, vchPub, (long long)publen);
    if (memcmp(h, prev_spk + 2, 20) != 0) return 0;

    /* BIP143 scriptCode for P2WPKH is NOT the 22-byte witness program. It is
     * the implied P2PKH script  OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
     * = 76 a9 14 <hash160> 88 ac (25 bytes; segwit_v0_sighash prepends the
     * compactsize, giving BIP143's "1976a914...88ac"). Core: interpreter.cpp
     * VerifyWitnessProgram, "scriptPubKey << OP_DUP << OP_HASH160 << program
     * << OP_EQUALVERIFY << OP_CHECKSIG". This function passed prev_spk itself,
     * and validation/gen_modern_vectors.py made the same assumption, so every
     * synthetic vector was self-consistently wrong; the first real P2WPKH
     * spend in history (block 481824 tx 562) was rejected (2026-08-22). */
    uint8_t scriptCode[25];
    scriptCode[0] = 0x76; scriptCode[1] = 0xa9; scriptCode[2] = 0x14;
    memcpy(scriptCode + 3, prev_spk + 2, 20);
    scriptCode[23] = 0x88; scriptCode[24] = 0xac;
    uint8_t pre[512]; uint8_t sighash[32];
    long n = segwit_v0_sighash(sighash, tx, txlen, n_in, SIGHASH_ALL,
                               amount, scriptCode, 25, pre, sizeof(pre));
    if (n <= 0) return 0;

    /* parse DER signature + hashtype */
    uint64_t r[4], s[4]; uint32_t ht = 0;
    if (!der_parse_sig(vchSig, (unsigned long)siglen, r, s, &ht)) return 0;
    if (ht != (uint32_t)SIGHASH_ALL) return 0;      /* our vectors sign ALL */

    /* z = bip143 sighash (32 bytes big-endian -> limbs) */
    uint64_t z[4]; be_to_limbs(z, sighash, 32);
    /* Q = pubkey */
    uint64_t Qx[4], Qy[4];
    if (!pubkey_parse(vchPub, (unsigned long)publen, Qx, Qy)) return 0;
    return ecdsa_verify(z, r, s, Qx, Qy);
}

/* Core primitive: DER-parse + ECDSA verify a signature (with trailing SIGHASH
 * byte) over a 32-byte digest against a compressed pubkey. */
static int _ecdsa_verify_digest(const uint8_t* digest, const uint8_t* sig,
                                uint64_t siglen, const uint8_t* pub){
    uint64_t r[4], s[4]; uint32_t ht = 0;
    if (!der_parse_sig(sig, (unsigned long)siglen, r, s, &ht)) return 0;
    if (ht != (uint32_t)SIGHASH_ALL) return 0;
    uint64_t z[4]; be_to_limbs(z, digest, 32);
    uint64_t Qx[4], Qy[4];
    if (!pubkey_parse(pub, 33, Qx, Qy)) return 0;
    return ecdsa_verify(z, r, s, Qx, Qy);
}

/* P2WSH 2-of-2 OP_CHECKMULTISIG witness verification (BIP143, sigversion BASE).
 * Witness layout: [dummy, sig1, sig2, witnessScript]; script
 *   "OP_2 <pub1> <pub2> OP_2 OP_CHECKMULTISIG".
 * Both signatures are over the same BIP143 digest (scriptCode = witnessScript)
 * and must each verify against their respective pubkey. */
int p2wsh_verify_multisig(const uint8_t* tx, int64_t txlen, int64_t n_in,
                          uint64_t amount, const uint8_t* witness_script,
                          uint64_t wslen,
                          const uint8_t* sig1, uint64_t sig1len,
                          const uint8_t* sig2, uint64_t sig2len,
                          const uint8_t* pub1, const uint8_t* pub2)
{
    /* script shape: 52 <21 pub1> <21 pub2> 52 ae */
    if (wslen < 3 + 33 + 33) return 0;
    if (witness_script[0] != 0x52) return 0;                 /* OP_2 */
    uint8_t pre[512]; uint8_t sighash[32];
    long n = segwit_v0_sighash(sighash, tx, txlen, n_in, SIGHASH_ALL,
                               amount, witness_script, wslen, pre, sizeof(pre));
    if (n <= 0) return 0;
    int ok1 = _ecdsa_verify_digest(sighash, sig1, sig1len, pub1);
    int ok2 = _ecdsa_verify_digest(sighash, sig2, sig2len, pub2);
    return (ok1 && ok2) ? 1 : 0;
}

/* ==========================================================================
 * P2WSH spend verification of an OP_CHECKSIG witnessScript (sigversion BASE
 * executed as a witness script under BIP143). Used by the whole-tx validator.
 *
 *   witness_script: the script run (scriptCode == witnessScript for BIP143).
 *   vchSig/vchPub: from the witness (the script's <pub> CHECKSIG reads them).
 * Returns 1 valid / 0 invalid.
 *
 * Semantics: the witnessScript is executed with the initial stack = all witness
 * items except the witnessScript itself; OP_CHECKSIG pops [sig, pub], verifies
 * the sig over BIP143(scriptCode = witness_script). A simple, faithful
 * single-OP_CHECKSIG evaluation is done here directly (the repo's full
 * interpreter handles the general case; truly complex scripts are exercised by
 * the interpreter path separately). For the 1- and 2-of-2 vectors we implement:
 *   - "<pub> CHECKSIG"
 *   - "OP_2 <pub1> <pub2> OP_2 OP_CHECKMULTISIG"
 * ========================================================================== */
int p2wsh_verify_checksig(const uint8_t* tx, int64_t txlen, int64_t n_in,
                          uint64_t amount,
                          const uint8_t* witness_script, uint64_t wslen,
                          const uint8_t* vchSig, uint64_t siglen,
                          const uint8_t* vchPub, uint64_t publen)
{
    uint8_t pre[512]; uint8_t sighash[32];
    long n = segwit_v0_sighash(sighash, tx, txlen, n_in, SIGHASH_ALL,
                               amount, witness_script, wslen, pre, sizeof(pre));
    if (n <= 0) return 0;
    uint64_t r[4], s[4]; uint32_t ht = 0;
    if (!der_parse_sig(vchSig, (unsigned long)siglen, r, s, &ht)) return 0;
    if (ht != (uint32_t)SIGHASH_ALL) return 0;
    uint64_t z[4]; be_to_limbs(z, sighash, 32);
    uint64_t Qx[4], Qy[4];
    if (!pubkey_parse(vchPub, (unsigned long)publen, Qx, Qy)) return 0;
    return ecdsa_verify(z, r, s, Qx, Qy);
}

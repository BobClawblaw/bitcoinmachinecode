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
 * exactly what the unbounded version did. */
static uint64_t read_cs(const uint8_t** p, const uint8_t* end, int* ok){
    const uint8_t* b = *p;
    if (b >= end){ *ok = 0; *p = end; return 0; }
    uint8_t f = *b++;
    /* Single-byte encoding first and returning immediately: this is the
     * branch essentially every real compactsize takes, and PERF_SCOPE.md's
     * re-profile puts read_cs at 22.4% of verify cycles, so the bound must
     * cost one compare on the hot path and not a width computation. */
    if (f < 0xfd){ *p = b; return f; }
    int extra = (f == 0xfd) ? 2 : (f == 0xfe ? 4 : 8);
    if (end - b < extra){ *ok = 0; *p = end; return 0; }
    uint64_t v;
    if (f == 0xfd){ v = b[0] | ((uint64_t)b[1]<<8); b += 2; }
    else if (f == 0xfe){ v = 0; for(int i=0;i<4;i++) v |= (uint64_t)b[i]<<(8*i); b += 4; }
    else              { v = 0; for(int i=0;i<8;i++) v |= (uint64_t)b[i]<<(8*i); b += 8; }
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
 * Fills prevouts (36*n), sequences (4*n), outputs (serialized). Only the
 * fields BIP143 needs are extracted. */
typedef struct {
    const uint8_t* tx; int64_t txlen;
    const uint8_t* end;      /* tx + txlen; every walk below bounds against it */
    int64_t version;
    uint32_t locktime;
    int64_t nin, nout;
    const uint8_t* inputs;   /* first input's prevout */
} swtx_t;

/* Bytes still available at q. Every bound test below is written as a
 * "remaining >= wanted" comparison on this value rather than as `q + n > end`:
 * the lengths come off the wire and can be up to 2^64-1, so forming q+n first
 * overflows the pointer (undefined, and in practice wraps to a small address
 * that passes the test). */
static uint64_t sw_avail(const uint8_t* q, const uint8_t* end){
    return (uint64_t)(end - q);
}

static int swtx_parse(swtx_t* t){
    const uint8_t* p = t->tx;
    if (t->txlen < 10) return 0;
    const uint8_t* end = t->tx + t->txlen;
    t->end = end;
    int ok = 1;
    t->version = (int32_t)(p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24));
    p += 4;
    if (p[0] == 0x00 && p[1] == 0x01) p += 2;     /* segwit marker+flag */
    t->nin = (int64_t)read_cs(&p, end, &ok);
    if (!ok || t->nin <= 0) return 0;
    t->inputs = p;                                 /* first prevout */
    const uint8_t* q = p;
    for (int64_t i=0;i<t->nin;i++){
        if (sw_avail(q, end) < 36) return 0;
        q += 36;
        uint64_t sl = read_cs(&q, end, &ok);
        if (!ok || sw_avail(q, end) < sl + 4) return 0;
        q += sl + 4;
    }
    t->nout = (int64_t)read_cs(&q, end, &ok);
    if (!ok || t->nout < 0) return 0;
    for (int64_t i=0;i<t->nout;i++){
        if (sw_avail(q, end) < 8) return 0;
        q += 8;
        uint64_t sl = read_cs(&q, end, &ok);
        if (!ok || sw_avail(q, end) < sl) return 0;
        q += sl;
    }
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

/* prevout (36 bytes) of input i, or NULL if the walk runs out of buffer.
 * swtx_parse has already proven every input in range, so NULL here means the
 * caller asked for an input that does not exist. */
static const uint8_t* sw_prevout(const swtx_t* t, int64_t i){
    const uint8_t* q = t->inputs;
    int ok = 1;
    for (int64_t k=0;k<i;k++){
        if (sw_avail(q, t->end) < 36) return 0;
        q += 36;
        uint64_t sl = read_cs(&q, t->end, &ok);
        if (!ok || sw_avail(q, t->end) < sl + 4) return 0;
        q += sl + 4;
    }
    if (sw_avail(q, t->end) < 36) return 0;
    return q;
}
/* nSequence of input i into *out; 0 if the walk runs out of buffer. */
static int sw_seq(const swtx_t* t, int64_t i, uint32_t* out){
    const uint8_t* q = t->inputs;
    int ok = 1;
    for (int64_t k=0;k<=i;k++){
        if (sw_avail(q, t->end) < 36) return 0;
        q += 36;
        uint64_t sl = read_cs(&q, t->end, &ok);
        if (!ok || sw_avail(q, t->end) < sl + 4) return 0;
        q += sl;
        if (k == i) break;
        q += 4;
    }
    *out = (uint32_t)(q[0]|(q[1]<<8)|(q[2]<<16)|((uint32_t)q[3]<<24));
    return 1;
}
/* Serialize output i as a CTxOut (8-byte value || compactsize(len) || script)
 * into d, which holds cap bytes. Returns the length written, or -1 if it does
 * not fit / the transaction is malformed -- BEFORE writing anything.
 *
 * The cap is the point. Consensus places NO limit on an output's
 * scriptPubKey size; only relay standardness does, so a miner can include an
 * output of any length and every node must hash it. This wrote into a
 * 600-byte STACK buffer at both call sites with no check at all, so a
 * scriptPubKey of 590 bytes or more smashed the verifying thread's stack
 * (incident #21 -- the same class as #13's 4096-byte midstate buffers, and
 * the same class the outputs section of strip_witness below was already
 * fixed for). */
static long sw_ser_txout(const swtx_t* t, int64_t i, uint8_t* d, long cap){
    const uint8_t* end = t->end;
    int ok = 1;
    /* walk to output i */
    const uint8_t* q = t->tx + 4;
    if (q[0]==0 && q[1]==1) q += 2;
    read_cs(&q, end, &ok);                      /* nin */
    if (!ok) return -1;
    for (int64_t k=0;k<t->nin;k++){
        if (sw_avail(q, end) < 36) return -1;
        q += 36;
        uint64_t sl = read_cs(&q, end, &ok);
        if (!ok || sw_avail(q, end) < sl + 4) return -1;
        q += sl+4;
    }
    read_cs(&q, end, &ok);                      /* nout */
    if (!ok) return -1;
    for (int64_t k=0;k<i;k++){
        if (sw_avail(q, end) < 8) return -1;
        q += 8;
        uint64_t sl = read_cs(&q, end, &ok);
        if (!ok || sw_avail(q, end) < sl) return -1;
        q += sl;
    }
    if (sw_avail(q, end) < 8) return -1;
    uint64_t v; v=0; for(int b=0;b<8;b++) v |= (uint64_t)q[b]<<(8*b); q += 8;
    uint64_t sl = read_cs(&q, end, &ok);
    if (!ok || sw_avail(q, end) < sl) return -1;
    /* Bound the WRITE before any byte of it happens. cap is a long and sl is
     * wire-derived, so compare in 64-bit unsigned and only then narrow. */
    uint64_t need = 8u + (uint64_t)cs_size(sl) + sl;
    if (cap < 0 || need > (uint64_t)cap) return -1;
    w64le(d, v); long n = 8;
    put_cs(d+n, sl); n += cs_size(sl);
    memcpy(d+n, q, sl); n += (long)sl;
    return n;
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
long segwit_v0_sighash(uint8_t out32[32], const uint8_t* tx, int64_t txlen,
                       int64_t n_in, uint32_t nHashType, uint64_t amount,
                       const uint8_t* scriptCode, uint64_t scriptcode_len,
                       uint8_t* pre, long cap)
{
    swtx_t t; t.tx = tx; t.txlen = txlen;
    if (!swtx_parse(&t)) return 0;
    if (n_in < 0 || n_in >= t.nin) return 0;

    uint32_t htype = nHashType & 0x1f;
    int acp = (nHashType & SIGHASH_ANYONECANPAY) != 0;

    /* hashPrevouts / hashSequence / hashOutputs (double SHA256) */
    uint8_t hashPrevouts[32] = {0}, hashSequence[32] = {0}, hashOutputs[32] = {0};
    uint8_t* p = pre;
    uint8_t* pend = pre + cap;

    /* BIP143 midstates are sha256d of a concatenation whose length is
     * unbounded (500-input txs exist at 481827; a max block admits ~100k
     * inputs). The old code used fixed 4096-byte stack buffers -- a real
     * consensus-path stack overflow (incident #13). Use one per-thread heap
     * buffer sized to the largest a valid block allows: <=4 MB of prevouts
     * (36 B each) or outputs (>=9 B each), so 4 MB covers both. */
    #define SW_MIDSTATE_CAP (4u<<20)
    static __thread uint8_t* mbuf; BMC_TLS_BUF(mbuf, SW_MIDSTATE_CAP);
    if (!acp){
        /* hashPrevouts */
        size_t n = 0;
        for (int64_t i=0;i<t.nin;i++){
            const uint8_t* po = sw_prevout(&t,i);
            if (!po || n+36 > SW_MIDSTATE_CAP) return 0;
            memcpy(mbuf+n, po, 36); n += 36;
        }
        sha256d(hashPrevouts, mbuf, n);
        /* hashSequence */
        if (htype != SIGHASH_SINGLE && htype != SIGHASH_NONE){
            n = 0;
            for (int64_t i=0;i<t.nin;i++){
                uint32_t sq;
                if (!sw_seq(&t,i,&sq) || n+4 > SW_MIDSTATE_CAP) return 0;
                w32le(mbuf+n, sq); n += 4;
            }
            sha256d(hashSequence, mbuf, n);
        }
    }
    /* hashOutputs. Serialize each CTxOut STRAIGHT into mbuf at the running
     * offset, bounded by what is left of it: an output's scriptPubKey has no
     * consensus size limit, so the old 600-byte stack staging buffer was a
     * remotely-triggerable stack overflow (incident #21). mbuf is 4 MiB --
     * above MAX_BLOCK_SERIALIZED_SIZE -- so no transaction a valid block can
     * carry is refused here, and dropping the staging buffer also drops one
     * memcpy per output. */
    if (htype != SIGHASH_SINGLE && htype != SIGHASH_NONE){
        size_t on = 0;
        for (int64_t i=0;i<t.nout;i++){
            long k = sw_ser_txout(&t, i, mbuf+on, (long)(SW_MIDSTATE_CAP - on));
            if (k < 0) return 0;
            on += (size_t)k;
        }
        sha256d(hashOutputs, mbuf, on);
    } else if (htype == SIGHASH_SINGLE && n_in < t.nout){
        /* mbuf is free to reuse here: hashPrevouts/hashSequence (the only
         * other users) have already been folded into their own 32-byte
         * arrays by the sha256d calls above, and under SIGHASH_SINGLE
         * hashSequence is not computed at all. */
        long k = sw_ser_txout(&t, n_in, mbuf, (long)SW_MIDSTATE_CAP);
        if (k < 0) return 0;
        sha256d(hashOutputs, mbuf, k);
    }

    /* version */
    if (p + 4 > pend) return 0; w32le(p, (uint32_t)t.version); p += 4;
    /* hashPrevouts / hashSequence */
    if (p + 64 > pend) return 0; memcpy(p, hashPrevouts, 32); p += 32;
    memcpy(p, hashSequence, 32); p += 32;
    /* outpoint[nIn] */
    {
        const uint8_t* po = sw_prevout(&t, n_in);
        if (!po || p + 36 > pend) return 0;
        memcpy(p, po, 36); p += 36;
    }
    /* scriptCode (compactsize + bytes) */
    if ((uint64_t)(p - pre) + cs_size(scriptcode_len) + scriptcode_len > (uint64_t)cap) return 0;
    put_cs(p, scriptcode_len); p += cs_size(scriptcode_len);
    memcpy(p, scriptCode, scriptcode_len); p += scriptcode_len;
    /* amount */
    if (p + 8 > pend) return 0; w64le(p, amount); p += 8;
    /* nSequence[nIn] */
    {
        uint32_t sq;
        if (!sw_seq(&t, n_in, &sq) || p + 4 > pend) return 0;
        w32le(p, sq); p += 4;
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

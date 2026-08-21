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

/* ---------------- compact-size (varint) helpers ---------------- */
static uint64_t read_cs(const uint8_t** p){
    const uint8_t* b = *p;
    uint8_t f = *b++;
    uint64_t v;
    if (f < 0xfd)      v = f;
    else if (f == 0xfd){ v = b[0] | ((uint64_t)b[1]<<8); b += 2; }
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

/* ---------------- transaction view ---------------- */
typedef struct {
    const uint8_t* tx;   int64_t txlen;
    int      version;
    uint32_t locktime;
    const uint8_t* inputs;   /* start of the input vector (after varint) */
    const uint8_t* outputs;  /* start of the output vector */
    int64_t  nin, nout;
} txview_t;

/* Parse the tx header enough to locate inputs/outputs/locktime.
 * Returns 0 on malformed. */
static int tx_parse(txview_t* t){
    const uint8_t* p = t->tx;
    if (t->txlen < 10) return 0;
    t->version = (int32_t)(p[0] | (p[1]<<8) | (p[2]<<16) | ((uint32_t)p[3]<<24));
    p += 4;
    t->nin = (int64_t)read_cs(&p);
    if (t->nin <= 0) return 0;
    t->inputs = p;
    /* walk inputs */
    const uint8_t* q = p;
    for (int64_t i=0;i<t->nin;i++){
        if (q + 36 > t->tx + t->txlen) return 0;
        q += 36;                         /* prevout */
        uint64_t sl = read_cs(&q);
        if (q + (int64_t)sl + 4 > t->tx + t->txlen) return 0;
        q += sl + 4;                     /* scriptSig + nSequence */
    }
    uint64_t nout = read_cs(&q);
    t->outputs = q;              /* point past the output-count varint */
    t->nout = (int64_t)nout;
    for (uint64_t i=0;i<nout;i++){
        if (q + 8 > t->tx + t->txlen) return 0;
        q += 8;                          /* value */
        uint64_t sl = read_cs(&q);
        if (q + (int64_t)sl > t->tx + t->txlen) return 0;
        q += sl;                         /* scriptPubKey */
    }
    if (q + 4 > t->tx + t->txlen) return 0;
    t->locktime = (uint32_t)(q[0]|(q[1]<<8)|(q[2]<<16)|((uint32_t)q[3]<<24));
    return 1;
}

/* nSequence of input i (start of its prevout = inputs + i*lenbytes walk). */
static uint32_t tx_seq(const txview_t* t, int64_t i){
    const uint8_t* q = t->inputs;
    for (int64_t k=0;k<i;k++){
        q += 36;
        uint64_t sl = read_cs(&q);
        q += sl + 4;
    }
    q += 36;
    uint64_t sl = read_cs(&q);
    q += sl;
    return (uint32_t)(q[0]|(q[1]<<8)|(q[2]<<16)|((uint32_t)q[3]<<24));
}

/* outpoint (36 bytes) of input i */
static const uint8_t* tx_outpoint(const txview_t* t, int64_t i){
    const uint8_t* q = t->inputs;
    for (int64_t k=0;k<i;k++){
        q += 36;
        uint64_t sl = read_cs(&q);
        q += sl + 4;
    }
    return q;
}

/* Serialize one CTxOut (value LE + compactsize spk + spk) into d, return len. */
static int ser_txout(const txview_t* t, int64_t i, uint8_t* d){
    const uint8_t* q = t->outputs;
    uint64_t cnt = (uint64_t)t->nout;
    /* skip i outputs */
    for (int64_t k=0;k<i;k++){
        q += 8;
        uint64_t sl = read_cs(&q);
        q += sl;
    }
    uint64_t val;
    val = 0; for(int b=0;b<8;b++) val |= (uint64_t)q[b]<<(8*b); q += 8;
    uint64_t sl = read_cs(&q);
    w64le(d, val);
    int n = 8;
    put_cs(d+n, sl); n += cs_size(sl);
    memcpy(d+n, q, sl); n += (int)sl;
    return n;
}
static int ser_txout_len(const txview_t* t, int64_t i){
    const uint8_t* q = t->outputs;
    for (int64_t k=0;k<i;k++){ q += 8; uint64_t sl=read_cs(&q); q += sl; }
    int n = 8 + cs_size(0);
    /* value(8) + cs + spk */
    /* recompute */
    q = t->outputs;
    for (int64_t k=0;k<i;k++){ q += 8; uint64_t sl=read_cs(&q); q += sl; }
    q += 8;
    uint64_t sl = read_cs(&q);
    return 8 + cs_size(sl) + (int)sl;
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

/* Compute sha256 of prevouts/amounts/spks/sequences into aggregates. */
static void agg_hashes(const tapctx_t* c, const txview_t* t,
                       uint8_t h_prev[32], uint8_t h_amt[32],
                       uint8_t h_spk[32], uint8_t h_seq[32])
{
    uint8_t buf[4096];
    /* prevouts */
    {
        size_t n = 0;
        for (int64_t i=0;i<c->num_inputs;i++){ memcpy(buf+n, c->prevouts+i*36, 36); n+=36; }
        sha256_full(h_prev, buf, n);
    }
    /* amounts */
    {
        size_t n = 0;
        for (int64_t i=0;i<c->num_inputs;i++){ memcpy(buf+n, c->amounts+i*8, 8); n+=8; }
        sha256_full(h_amt, buf, n);
    }
    /* scriptpubkeys (compactsize + data) */
    {
        size_t n = 0;
        const uint8_t* p = c->spks;
        for (int64_t i=0;i<c->num_inputs;i++){
            uint64_t sl = read_cs(&p);
            int cs = cs_size(sl);
            memcpy(buf+n, p-cs, (size_t)cs + sl); n += (size_t)cs + sl;
            p += sl;
        }
        sha256_full(h_spk, buf, n);
    }
    /* sequences */
    {
        size_t n = 0;
        for (int64_t i=0;i<c->num_inputs;i++){ w32le(buf+n, tx_seq(t,i)); n+=4; }
        sha256_full(h_seq, buf, n);
    }
}

/* Build the full TapSighash preimage "0x00 || SigMsg || ext" into pre (cap),
 * return its length, or 0 on error. Then compute TaggedHash("TapSighash", pre)
 * into out32. */
long taproot_sighash(uint8_t* out32, const tapctx_t* c, uint8_t* pre, long cap)
{
    txview_t t; t.tx = c->tx; t.txlen = c->txlen;
    if (!tx_parse(&t)) return 0;
    if (c->n_in < 0 || c->n_in >= t.nin) return 0;
    if (c->n_in >= c->num_inputs) return 0;

    uint8_t h_prev[32], h_amt[32], h_spk[32], h_seq[32];
    agg_hashes(c, &t, h_prev, h_amt, h_spk, h_seq);

    uint8_t ht = c->hash_type;
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
    /* sha_outputs (not NONE, not SINGLE) */
    if (!is_none && !is_single){
        uint8_t obuf[1024]; size_t on = 0;
        for (int64_t i=0;i<t.nout;i++){
            int len = ser_txout_len(&t, i);
            uint8_t tmp[600]; int n = ser_txout(&t, i, tmp);
            (void)len;
            memcpy(obuf+on, tmp, n); on += n;
        }
        uint8_t ho[32]; sha256_full(ho, obuf, on);
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
        /* scriptPubKey: find index n_in spk in c->spks */
        const uint8_t* sp = c->spks;
        for (int64_t i=0;i<c->n_in;i++){ uint64_t sl = read_cs(&sp); sp += sl; }
        uint64_t sl = read_cs(&sp);
        if ((uint64_t)(p - pre) + cs_size(sl) + (uint64_t)sl > (uint64_t)cap) return 0;
        put_cs(p, sl); p += cs_size(sl);
        memcpy(p, sp, sl); p += sl;
        /* nSequence */
        uint32_t seq = tx_seq(&t, c->n_in);
        if (p + 4 > pend) return 0; w32le(p, seq); p += 4;
    } else {
        /* input_index */
        if (p + 4 > pend) return 0; w32le(p, (uint32_t)c->n_in); p += 4;
    }
    /* annex (BIP341): sha256(compactsize(len) || annex) */
    if (annex_present){
        uint8_t abuf[4096]; size_t an = 0;
        put_cs(abuf, c->annexlen); an += cs_size(c->annexlen);
        memcpy(abuf+an, c->annex, (size_t)c->annexlen); an += (size_t)c->annexlen;
        uint8_t ha[32]; sha256_full(ha, abuf, an);
        if (p + 32 > pend) return 0; memcpy(p, ha, 32); p += 32;
    }
    /* SINGLE: sha_single_output */
    if (is_single){
        if (c->n_in < t.nout){
            uint8_t tmp[600]; int n = ser_txout(&t, c->n_in, tmp);
            uint8_t hs[32]; sha256_full(hs, tmp, n);
            if (p + 32 > pend) return 0; memcpy(p, hs, 32); p += 32;
        } else {
            if (p + 32 > pend) return 0; memset(p, 0, 32); p += 32;
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

    uint8_t pre[256]; uint8_t hash[32];
    if (taproot_sighash(hash, &c, pre, sizeof(pre)) <= 0) return 0;
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

    uint8_t pre[256]; uint8_t hash[32];
    if (taproot_sighash(hash, &c, pre, sizeof(pre)) <= 0) return 0;
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

    uint8_t pre[256]; uint8_t hash[32];
    if (taproot_sighash(hash, &c, pre, sizeof(pre)) <= 0) return 0;
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
    (void)slice;
    if (siglen == 0) return 0;                     /* no signature provided */
    c->weight_left -= 50;
    if (c->weight_left < 0) return 0;               /* BIP342 validation-weight budget exceeded */
    if (publen != 32) return 0;                    /* x-only pubkey required */
    int r = tapscript_checksig_annex(sig, (int)siglen, pub,
                                     c->tx, c->txlen, c->n_in,
                                     c->prevouts, c->amounts, c->spks,
                                     c->num_inputs, c->tapleaf,
                                     c->codesep_pos, c->annex, c->annexlen, NULL);
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
 * KNOWN, DELIBERATE LIMITATION: does not track OP_CODESEPARATOR position
 * inside a tapscript for the BIP342 codesep_pos sighash field (always
 * 0xffffffff, "none executed"). This is safety-neutral to omit: a
 * tapscript that actually executes OP_CODESEPARATOR before a CHECKSIG
 * would get a sighash preimage that differs from the real one, and any
 * genuinely valid signature over the REAL sighash would then fail to
 * verify here -- a false-REJECT, never a false-accept (the final gate is
 * always a real Schnorr verify over whatever sighash got computed; an
 * attacker cannot leverage a wrong sighash to forge acceptance of a bad
 * signature). OP_CODESEPARATOR inside a tapscript is essentially unheard
 * of on real chain data. To avoid ever silently mis-verifying rather than
 * cleanly refusing, any tapscript containing the raw byte 0xab anywhere is
 * refused outright before execution (over-conservative -- a 0xab byte
 * inside push DATA also refuses -- but always safe and always loud, never
 * silent). */
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

    /* See this function's header comment: OP_CODESEPARATOR (0xab) inside a
     * known-leaf-version tapscript is not tracked; refuse rather than risk
     * a silently-wrong sighash. */
    for (uint64_t i = 0; i < slen; i++) {
        if (script[i] == 0xab) {
            *reason = "p2tr tapscript uses OP_CODESEPARATOR (not supported)";
            return 0;
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

    static __thread uint8_t ts_main_e[TS_MAX_STACK*TS_ELEM_SIZE];
    static __thread uint8_t ts_alt_e[TS_MAX_STACK*TS_ELEM_SIZE];
    static __thread uint8_t ts_work[1<<16];

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
    st.flags = 0;
    st.work = ts_work; st.work_cap = sizeof ts_work;
    uint64_t err = 0; st.error_out = &err;
    st.checksig_ctx = &ctx;
    st.checksig_fn  = taproot_checksig_fn;

    if (!script_eval(&st)) { *reason = "p2tr tapscript execution failed"; return 0; }
    /* script_eval returning 1 already means the interpreter's own
     * SIGVERSION_TAPSCRIPT-specific cleanstack/empty-result rule (exactly
     * one truthy element left) passed -- nothing further to check here. */
    return 1;
}

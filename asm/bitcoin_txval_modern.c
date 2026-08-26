#include "bmc_thread.h"
/* bitcoin_txval_modern.c -- whole-transaction mempool-acceptance validator for
 * modern output types (P2WPKH / P2WSH / P2TR), the acceptance gate that sits
 * on top of the mempool POLICY layer (bitcoin_mempool_policy.c) and runs a full
 * serialized segwit tx through:
 *     structural parse + witness extraction
 *     per-input signature verification (ECDSA for segwit v0, Schnorr for P2TR)
 *     fee / balance check  (sum(inputs) >= sum(outputs))
 *
 * Signature crypto is all verified ASM (ecdsa_verify / schnorr_verify) wrapped
 * by bitcoin_segwit.c (BIP143) and bitcoin_taproot_sighash.c (BIP341).
 *
 * The waxid (txid) is NOT computed here; the caller (the mempool acceptance
 * harness) supplies it via the policy layer (bitcoin_tx.asm tx_txid).
 */
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>

/* ---- bitcoin_segwit.c / bitcoin_taproot_sighash.c / asm ---- */
extern long strip_witness(const uint8_t* tx, int64_t txlen, uint8_t* out, long cap);
extern int  p2wpkh_verify(const uint8_t* tx, int64_t txlen, int64_t n_in,
                          const uint8_t* prev_spk, int64_t prev_spklen, uint64_t amount,
                          const uint8_t* vchSig, uint64_t siglen,
                          const uint8_t* vchPub, uint64_t publen);
extern int  sv_classify_segwit(const uint8_t* spk, uint32_t spl, const uint8_t* ss, uint32_t ssl,
                               uint32_t* version, const uint8_t** prog, uint32_t* proglen, int* wrapped);
extern int  sv_verify_witness_v0(const uint8_t* prog, uint32_t proglen,
                                 const uint8_t* const* wit, const uint32_t* witlen, uint32_t nwit,
                                 uint64_t amount, unsigned long long flags, unsigned long nIn,
                                 const uint8_t* tx, unsigned long txlen, uint8_t* work, unsigned long workcap);
/* Mempool script flags for witness-v0 execution: the consensus set this
 * validator already implies (P2SH, DERSIG, NULLDUMMY, CLTV, CSV, WITNESS)
 * plus CLEANSTACK, which witness execution requires anyway. Core bit values. */
#define MV_WITNESS_FLAGS ((1ULL<<0)|(1ULL<<2)|(1ULL<<4)|(1ULL<<8)|(1ULL<<9)|(1ULL<<10)|(1ULL<<11))
extern int  p2wsh_verify_checksig(const uint8_t* tx, int64_t txlen, int64_t n_in,
                                  uint64_t amount, const uint8_t* witness_script,
                                  uint64_t wslen, const uint8_t* vchSig, uint64_t siglen,
                                  const uint8_t* vchPub, uint64_t publen);
extern int  p2wsh_verify_multisig(const uint8_t* tx, int64_t txlen, int64_t n_in,
                                  uint64_t amount, const uint8_t* witness_script,
                                  uint64_t wslen,
                                  const uint8_t* sig1, uint64_t sig1len,
                                  const uint8_t* sig2, uint64_t sig2len,
                                  const uint8_t* pub1, const uint8_t* pub2);
extern int  taproot_keypath_verify(const uint8_t* spk, const uint8_t* sig, int siglen,
                                   const uint8_t* tx, int64_t txlen, int64_t n_in,
                                   const uint8_t* prevouts, const uint8_t* amounts,
                                   const uint8_t* spks, int64_t num_inputs);

/* ---- UTXO set ---- */
/* NOT bitcoin_utxo.asm's own `utxo_get` directly -- see bitcoin_mempool_
 * policy.c's identical extern for why: that symbol is already bound to a
 * different, unrelated purpose (bitcoin_utxo_lsm.asm's own memtable
 * internals) in any binary that also links the LSM store, so this needs
 * its own distinct name. Each binary that links this file provides its own
 * definition (old-table test harnesses pass through to utxo_get; the live
 * daemon provides an LSM-backed one, see daemon/tx_accept.c). */
extern long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script,
                     unsigned long* slen);

/* ================= helpers ================= */
/* prev_spk points into prev_spk_buf (owned, copied by value in mv_resolve),
 * NOT directly into whatever utxo_get/utxo_lsm_get returned. Required for
 * utxo_lsm_get specifically: on a disk-run hit its returned script pointer
 * is only valid until the NEXT utxo_lsm_get call (see bitcoin_utxo_lsm.asm's
 * header comment), and mv_resolve below resolves ALL inputs in one loop
 * before any of them are consumed -- including P2TR's own aggregation of
 * every input's prev_spk together for the combined sighash, further below
 * in this file. Sized to comfortably cover the fixed-size scriptPubKey
 * forms this validator actually supports (P2WPKH 22B, P2WSH/P2TR 34B). */
#define PREV_SPK_BUF_MAX 42
/* Mempool-admission witness-item cap. This is a simplified standardness
 * parser (inputs/outputs also bounded at 16 below); mempool policy may be
 * stricter than consensus, so a modest inline bound is fine here. It was 16,
 * which rejected an ordinary >16-item P2WSH witness (e.g. a 15-of-15 or an
 * HTLC-style script). 100 covers realistic standard witnesses cheaply on the
 * stack. CONSENSUS block validation is daemon/tx_verify.c, which pools the
 * items and admits the full ~1004-item range -- see TXV_MAX_WIT_ITEMS. */
#define MV_MAX_WIT 100
/* Input/output bounds for mempool admission. These were BOTH 16 -- fine for
 * every synthetic fixture, and a mass-rejector ("malformed tx") the first
 * day the node fetched REAL relayed transactions: exchange batching and
 * consolidation txs routinely carry hundreds of inputs/outputs. Core's
 * standardness cap is MAX_STANDARD_TX_WEIGHT (400k WU = 100 kvB), which
 * bounds inputs at ~1,500 (P2WPKH ~68 vB each) and outputs at ~3,200
 * (~31 vB each); the sizes below cover the full standard range with slack.
 * Consensus block validation is daemon/tx_verify.c with its own bounds. */
#define MV_MAX_IN  2048
#define MV_MAX_OUT 4096
typedef struct {
    uint8_t outpoint[36];
    uint8_t scriptSig[64]; uint32_t scriptSiglen;   /* 35 for P2SH-P2WSH (0x22 + 34); was 32, which silently truncated it */
    uint32_t sequence;
    const uint8_t* wit[MV_MAX_WIT]; uint32_t witlen[MV_MAX_WIT]; uint32_t nwit;
    uint64_t amount;
    uint8_t prev_spk_buf[PREV_SPK_BUF_MAX];
    const uint8_t* prev_spk; uint32_t prev_spklen;
} inrec_t;

typedef struct {
    const uint8_t* tx; int64_t txlen;
    uint64_t version;
    uint64_t nin, nout;
    inrec_t in[MV_MAX_IN];
    uint64_t out_total;
} mv_tx_t;

/* Bounded compactsize (incident #37, 2026-08-24): the previous rd_cs took no
 * `end` and read 1/3/5/9 bytes unconditionally, so on the no-PoW inbound-tx
 * path a varint near the buffer's end read up to 8 bytes past it. It also let
 * the CALLERS use `p + len > end` bounds that overflow for attacker-supplied
 * lengths near 2^64 (the same wrap as incident #36, here on a peer-reachable
 * path with no PoW gate). Now it bounds the encoding read and sets *ok=0 on
 * truncation; callers use split bounds that cannot overflow. */
static uint64_t rd_cs(const uint8_t** p, const uint8_t* end, int* ok){
    const uint8_t* b = *p;
    if (b >= end){ *ok = 0; return 0; }
    uint8_t f = *b++;
    uint64_t v;
    if (f < 0xfd) v = f;
    else if (f == 0xfd){ if (end - b < 2){*ok=0;return 0;} v = b[0]|((uint64_t)b[1]<<8); b += 2; }
    else if (f == 0xfe){ if (end - b < 4){*ok=0;return 0;} v = 0; for(int i=0;i<4;i++) v |= (uint64_t)b[i]<<(8*i); b += 4; }
    else { if (end - b < 8){*ok=0;return 0;} v = 0; for(int i=0;i<8;i++) v |= (uint64_t)b[i]<<(8*i); b += 8; }
    *p = b; return v;
}

/* Parse a full segwit tx into the mv_tx_t view (outpoints, witness, outputs). */
static int mv_parse(mv_tx_t* T){
    const uint8_t* tx = T->tx; const uint8_t* end = tx + T->txlen;
    if (T->txlen < 10) return 0;
    const uint8_t* p = tx; int ok = 1;
    T->version = 0; for(int i=0;i<4;i++) T->version |= (uint64_t)p[i]<<(8*i);
    p += 4;
    int segwit = (p[0]==0x00 && p[1]==0x01);
    if (segwit) p += 2;
    uint64_t nin = rd_cs(&p, end, &ok);
    if (!ok || nin == 0 || nin > MV_MAX_IN) return 0;
    T->nin = nin;
    for (uint64_t i=0;i<nin;i++){
        inrec_t* in = &T->in[i];
        /* T is static now (in[] alone is ~2.8 MB -- too large to memset per
         * call, never mind carve from the stack); each input record is
         * zeroed here, exactly when it is about to be filled, so state from
         * the previous transaction (a non-segwit tx after a segwit one
         * would otherwise inherit stale wit/nwit) cannot leak forward. */
        memset(in, 0, sizeof *in);
        if (p + 36 > end) return 0;
        memcpy(in->outpoint, p, 36); p += 36;
        uint64_t sl = rd_cs(&p, end, &ok);
        if (!ok) return 0;
        /* split bound: (end-p) must hold sl + 4, computed so neither side
         * overflows for sl near 2^64 (incident #37, the #36 wrap on the
         * mempool path). */
        { uint64_t avail = (uint64_t)(end - p); if (avail < sl || avail - sl < 4) return 0; }
        if (sl > sizeof in->scriptSig) return 0;
        memcpy(in->scriptSig, p, sl); in->scriptSiglen = (uint32_t)sl; p += sl;
        in->sequence = (uint32_t)(p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24)); p += 4;
    }
    uint64_t nout = rd_cs(&p, end, &ok);
    if (!ok || nout > MV_MAX_OUT) return 0;
    T->nout = nout;
    T->out_total = 0;
    for (uint64_t i=0;i<nout;i++){
        if (p + 8 > end) return 0;
        uint64_t v = 0; for(int k=0;k<8;k++) v |= (uint64_t)p[k]<<(8*k); p += 8;
        T->out_total += v;
        uint64_t sl = rd_cs(&p, end, &ok);
        if (!ok || sl > (uint64_t)(end - p)) return 0; p += sl;
    }
    /* witness: no overall stack-count field on the wire -- exactly one
     * stack per input, back-to-back (Core's SerializeTransaction writes
     * tx.vin[i].scriptWitness.stack for i in [0, vin.size())). */
    if (segwit){
        for (uint64_t i=0;i<nin;i++){
            inrec_t* in = &T->in[i];
            uint64_t nitems = rd_cs(&p, end, &ok);
            if (!ok || nitems > MV_MAX_WIT) return 0;
            in->nwit = (uint32_t)nitems;
            for (uint64_t j=0;j<nitems;j++){
                uint64_t il = rd_cs(&p, end, &ok);
                if (!ok || il > (uint64_t)(end - p)) return 0;
                in->wit[j] = p; in->witlen[j] = (uint32_t)il; p += il;
            }
        }
    }
    return 1;
}
/* incident #37 test hook: expose mv_parse's verdict and the parsed witness
 * length of input 0 so a test can prove the fix rejects at PARSE rather than
 * accepting with a truncated length that a resolve-failure happens to hide. */
int mv_test_parse(const uint8_t* tx, long txlen, uint32_t* wl0_out){
    mv_tx_t T; memset(&T,0,sizeof T); T.tx=tx; T.txlen=txlen;
    int r = mv_parse(&T);
    if (wl0_out) *wl0_out = (r && T.nin>0 && T.in[0].nwit>0) ? T.in[0].witlen[0] : 0;
    return r;
}

/* Resolve the prevout script+amount for every input from the UTXO set. */
static int mv_resolve(mv_tx_t* T, void* utxo, const char** err){
    for (uint64_t i=0;i<T->nin;i++){
        inrec_t* in = &T->in[i];
        unsigned long long val; const unsigned char* sp; unsigned long sl;
        /* txid (32 bytes) + vout (4 LE) from outpoint */
        if (mempool_resolve_confirmed_utxo(utxo, in->outpoint,
                     (unsigned long)(in->outpoint[32] | (in->outpoint[33]<<8)
                                     | (in->outpoint[34]<<16) | ((uint32_t)in->outpoint[35]<<24)),
                     &val, &sp, &sl) != 1){
            if (err) *err = "input not found in utxo";
            return 0;
        }
        if (sl > PREV_SPK_BUF_MAX){
            if (err) *err = "prevout script too large";
            return 0;
        }
        in->amount = (uint64_t)val;
        memcpy(in->prev_spk_buf, sp, sl);
        in->prev_spk = in->prev_spk_buf; in->prev_spklen = (uint32_t)sl;
    }
    return 1;
}

static const char* g_reason = "accepted";

/* ==========================================================================
 * Whole-tx modern validation. `utxo` is the confirmed-UTXO set providing the
 * prevout scripts/amounts. Returns 1 = accept, 0 = reject (reason in g_reason).
 * ========================================================================== */
const char* txval_last_reason(void){ return g_reason; }
int txval_modern(const uint8_t* tx, int64_t txlen, void* utxo){
    g_reason = "accepted";
    /* static: in[MV_MAX_IN] is megabytes. Callers are single-threaded by
     * architecture (the download worker's main loop; one serve child per
     * inbound connection) -- consensus block validation never comes through
     * here (daemon/tx_verify.c). Scalars reset here; per-input records are
     * zeroed in mv_parse as they are filled. */
    static mv_tx_t T;
    T.tx = tx; T.txlen = txlen;
    T.version = 0; T.nin = 0; T.nout = 0; T.out_total = 0;
    if (!mv_parse(&T)){ g_reason = "malformed tx"; return 0; }
    if (T.nin == 0 || T.nout == 0){ g_reason = "empty inputs/outputs"; return 0; }
    if (!mv_resolve(&T, utxo, &g_reason)) return 0;

    /* strip witness for BIP341 (taproot) -- BIP143 paths accept full segwit.
     * Sized for the LARGEST STANDARD transaction (100 kvB), not the 1 KB the
     * first draft used -- which "malformed witness"-rejected every real tx
     * whose stripped serialization passed 1 KB, the same first-contact
     * failure shape as the 16-input cap above. */
    static uint8_t ns[400*1024];
    long nslen = strip_witness(tx, txlen, ns, sizeof ns);
    if (nslen <= 0){ g_reason = "malformed witness"; return 0; }

    uint64_t sum_in = 0;
    for (uint64_t i=0;i<T.nin;i++){
        inrec_t* in = &T.in[i];
        sum_in += in->amount;
        const uint8_t* spk = in->prev_spk;
        uint32_t sl = in->prev_spklen;

        /* ---- witness v0, native (00 14 <20> / 00 20 <32>) or P2SH-wrapped
         * (BIP141 P2SH-P2WPKH / P2SH-P2WSH): one general path through the
         * shared interpreter (sv_verify_witness_v0), replacing the former
         * two-shape fast paths (single CHECKSIG, 2-of-2 CHECKMULTISIG) that
         * could not verify the real chain (2026-08-22). ---- */
        {
            uint32_t wver=0, wplen=0; const uint8_t* wprog=0; int wrapped=0;
            int cls = sv_classify_segwit(spk, sl, in->scriptSig, in->scriptSiglen, &wver, &wprog, &wplen, &wrapped);
            if (cls < 0){ g_reason = "p2sh-wrapped witness program: malformed scriptSig"; return 0; }
            if (cls > 0 && !(wver == 1 && wplen == 32 && !wrapped)){   /* native v1/32 = taproot, handled below */
                if (!wrapped && in->scriptSiglen != 0){ g_reason = "witness program scriptSig must be empty"; return 0; }
                if (wver != 0){ g_reason = "unknown witness version (policy: discouraged)"; return 0; }
                if (wplen == 20 && in->nwit != 2){ g_reason = "p2wpkh needs 2 witness items"; return 0; }
                if (wplen == 32 && in->nwit < 1){ g_reason = "p2wsh needs witnessScript"; return 0; }
                static __thread uint8_t* sv_work; BMC_TLS_BUF(sv_work, 1<<20);
                int err = sv_verify_witness_v0(wprog, wplen, in->wit, in->witlen, in->nwit, in->amount,
                                               MV_WITNESS_FLAGS, (unsigned long)i, tx, (unsigned long)txlen,
                                               sv_work, (unsigned long)(1<<20));
                if (err != 0){ g_reason = wplen == 20 ? "p2wpkh signature invalid" : "p2wsh script verification failed"; return 0; }
                continue;
            }
        }
        /* ---- P2TR: 51 20 <32> ; witness [sig] (key-path) ---- */
        if (sl == 34 && spk[0]==0x51 && spk[1]==0x20){
            if (in->scriptSiglen != 0){ g_reason="p2tr scriptSig must be empty"; return 0; }
            if (in->nwit != 1){ g_reason="p2tr keypath needs 1 witness item"; return 0; }
            /* build prevouts/amounts/spks arrays for taproot_keypath_verify */
            uint8_t po[16*36]; uint8_t am[16*8], sp[16*70];
            for (uint64_t k=0;k<T.nin;k++){ memcpy(po+k*36, T.in[k].outpoint, 36);
                uint64_t a=T.in[k].amount; for(int b=0;b<8;b++) am[k*8+b]=(uint8_t)(a>>(8*b));
            }
            {
                int off=0;
                for (uint64_t k=0;k<T.nin;k++){
                    if (T.in[k].prev_spklen < 0xfd) sp[off++]=(uint8_t)T.in[k].prev_spklen;
                    else return 0;
                    memcpy(sp+off, T.in[k].prev_spk, T.in[k].prev_spklen);
                    off += T.in[k].prev_spklen;
                }
                if (!taproot_keypath_verify(spk, in->wit[0], (int)in->witlen[0],
                                            ns, nslen, (int64_t)i, po, am, sp, (int64_t)T.nin)){
                    g_reason = "p2tr keypath invalid"; return 0; }
            }
            continue;
        }
        g_reason = "unsupported prevout script type";
        return 0;
    }
    /* fee: sum(in) >= sum(out) */
    if (sum_in < T.out_total){ g_reason = "negative fee"; return 0; }
    return 1;
}

const char* txval_modern_reason(void){ return g_reason; }

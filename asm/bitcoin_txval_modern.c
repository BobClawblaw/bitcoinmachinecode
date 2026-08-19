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
typedef struct {
    uint8_t outpoint[36];
    uint8_t scriptSig[32]; uint32_t scriptSiglen;
    uint32_t sequence;
    const uint8_t* wit[16]; uint32_t witlen[16]; uint32_t nwit;
    uint64_t amount;
    uint8_t prev_spk_buf[PREV_SPK_BUF_MAX];
    const uint8_t* prev_spk; uint32_t prev_spklen;
} inrec_t;

typedef struct {
    const uint8_t* tx; int64_t txlen;
    uint64_t version;
    uint64_t nin, nout;
    inrec_t in[16];
    uint64_t out_total;
} mv_tx_t;

static uint64_t rd_cs(const uint8_t** p){
    const uint8_t* b = *p; uint8_t f = *b++;
    uint64_t v;
    if (f < 0xfd) v = f;
    else if (f == 0xfd){ v = b[0]|((uint64_t)b[1]<<8); b += 2; }
    else if (f == 0xfe){ v = 0; for(int i=0;i<4;i++) v |= (uint64_t)b[i]<<(8*i); b += 4; }
    else { v = 0; for(int i=0;i<8;i++) v |= (uint64_t)b[i]<<(8*i); b += 8; }
    *p = b; return v;
}

/* Parse a full segwit tx into the mv_tx_t view (outpoints, witness, outputs). */
static int mv_parse(mv_tx_t* T){
    const uint8_t* tx = T->tx; const uint8_t* end = tx + T->txlen;
    if (T->txlen < 10) return 0;
    const uint8_t* p = tx;
    T->version = 0; for(int i=0;i<4;i++) T->version |= (uint64_t)p[i]<<(8*i);
    p += 4;
    int segwit = (p[0]==0x00 && p[1]==0x01);
    if (segwit) p += 2;
    uint64_t nin = rd_cs(&p);
    if (nin == 0 || nin > 16) return 0;
    T->nin = nin;
    for (uint64_t i=0;i<nin;i++){
        inrec_t* in = &T->in[i];
        if (p + 36 > end) return 0;
        memcpy(in->outpoint, p, 36); p += 36;
        uint64_t sl = rd_cs(&p);
        if (p + sl + 4 > end) return 0;
        if (sl > sizeof in->scriptSig) return 0;
        memcpy(in->scriptSig, p, sl); in->scriptSiglen = (uint32_t)sl; p += sl;
        in->sequence = (uint32_t)(p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24)); p += 4;
    }
    uint64_t nout = rd_cs(&p);
    if (nout > 16) return 0;
    T->nout = nout;
    T->out_total = 0;
    for (uint64_t i=0;i<nout;i++){
        if (p + 8 > end) return 0;
        uint64_t v = 0; for(int k=0;k<8;k++) v |= (uint64_t)p[k]<<(8*k); p += 8;
        T->out_total += v;
        uint64_t sl = rd_cs(&p);
        if (p + sl > end) return 0; p += sl;
    }
    /* witness: no overall stack-count field on the wire -- exactly one
     * stack per input, back-to-back (Core's SerializeTransaction writes
     * tx.vin[i].scriptWitness.stack for i in [0, vin.size())). */
    if (segwit){
        for (uint64_t i=0;i<nin;i++){
            inrec_t* in = &T->in[i];
            uint64_t nitems = rd_cs(&p);
            if (nitems > 16) return 0;
            in->nwit = (uint32_t)nitems;
            for (uint64_t j=0;j<nitems;j++){
                uint64_t il = rd_cs(&p);
                if (p + il > end) return 0;
                in->wit[j] = p; in->witlen[j] = (uint32_t)il; p += il;
            }
        }
    }
    return 1;
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
int txval_modern(const uint8_t* tx, int64_t txlen, void* utxo){
    g_reason = "accepted";
    mv_tx_t T; memset(&T, 0, sizeof T); T.tx = tx; T.txlen = txlen;
    if (!mv_parse(&T)){ g_reason = "malformed tx"; return 0; }
    if (T.nin == 0 || T.nout == 0){ g_reason = "empty inputs/outputs"; return 0; }
    if (!mv_resolve(&T, utxo, &g_reason)) return 0;

    /* strip witness for BIP341 (taproot) -- BIP143 paths accept full segwit */
    static uint8_t ns[1024];
    long nslen = strip_witness(tx, txlen, ns, sizeof ns);
    if (nslen <= 0){ g_reason = "malformed witness"; return 0; }

    uint64_t sum_in = 0;
    for (uint64_t i=0;i<T.nin;i++){
        inrec_t* in = &T.in[i];
        sum_in += in->amount;
        const uint8_t* spk = in->prev_spk;
        uint32_t sl = in->prev_spklen;

        /* ---- P2WPKH: 00 14 <20> ; witness [sig, pub] ---- */
        if (sl == 22 && spk[0]==0x00 && spk[1]==0x14){
            if (in->scriptSiglen != 0){ g_reason="p2wpkh scriptSig must be empty"; return 0; }
            if (in->nwit != 2){ g_reason="p2wpkh needs 2 witness items"; return 0; }
            if (!p2wpkh_verify(tx, txlen, (int64_t)i, spk, sl, in->amount,
                               in->wit[0], in->witlen[0], in->wit[1], in->witlen[1])){
                g_reason = "p2wpkh signature invalid"; return 0; }
            continue;
        }
        /* ---- P2WSH: 00 20 <32> ; witness [... , witnessScript] ---- */
        if (sl == 34 && spk[0]==0x00 && spk[1]==0x20){
            if (in->scriptSiglen != 0){ g_reason="p2wsh scriptSig must be empty"; return 0; }
            if (in->nwit < 2){ g_reason="p2wsh needs witnessScript"; return 0; }
            const uint8_t* ws = in->wit[in->nwit-1];
            uint32_t wslen = in->witlen[in->nwit-1];
            /* OP_CHECKSIG form: <0x21 pub> 0xac ; witness [sig, script] */
            if (wslen >= 34 && ws[0]==0x21 && ws[wslen-1]==0xac){
                if (!p2wsh_verify_checksig(tx, txlen, (int64_t)i, in->amount,
                                           ws, wslen, in->wit[0], in->witlen[0],
                                           ws+1, 33)){
                    g_reason = "p2wsh checksig invalid"; return 0; }
                continue;
            }
            /* 2-of-2 CHECKMULTISIG: 52 <21 p1> <21 p2> 52 ae ; witness
             * [dummy, sig2, sig1, script] where stack order puts sig1 on top
             * (CHECKMULTISIG tries pub1 against sig1, pub2 against sig2) */
            if (wslen >= 3+33+33 && ws[0]==0x52 && ws[wslen-1]==0xae){
                if (in->nwit < 4){ g_reason="p2wsh multisig needs 4 witness items"; return 0; }
                if (!p2wsh_verify_multisig(tx, txlen, (int64_t)i, in->amount, ws, wslen,
                                           in->wit[2], in->witlen[2],
                                           in->wit[1], in->witlen[1],
                                           ws+2, ws+36)){
                    g_reason = "p2wsh multisig invalid"; return 0; }
                continue;
            }
            g_reason = "unsupported p2wsh witnessScript";
            return 0;
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

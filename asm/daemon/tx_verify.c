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
 */
#include <string.h>
#include <stdint.h>

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

typedef struct {
    const u8* outpoint;             /* 36 bytes: txid(32)+index(4), in tx bytes */
    const u8* scriptSig; u32 scriptSiglen;
    const u8* wit[TXV_MAX_WIT_ITEMS]; u32 witlen[TXV_MAX_WIT_ITEMS]; u32 nwit;
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

/* tx_verify_block_connect(tx, txlen, height, block_hash32, lst, u, &reason)
 * -> 1 accept / 0 reject (reason set to a static string literal). Caller
 * must have already excluded the coinbase tx -- every input seen here is a
 * real spend, never a coinbase's null prevout. */
int tx_verify_block_connect(const u8* tx, u64 txlen, long height, const u8 block_hash32[32],
                            void* lst, void* u, const char** reason){
    static u8 sv_work[1<<20];
    u64 nin;
    if (!txv_parse(tx, txlen, &nin, reason)) return 0;

    unsigned long long flags = script_flags_for_block((unsigned long long)height, block_hash32);
    int has_taproot = 0;

    /* ---- pass 1: maturity check + every self-contained (non-taproot)
     * input. Legacy/P2WPKH/P2WSH verification only ever needs THIS input's
     * own resolved prevout, never any sibling input's -- so they verify
     * immediately, one utxo_lsm_get at a time. ---- */
    for (u64 i=0;i<nin;i++){
        u32 index; memcpy(&index, g_txv_in[i].outpoint+32, 4);
        u64 value=0, uheight=0, ucb=0; const u8* spk=0; unsigned long spklen=0;
        long r = utxo_lsm_get(lst, u, g_txv_in[i].outpoint, index, &value, &uheight, &ucb, &spk, &spklen);
        if (r != 1) { *reason = "input references a missing/already-spent UTXO"; return 0; }
        if (ucb) {
            long conf = height - (long)uheight;
            if (conf < COINBASE_MATURITY) { *reason = "immature coinbase spend (100-block rule)"; return 0; }
        }

        if (is_p2tr(spk, (u32)spklen)) {
            has_taproot = 1;
            if (g_txv_in[i].scriptSiglen != 0) { *reason = "p2tr scriptSig must be empty"; return 0; }
            if (g_txv_in[i].nwit != 1) { *reason = "p2tr keypath needs exactly 1 witness item"; return 0; }
            continue; /* verified in pass 2 -- BIP341 needs every input's prevout */
        }
        if (is_p2wpkh(spk, (u32)spklen)) {
            if (g_txv_in[i].scriptSiglen != 0) { *reason = "p2wpkh scriptSig must be empty"; return 0; }
            if (g_txv_in[i].nwit != 2) { *reason = "p2wpkh needs exactly 2 witness items"; return 0; }
            if (!p2wpkh_verify(tx, (int64_t)txlen, (int64_t)i, spk, (int64_t)spklen, value,
                               g_txv_in[i].wit[0], g_txv_in[i].witlen[0],
                               g_txv_in[i].wit[1], g_txv_in[i].witlen[1])) {
                *reason = "p2wpkh signature invalid"; return 0;
            }
            continue;
        }
        if (is_p2wsh(spk, (u32)spklen)) {
            if (g_txv_in[i].scriptSiglen != 0) { *reason = "p2wsh scriptSig must be empty"; return 0; }
            if (g_txv_in[i].nwit < 2) { *reason = "p2wsh needs a witnessScript"; return 0; }
            const u8* ws = g_txv_in[i].wit[g_txv_in[i].nwit-1];
            u32 wslen = g_txv_in[i].witlen[g_txv_in[i].nwit-1];
            /* OP_CHECKSIG form: <0x21 pub> 0xac ; witness [sig, script] */
            if (wslen >= 34 && ws[0]==0x21 && ws[wslen-1]==0xac){
                if (!p2wsh_verify_checksig(tx, (int64_t)txlen, (int64_t)i, value, ws, wslen,
                                           g_txv_in[i].wit[0], g_txv_in[i].witlen[0], ws+1, 33)) {
                    *reason = "p2wsh checksig invalid"; return 0;
                }
                continue;
            }
            /* 2-of-2 CHECKMULTISIG: witness [dummy, sig2, sig1, script] */
            if (wslen >= 3+33+33 && ws[0]==0x52 && ws[wslen-1]==0xae && g_txv_in[i].nwit >= 4){
                if (!p2wsh_verify_multisig(tx, (int64_t)txlen, (int64_t)i, value, ws, wslen,
                                           g_txv_in[i].wit[2], g_txv_in[i].witlen[2],
                                           g_txv_in[i].wit[1], g_txv_in[i].witlen[1],
                                           ws+2, ws+36)) {
                    *reason = "p2wsh multisig invalid"; return 0;
                }
                continue;
            }
            *reason = "unsupported p2wsh witnessScript shape"; return 0;
        }

        /* ---- legacy: not one of the three witness-program shapes above ---- */
        int err = sv_verify_script(g_txv_in[i].scriptSig, g_txv_in[i].scriptSiglen,
                                   spk, spklen, flags, (unsigned long)i,
                                   tx, txlen, sv_work, sizeof sv_work);
        if (err != 0) { *reason = "legacy script verification failed"; return 0; }
    }

    if (!has_taproot) return 1;

    /* ---- pass 2: taproot key-path inputs, which need EVERY input's
     * resolved prevout (amount+scriptPubKey) for BIP341's aggregate
     * sighash. Re-resolves rather than retaining pass 1's pointers --
     * utxo_lsm_get's returned script pointer is only valid until the NEXT
     * call (see bitcoin_utxo_lsm.asm's header comment), so pass 1 could not
     * have held onto all of them simultaneously anyway. Paid only on the
     * minority of txs that actually contain a taproot input. ---- */
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

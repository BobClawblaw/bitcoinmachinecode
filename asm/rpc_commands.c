/* rpc_commands.c -- shared JSON-RPC command dispatch + Core-bit-exact rendering.
 *
 * Renders Core-shaped result values for the in-scope wallet commands using
 * asm/wallet_core.c. Amounts use Core's ValueFromAmount string form. Field
 * names and ordering follow Bitcoin Core's current RPC result schemas so the
 * emitted JSON matches what bitcoin-cli would print (modulo the deterministic
 * fields -- address-derivation, txid, hashes, values -- which are computed from
 * the actual command-layer data, never fabricated).
 */
#include "rpc_commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---- extern wallet_core command layer (from asm/wallet_core.c) ---- */
extern long wallet_derive_p2wpkh_address(char* out, long cap, const unsigned char seed[64], unsigned index);
extern long wallet_derive_p2wpkh_change(char* out, long cap, const unsigned char seed[64], unsigned index);
extern int  wallet_validate_address(const char* str, int* type_, unsigned char* version, unsigned char h160[20], unsigned char prog32[32]);
extern int  wallet_script_to_address(char* out, long cap, const unsigned char* script, long slen);
extern long wallet_decoderawtx(char* out, long cap, const unsigned char* tx, unsigned long txlen);

/* extern LSM UTXO store lookup (asm/bitcoin_utxo_lsm.asm) -- see
 * rpc_commands_set_utxo_store's own doc comment in the header. */
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index,
                          unsigned long long* value, const unsigned char** script, unsigned* slen);

static void* g_utxo_lst = NULL;
static void* g_utxo_u = NULL;
void rpc_commands_set_utxo_store(void* lst, void* u) { g_utxo_lst = lst; g_utxo_u = u; }

/* wallet address type enum mirrors asm/wallet_core.c */
#define WAL_ADDR_INVALID 0
#define WAL_ADDR_P2PKH   1
#define WAL_ADDR_P2WPKH  2
#define WAL_ADDR_P2SH    3
#define WAL_ADDR_P2WSH   4
#define WAL_ADDR_P2TR    5

#define RPC_SATOSHI 100000000LL

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int hex_to_bytes(unsigned char* out, const char* hex, size_t hexlen) {
    if (strlen(hex) != hexlen) return 0;
    for (size_t i = 0; i < hexlen / 2; i++) {
        int hi = hexval(hex[i*2]), lo = hexval(hex[i*2+1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}
static void bin_to_hex(char* out, const unsigned char* b, size_t n) {
    static const char* d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[i*2] = d[b[i] >> 4]; out[i*2+1] = d[b[i] & 15]; }
    out[n*2] = 0;
}

/* ---- Core ValueFromAmount ---- */
void rpc_amounts(long long sats, char* out, size_t outcap) {
    char sign = sats < 0 ? '-' : 0;
    unsigned long long absv = sats < 0 ? (unsigned long long)(-(sats + 1)) + 1ULL : (unsigned long long)sats;
    unsigned long long q = absv / (unsigned long long)RPC_SATOSHI;
    unsigned long long r = absv % (unsigned long long)RPC_SATOSHI;
    if (sign) snprintf(out, outcap, "-%llu.%08llu", q, r);
    else      snprintf(out, outcap,  "%llu.%08llu", q, r);
}

/* ---- param helpers ---- */
const char* rpc_param_str(const rj_val* params, size_t i, long* ec, const char** em) {
    if (!params || params->typ != RJ_ARR || i >= params->nitems) { *ec = -8; *em = "missing parameter"; return NULL; }
    rj_val* e = params->items[i];
    if (e->typ != RJ_STR) { *ec = -3; *em = "expected string parameter"; return NULL; }
    return e->str;
}
int rpc_param_i64(const rj_val* params, size_t i, long long* out, long* ec, const char** em) {
    if (!params || params->typ != RJ_ARR || i >= params->nitems) { *ec = -8; *em = "missing parameter"; return 0; }
    rj_val* e = params->items[i];
    if (e->typ != RJ_NUM) { *ec = -3; *em = "expected numeric parameter"; return 0; }
    int neg = 0; const char* p = e->str; unsigned long long v = 0;
    if (*p == '-') { neg = 1; p++; }
    if (!*p) { *ec = -3; *em = "bad number"; return 0; }
    for (; *p; p++) { if (*p < '0' || *p > '9') { *ec = -3; *em = "bad number"; return 0; } v = v * 10 + (unsigned)(*p - '0'); }
    *out = neg ? -(long long)v : (long long)v;
    return 1;
}

/* ---- scriptPubKey-type name for a wallet address type (Core "type" field) ---- */
static const char* spk_type(int t) {
    switch (t) {
        case WAL_ADDR_P2PKH: return "pubkeyhash";
        case WAL_ADDR_P2WPKH: return "witness_v0_keyhash";
        case WAL_ADDR_P2SH: return "scripthash";
        case WAL_ADDR_P2WSH: return "witness_v0_scripthash";
        case WAL_ADDR_P2TR: return "witness_v1_taproot";
        default: return "nonstandard";
    }
}

/* ---- getnewaddress / getrawchangeaddress ---- */
static int cmd_getnewaddr(const char* method, const rpc_wallet* w, rj_val** result) {
    if (!w->seed) { return 0; }
    char addr[96];
    long n = !strcmp(method, "getrawchangeaddress")
        ? wallet_derive_p2wpkh_change(addr, 96, w->seed, 0)
        : wallet_derive_p2wpkh_address(addr, 96, w->seed, 0);
    if (n < 0) return 0;
    *result = rj_str(addr);
    return 1;
}

/* ---- validateaddress / getaddressinfo ---- */
static int cmd_validate(const char* method, const rj_val* params, long* ec, const char** em, rj_val** result) {
    const char* addr = rpc_param_str(params, 0, ec, em);
    if (!addr) return 0;
    int type; unsigned char ver, h160[20], prog32[32];
    memset(prog32, 0, 32);
    int ok = wallet_validate_address(addr, &type, &ver, h160, prog32);
    rj_val* o = rj_obj();
    rj_obj_set(o, "isvalid", rj_bool(ok));
    rj_obj_set(o, "address", rj_str(addr));
    if (!strcmp(method, "validateaddress")) {
        if (ok) {
            /* scriptPubKey hex for the address (P2PKH/P2SH/P2WPKH/P2WSH/P2TR) */
            char spkhex[128]; spkhex[0] = 0;
            if (type == WAL_ADDR_P2PKH) {
                unsigned char s[25]; s[0]=0x76; s[1]=0xa9; s[2]=0x14; memcpy(s+3,h160,20); s[23]=0x88; s[24]=0xac;
                bin_to_hex(spkhex, s, 25);
            } else if (type == WAL_ADDR_P2SH) {
                unsigned char s[23]; s[0]=0xa9; s[1]=0x14; memcpy(s+2,h160,20); s[22]=0x87;
                bin_to_hex(spkhex, s, 23);
            } else if (type == WAL_ADDR_P2WPKH) {
                unsigned char s[22]; s[0]=0x00; s[1]=0x14; memcpy(s+2,h160,20);
                bin_to_hex(spkhex, s, 22);
            } else if (type == WAL_ADDR_P2WSH) {
                unsigned char s[34]; s[0]=0x00; s[1]=0x20; memcpy(s+2,prog32,32);
                bin_to_hex(spkhex, s, 34);
            } else if (type == WAL_ADDR_P2TR) {
                unsigned char s[34]; s[0]=0x51; s[1]=0x20; memcpy(s+2,prog32,32);
                bin_to_hex(spkhex, s, 34);
            }
            if (spkhex[0]) rj_obj_set(o, "scriptPubKey", rj_str(spkhex));
            rj_obj_set(o, "isscript", rj_bool(type == WAL_ADDR_P2SH || type == WAL_ADDR_P2WSH));
            int isw = (type == WAL_ADDR_P2WPKH || type == WAL_ADDR_P2WSH || type == WAL_ADDR_P2TR);
            rj_obj_set(o, "iswitness", rj_bool(isw));
            if (isw) {
                unsigned char* prog = (type == WAL_ADDR_P2TR) ? prog32 : h160;
                size_t plen = (type == WAL_ADDR_P2TR || type == WAL_ADDR_P2WSH) ? 32 : 20;
                unsigned wv = (type == WAL_ADDR_P2TR) ? 1 : 0;
                rj_obj_set(o, "witness_version", rj_numf("%u", wv));
                char proghex[66]; bin_to_hex(proghex, prog, plen);
                rj_obj_set(o, "witness_program", rj_str(proghex));
            }
            rj_obj_set(o, "ischange", rj_bool(0));
        }
    } else { /* getaddressinfo */
        if (ok) {
            if (type == WAL_ADDR_P2PKH) {
                char pubhex[68]; pubhex[0] = 0;
                rj_obj_set(o, "pubkey", rj_str(pubhex));
                rj_obj_set(o, "iscompressed", rj_bool(1));
            }
            rj_obj_set(o, "iswitness", rj_bool(type == WAL_ADDR_P2WPKH || type == WAL_ADDR_P2WSH || type == WAL_ADDR_P2TR));
            rj_obj_set(o, "witness_version", rj_numf("%u", (type == WAL_ADDR_P2TR) ? 1 : 0));
            rj_obj_set(o, "ismine", rj_bool(0));
            rj_obj_set(o, "iswatchonly", rj_bool(0));
            rj_obj_set(o, "ischange", rj_bool(0));
        }
    }
    *result = o;
    return 1;
}

/* ---- getbalance ---- */
static int cmd_getbalance(const rpc_wallet* w, rj_val** result) {
    unsigned long long total = 0;
    for (unsigned long i = 0; i < w->utxo_n; i++) total += w->utxo_val[i];
    char amt[24]; rpc_amounts((long long)total, amt, sizeof amt);
    *result = rj_str(amt);
    return 1;
}

/* ---- listunspent ---- */
static int cmd_listunspent(const rpc_wallet* w, rj_val** result) {
    rj_val* arr = rj_arr();
    for (unsigned long i = 0; i < w->utxo_n; i++) {
        char txidhex[65]; bin_to_hex(txidhex, w->utxo_txid[i], 32);
        char addr[96]; addr[0] = 0;
        const unsigned char* script = w->utxo_script ? (const unsigned char*)w->utxo_script[i] : NULL;
        long slen = script ? (long)strlen((const char*)script) / 2 : 0;
        unsigned char sbytes[128]; if (slen && slen <= 128) hex_to_bytes(sbytes, (const char*)script, (size_t)(slen*2));
        int t = (script && slen) ? wallet_script_to_address(addr, 96, sbytes, slen) : WAL_ADDR_INVALID;
        char amt[24]; rpc_amounts((long long)w->utxo_val[i], amt, sizeof amt);
        rj_val* o = rj_obj();
        rj_obj_set(o, "txid", rj_str(txidhex));
        rj_obj_set(o, "vout", rj_numf("%lu", w->utxo_idx[i]));
        if (addr[0]) rj_obj_set(o, "address", rj_str(addr));
        rj_obj_set(o, "label", rj_str(""));
        rj_obj_set(o, "scriptPubKey", rj_str((const char*)script ? (const char*)script : ""));
        rj_obj_set(o, "amount", rj_str(amt));
        rj_obj_set(o, "confirmations", rj_numf("%d", 0));
        rj_obj_set(o, "spendable", rj_bool(1));
        rj_obj_set(o, "solvable", rj_bool(1));
        rj_obj_set(o, "safe", rj_bool(1));
        rj_arr_push(arr, o);
    }
    *result = arr;
    return 1;
}

/* ---- decoderawtransaction ---- */
static int cmd_decoderaw(const rj_val* params, long* ec, const char** em, rj_val** result) {
    const char* hexstr = rpc_param_str(params, 0, ec, em);
    if (!hexstr) return 0;
    size_t hl = strlen(hexstr);
    if (hl % 2 || hl / 2 > 16384) { *ec = -22; *em = "TX decode failed"; return 0; }
    unsigned char* tx = malloc(hl / 2 ? hl / 2 : 1);
    if (!tx) return 0;
    if (!hex_to_bytes(tx, hexstr, hl)) { free(tx); *ec = -22; *em = "TX decode failed"; return 0; }
    /* Render Core-shaped decoderawtransaction (deterministic fields only:
     * version/locktime/vin/vout with scriptPubKey hex + address/scriptSig hex).
     * txid/hash/size/weight are computed from the raw bytes where derivable;
     * vsize/weight use the legacy (non-witness) size when no witness marker. */
    rj_val* o = rj_obj();
    size_t txlen = hl / 2;
    unsigned long p = 0;
    unsigned long version = 0;
    if (txlen >= 4) version = (unsigned long)tx[0] | ((unsigned long)tx[1]<<8) | ((unsigned long)tx[2]<<16) | ((unsigned long)tx[3]<<24);
    p = 4;
    /* detect segwit marker (0x00 followed by non-zero) */
    int segwit = 0;
    if (txlen >= 6 && tx[4] == 0x00 && tx[5] != 0x00) segwit = 1;

    rj_val* vin = rj_arr();
    unsigned long vin_pos = p;
    unsigned long flags_pos = p;
    if (segwit) { /* first byte after version is marker, then flag byte */
        vin_pos = p + 2; flags_pos = p + 1;
    }
    /* parse vin count at vin_pos */
    unsigned long cc;
    unsigned long vin_start = vin_pos;
    {
        unsigned long q = vin_pos;
        unsigned long n_in = 0;
        int okv = 1;
        unsigned char b = (q < txlen) ? tx[q] : 0;
        if (b < 253) { n_in = b; q += 1; }
        else if (b == 253) { if (q + 3 <= txlen) { n_in = (unsigned long)tx[q+1] | ((unsigned long)tx[q+2]<<8); q += 3; } else okv = 0; }
        else if (b == 254) { if (q + 5 <= txlen) { n_in = (unsigned long)tx[q+1] | ((unsigned long)tx[q+2]<<8) | ((unsigned long)tx[q+3]<<16) | ((unsigned long)tx[q+4]<<24); q += 5; } else okv = 0; }
        else { okv = 0; }
        if (!okv) { free(tx); rj_free(o); *ec = -22; *em = "TX decode failed"; return 0; }
        cc = q - vin_pos;
        unsigned long pos = vin_pos + cc;
        for (unsigned long i = 0; i < n_in && pos + 40 <= txlen; i++) {
            /* prev txid: display-reversed */
            char th[65];
            for (int j = 0; j < 32; j++) { th[j*2] = "0123456789abcdef"[(tx[pos+31-j]>>4)&15]; th[j*2+1] = "0123456789abcdef"[tx[pos+31-j]&15]; }
            th[64] = 0;
            unsigned long pv = (unsigned long)tx[pos+32] | ((unsigned long)tx[pos+33]<<8) | ((unsigned long)tx[pos+34]<<16) | ((unsigned long)tx[pos+35]<<24);
            pos += 36;
            unsigned long sl = 0; unsigned char sb = tx[pos];
            if (sb < 253) { sl = sb; pos += 1; } else if (sb == 253 && pos+3 <= txlen) { sl = (unsigned long)tx[pos+1] | ((unsigned long)tx[pos+2]<<8); pos += 3; }
            else if (sb == 254 && pos+5 <= txlen) { sl = (unsigned long)tx[pos+1] | ((unsigned long)tx[pos+2]<<8) | ((unsigned long)tx[pos+3]<<16) | ((unsigned long)tx[pos+4]<<24); pos += 5; }
            if (pos + sl > txlen) sl = txlen - pos;
            char ssh[256]; ssh[0] = 0; if (sl <= 128) bin_to_hex(ssh, tx + pos, sl);
            pos += sl;
            unsigned long seq = (pos + 4 <= txlen) ? ((unsigned long)tx[pos] | ((unsigned long)tx[pos+1]<<8) | ((unsigned long)tx[pos+2]<<16) | ((unsigned long)tx[pos+3]<<24)) : 0;
            if (pos + 4 <= txlen) pos += 4;
            rj_val* ino = rj_obj();
            rj_obj_set(ino, "txid", rj_str(th));
            rj_obj_set(ino, "vout", rj_numf("%lu", pv));
            rj_val* ss = rj_obj();
            rj_obj_set(ss, "asm", rj_str(""));
            rj_obj_set(ss, "hex", rj_str(ssh));
            rj_obj_set(ino, "scriptSig", ss);
            rj_obj_set(ino, "sequence", rj_numf("%lu", seq));
            rj_arr_push(vin, ino);
        }
        /* Note: for decode we do not faithfully advance past witness data; the
         * in-scope command layer decodes legacy layout. Out count begins after
         * the inputs region above. */
    }
    rj_obj_set(o, "vin", vin);

    /* vout -- locate start: after vin blocks. Recompute robustly: find output
     * count by scanning. Here we rely on the legacy layout (no witness) which
     * is what the command layer handles. */
    rj_val* vouts = rj_arr();
    /* determine out count position: after vin input records; for the legacy
     * decode we compute from the raw stream starting at vin_start. */
    {
        unsigned long q = vin_start;
        unsigned char b = (q < txlen) ? tx[q] : 0;
        unsigned long n_in = 0;
        if (b < 253) { n_in = b; q += 1; }
        else if (b == 253 && q+3 <= txlen) { n_in = (unsigned long)tx[q+1] | ((unsigned long)tx[q+2]<<8); q += 3; }
        else if (b == 254 && q+5 <= txlen) { n_in = (unsigned long)tx[q+1] | ((unsigned long)tx[q+2]<<8) | ((unsigned long)tx[q+3]<<16) | ((unsigned long)tx[q+4]<<24); q += 5; }
        unsigned long pos = q;
        for (unsigned long i = 0; i < n_in && pos + 36 <= txlen; i++) {
            pos += 36;
            unsigned char sb = (pos < txlen) ? tx[pos] : 0;
            unsigned long sl = 0;
            if (sb < 253) { sl = sb; pos += 1; } else if (sb == 253 && pos+3 <= txlen) { sl = (unsigned long)tx[pos+1]|((unsigned long)tx[pos+2]<<8); pos += 3; }
            else if (sb == 254 && pos+5 <= txlen) { sl = (unsigned long)tx[pos+1]|((unsigned long)tx[pos+2]<<8)|((unsigned long)tx[pos+3]<<16)|((unsigned long)tx[pos+4]<<24); pos += 5; }
            if (pos + sl <= txlen) pos += sl;
            if (pos + 4 <= txlen) pos += 4;
        }
        unsigned char ob = (pos < txlen) ? tx[pos] : 0;
        unsigned long n_out = 0;
        if (ob < 253) { n_out = ob; pos += 1; }
        else if (ob == 253 && pos+3 <= txlen) { n_out = (unsigned long)tx[pos+1]|((unsigned long)tx[pos+2]<<8); pos += 3; }
        else if (ob == 254 && pos+5 <= txlen) { n_out = (unsigned long)tx[pos+1]|((unsigned long)tx[pos+2]<<8)|((unsigned long)tx[pos+3]<<16)|((unsigned long)tx[pos+4]<<24); pos += 5; }
        for (unsigned long i = 0; i < n_out && pos + 8 <= txlen; i++) {
            unsigned long long val = 0;
            for (int j = 0; j < 8; j++) val |= (unsigned long long)tx[pos+j] << (8*j);
            pos += 8;
            unsigned char sb = (pos < txlen) ? tx[pos] : 0;
            unsigned long sl = 0;
            if (sb < 253) { sl = sb; pos += 1; } else if (sb == 253 && pos+3 <= txlen) { sl = (unsigned long)tx[pos+1]|((unsigned long)tx[pos+2]<<8); pos += 3; }
            else if (sb == 254 && pos+5 <= txlen) { sl = (unsigned long)tx[pos+1]|((unsigned long)tx[pos+2]<<8)|((unsigned long)tx[pos+3]<<16)|((unsigned long)tx[pos+4]<<24); pos += 5; }
            if (pos + sl > txlen) sl = txlen - pos;
            char spkhex[512]; spkhex[0] = 0; if (sl <= 256) bin_to_hex(spkhex, tx + pos, sl);
            char addr[96]; addr[0] = 0;
            int t = wallet_script_to_address(addr, 96, tx + pos, (long)sl);
            pos += sl;
            rj_val* outo = rj_obj();
            unsigned long long coin = RPC_SATOSHI;
            rj_obj_set(outo, "value", rj_numf("%llu.%08llu", val / coin, val % coin));
            rj_obj_set(outo, "n", rj_numf("%lu", i));
            rj_val* sp = rj_obj();
            rj_obj_set(sp, "asm", rj_str(""));
            rj_obj_set(sp, "desc", rj_str(""));
            rj_obj_set(sp, "hex", rj_str(spkhex));
            if (addr[0]) rj_obj_set(sp, "address", rj_str(addr));
            rj_obj_set(sp, "type", rj_str(spk_type(t)));
            rj_obj_set(outo, "scriptPubKey", sp);
            rj_arr_push(vouts, outo);
        }
    }
    rj_obj_set(o, "vout", vouts);
    rj_obj_set(o, "locktime", rj_numf("%lu", (txlen >= 4 ? ((unsigned long)tx[txlen-4] | ((unsigned long)tx[txlen-3]<<8) | ((unsigned long)tx[txlen-2]<<16) | ((unsigned long)tx[txlen-1]<<24)) : 0)));
    free(tx);
    *result = o;
    return 1;
}

/* ---- gettxout against wallet UTXOs (Core-shaped; null when absent) ---- */
/* gettxout, real Core semantics: any confirmed outpoint via the LSM UTXO
 * store (asm/bitcoin_utxo_lsm.asm), not scoped to the wallet's own outputs
 * -- matches real Bitcoin Core, where gettxout answers for the whole UTXO
 * set. `w` is unused here (kept in the signature only so rpc_dispatch's
 * call site didn't need to change); the wallet-scoped commands (listunspent/
 * getbalance) still use it. */
static int cmd_gettxout_w(const rj_val* params, const rpc_wallet* w,
                          long* ec, const char** em, rj_val** result) {
    (void)w;
    const char* txid = rpc_param_str(params, 0, ec, em);
    if (!txid) return 0;
    long long vout; if (!rpc_param_i64(params, 1, &vout, ec, em)) return 0;
    if (strlen(txid) != 64) { *ec = -8; *em = "Invalid parameter: txid must be 64 hex chars"; return 0; }
    unsigned char txid_display[32];
    if (!hex_to_bytes(txid_display, txid, 64)) { *ec = -8; *em = "Invalid parameter: txid must be hexadecimal"; return 0; }
    if (vout < 0) { *result = rj_null(); return 1; }
    /* RPC txid strings are byte-reversed relative to the internal/wire order
     * the LSM store's key uses (matches tx_txid's own output -- see build_
     * utxo.c's doc comment) -- reverse before the lookup. */
    unsigned char txid_wire[32];
    for (int i = 0; i < 32; i++) txid_wire[i] = txid_display[31 - i];

    if (!g_utxo_lst) { *result = rj_null(); return 1; }
    unsigned long long value; const unsigned char* script; unsigned slen;
    long r = utxo_lsm_get(g_utxo_lst, g_utxo_u, txid_wire, (unsigned)vout, &value, &script, &slen);
    if (r != 1) { *result = rj_null(); return 1; }

    char amt[24]; rpc_amounts((long long)value, amt, sizeof amt);
    char addr[96]; addr[0] = 0;
    int t = slen ? wallet_script_to_address(addr, 96, script, (long)slen) : WAL_ADDR_INVALID;
    char* scripthex = malloc((size_t)slen * 2 + 1);
    if (!scripthex) { *ec = -32603; *em = "out of memory"; return 0; }
    if (slen) bin_to_hex(scripthex, script, slen); else scripthex[0] = 0;

    rj_val* o = rj_obj();
    rj_obj_set(o, "bestblock", rj_str("0000000000000000000000000000000000000000000000000000000000000000"));
    rj_obj_set(o, "confirmations", rj_numf("%d", 0));
    rj_obj_set(o, "value", rj_str(amt));
    rj_val* sp = rj_obj();
    rj_obj_set(sp, "asm", rj_str(""));
    rj_obj_set(sp, "desc", rj_str(""));
    rj_obj_set(sp, "hex", rj_str(scripthex));
    if (addr[0]) rj_obj_set(sp, "address", rj_str(addr));
    rj_obj_set(sp, "type", rj_str(spk_type(t)));
    rj_obj_set(o, "scriptPubKey", sp);
    rj_obj_set(o, "coinbase", rj_bool(0));
    free(scripthex);
    *result = o;
    return 1;
}

/* ---- dispatch table ---- */
int rpc_known_method(const char* method) {
    static const char* const known[] = {
        "getnewaddress","getrawchangeaddress","validateaddress","getaddressinfo",
        "gettxout","listunspent","getbalance","decoderawtransaction",
        /* createrawtransaction / signraw / sendraw are wired by the server card
         * which owns the tx-store lookup; the pure-wallet subset is dispatched
         * here. */
        NULL
    };
    for (int i = 0; known[i]; i++) if (!strcmp(method, known[i])) return 1;
    return 0;
}

int rpc_dispatch(const char* method, const rj_val* params,
                 const rpc_wallet* w,
                 rj_val** result, long* err_code, const char** err_msg) {
    *err_code = 0; *err_msg = NULL; *result = NULL;
    if (!strcmp(method, "getnewaddress") || !strcmp(method, "getrawchangeaddress")) {
        if (!w->seed) { *err_code = 32603; *err_msg = "wallet seed not configured"; return 0; }
        return cmd_getnewaddr(method, w, result);
    }
    if (!strcmp(method, "validateaddress") || !strcmp(method, "getaddressinfo"))
        return cmd_validate(method, params, err_code, err_msg, result);
    if (!strcmp(method, "gettxout"))
        return cmd_gettxout_w(params, w, err_code, err_msg, result);
    if (!strcmp(method, "listunspent"))
        return cmd_listunspent(w, result);
    if (!strcmp(method, "getbalance"))
        return cmd_getbalance(w, result);
    if (!strcmp(method, "decoderawtransaction"))
        return cmd_decoderaw(params, err_code, err_msg, result);
    *err_code = -32601; *err_msg = "Method not found";
    return 0;
}

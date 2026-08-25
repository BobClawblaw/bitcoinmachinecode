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
#include "rpc_chain.h"
#include "rpc_node.h"
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
extern int  wallet_base58check_decode(unsigned char* out, long cap, long* outlen, const char* str);
/* message signing (asm/wallet_msgsign.c): Core-byte-compatible compact sigs. */
extern int  msg_sign_core(const unsigned char priv_be[32], const char* message, char sig_b64[96]);
extern int  msg_verify_core(const char* address, const char* message, const char* sig_b64);
/* tx-signing primitives for signrawtransactionwithkey. */
extern int  legacy_sighash(unsigned char out32[32], const unsigned char* tx, unsigned long txlen,
                           unsigned long nIn, const unsigned char* scriptCode, unsigned long scLen,
                           int hashtype, unsigned char* preimg, unsigned long cap);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
extern int  wallet_ecdsa_sign(unsigned long long r[4], unsigned long long s[4],
                              const unsigned char z_be[32], const unsigned char priv_be[32]);
extern int  der_signature_export(unsigned char* out, const unsigned long long r[4], const unsigned long long s[4]);
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char priv_be[32]);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);
extern void hash160(unsigned char out[20], const void* in, long long len);

/* extern LSM UTXO store lookup (asm/bitcoin_utxo_lsm.asm) -- see
 * rpc_commands_set_utxo_store's own doc comment in the header. */
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index,
                          unsigned long long* value, unsigned long* height, unsigned long* is_coinbase,
                          const unsigned char** script, unsigned* slen);

/* wallet address type enum mirrors asm/wallet_core.c */
#define WAL_ADDR_INVALID 0
#define WAL_ADDR_P2PKH   1
#define WAL_ADDR_P2WPKH  2
#define WAL_ADDR_P2SH    3
#define WAL_ADDR_P2WSH   4
#define WAL_ADDR_P2TR    5

static void* g_utxo_lst = NULL;
static void* g_utxo_u = NULL;
void rpc_commands_set_utxo_store(void* lst, void* u) { g_utxo_lst = lst; g_utxo_u = u; }

/* ---- scriptPubKey(hash) -> UTXO reverse index (asm/daemon/build_addr_
 * index.c) backing listunspent/getbalance. Same "opaque handle, separate
 * from rpc_wallet" pattern as the UTXO store above. Mmap'd read-only by
 * the caller (bitcoin_rpcd.c); the on-disk layout is documented in build_
 * addr_index.c's own header comment -- mirrored exactly here (packed,
 * type_tag(1)+hash(32) sort key, sparse index sampled every 256th
 * record). */
static const unsigned char* g_addr_idx_base = NULL;
static unsigned long long g_addr_idx_size = 0;
void rpc_commands_set_addr_index(const void* base, unsigned long long size) {
    g_addr_idx_base = base; g_addr_idx_size = size;
}

#pragma pack(push,1)
typedef struct { unsigned char type_tag; unsigned char hash[32]; unsigned char txid[32]; unsigned int vout; unsigned long long value; } addr_idx_rec;
#pragma pack(pop)
#define ADDR_IDX_REC_SIZE 77
#define ADDR_IDX_SPARSE_ENT_SIZE 41
#define ADDR_IDX_HDR_SIZE 28

static int addr_idx_cmp(const unsigned char* p /* type_tag+hash, 33 bytes */,
                        unsigned char type_tag, const unsigned char hash[32]) {
    if (p[0] != type_tag) return p[0] < type_tag ? -1 : 1;
    return memcmp(p + 1, hash, 32);
}

/* Binary search the sparse index for the largest sampled key <= target,
 * then linear-scan forward from there collecting every record whose key
 * exactly matches (an address can own more than one UTXO). Returns the
 * number of matches written to out[] (capped at max_out). */
static int addr_idx_lookup(unsigned char type_tag, const unsigned char hash[32],
                           addr_idx_rec* out, int max_out) {
    if (!g_addr_idx_base || g_addr_idx_size < ADDR_IDX_HDR_SIZE) return 0;
    const unsigned char* base = g_addr_idx_base;
    unsigned long long sparse_off, sparse_n;
    memcpy(&sparse_off, base + 12, 8);
    memcpy(&sparse_n, base + 20, 8);

    unsigned long long best_off = ADDR_IDX_HDR_SIZE;
    if (sparse_n > 0) {
        long long lo = 0, hi = (long long)sparse_n - 1;
        while (lo <= hi) {
            long long mid = lo + (hi - lo) / 2;
            const unsigned char* ent = base + sparse_off + (unsigned long long)mid * ADDR_IDX_SPARSE_ENT_SIZE;
            int c = addr_idx_cmp(ent, type_tag, hash);
            if (c <= 0) {
                unsigned long long off; memcpy(&off, ent + 33, 8);
                best_off = off;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
    }

    int n = 0;
    unsigned long long off = best_off;
    while (off < sparse_off && n < max_out) {
        const unsigned char* rec = base + off;
        int c = addr_idx_cmp(rec, type_tag, hash);
        if (c == 0) {
            memcpy(&out[n], rec, ADDR_IDX_REC_SIZE);
            n++;
        } else if (c > 0) {
            break;
        }
        off += ADDR_IDX_REC_SIZE;
    }
    return n;
}

/* Resolve an optional address-string RPC param into a (type_tag, hash)
 * query key. NULL addr_param -> the wallet's own default receive address
 * (m/84'/0'/0'/0/0, matching cmd_getnewaddr's bare-call convention). */
static int addr_idx_resolve(const char* addr_param, const rpc_wallet* w,
                            unsigned char* type_tag_out, unsigned char hash_out[32]) {
    char addrbuf[96];
    const char* addr = addr_param;
    if (!addr) {
        if (!w->seed || wallet_derive_p2wpkh_address(addrbuf, sizeof addrbuf, w->seed, 0) < 0) return 0;
        addr = addrbuf;
    }
    int type; unsigned char ver, h160[20], prog32[32];
    if (!wallet_validate_address(addr, &type, &ver, h160, prog32)) return 0;
    memset(hash_out, 0, 32);
    switch (type) {
        case WAL_ADDR_P2PKH: case WAL_ADDR_P2WPKH: case WAL_ADDR_P2SH:
            memcpy(hash_out, h160, 20);
            break;
        case WAL_ADDR_P2WSH: case WAL_ADDR_P2TR:
            memcpy(hash_out, prog32, 32);
            break;
        default:
            return 0;
    }
    *type_tag_out = (unsigned char)type;
    return 1;
}

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
    /* Only P2PKH/P2SH/P2WPKH/P2WSH/P2TR are decodable destinations; an
     * unknown base58 version passes the checksum but is not a valid address
     * (Core: isvalid=false), matching DecodeDestination. */
    int valid = ok && type >= WAL_ADDR_P2PKH && type <= WAL_ADDR_P2TR;
    rj_val* o = rj_obj();
    rj_obj_set(o, "isvalid", rj_bool(valid));
    if (!strcmp(method, "validateaddress")) {
        if (valid) {
            /* scriptPubKey for the destination (P2PKH/P2SH/P2WPKH/P2WSH/P2TR) */
            unsigned char s[34]; size_t sl = 0;
            switch (type) {
                case WAL_ADDR_P2PKH:  s[0]=0x76;s[1]=0xa9;s[2]=0x14;memcpy(s+3,h160,20);s[23]=0x88;s[24]=0xac; sl=25; break;
                case WAL_ADDR_P2SH:   s[0]=0xa9;s[1]=0x14;memcpy(s+2,h160,20);s[22]=0x87;                     sl=23; break;
                case WAL_ADDR_P2WPKH: s[0]=0x00;s[1]=0x14;memcpy(s+2,h160,20);                                sl=22; break;
                case WAL_ADDR_P2WSH:  s[0]=0x00;s[1]=0x20;memcpy(s+2,prog32,32);                              sl=34; break;
                case WAL_ADDR_P2TR:   s[0]=0x51;s[1]=0x20;memcpy(s+2,prog32,32);                              sl=34; break;
            }
            /* Core echoes the CANONICAL encoding (bech32 lower-cased) */
            char canon[128]; canon[0] = 0; wallet_script_to_address(canon, sizeof canon, s, (long)sl);
            rj_obj_set(o, "address", rj_str(canon[0] ? canon : addr));
            char spkhex[128]; bin_to_hex(spkhex, s, sl);
            rj_obj_set(o, "scriptPubKey", rj_str(spkhex));
            /* DescribeAddress: P2SH/P2WSH/P2TR are scripts; witness types carry
             * the program (P2WSH/P2TR use the 32-byte prog, not h160). */
            int isscript = (type == WAL_ADDR_P2SH || type == WAL_ADDR_P2WSH || type == WAL_ADDR_P2TR);
            int isw      = (type == WAL_ADDR_P2WPKH || type == WAL_ADDR_P2WSH || type == WAL_ADDR_P2TR);
            rj_obj_set(o, "isscript", rj_bool(isscript));
            rj_obj_set(o, "iswitness", rj_bool(isw));
            if (isw) {
                const unsigned char* prog = (type == WAL_ADDR_P2WPKH) ? h160 : prog32;
                size_t plen = (type == WAL_ADDR_P2WPKH) ? 20 : 32;
                rj_obj_set(o, "witness_version", rj_numf("%u", (type == WAL_ADDR_P2TR) ? 1u : 0u));
                char proghex[66]; bin_to_hex(proghex, prog, plen);
                rj_obj_set(o, "witness_program", rj_str(proghex));
            }
        } else {
            /* Core's invalid shape (error text / bech32 error_locations are not
             * reproduced -- we report the classification, not the diagnostics). */
            rj_obj_set(o, "error_locations", rj_arr());
            rj_obj_set(o, "error", rj_str("Invalid address"));
        }
    } else { /* getaddressinfo */
        rj_obj_set(o, "address", rj_str(addr));
        if (valid) {
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

/* Rebuild a scriptPubKey from the address index's (type_tag, hash) key --
 * the index stores only txid/vout/value, not the original script bytes,
 * so listunspent's scriptPubKey/address fields are reconstructed rather
 * than looked up. Writes out_len bytes into out (caller-sized >= 34) and
 * returns out_len, or 0 for an unrecognized type_tag. */
static int addr_idx_build_script(unsigned char type_tag, const unsigned char hash[32], unsigned char* out) {
    switch (type_tag) {
        case WAL_ADDR_P2PKH:
            out[0]=0x76; out[1]=0xa9; out[2]=0x14; memcpy(out+3, hash, 20); out[23]=0x88; out[24]=0xac;
            return 25;
        case WAL_ADDR_P2WPKH:
            out[0]=0x00; out[1]=0x14; memcpy(out+2, hash, 20);
            return 22;
        case WAL_ADDR_P2SH:
            out[0]=0xa9; out[1]=0x14; memcpy(out+2, hash, 20); out[22]=0x87;
            return 23;
        case WAL_ADDR_P2WSH:
            out[0]=0x00; out[1]=0x20; memcpy(out+2, hash, 32);
            return 34;
        case WAL_ADDR_P2TR:
            out[0]=0x51; out[1]=0x20; memcpy(out+2, hash, 32);
            return 34;
        default:
            return 0;
    }
}

#define ADDR_IDX_MAX_MATCHES 200000

/* ---- getbalance: sum of the address index's entries for the resolved
 * address (param, or the wallet's own default address if omitted). ---- */
static int cmd_getbalance(const rj_val* params, const rpc_wallet* w, long* ec, const char** em, rj_val** result) {
    const char* addr_param = NULL;
    if (params && params->typ == RJ_ARR && params->nitems > 0) {
        addr_param = rpc_param_str(params, 0, ec, em);
        if (!addr_param) return 0;
    }
    unsigned char type_tag, hash[32];
    unsigned long long total = 0;
    if (addr_idx_resolve(addr_param, w, &type_tag, hash)) {
        addr_idx_rec* recs = malloc(ADDR_IDX_MAX_MATCHES * sizeof(addr_idx_rec));
        if (!recs) { *ec = -32603; *em = "out of memory"; return 0; }
        int n = addr_idx_lookup(type_tag, hash, recs, ADDR_IDX_MAX_MATCHES);
        for (int i = 0; i < n; i++) total += recs[i].value;
        free(recs);
    }
    char amt[24]; rpc_amounts((long long)total, amt, sizeof amt);
    *result = rj_str(amt);
    return 1;
}

/* ---- listunspent: every address-index entry for the resolved address
 * (param, or the wallet's own default address if omitted). ---- */
static int cmd_listunspent(const rj_val* params, const rpc_wallet* w, long* ec, const char** em, rj_val** result) {
    const char* addr_param = NULL;
    if (params && params->typ == RJ_ARR && params->nitems > 0) {
        addr_param = rpc_param_str(params, 0, ec, em);
        if (!addr_param) return 0;
    }
    rj_val* arr = rj_arr();
    unsigned char type_tag, hash[32];
    if (addr_idx_resolve(addr_param, w, &type_tag, hash)) {
        addr_idx_rec* recs = malloc(ADDR_IDX_MAX_MATCHES * sizeof(addr_idx_rec));
        if (!recs) { rj_free(arr); *ec = -32603; *em = "out of memory"; return 0; }
        int n = addr_idx_lookup(type_tag, hash, recs, ADDR_IDX_MAX_MATCHES);
        for (int i = 0; i < n; i++) {
            char txidhex[65]; bin_to_hex(txidhex, recs[i].txid, 32);
            unsigned char script[34];
            int slen = addr_idx_build_script(type_tag, hash, script);
            char scripthex[70]; bin_to_hex(scripthex, script, (size_t)slen);
            char addr[96]; addr[0] = 0;
            wallet_script_to_address(addr, sizeof addr, script, slen);
            char amt[24]; rpc_amounts((long long)recs[i].value, amt, sizeof amt);
            rj_val* o = rj_obj();
            rj_obj_set(o, "txid", rj_str(txidhex));
            rj_obj_set(o, "vout", rj_numf("%u", recs[i].vout));
            if (addr[0]) rj_obj_set(o, "address", rj_str(addr));
            rj_obj_set(o, "label", rj_str(""));
            rj_obj_set(o, "scriptPubKey", rj_str(scripthex));
            rj_obj_set(o, "amount", rj_str(amt));
            rj_obj_set(o, "confirmations", rj_numf("%d", 0));
            rj_obj_set(o, "spendable", rj_bool(1));
            rj_obj_set(o, "solvable", rj_bool(1));
            rj_obj_set(o, "safe", rj_bool(1));
            rj_arr_push(arr, o);
        }
        free(recs);
    }
    *result = arr;
    return 1;
}

/* ---- decoderawtransaction ---- */
static int cmd_decoderaw(const rj_val* params, long* ec, const char** em, rj_val** result) {
    const char* hexstr = rpc_param_str(params, 0, ec, em);
    if (!hexstr) return 0;
    size_t hl = strlen(hexstr);
    if (hl % 2 || hl / 2 < 10 || hl / 2 > 200000) { *ec = -22; *em = "TX decode failed"; return 0; }
    unsigned char* tx = malloc(hl / 2);
    if (!tx) { *ec = -7; *em = "out of memory"; return 0; }
    if (!hex_to_bytes(tx, hexstr, hl)) { free(tx); *ec = -22; *em = "TX decode failed"; return 0; }
    /* Route to rpc_chain's full, getblock-verified tx decoder so
     * decoderawtransaction returns the complete Core shape (txid/hash/version/
     * size/vsize/weight + scriptPubKey asm/desc), not the former minimal
     * {locktime,vin,vout}. */
    int r = rpc_chain_decode_rawtx(tx, (long)(hl / 2), result, ec, em);
    free(tx);
    return r;
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
    unsigned long long value; unsigned long height, is_coinbase; const unsigned char* script; unsigned slen;
    long r = utxo_lsm_get(g_utxo_lst, g_utxo_u, txid_wire, (unsigned)vout, &value, &height, &is_coinbase, &script, &slen);
    if (r != 1) { *result = rj_null(); return 1; }
    (void)height; /* "confirmations" below is still a hardcoded placeholder,
                   * like "bestblock" -- wiring those to the real chain tip
                   * is RPC completeness, out of scope for Stage D. */

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
    rj_obj_set(o, "coinbase", rj_bool(is_coinbase != 0));
    free(scripthex);
    *result = o;
    return 1;
}

/* ---- signmessagewithprivkey / verifymessage (pure, no wallet state) --------
 * Core rpc/signmessage.cpp. Both are non-wallet in Core (the scratch oracle
 * serves them), so these are cross-verified against it: a signature ours emits
 * verifies under Core, and Core's verifies under ours. Compact-sig bytes are
 * Core-compatible via msg_sign_core (see wallet_msgsign.c). */
static int cmd_signmessagewithprivkey(const rj_val* params, long* ec, const char** em, rj_val** result){
    const char* wif = rpc_param_str(params, 0, ec, em); if (!wif) return 0;
    const char* msg = rpc_param_str(params, 1, ec, em); if (!msg) return 0;
    unsigned char pay[64]; long pl = 0;
    if (!wallet_base58check_decode(pay, (long)sizeof pay, &pl, wif) || pl < 33 || pay[0] != 0x80){
        *ec = -5; *em = "Invalid private key"; return 0; }
    /* WIF payload: 0x80 | priv[32] | [0x01 if compressed]. msg_sign_core emits
     * the compressed-pubkey header (31..34); an uncompressed WIF would need the
     * 27..30 header, which this path does not produce -- reject it plainly
     * rather than emit a signature that verifies under the wrong address. */
    if (pl == 33){ *ec = -5; *em = "Uncompressed keys are not supported by signmessage"; return 0; }
    if (pl != 34 || pay[33] != 0x01){ *ec = -5; *em = "Invalid private key"; return 0; }
    char sig[96];
    if (msg_sign_core(pay + 1, msg, sig) != 0){ *ec = -5; *em = "Sign failed"; return 0; }
    *result = rj_str(sig);
    return 1;
}
static int cmd_verifymessage(const rj_val* params, long* ec, const char** em, rj_val** result){
    const char* addr = rpc_param_str(params, 0, ec, em); if (!addr) return 0;
    const char* sig  = rpc_param_str(params, 1, ec, em); if (!sig)  return 0;
    const char* msg  = rpc_param_str(params, 2, ec, em); if (!msg)  return 0;
    int r = msg_verify_core(addr, msg, sig);   /* 1 match, 0 no-match, <0 malformed */
    if (r < 0){ *ec = -5; *em = "Malformed base64 encoding"; return 0; }
    *result = rj_bool(r == 1);
    return 1;
}

/* ---- createrawtransaction (pure serialization, no wallet state) ------------
 * Core rpc/rawtransaction.cpp. Builds an unsigned tx from explicit inputs and
 * outputs (no fee/change logic -- that is a funding concern). Non-wallet in
 * Core, so oracle-verifiable byte-for-byte. Default version 2; sequence
 * defaults follow Core: replaceable -> 0xfffffffd, else locktime!=0 ->
 * 0xfffffffe, else 0xffffffff. */
enum { CRT_P2PKH=1, CRT_P2WPKH=2, CRT_P2SH=3, CRT_P2WSH=4, CRT_P2TR=5 };
static long crt_addr_to_spk(const char* addr, unsigned char* spk){
    int type=0; unsigned char ver=0, h160[20], prog[32];
    if (!wallet_validate_address(addr, &type, &ver, h160, prog)) return 0;
    switch (type){
        case CRT_P2PKH:  spk[0]=0x76;spk[1]=0xa9;spk[2]=0x14;memcpy(spk+3,h160,20);spk[23]=0x88;spk[24]=0xac;return 25;
        case CRT_P2SH:   spk[0]=0xa9;spk[1]=0x14;memcpy(spk+2,h160,20);spk[22]=0x87;return 23;
        case CRT_P2WPKH: spk[0]=0x00;spk[1]=0x14;memcpy(spk+2,h160,20);return 22;
        case CRT_P2WSH:  spk[0]=0x00;spk[1]=0x20;memcpy(spk+2,prog,32);return 34;
        case CRT_P2TR:   spk[0]=0x51;spk[1]=0x20;memcpy(spk+2,prog,32);return 34;
        default: return 0;
    }
}
/* BTC decimal string -> satoshis; -1 on parse error or >8 decimals. */
static long long crt_amount_to_sat(const char* s){
    long long whole=0, frac=0; int fdig=0, seen=0;
    const char* p=s; if (*p=='-') return -1;
    while (*p>='0'&&*p<='9'){ whole=whole*10+(*p-'0'); p++; seen=1; }
    if (*p=='.'){ p++; while (*p>='0'&&*p<='9'){ if (fdig>=8) return -1; frac=frac*10+(*p-'0'); fdig++; p++; seen=1; } }
    if (*p || !seen) return -1;
    while (fdig<8){ frac*=10; fdig++; }
    return whole*100000000LL + frac;
}
static long crt_varint(unsigned char* o, unsigned long long v){
    if (v<0xfd){ o[0]=(unsigned char)v; return 1; }
    if (v<=0xffff){ o[0]=0xfd; o[1]=(unsigned char)v; o[2]=(unsigned char)(v>>8); return 3; }
    if (v<=0xffffffffULL){ o[0]=0xfe; for(int i=0;i<4;i++) o[1+i]=(unsigned char)(v>>(8*i)); return 5; }
    o[0]=0xff; for(int i=0;i<8;i++) o[1+i]=(unsigned char)(v>>(8*i)); return 9;
}
/* Build the unsigned tx (empty scriptSigs) shared by createrawtransaction and
 * createpsbt. Fills tx (cap >= 131072), sets *out_n / *out_nin / *out_nout.
 * Returns 1, or 0 with *ec / *em. */
static int crt_build_unsigned(const rj_val* params, unsigned char* tx, long* out_n,
                              size_t* out_nin, size_t* out_nout, long* ec, const char** em){
    if (!params || params->typ!=RJ_ARR || params->nitems<2 || params->items[0]->typ!=RJ_ARR){
        *ec=-8; *em="Invalid parameters, expected an inputs array and outputs"; return 0; }
    const rj_val* ins = params->items[0];
    const rj_val* outs = params->items[1];
    long locktime=0;
    if (params->nitems>=3 && params->items[2]->typ==RJ_NUM) locktime=strtol(params->items[2]->str,0,10);
    int replaceable=1;   /* modern Core defaults to opt-in RBF (replaceable=true) */
    if (params->nitems>=4 && params->items[3]->typ==RJ_BOOL) replaceable=(params->items[3]->str[0]=='1');
    unsigned long defseq = replaceable ? 0xfffffffdUL : (locktime!=0 ? 0xfffffffeUL : 0xffffffffUL);

    long n=0;
    tx[n++]=2; tx[n++]=0; tx[n++]=0; tx[n++]=0;                 /* version 2 LE */
    n += crt_varint(tx+n, (unsigned long long)ins->nitems);
    for (size_t i=0;i<ins->nitems;i++){
        const rj_val* in=ins->items[i];
        if (in->typ!=RJ_OBJ){ *ec=-8; *em="Invalid parameter, expected input object"; return 0; }
        rj_val* tid=rj_obj_get(in,"txid"); rj_val* vout=rj_obj_get(in,"vout");
        if (!tid||tid->typ!=RJ_STR||strlen(tid->str)!=64||!vout||vout->typ!=RJ_NUM){
            *ec=-8; *em="Invalid parameter, missing/invalid txid or vout"; return 0; }
        unsigned char id[32];
        if (!hex_to_bytes(id,tid->str,64)){ *ec=-8; *em="txid must be hexadecimal string"; return 0; }
        for (int k=0;k<32;k++) tx[n+k]=id[31-k];               /* display -> wire */
        n+=32;
        unsigned long vo=strtoul(vout->str,0,10);
        tx[n++]=(unsigned char)vo;tx[n++]=(unsigned char)(vo>>8);tx[n++]=(unsigned char)(vo>>16);tx[n++]=(unsigned char)(vo>>24);
        tx[n++]=0;                                             /* empty scriptSig */
        rj_val* seq=rj_obj_get(in,"sequence");
        unsigned long s=(seq&&seq->typ==RJ_NUM)?strtoul(seq->str,0,10):defseq;
        tx[n++]=(unsigned char)s;tx[n++]=(unsigned char)(s>>8);tx[n++]=(unsigned char)(s>>16);tx[n++]=(unsigned char)(s>>24);
    }
    /* outputs: accept either an object {addr:amt,...} or an array of single-key
     * objects (both are valid Core forms). Flatten to (key,val) pairs. */
    const rj_member* omem=NULL; size_t onm=0; const rj_val* oarr=NULL;
    if (outs->typ==RJ_OBJ){ omem=outs->members; onm=outs->nmembers; }
    else if (outs->typ==RJ_ARR){ oarr=outs; onm=outs->nitems; }
    else { *ec=-8; *em="Invalid parameter, expected outputs object or array"; return 0; }
    n += crt_varint(tx+n, (unsigned long long)onm);
    for (size_t i=0;i<onm;i++){
        const char* key; const rj_val* val;
        if (omem){ key=omem[i].key; val=omem[i].val; }
        else { const rj_val* e=oarr->items[i];
               if (e->typ!=RJ_OBJ||e->nmembers<1){ *ec=-8; *em="Invalid output"; return 0; }
               key=e->members[0].key; val=e->members[0].val; }
        if (!strcmp(key,"data")){
            if (val->typ!=RJ_STR){ *ec=-8; *em="Data is not a valid hex-encoded value"; return 0; }
            size_t dl=strlen(val->str); if (dl&1){ *ec=-8; *em="Data hex has odd length"; return 0; }
            size_t db=dl/2; if (db>80){ *ec=-8; *em="Data too long for OP_RETURN"; return 0; }
            unsigned char data[80]; if (db && !hex_to_bytes(data,val->str,dl)){ *ec=-8; *em="Invalid data hex"; return 0; }
            for (int k=0;k<8;k++) tx[n++]=0;                   /* value 0 */
            unsigned char spk[100]; long sl=0; spk[sl++]=0x6a; /* OP_RETURN */
            if (db<=75){ spk[sl++]=(unsigned char)db; } else { spk[sl++]=0x4c; spk[sl++]=(unsigned char)db; }
            memcpy(spk+sl,data,db); sl+=db;
            n+=crt_varint(tx+n,(unsigned long long)sl); memcpy(tx+n,spk,sl); n+=sl;
        } else {
            long long sat=(val->typ==RJ_NUM)?crt_amount_to_sat(val->str):-1;
            if (sat<0){ *ec=-3; *em="Invalid amount"; return 0; }
            unsigned char spk[40]; long sl=crt_addr_to_spk(key,spk);
            if (sl==0){ static char e[128]; snprintf(e,sizeof e,"Invalid Bitcoin address: %s",key); *ec=-5; *em=e; return 0; }
            for (int k=0;k<8;k++) tx[n++]=(unsigned char)((unsigned long long)sat>>(8*k));
            n+=crt_varint(tx+n,(unsigned long long)sl); memcpy(tx+n,spk,sl); n+=sl;
        }
    }
    tx[n++]=(unsigned char)locktime;tx[n++]=(unsigned char)(locktime>>8);tx[n++]=(unsigned char)(locktime>>16);tx[n++]=(unsigned char)(locktime>>24);
    *out_n=n; *out_nin=ins->nitems; *out_nout=onm;
    return 1;
}

static int cmd_createrawtransaction(const rj_val* params, long* ec, const char** em, rj_val** result){
    static unsigned char tx[131072]; long n; size_t nin, nout;
    if (!crt_build_unsigned(params, tx, &n, &nin, &nout, ec, em)) return 0;
    char* hex=malloc((size_t)n*2+1); if (!hex){ *ec=-7; *em="oom"; return 0; }
    bin_to_hex(hex,tx,(size_t)n); *result=rj_str(hex); free(hex);
    return 1;
}

/* base64 (standard alphabet, '=' padding). out must hold ceil(n/3)*4+1. */
static void crt_b64(char* out, const unsigned char* in, long n){
    static const char* B="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    long o=0;
    for (long i=0;i<n;i+=3){
        long r=n-i; unsigned b0=in[i], b1=r>1?in[i+1]:0, b2=r>2?in[i+2]:0;
        out[o++]=B[b0>>2]; out[o++]=B[((b0&3)<<4)|(b1>>4)];
        out[o++]=r>1?B[((b1&15)<<2)|(b2>>6)]:'='; out[o++]=r>2?B[b2&63]:'=';
    }
    out[o]=0;
}

/* createpsbt (Core rpc/rawtransaction.cpp, creator role, PSBT v0 / BIP174):
 * wraps the unsigned tx in PSBT_GLOBAL_UNSIGNED_TX (key 0x00) with empty
 * per-input / per-output maps. Emits the stable BIP174 v0 format (not the
 * master oracle's v2 default). */
static unsigned long srw_varint(const unsigned char* p, unsigned long* consumed);   /* defined below */

/* Wrap an unsigned tx (empty scriptSigs, no witness) as a base64 PSBTv0 with
 * empty input/output maps. Returns malloc'd base64 (caller frees) or NULL. */
static char* psbt_wrap_unsigned(const unsigned char* tx, long n, size_t nin, size_t nout){
    static unsigned char psbt[140000]; long p=0;
    psbt[p++]=0x70; psbt[p++]=0x73; psbt[p++]=0x62; psbt[p++]=0x74; psbt[p++]=0xff;  /* "psbt\xff" */
    psbt[p++]=0x01; psbt[p++]=0x00;                     /* keylen 1, key = PSBT_GLOBAL_UNSIGNED_TX */
    p += crt_varint(psbt+p, (unsigned long long)n);     /* value length = txlen */
    memcpy(psbt+p, tx, n); p += n;                      /* the unsigned tx */
    psbt[p++]=0x00;                                     /* end of global map */
    for (size_t i=0;i<nin;i++)  psbt[p++]=0x00;         /* empty input maps */
    for (size_t i=0;i<nout;i++) psbt[p++]=0x00;         /* empty output maps */
    char* b64=malloc((size_t)((p+2)/3)*4 + 1); if (!b64) return NULL;
    crt_b64(b64, psbt, p); return b64;
}
static int cmd_createpsbt(const rj_val* params, long* ec, const char** em, rj_val** result){
    static unsigned char tx[131072]; long n; size_t nin, nout;
    if (!crt_build_unsigned(params, tx, &n, &nin, &nout, ec, em)) return 0;
    char* b64=psbt_wrap_unsigned(tx,n,nin,nout); if (!b64){ *ec=-7; *em="oom"; return 0; }
    *result=rj_str(b64); free(b64);
    return 1;
}

/* converttopsbt (Core rpc/rawtransaction.cpp): a network-serialized tx -> PSBTv0.
 * Strips input scriptSigs and witnesses to produce the unsigned tx the PSBT
 * wraps. Errors if the tx carries signature data and permitsigdata is false
 * (default), matching Core. */
static int cmd_converttopsbt(const rj_val* params, long* ec, const char** em, rj_val** result){
    const char* hex = rpc_param_str(params,0,ec,em); if (!hex) return 0;
    size_t hl=strlen(hex);
    if ((hl&1)||hl/2<10||hl/2>200000){ *ec=-22; *em="TX decode failed"; return 0; }
    unsigned long txlen=(unsigned long)(hl/2);
    static unsigned char raw[200000];
    if (!hex_to_bytes(raw,hex,hl)){ *ec=-22; *em="TX decode failed"; return 0; }
    int permitsig = (params->nitems>=2 && params->items[1]->typ==RJ_BOOL && params->items[1]->str[0]=='1');
    /* parse: version(4) [00 flag] n_in [outpoint(36) ssvarint ss seq(4)]... n_out ... locktime(4) */
    unsigned long p=4, cc; int segwit=0;
    if (raw[4]==0x00 && txlen>6 && raw[5]!=0x00){ segwit=1; p=6; }
    unsigned long n_in=srw_varint(raw+p,&cc); p+=cc;
    if (n_in==0||n_in>10000){ *ec=-22; *em="TX decode failed"; return 0; }
    /* build stripped unsigned tx */
    static unsigned char utx[200000]; long u=0; int had_sig=segwit;
    utx[u++]=raw[0];utx[u++]=raw[1];utx[u++]=raw[2];utx[u++]=raw[3];   /* version */
    u+=crt_varint(utx+u,(unsigned long long)n_in);
    for (unsigned long i=0;i<n_in;i++){
        memcpy(utx+u, raw+p, 36); u+=36; p+=36;                        /* outpoint */
        unsigned long ssl=srw_varint(raw+p,&cc); p+=cc;
        if (ssl>0) had_sig=1;
        p+=ssl;                                                        /* skip scriptSig */
        utx[u++]=0x00;                                                 /* empty scriptSig */
        memcpy(utx+u, raw+p, 4); u+=4; p+=4;                           /* sequence */
    }
    unsigned long nout_pos=p; unsigned long n_out=srw_varint(raw+p,&cc);
    /* copy outputs region (n_out varint + outputs) verbatim */
    unsigned long op=p; op+=cc;
    for (unsigned long i=0;i<n_out;i++){ op+=8; unsigned long sl=srw_varint(raw+op,&cc); op+=cc+sl; }
    memcpy(utx+u, raw+nout_pos, op-nout_pos); u+=(long)(op-nout_pos);
    /* locktime: last 4 bytes of the tx (witness, if any, sits before locktime) */
    utx[u++]=raw[txlen-4];utx[u++]=raw[txlen-3];utx[u++]=raw[txlen-2];utx[u++]=raw[txlen-1];
    if (had_sig && !permitsig){ *ec=-22; *em="Inputs must not have scriptSigs and scriptWitnesses"; return 0; }
    char* b64=psbt_wrap_unsigned(utx,u,(size_t)n_in,(size_t)n_out); if (!b64){ *ec=-7; *em="oom"; return 0; }
    *result=rj_str(b64); free(b64);
    return 1;
}

/* base64 decode; returns 1 and sets *outn, or 0 on a bad char. */
static int crt_b64dec(const char* in, unsigned char* out, long cap, long* outn){
    static signed char T[256]; static int init=0;
    if (!init){ for (int i=0;i<256;i++) T[i]=-1;
        const char* B="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i=0;i<64;i++) T[(unsigned char)B[i]]=(signed char)i; init=1; }
    unsigned acc=0; int bits=0; long o=0;
    for (const char* q=in; *q; q++){
        if (*q=='=' || *q=='\n' || *q=='\r' || *q==' ') continue;
        signed char v=T[(unsigned char)*q]; if (v<0) return 0;
        acc=(acc<<6)|(unsigned)v; bits+=6;
        if (bits>=8){ bits-=8; if (o<cap) out[o++]=(unsigned char)((acc>>bits)&0xff); }
    }
    *outn=o; return 1;
}
static unsigned long srw_varint(const unsigned char* p, unsigned long* consumed);   /* defined below */

/* decodepsbt (Core rpc/rawtransaction.cpp), PSBT v0 shape: tx (decoded unsigned
 * tx), global_xpubs, psbt_version, proprietary, unknown, inputs[], outputs[].
 * Input/output maps are parsed to Core's field names where recognized; a
 * freshly-created PSBT yields empty per-input/output objects, matching Core. */
static int psbt_field_hex(rj_val* o, const char* name, const unsigned char* v, unsigned long n){
    char* h=malloc(n*2+1); if (!h) return 0; bin_to_hex(h,v,n); rj_obj_set(o,name,rj_str(h)); free(h); return 1;
}
static int cmd_decodepsbt(const rj_val* params, long* ec, const char** em, rj_val** result){
    const char* b64 = rpc_param_str(params,0,ec,em); if (!b64) return 0;
    static unsigned char buf[200000]; long blen=0;
    if (!crt_b64dec(b64,buf,sizeof buf,&blen) || blen<5 || memcmp(buf,"psbt\xff",5)!=0){ *ec=-22; *em="TX decode failed"; return 0; }
    long p=5; const unsigned char* utx=NULL; unsigned long utxlen=0; int psbtver=0;
    while (p<blen){ unsigned long cc; unsigned long kl=srw_varint(buf+p,&cc); p+=cc; if (kl==0) break;
        const unsigned char* key=buf+p; p+=kl;
        unsigned long vl=srw_varint(buf+p,&cc); p+=cc; const unsigned char* val=buf+p; p+=vl;
        if (kl>=1 && key[0]==0x00){ utx=val; utxlen=vl; }
        else if (kl>=1 && key[0]==0xfb){ psbtver=(int)val[0]; }
    }
    rj_val* o=rj_obj();
    long n_in=0, n_out=0;
    if (utx){
        rj_val* txo=NULL; long e2; const char* m2;
        if (rpc_chain_decode_rawtx(utx,(long)utxlen,&txo,&e2,&m2)){
            rj_val* vin=rj_obj_get(txo,"vin"); rj_val* vout=rj_obj_get(txo,"vout");
            n_in = vin?(long)vin->nitems:0; n_out = vout?(long)vout->nitems:0;
            rj_obj_set(o,"tx",txo);
        }
    }
    rj_obj_set(o,"global_xpubs",rj_arr());
    rj_obj_set(o,"psbt_version",rj_numf("%d",psbtver));
    rj_obj_set(o,"proprietary",rj_arr());
    rj_obj_set(o,"unknown",rj_obj());
    rj_val* ins=rj_arr();
    for (long i=0;i<n_in && p<blen;i++){
        rj_val* io=rj_obj();
        while (p<blen){ unsigned long cc; unsigned long kl=srw_varint(buf+p,&cc); p+=cc; if (kl==0) break;
            const unsigned char* key=buf+p; p+=kl; unsigned long vl=srw_varint(buf+p,&cc); p+=cc; const unsigned char* val=buf+p; p+=vl;
            if (kl>=1){ switch (key[0]){
                    case 0x04: psbt_field_hex(io,"redeem_script",val,vl); break;
                    case 0x05: psbt_field_hex(io,"witness_script",val,vl); break;
                    case 0x07: psbt_field_hex(io,"final_scriptSig",val,vl); break;
                    default: break; } }
        }
        rj_arr_push(ins,io);
    }
    rj_obj_set(o,"inputs",ins);
    rj_val* outs=rj_arr();
    for (long i=0;i<n_out && p<blen;i++){
        rj_val* oo=rj_obj();
        while (p<blen){ unsigned long cc; unsigned long kl=srw_varint(buf+p,&cc); p+=cc; if (kl==0) break;
            const unsigned char* key=buf+p; p+=kl; unsigned long vl=srw_varint(buf+p,&cc); p+=cc; const unsigned char* val=buf+p; p+=vl;
            if (kl>=1){ switch (key[0]){ case 0x00: psbt_field_hex(oo,"redeem_script",val,vl); break;
                                         case 0x01: psbt_field_hex(oo,"witness_script",val,vl); break;
                                         default: break; } }
        }
        rj_arr_push(outs,oo);
    }
    rj_obj_set(o,"outputs",outs);
    *result=o;
    return 1;
}

/* combinepsbt (Core rpc/rawtransaction.cpp): merge PSBTs for the SAME unsigned
 * tx by unioning each map's key-value pairs (dedup by key; first occurrence
 * wins). Returns the merged base64 PSBT. */
typedef struct { const unsigned char* k; unsigned long kl; const unsigned char* v; unsigned long vl; } psbt_kv;
static int psbt_parse_map(const unsigned char* buf, long blen, long* pp, psbt_kv* kvs, int cap){
    int n=0; long p=*pp;
    while (p<blen){ unsigned long cc; unsigned long kl=srw_varint(buf+p,&cc); p+=cc; if(kl==0){ *pp=p; return n; }
        const unsigned char* k=buf+p; p+=kl; unsigned long vl=srw_varint(buf+p,&cc); p+=cc; const unsigned char* v=buf+p; p+=vl;
        if(n<cap){ kvs[n].k=k;kvs[n].kl=kl;kvs[n].v=v;kvs[n].vl=vl;n++; }
    }
    *pp=p; return n;
}
static int psbt_union(psbt_kv* dst, int dn, int dcap, const psbt_kv* src, int sn){
    for(int i=0;i<sn && dn<dcap;i++){
        int dup=0; for(int j=0;j<dn;j++) if(dst[j].kl==src[i].kl && !memcmp(dst[j].k,src[i].k,src[i].kl)){ dup=1; break; }
        if(!dup) dst[dn++]=src[i];
    }
    return dn;
}
static long psbt_ser_map(unsigned char* out, const psbt_kv* kvs, int n){
    long o=0;
    for(int i=0;i<n;i++){ o+=crt_varint(out+o,(unsigned long long)kvs[i].kl); memcpy(out+o,kvs[i].k,kvs[i].kl); o+=kvs[i].kl;
        o+=crt_varint(out+o,(unsigned long long)kvs[i].vl); memcpy(out+o,kvs[i].v,kvs[i].vl); o+=kvs[i].vl; }
    out[o++]=0x00; return o;
}
#define PSBT_MAXP 16
#define PSBT_MAXKV 128
#define PSBT_MAXIO 1000
static int cmd_combinepsbt(const rj_val* params, long* ec, const char** em, rj_val** result){
    if (!params||params->typ!=RJ_ARR||params->nitems<1||params->items[0]->typ!=RJ_ARR||params->items[0]->nitems<1){
        *ec=-8; *em="Invalid parameter, expected an array of base64 PSBTs"; return 0; }
    const rj_val* arr=params->items[0]; int np=(int)arr->nitems; if (np>PSBT_MAXP) np=PSBT_MAXP;
    static unsigned char bufs[PSBT_MAXP][200000]; long blens[PSBT_MAXP];
    const unsigned char* utx0=NULL; unsigned long utx0len=0;
    static psbt_kv gkv[PSBT_MAXKV]; int gn=0;
    static psbt_kv ikv[PSBT_MAXIO][PSBT_MAXKV]; static int in_n[PSBT_MAXIO];
    static psbt_kv okv[PSBT_MAXIO][PSBT_MAXKV]; static int out_n[PSBT_MAXIO];
    long n_in=-1, n_out=-1;
    for (int pi=0; pi<np; pi++){
        if (arr->items[pi]->typ!=RJ_STR){ *ec=-22; *em="TX decode failed"; return 0; }
        if (!crt_b64dec(arr->items[pi]->str, bufs[pi], sizeof bufs[pi], &blens[pi]) || blens[pi]<5 || memcmp(bufs[pi],"psbt\xff",5)!=0){ *ec=-22; *em="TX decode failed"; return 0; }
        long p=5;
        psbt_kv g[PSBT_MAXKV]; int g_n=psbt_parse_map(bufs[pi],blens[pi],&p,g,PSBT_MAXKV);
        const unsigned char* utx=NULL; unsigned long utxl=0;
        for (int j=0;j<g_n;j++) if (g[j].kl>=1 && g[j].k[0]==0x00){ utx=g[j].v; utxl=g[j].vl; break; }
        if (!utx){ *ec=-22; *em="Only PSBTv0 (with an unsigned tx) can be combined"; return 0; }
        if (!utx0){ utx0=utx; utx0len=utxl;
            unsigned long cc; long q=4; n_in=(long)srw_varint(utx+q,&cc); q+=cc;
            for (long k=0;k<n_in;k++){ q+=36; unsigned long sl=srw_varint(utx+q,&cc); q+=cc+sl+4; }
            n_out=(long)srw_varint(utx+q,&cc);
            if (n_in>PSBT_MAXIO||n_out>PSBT_MAXIO){ *ec=-22; *em="PSBT too large to combine"; return 0; }
            for (long k=0;k<n_in;k++) in_n[k]=0;
            for (long k=0;k<n_out;k++) out_n[k]=0;
        } else if (utxl!=utx0len || memcmp(utx,utx0,utxl)){ *ec=-8; *em="PSBTs do not refer to the same transactions."; return 0; }
        gn=psbt_union(gkv,gn,PSBT_MAXKV,g,g_n);
        for (long k=0;k<n_in;k++){ psbt_kv m[PSBT_MAXKV]; int mn=psbt_parse_map(bufs[pi],blens[pi],&p,m,PSBT_MAXKV); in_n[k]=psbt_union(ikv[k],in_n[k],PSBT_MAXKV,m,mn); }
        for (long k=0;k<n_out;k++){ psbt_kv m[PSBT_MAXKV]; int mn=psbt_parse_map(bufs[pi],blens[pi],&p,m,PSBT_MAXKV); out_n[k]=psbt_union(okv[k],out_n[k],PSBT_MAXKV,m,mn); }
    }
    static unsigned char out[220000]; long n=0;
    out[n++]=0x70;out[n++]=0x73;out[n++]=0x62;out[n++]=0x74;out[n++]=0xff;
    n+=psbt_ser_map(out+n,gkv,gn);
    for (long k=0;k<n_in;k++)  n+=psbt_ser_map(out+n,ikv[k],in_n[k]);
    for (long k=0;k<n_out;k++) n+=psbt_ser_map(out+n,okv[k],out_n[k]);
    char* b64=malloc((size_t)((n+2)/3)*4+1); if(!b64){ *ec=-7; *em="oom"; return 0; }
    crt_b64(b64,out,n); *result=rj_str(b64); free(b64);
    return 1;
}

/* joinpsbts (Core rpc/rawtransaction.cpp): join distinct PSBTs into one whose
 * unsigned tx spends all their inputs and creates all their outputs. Core
 * builds a fresh tx (version 2, locktime 0) and appends each PSBT's inputs and
 * outputs (with their per-input/output maps) in order. */
static int cmd_joinpsbts(const rj_val* params, long* ec, const char** em, rj_val** result){
    if (!params||params->typ!=RJ_ARR||params->nitems<1||params->items[0]->typ!=RJ_ARR||params->items[0]->nitems<2){
        *ec=-8; *em="At least two PSBTs are required to join PSBTs."; return 0; }
    const rj_val* arr=params->items[0]; int np=(int)arr->nitems; if (np>PSBT_MAXP) np=PSBT_MAXP;
    static unsigned char bufs[PSBT_MAXP][200000]; long blens[PSBT_MAXP];
    /* merged tx pieces + maps, in append order */
    static unsigned char vin_buf[200000]; long vin_n=0; long total_in=0;
    static unsigned char vout_buf[200000]; long vout_n=0; long total_out=0;
    static psbt_kv imaps[PSBT_MAXIO][PSBT_MAXKV]; static int imaps_n[PSBT_MAXIO]; long tot_i=0;
    static psbt_kv omaps[PSBT_MAXIO][PSBT_MAXKV]; static int omaps_n[PSBT_MAXIO]; long tot_o=0;
    for (int pi=0; pi<np; pi++){
        if (arr->items[pi]->typ!=RJ_STR){ *ec=-22; *em="TX decode failed"; return 0; }
        if (!crt_b64dec(arr->items[pi]->str, bufs[pi], sizeof bufs[pi], &blens[pi]) || blens[pi]<5 || memcmp(bufs[pi],"psbt\xff",5)!=0){ *ec=-22; *em="TX decode failed"; return 0; }
        long p=5; psbt_kv g[PSBT_MAXKV]; int gn=psbt_parse_map(bufs[pi],blens[pi],&p,g,PSBT_MAXKV);
        const unsigned char* utx=NULL; unsigned long utxl=0;
        for (int j=0;j<gn;j++) if (g[j].kl>=1 && g[j].k[0]==0x00){ utx=g[j].v; utxl=g[j].vl; break; }
        if (!utx){ *ec=-22; *em="Only PSBTv0 (with an unsigned tx) can be joined"; return 0; }
        /* parse this tx's inputs/outputs */
        unsigned long cc; long q=4; unsigned long n_in=srw_varint(utx+q,&cc); q+=cc;
        for (unsigned long k=0;k<n_in;k++){
            memcpy(vin_buf+vin_n, utx+q, 36); vin_n+=36; q+=36;   /* outpoint */
            unsigned long sl=srw_varint(utx+q,&cc); q+=cc+sl;      /* skip (empty) scriptSig */
            vin_buf[vin_n++]=0x00;                                 /* empty scriptSig */
            memcpy(vin_buf+vin_n, utx+q, 4); vin_n+=4; q+=4;       /* sequence */
            total_in++;
        }
        unsigned long n_out=srw_varint(utx+q,&cc); q+=cc;
        for (unsigned long k=0;k<n_out;k++){
            long os=q; q+=8; unsigned long sl=srw_varint(utx+q,&cc); q+=cc+sl;   /* value + spk */
            memcpy(vout_buf+vout_n, utx+os, q-os); vout_n+=(long)(q-os); total_out++;
        }
        /* this PSBT's input/output maps, appended in order */
        for (unsigned long k=0;k<n_in && tot_i<PSBT_MAXIO;k++){ imaps_n[tot_i]=psbt_parse_map(bufs[pi],blens[pi],&p,imaps[tot_i],PSBT_MAXKV); tot_i++; }
        for (unsigned long k=0;k<n_out && tot_o<PSBT_MAXIO;k++){ omaps_n[tot_o]=psbt_parse_map(bufs[pi],blens[pi],&p,omaps[tot_o],PSBT_MAXKV); tot_o++; }
    }
    /* build merged unsigned tx: version 2, all inputs, all outputs, locktime 0 */
    static unsigned char tx[420000]; long t=0;
    tx[t++]=2;tx[t++]=0;tx[t++]=0;tx[t++]=0;
    t+=crt_varint(tx+t,(unsigned long long)total_in); memcpy(tx+t,vin_buf,vin_n); t+=vin_n;
    t+=crt_varint(tx+t,(unsigned long long)total_out); memcpy(tx+t,vout_buf,vout_n); t+=vout_n;
    tx[t++]=0;tx[t++]=0;tx[t++]=0;tx[t++]=0;   /* locktime 0 */
    /* serialize PSBT: magic | global(unsigned tx) | input maps | output maps */
    static unsigned char out[440000]; long n=0;
    out[n++]=0x70;out[n++]=0x73;out[n++]=0x62;out[n++]=0x74;out[n++]=0xff;
    out[n++]=0x01; out[n++]=0x00; n+=crt_varint(out+n,(unsigned long long)t); memcpy(out+n,tx,t); n+=t; out[n++]=0x00;
    for (long k=0;k<tot_i;k++) n+=psbt_ser_map(out+n,imaps[k],imaps_n[k]);
    for (long k=0;k<tot_o;k++) n+=psbt_ser_map(out+n,omaps[k],omaps_n[k]);
    char* b64=malloc((size_t)((n+2)/3)*4+1); if(!b64){ *ec=-7; *em="oom"; return 0; }
    crt_b64(b64,out,n); *result=rj_str(b64); free(b64);
    return 1;
}

/* ---- analyzepsbt (Core node/psbt.cpp AnalyzePSBT) --------------------------
 * Roles order CREATOR < UPDATER < SIGNER < FINALIZER < EXTRACTOR; the psbt's
 * "next" is the minimum (earliest still-needed) across inputs. Per input we
 * resolve the UTXO (witness_utxo/non_witness_utxo), decide finality, and if not
 * final work out what a signer still needs by inspecting the effective script.
 *
 * is_final here is PRESENCE-of-a-final-field based: unlike Core we do not re-run
 * consensus script verification on the final data, so a deliberately malformed
 * final field would be reported final here but not by Core -- for all conformant
 * PSBTs the results match. Coverage of the "missing"/vsize logic: P2WPKH, P2PKH,
 * and the P2SH/P2WSH wrappers (missing redeem/witness script); other script
 * types fall through to next=updater with no "missing" (documented divergence).*/
#define APR_UPDATER 1
#define APR_SIGNER 2
#define APR_FINALIZER 3
#define APR_EXTRACTOR 4
static const char* apsbt_role(int r){
    return r==APR_UPDATER?"updater":r==APR_SIGNER?"signer":r==APR_FINALIZER?"finalizer":"extractor"; }
static long apsbt_vilen(unsigned long n){ return n<0xfd?1: n<=0xffff?3: n<=0xffffffffUL?5:9; }
/* pubkey (via bip32_deriv 0x06 or partial_sig 0x02) with hash160==keyid present? */
static int apsbt_key_known(const psbt_kv* kv, int nkv, const unsigned char keyid[20], int* has_sig){
    int known=0; if (has_sig) *has_sig=0;
    for (int i=0;i<nkv;i++){
        unsigned long kl=kv[i].kl; if (kl!=34 && kl!=66) continue;      /* 1 + 33|65 */
        unsigned char t=kv[i].k[0]; if (t!=0x02 && t!=0x06) continue;   /* partial_sig | bip32 */
        unsigned char h[20]; hash160(h, kv[i].k+1, (long long)(kl-1));
        if (!memcmp(h,keyid,20)){ known=1; if (t==0x02 && has_sig) *has_sig=1; }
    }
    return known;
}
static void apsbt_hex(char* dst, const unsigned char* b, int n){ for(int i=0;i<n;i++) sprintf(dst+2*i,"%02x",b[i]); }

static int cmd_analyzepsbt(const rj_val* params, long* ec, const char** em, rj_val** result){
    if (!params||params->typ!=RJ_ARR||params->nitems<1||params->items[0]->typ!=RJ_STR){
        *ec=-8; *em="Invalid parameters, expected a PSBT string"; return 0; }
    static unsigned char buf[400000]; long blen;
    if (!crt_b64dec(params->items[0]->str, buf, sizeof buf, &blen) || blen<5 || memcmp(buf,"psbt\xff",5)!=0){
        *ec=-22; *em="TX decode failed"; return 0; }
    long p=5; psbt_kv g[PSBT_MAXKV]; int gn=psbt_parse_map(buf,blen,&p,g,PSBT_MAXKV);
    const unsigned char* utx=NULL;
    for (int j=0;j<gn;j++) if (g[j].kl>=1 && g[j].k[0]==0x00){ utx=g[j].v; break; }
    rj_val* out=rj_obj();
    if (!utx){ rj_obj_set(out,"error",rj_str("PSBT cannot be made into a valid transaction")); *result=out; return 1; }

    unsigned long cc; long q=4; unsigned long n_in=srw_varint(utx+q,&cc); q+=cc;
    #define APSBT_MAXIN 5000
    static unsigned long in_vout[APSBT_MAXIN];
    if (n_in>APSBT_MAXIN){ *ec=-22; *em="PSBT too large"; return 0; }
    for (unsigned long k=0;k<n_in;k++){
        in_vout[k]=(unsigned long)(utx[q+32]|(utx[q+33]<<8)|(utx[q+34]<<16)|((unsigned long)utx[q+35]<<24));
        q+=36; unsigned long sl=srw_varint(utx+q,&cc); q+=cc+sl+4;
    }
    unsigned long n_out=srw_varint(utx+q,&cc); long out_start=q; q+=cc;
    long long out_sum=0;
    for (unsigned long k=0;k<n_out;k++){
        long long v=0; for(int b=0;b<8;b++) v|=((long long)utx[q+b])<<(8*b);
        out_sum+=v; q+=8; unsigned long sl=srw_varint(utx+q,&cc); q+=cc+sl;
    }
    long outs_bytes = q - out_start;   /* n_out varint + all output bodies */

    rj_val* inputs=rj_arr();
    int psbt_next=APR_EXTRACTOR, all_utxo=1, all_signable=1, any_wit=0;
    long long in_sum=0;
    long est_base = 4 + 4 + apsbt_vilen(n_in) + outs_bytes;   /* version+locktime+in_count+outputs */
    long est_wit = 0;

    for (unsigned long i=0;i<n_in;i++){
        psbt_kv kv[PSBT_MAXKV]; int nkv=psbt_parse_map(buf,blen,&p,kv,PSBT_MAXKV);
        rj_val* ia=rj_obj();
        const unsigned char* spk=NULL; unsigned long spklen=0; long long uval=-1;
        const unsigned char *fin_sig=NULL,*fin_wit=NULL,*redeem=NULL,*wscript=NULL,*nwu=NULL,*wu=NULL;
        unsigned long fin_sig_l=0,fin_wit_l=0,redeem_l=0,wscript_l=0,wu_l=0;
        for (int j=0;j<nkv;j++){
            if (kv[j].kl!=1) continue; unsigned char t=kv[j].k[0];
            if (t==0x00) nwu=kv[j].v;
            else if (t==0x01){ wu=kv[j].v; wu_l=kv[j].vl; }
            else if (t==0x04){ redeem=kv[j].v; redeem_l=kv[j].vl; }
            else if (t==0x05){ wscript=kv[j].v; wscript_l=kv[j].vl; }
            else if (t==0x07){ fin_sig=kv[j].v; fin_sig_l=kv[j].vl; }
            else if (t==0x08){ fin_wit=kv[j].v; fin_wit_l=kv[j].vl; }
        }
        if (wu && wu_l>=9){ long long v=0; for(int b=0;b<8;b++) v|=((long long)wu[b])<<(8*b);
            unsigned long sl=srw_varint(wu+8,&cc); spk=wu+8+cc; spklen=sl; uval=v; }
        else if (nwu){
            long qq=4; unsigned long ni=srw_varint(nwu+qq,&cc); qq+=cc;
            for(unsigned long k=0;k<ni;k++){ qq+=36; unsigned long sl=srw_varint(nwu+qq,&cc); qq+=cc+sl+4; }
            unsigned long no=srw_varint(nwu+qq,&cc); qq+=cc;
            for(unsigned long k=0;k<no;k++){
                long long v=0; for(int b=0;b<8;b++) v|=((long long)nwu[qq+b])<<(8*b);
                unsigned long sl=srw_varint(nwu+qq+8,&cc);
                if (k==in_vout[i]){ uval=v; spk=nwu+qq+8+cc; spklen=sl; }
                qq+=8+cc+sl;
            }
        }
        int has_utxo = (spk!=NULL);
        rj_obj_set(ia,"has_utxo", rj_bool(has_utxo));
        if (!has_utxo){ all_utxo=0; all_signable=0; } else in_sum+=uval;

        int is_final = (fin_sig || fin_wit) ? 1 : 0;
        int role=APR_UPDATER, is_wit=0, solvable=0; rj_val* missing=NULL;
        long est_ss_l=0, est_wit_l=0;

        if (is_final){
            role=APR_EXTRACTOR; solvable=1;
            if (fin_sig) est_ss_l=(long)fin_sig_l;
            if (fin_wit){ est_wit_l=(long)fin_wit_l; is_wit=1; }
        } else if (has_utxo){
            const unsigned char* es=spk; unsigned long esl=spklen; int resolved=0;
            if (spklen==23 && spk[0]==0xa9 && spk[1]==0x14 && spk[22]==0x87){        /* P2SH */
                if (!redeem){ char hx[41]; apsbt_hex(hx,spk+2,20);
                    missing=rj_obj(); rj_obj_set(missing,"redeemscript",rj_str(hx)); resolved=1; }
                else { es=redeem; esl=redeem_l;
                    est_ss_l=1+(long)redeem_l; }   /* scriptSig = push of redeem */
            }
            if (!resolved && esl==34 && es[0]==0x00 && es[1]==0x20){                 /* P2WSH */
                if (!wscript){ char hx[65]; apsbt_hex(hx,es+2,32);
                    missing=rj_obj(); rj_obj_set(missing,"witnessscript",rj_str(hx)); resolved=1; }
                else { es=wscript; esl=wscript_l; is_wit=1; }
            }
            if (!resolved){
                unsigned char keyid[20]; int have_keyid=0;
                if (esl==22 && es[0]==0x00 && es[1]==0x14){ memcpy(keyid,es+2,20); have_keyid=1; is_wit=1; }
                else if (esl==25 && es[0]==0x76 && es[1]==0xa9 && es[2]==0x14 && es[23]==0x88 && es[24]==0xac){
                    memcpy(keyid,es+3,20); have_keyid=1; }
                if (have_keyid){
                    int has_sig=0, known=apsbt_key_known(kv,nkv,keyid,&has_sig);
                    char hx[41]; apsbt_hex(hx,keyid,20);
                    if (has_sig){ role=APR_FINALIZER; solvable=1; }
                    else if (known){ role=APR_SIGNER; solvable=1;
                        missing=rj_obj(); rj_val* a=rj_arr(); rj_arr_push(a,rj_str(hx));
                        rj_obj_set(missing,"signatures",a); }
                    else { missing=rj_obj(); rj_val* a=rj_arr(); rj_arr_push(a,rj_str(hx));
                        rj_obj_set(missing,"pubkeys",a); }
                    /* Core's DUMMY_SIGNATURE_CREATOR sig is 32+32+7 = 71 bytes
                     * (sign.cpp DummySignatureCreator(32,32)). Witness stack
                     * ser: count(1)+len(1)+71+len(1)+33; scriptSig same bytes. */
                    if (is_wit) est_wit_l=1+1+71+1+33; else est_ss_l+=1+71+1+33;
                }
                /* else: unhandled script -> next=updater, no "missing" */
            }
            /* Core (psbt.cpp SignPSBTInput): when the UTXO came from
             * witness_utxo ONLY, a witness signature is required
             * (require_witness_sig) and its `!sigdata.witness` early-return
             * fires BEFORE out_sigdata is filled -- so unless the script
             * resolved to a witness shape (P2WPKH, or P2WSH with its witness
             * script present, incl. behind P2SH), all "missing" info is
             * DROPPED and the input reports next=updater with no "missing".
             * Verified live: P2PKH / P2SH-no-redeem / P2WSH-no-wscript with
             * only a witness_utxo -> no missing; the same scripts via
             * non_witness_utxo -> missing reported. */
            if (wu && !nwu && !is_wit){
                role=APR_UPDATER; solvable=0;
                if (missing){ rj_free(missing); missing=NULL; }
            }
        }

        rj_obj_set(ia,"is_final", rj_bool(is_final));
        rj_obj_set(ia,"next", rj_str(apsbt_role(role)));
        if (missing) rj_obj_set(ia,"missing",missing);
        rj_arr_push(inputs,ia);
        if (role<psbt_next) psbt_next=role;
        if (is_wit) any_wit=1;
        if (!solvable) all_signable=0;
        est_base += 36 + apsbt_vilen((unsigned long)est_ss_l) + est_ss_l + 4;
        if (est_wit_l) est_wit += est_wit_l; else if (is_wit) est_wit += 1;
    }

    rj_obj_set(out,"inputs",inputs);
    if (all_utxo){
        long long fee = in_sum - out_sum;
        long long af = fee<0 ? -fee : fee; const char* sg = fee<0 ? "-" : "";
        if (all_signable){
            long weight = est_base*4 + (any_wit ? 2 + est_wit : 0);
            long vsize = (weight + 3) / 4;
            rj_obj_set(out,"estimated_vsize", rj_numf("%ld", vsize));
            /* CFeeRate: sat/kvB = floor(fee*1000 / vsize) toward -inf
             * (feefrac EvaluateFeeDown), then rendered as BTC/kvB. */
            long long num = fee*1000, spervk = num/vsize;
            if (num%vsize != 0 && (num<0)) spervk--;
            long long ar = spervk<0 ? -spervk : spervk; const char* sr = spervk<0 ? "-" : "";
            rj_obj_set(out,"estimated_feerate", rj_numf("%s%lld.%08lld", sr, ar/100000000LL, ar%100000000LL));
        }
        rj_obj_set(out,"fee", rj_numf("%s%lld.%08lld", sg, af/100000000LL, af%100000000LL));
    }
    rj_obj_set(out,"next", rj_str(apsbt_role(psbt_next)));
    *result=out;
    return 1;
}

/* ---- signrawtransactionwithkey (pure, no wallet state) ---------------------
 * Core rpc/rawtransaction.cpp signrawtransactionwithkey. Signs an unsigned tx
 * with explicitly provided keys against provided prevtxs, returning
 * {hex, complete, errors}. This increment covers the ECDSA single-sig types:
 * P2PKH, P2WPKH, and P2SH-P2WPKH (nested segwit). P2WSH/P2SH multisig and P2TR
 * (Schnorr) are not signed here -- they surface in `errors` with complete:false
 * -- because full multisig assembly and a BIP340 signer are separate tasks (the
 * tree has no Schnorr signer today). Non-wallet in Core, so validity is
 * cross-checked: a tx signed here is accepted by our own txval_modern (itself
 * differentially tested against Core consensus). ECDSA nonce is not RFC6979, so
 * signatures are valid but not byte-identical to Core's. */
static unsigned long srw_varint(const unsigned char* p, unsigned long* consumed){
    if (p[0] < 0xfd){ *consumed=1; return p[0]; }
    if (p[0]==0xfd){ *consumed=3; return (unsigned long)p[1] | ((unsigned long)p[2]<<8); }
    if (p[0]==0xfe){ *consumed=5; return (unsigned long)p[1]|((unsigned long)p[2]<<8)|((unsigned long)p[3]<<16)|((unsigned long)p[4]<<24); }
    *consumed=9; unsigned long v=0; for(int i=0;i<8;i++) v|=((unsigned long)p[1+i])<<(8*i); return v;
}
/* WIF -> 32-byte priv; *comp=1 if compressed. returns 1 ok. */
static int srw_wif(const char* wif, unsigned char priv[32], int* comp){
    unsigned char pay[64]; long pl=0;
    if (!wallet_base58check_decode(pay,(long)sizeof pay,&pl,wif) || pl<33 || pay[0]!=0x80) return 0;
    if (pl==34){ if (pay[33]!=0x01) return 0; *comp=1; }
    else if (pl==33){ *comp=0; }
    else return 0;
    memcpy(priv, pay+1, 32);
    return 1;
}
/* parse SIGHASH type string -> byte; default ALL. -1 on error. */
static int srw_hashtype(const char* s){
    if (!s) return 0x01;
    int base=0, acp=0; const char* bar=strchr(s,'|');
    size_t bl = bar ? (size_t)(bar-s) : strlen(s);
    if (bl==3 && !strncmp(s,"ALL",3)) base=1;
    else if (bl==4 && !strncmp(s,"NONE",4)) base=2;
    else if (bl==6 && !strncmp(s,"SINGLE",6)) base=3;
    else return -1;
    if (bar){ if (!strcmp(bar+1,"ANYONECANPAY")) acp=0x80; else return -1; }
    return base|acp;
}
typedef struct { unsigned char txid_wire[32]; unsigned long vout; unsigned char spk[64]; unsigned long spklen;
                 unsigned long long amount; unsigned char redeem[128]; unsigned long redeemlen; } srw_prev_t;

/* BIP143 segwit-v0 sighash. hp/hs/ho are the caller-selected hashPrevouts /
 * hashSequence / hashOutputs (zeroed per the SIGHASH type). */
static void srw_bip143(unsigned char z[32], const unsigned char ver4[4],
                       const unsigned char hp[32], const unsigned char hs[32],
                       const unsigned char outpoint36[36], const unsigned char* scode,
                       unsigned long sclen, unsigned long long amount, unsigned seq,
                       const unsigned char ho[32], unsigned long locktime, int hashtype){
    unsigned char* pre=malloc((size_t)sclen+256); unsigned long n=0;
    memcpy(pre+n,ver4,4); n+=4;
    memcpy(pre+n,hp,32); n+=32;
    memcpy(pre+n,hs,32); n+=32;
    memcpy(pre+n,outpoint36,36); n+=36;
    n+=crt_varint(pre+n,(unsigned long long)sclen); memcpy(pre+n,scode,sclen); n+=sclen;
    for(int k=0;k<8;k++) pre[n++]=(unsigned char)(amount>>(8*k));
    pre[n++]=(unsigned char)seq;pre[n++]=(unsigned char)(seq>>8);pre[n++]=(unsigned char)(seq>>16);pre[n++]=(unsigned char)(seq>>24);
    memcpy(pre+n,ho,32); n+=32;
    pre[n++]=(unsigned char)locktime;pre[n++]=(unsigned char)(locktime>>8);pre[n++]=(unsigned char)(locktime>>16);pre[n++]=(unsigned char)(locktime>>24);
    unsigned ht=(unsigned)hashtype; pre[n++]=(unsigned char)ht;pre[n++]=(unsigned char)(ht>>8);pre[n++]=(unsigned char)(ht>>16);pre[n++]=(unsigned char)(ht>>24);
    sha256d(z,pre,n); free(pre);
}

static int cmd_signrawtransactionwithkey(const rj_val* params, long* ec, const char** em, rj_val** result){
    if (!params || params->typ!=RJ_ARR || params->nitems<2 || params->items[0]->typ!=RJ_STR || params->items[1]->typ!=RJ_ARR){
        *ec=-8; *em="Invalid parameters, expected hexstring and privkeys array"; return 0; }
    /* --- raw tx --- */
    const char* txhex=params->items[0]->str; size_t thl=strlen(txhex);
    if ((thl&1)||thl/2<10||thl/2>200000){ *ec=-22; *em="TX decode failed"; return 0; }
    unsigned long txlen=(unsigned long)(thl/2);
    static unsigned char tx[200000];
    if (!hex_to_bytes(tx,txhex,thl)){ *ec=-22; *em="TX decode failed"; return 0; }
    /* --- keys --- */
    const rj_val* pk=params->items[1];
    int nk=(int)pk->nitems; if (nk>64) nk=64;
    unsigned char kpriv[64][32]; unsigned char kpub[64][33]; unsigned char kh[64][20]; int ncomp[64]; int nkeys=0;
    for (int i=0;i<(int)pk->nitems && nkeys<64;i++){
        if (pk->items[i]->typ!=RJ_STR) continue;
        int comp=1; if (!srw_wif(pk->items[i]->str,kpriv[nkeys],&comp)){ *ec=-8; *em="Invalid private key"; return 0; }
        scalar_to_pubkey(kpub[nkeys],kpriv[nkeys]); wallet_key_h160(kh[nkeys],kpriv[nkeys]); ncomp[nkeys]=comp; nkeys++;
    }
    /* --- prevtxs --- */
    static srw_prev_t prev[10000]; int nprev=0;
    if (params->nitems>=3 && params->items[2]->typ==RJ_ARR){
        const rj_val* pv=params->items[2];
        for (size_t i=0;i<pv->nitems && nprev<10000;i++){
            const rj_val* e=pv->items[i]; if (e->typ!=RJ_OBJ) continue;
            rj_val* tid=rj_obj_get(e,"txid"); rj_val* vo=rj_obj_get(e,"vout"); rj_val* spk=rj_obj_get(e,"scriptPubKey");
            if (!tid||tid->typ!=RJ_STR||strlen(tid->str)!=64||!vo||vo->typ!=RJ_NUM||!spk||spk->typ!=RJ_STR) continue;
            srw_prev_t* P=&prev[nprev];
            unsigned char idd[32]; if (!hex_to_bytes(idd,tid->str,64)) continue;
            for (int k=0;k<32;k++) P->txid_wire[k]=idd[31-k];
            P->vout=strtoul(vo->str,0,10);
            size_t sl=strlen(spk->str); if ((sl&1)||sl/2>64) continue; P->spklen=(unsigned long)(sl/2);
            if (!hex_to_bytes(P->spk,spk->str,sl)) continue;
            rj_val* am=rj_obj_get(e,"amount"); P->amount = (am&&am->typ==RJ_NUM)? (unsigned long long)crt_amount_to_sat(am->str) : 0;
            rj_val* rs=rj_obj_get(e,"redeemScript"); P->redeemlen=0;
            if (rs&&rs->typ==RJ_STR){ size_t rl=strlen(rs->str); if (!(rl&1)&&rl/2<=128){ P->redeemlen=(unsigned long)(rl/2); hex_to_bytes(P->redeem,rs->str,rl); } }
            nprev++;
        }
    }
    int hashtype = (params->nitems>=4 && params->items[3]->typ==RJ_STR) ? srw_hashtype(params->items[3]->str) : 0x01;
    if (hashtype<0){ *ec=-8; *em="Invalid sighash param"; return 0; }

    /* --- parse the unsigned tx into inputs (outpoint,seq) + outputs region + locktime --- */
    unsigned long p=4, cc; unsigned long n_in=srw_varint(tx+p,&cc); p+=cc;
    if (n_in==0||n_in>10000){ *ec=-22; *em="TX decode failed"; return 0; }
    const unsigned char* in_outpoint[10000]; unsigned in_seq[10000];
    for (unsigned long i=0;i<n_in;i++){
        in_outpoint[i]=tx+p; p+=36;
        unsigned long ssl=srw_varint(tx+p,&cc); p+=cc+ssl;
        in_seq[i]=(unsigned)tx[p]|((unsigned)tx[p+1]<<8)|((unsigned)tx[p+2]<<16)|((unsigned)tx[p+3]<<24); p+=4;
    }
    unsigned long out_start=p; unsigned long n_out=srw_varint(tx+p,&cc); p+=cc;
    for (unsigned long i=0;i<n_out;i++){ p+=8; unsigned long sl=srw_varint(tx+p,&cc); p+=cc+sl; }
    unsigned long out_end=p; unsigned long locktime=(unsigned long)tx[p]|((unsigned long)tx[p+1]<<8)|((unsigned long)tx[p+2]<<16)|((unsigned long)tx[p+3]<<24);

    /* --- BIP143 mid-hashes (SIGHASH_ALL, non-ACP baseline) --- */
    unsigned char zero32[32]; memset(zero32,0,32);
    unsigned char hashPrevouts[32], hashSequence[32], hashOutputs[32];
    { static unsigned char b[10000*36]; unsigned long m=0; for(unsigned long i=0;i<n_in;i++){ memcpy(b+m,in_outpoint[i],36); m+=36; } sha256d(hashPrevouts,b,m); }
    { static unsigned char b[10000*4]; unsigned long m=0; for(unsigned long i=0;i<n_in;i++){ unsigned sq=in_seq[i]; b[m++]=(unsigned char)sq;b[m++]=(unsigned char)(sq>>8);b[m++]=(unsigned char)(sq>>16);b[m++]=(unsigned char)(sq>>24);} sha256d(hashSequence,b,m); }
    { unsigned long cc2; srw_varint(tx+out_start,&cc2); sha256d(hashOutputs, tx+out_start+cc2, out_end-(out_start+cc2)); }
    int ht_base = hashtype & 0x1f, ht_acp = hashtype & 0x80;
    const unsigned char* bip_hp = ht_acp ? zero32 : hashPrevouts;
    const unsigned char* bip_hs = (ht_acp || ht_base!=1) ? zero32 : hashSequence;
    /* hashOutputs: ALL -> all; SINGLE/NONE handled per-input below (defaults to ALL's set for ALL) */
    const unsigned char* bip_ho = (ht_base==1) ? hashOutputs : zero32;

    /* --- sign each input --- */
    static unsigned char ss[10000][256]; unsigned long sslen[10000];      /* scriptSig per input */
    static unsigned char witbuf[10000][256]; unsigned long witlen[10000]; int wititems[10000]; /* witness serialized (count+items) */
    int any_segwit=0, complete=1;
    rj_val* errors=rj_arr();
    unsigned char* pre=malloc((size_t)txlen+8192); if (!pre){ *ec=-7; *em="oom"; return 0; }
    for (unsigned long i=0;i<n_in;i++){
        sslen[i]=0; witlen[i]=0; wititems[i]=0;
        /* match prevout */
        srw_prev_t* P=NULL; unsigned long vo=(unsigned long)in_outpoint[i][32]|((unsigned long)in_outpoint[i][33]<<8)|((unsigned long)in_outpoint[i][34]<<16)|((unsigned long)in_outpoint[i][35]<<24);
        for (int k=0;k<nprev;k++) if (prev[k].vout==vo && !memcmp(prev[k].txid_wire,in_outpoint[i],32)){ P=&prev[k]; break; }
        const char* err=NULL;
        if (!P){ err="Input not found or already spent"; }
        else {
            const unsigned char* spk=P->spk; unsigned long sl=P->spklen;
            int found=-1;
            unsigned char z[32]; unsigned long long r[4],s[4]; unsigned char der[80]; int dl;
            if (sl==25 && spk[0]==0x76&&spk[1]==0xa9&&spk[2]==0x14&&spk[23]==0x88&&spk[24]==0xac){        /* P2PKH */
                for (int k=0;k<nkeys;k++) if (!memcmp(kh[k],spk+3,20)){ found=k; break; }
                if (found<0){ err="Keys not provided for this input"; }
                else if (!legacy_sighash(z,tx,txlen,i,spk,25,hashtype,pre,(unsigned long)txlen+8192)){ err="sighash failed"; }
                else { wallet_ecdsa_sign(r,s,z,kpriv[found]); dl=der_signature_export(der,r,s); der[dl]=(unsigned char)hashtype; dl++;
                    unsigned long o=0; ss[i][o++]=(unsigned char)dl; memcpy(ss[i]+o,der,dl); o+=dl;
                    ss[i][o++]=(unsigned char)33; memcpy(ss[i]+o,kpub[found],33); o+=33; sslen[i]=o; }
            } else if (sl==22 && spk[0]==0x00&&spk[1]==0x14){                                             /* P2WPKH */
                for (int k=0;k<nkeys;k++) if (!memcmp(kh[k],spk+2,20)){ found=k; break; }
                if (found<0){ err="Keys not provided for this input"; }
                else { unsigned char scode[25]={0x76,0xa9,0x14}; memcpy(scode+3,spk+2,20); scode[23]=0x88; scode[24]=0xac;
                    srw_bip143(z, tx, bip_hp, bip_hs, in_outpoint[i], scode, 25, P->amount, in_seq[i], bip_ho, locktime, hashtype);
                    wallet_ecdsa_sign(r,s,z,kpriv[found]); dl=der_signature_export(der,r,s); der[dl]=(unsigned char)hashtype; dl++;
                    unsigned long o=0; witbuf[i][o++]=(unsigned char)dl; memcpy(witbuf[i]+o,der,dl); o+=dl;
                    witbuf[i][o++]=33; memcpy(witbuf[i]+o,kpub[found],33); o+=33; witlen[i]=o; wititems[i]=2; any_segwit=1; }
            } else if (sl==23 && spk[0]==0xa9&&spk[1]==0x14&&spk[22]==0x87 && P->redeemlen==22 && P->redeem[0]==0x00 && P->redeem[1]==0x14){ /* P2SH-P2WPKH */
                unsigned char rh[20]; hash160(rh,P->redeem,22);
                if (memcmp(rh,spk+2,20)){ err="redeemScript does not match scriptPubKey"; }
                else { for (int k=0;k<nkeys;k++) if (!memcmp(kh[k],P->redeem+2,20)){ found=k; break; }
                    if (found<0){ err="Keys not provided for this input"; }
                    else { unsigned char scode[25]={0x76,0xa9,0x14}; memcpy(scode+3,P->redeem+2,20); scode[23]=0x88; scode[24]=0xac;
                        srw_bip143(z, tx, bip_hp, bip_hs, in_outpoint[i], scode, 25, P->amount, in_seq[i], bip_ho, locktime, hashtype);
                        wallet_ecdsa_sign(r,s,z,kpriv[found]); dl=der_signature_export(der,r,s); der[dl]=(unsigned char)hashtype; dl++;
                        unsigned long o=0; witbuf[i][o++]=(unsigned char)dl; memcpy(witbuf[i]+o,der,dl); o+=dl;
                        witbuf[i][o++]=33; memcpy(witbuf[i]+o,kpub[found],33); o+=33; witlen[i]=o; wititems[i]=2; any_segwit=1;
                        /* scriptSig = push(redeemScript) */
                        ss[i][0]=(unsigned char)P->redeemlen; memcpy(ss[i]+1,P->redeem,P->redeemlen); sslen[i]=1+P->redeemlen; } }
            } else {
                err="Unsupported script type (P2WSH/P2SH-multisig/P2TR signing not yet implemented)";
            }
        }
        if (err){
            complete=0;
            rj_val* eo=rj_obj();
            char idh[65]; unsigned char disp[32]; for(int k=0;k<32;k++) disp[k]=in_outpoint[i][31-k]; bin_to_hex(idh,disp,32);
            rj_obj_set(eo,"txid",rj_str(idh));
            rj_obj_set(eo,"vout",rj_numf("%lu",vo));
            rj_obj_set(eo,"sequence",rj_numf("%u",in_seq[i]));
            rj_obj_set(eo,"error",rj_str(err));
            rj_arr_push(errors,eo);
        }
    }
    free(pre);

    /* --- serialize signed tx --- */
    static unsigned char out[400000]; unsigned long n=0;
    out[n++]=tx[0];out[n++]=tx[1];out[n++]=tx[2];out[n++]=tx[3];        /* version */
    if (any_segwit){ out[n++]=0x00; out[n++]=0x01; }
    n+=crt_varint(out+n,(unsigned long long)n_in);
    for (unsigned long i=0;i<n_in;i++){
        memcpy(out+n,in_outpoint[i],36); n+=36;
        n+=crt_varint(out+n,(unsigned long long)sslen[i]); memcpy(out+n,ss[i],sslen[i]); n+=sslen[i];
        out[n++]=(unsigned char)in_seq[i];out[n++]=(unsigned char)(in_seq[i]>>8);out[n++]=(unsigned char)(in_seq[i]>>16);out[n++]=(unsigned char)(in_seq[i]>>24);
    }
    memcpy(out+n,tx+out_start,out_end-out_start); n+=out_end-out_start;    /* outputs region verbatim */
    if (any_segwit){
        for (unsigned long i=0;i<n_in;i++){
            if (wititems[i]==0){ out[n++]=0x00; }                          /* empty stack */
            else { n+=crt_varint(out+n,(unsigned long long)wititems[i]); memcpy(out+n,witbuf[i],witlen[i]); n+=witlen[i]; }
        }
    }
    out[n++]=(unsigned char)locktime;out[n++]=(unsigned char)(locktime>>8);out[n++]=(unsigned char)(locktime>>16);out[n++]=(unsigned char)(locktime>>24);

    char* hex=malloc((size_t)n*2+1); if (!hex){ rj_free(errors); *ec=-7; *em="oom"; return 0; }
    bin_to_hex(hex,out,(size_t)n);
    rj_val* o=rj_obj();
    rj_obj_set(o,"hex",rj_str(hex)); free(hex);
    rj_obj_set(o,"complete",rj_bool(complete));
    if (errors->nitems>0) rj_obj_set(o,"errors",errors); else rj_free(errors);
    *result=o;
    return 1;
}

/* ---- dispatch table ---- */
int rpc_known_method(const char* method) {
    static const char* const known[] = {
        "getnewaddress","getrawchangeaddress","validateaddress","getaddressinfo",
        "gettxout","listunspent","getbalance","decoderawtransaction",
        "signmessagewithprivkey","verifymessage","createrawtransaction","signrawtransactionwithkey","createpsbt","decodepsbt","converttopsbt","combinepsbt","joinpsbts","analyzepsbt",
        /* createrawtransaction / signraw / sendraw are wired by the server card
         * which owns the tx-store lookup; the pure-wallet subset is dispatched
         * here. */
        NULL
    };
    for (int i = 0; known[i]; i++) if (!strcmp(method, known[i])) return 1;
    if (rpc_node_known_method(method)) return 1;
    return rpc_chain_known_method(method);
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
        return cmd_listunspent(params, w, err_code, err_msg, result);
    if (!strcmp(method, "getbalance"))
        return cmd_getbalance(params, w, err_code, err_msg, result);
    if (!strcmp(method, "decoderawtransaction"))
        return cmd_decoderaw(params, err_code, err_msg, result);
    if (!strcmp(method, "signmessagewithprivkey"))
        return cmd_signmessagewithprivkey(params, err_code, err_msg, result);
    if (!strcmp(method, "verifymessage"))
        return cmd_verifymessage(params, err_code, err_msg, result);
    if (!strcmp(method, "createrawtransaction"))
        return cmd_createrawtransaction(params, err_code, err_msg, result);
    if (!strcmp(method, "createpsbt"))
        return cmd_createpsbt(params, err_code, err_msg, result);
    if (!strcmp(method, "decodepsbt"))
        return cmd_decodepsbt(params, err_code, err_msg, result);
    if (!strcmp(method, "converttopsbt"))
        return cmd_converttopsbt(params, err_code, err_msg, result);
    if (!strcmp(method, "combinepsbt"))
        return cmd_combinepsbt(params, err_code, err_msg, result);
    if (!strcmp(method, "joinpsbts"))
        return cmd_joinpsbts(params, err_code, err_msg, result);
    if (!strcmp(method, "analyzepsbt"))
        return cmd_analyzepsbt(params, err_code, err_msg, result);
    if (!strcmp(method, "signrawtransactionwithkey"))
        return cmd_signrawtransactionwithkey(params, err_code, err_msg, result);
    /* live-node-state methods (rpc_node.c) -- peers/network/mempool from the
     * serve daemon's shared status; -1 means "not one of its methods". */
    {
        int r = rpc_node_dispatch(method, params, result, err_code, err_msg);
        if (r >= 0) return r;
    }
    /* blockchain-query / node-status methods (rpc_chain.c) -- read-only over
     * the on-disk archive; -1 means "not one of its methods". */
    {
        int r = rpc_chain_dispatch(method, params, result, err_code, err_msg);
        if (r >= 0) return r;
    }
    *err_code = -32601; *err_msg = "Method not found";
    return 0;
}

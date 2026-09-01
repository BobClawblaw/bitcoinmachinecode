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
#include "rpc_wallet_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <malloc.h>

/* ---- extern wallet_core command layer (from asm/wallet_core.c) ---- */
extern long wallet_derive_p2wpkh_address(char* out, long cap, const unsigned char seed[64], unsigned index);
#include "rpc_wallet_ops.h"   /* output types: rpc_wops_type_path / rpc_wops_type_spk / rpc_wops_active_types */
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
extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);
extern int  bip32_derive_path(unsigned char k[32], unsigned char c[32],
                              const unsigned char* seed, long seedlen,
                              const unsigned* indexes, long n);

/* extern LSM UTXO store lookup (asm/bitcoin_utxo_lsm.asm) -- see
 * rpc_commands_set_utxo_store's own doc comment in the header. */
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index,
                          unsigned long long* value, unsigned long* height, unsigned long* is_coinbase,
                          const unsigned char** script, unsigned long* slen);

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

/* gettxout's out-of-process path. The embedded RPC server (serve parent) has
 * no UTXO handle -- the download worker owns that state -- so daemon/main.c
 * installs a query that asks the worker over a socketpair. 1 found /
 * 0 genuinely absent / -1 cannot answer (no worker, busy, timeout). The
 * standalone rpcd sets the store above instead and never uses this. */
#define TXO_SPK_CAP 16384u
typedef long (*rpc_txo_query_fn)(const unsigned char txid_wire[32], unsigned int vout,
                                 unsigned long long* value, unsigned long* height,
                                 unsigned long* is_coinbase, unsigned char* spk,
                                 unsigned long spk_cap, unsigned long* spk_len);
static rpc_txo_query_fn g_txo_query = NULL;
void rpc_commands_set_txo_query(rpc_txo_query_fn fn) { g_txo_query = fn; }

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
/* getnewaddress ( "label" "address_type" ) / getrawchangeaddress ( "address_type" ):
 * bech32 by default; legacy / p2sh-segwit / bech32m once createwalletdescriptor
 * activated them (Core: an inactive type is "No <type> addresses available"). */
static int cmd_getnewaddr(const char* method, const rj_val* params, const rpc_wallet* w, long* ec, const char** em, rj_val** result) {
    if (!w->seed) { return 0; }
    int is_change = !strcmp(method, "getrawchangeaddress");
    const char* tname = NULL;
    if (params && params->typ == RJ_ARR){
        int ai = is_change ? 0 : 1;
        if ((int)params->nitems > ai && params->items[ai]->typ == RJ_STR && params->items[ai]->str[0]) tname = params->items[ai]->str;
    }
    int t = rpc_wops_default_type(is_change);       /* -addresstype / -changetype */
    static char msg[160];
    if (tname){
        t = rpc_wops_type_from_name(tname);
        if (t < 0){ snprintf(msg, sizeof msg, "Unknown address type '%s'", tname); *ec = -5; *em = msg; return 0; }
        if (!(rpc_wops_active_types() & (1 << t))){ snprintf(msg, sizeof msg, "Error: No %s addresses available for this wallet", tname); *ec = -4; *em = msg; return 0; }
    }
    unsigned idx[5]; rpc_wops_type_path(t, 0, is_change, idx);
    unsigned char k[32], c[32], pub[33], spk[34], h20[20]; unsigned long sl;
    if (bip32_derive_path(k, c, w->seed, 64, idx, 5) != 1) return 0;
    scalar_to_pubkey(pub, k);
    if (!rpc_wops_type_spk(t, pub, spk, &sl, h20)) return 0;
    char addr[96]; addr[0] = 0;
    if (wallet_script_to_address(addr, sizeof addr, spk, (long)sl) <= 0 || !addr[0]) return 0;
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

#define WOP_COIN_CAP 200000
/* Core matures a coinbase at 100 confirmations; everything else is spendable
 * as soon as it is in a block, and the scan only records confirmed outputs.
 * A scan file older than format 3 carries no coinbase flag (wscan_flags_known
 * is 0): those coins are treated as spendable, which is right for any wallet
 * that has never been paid a coinbase and is corrected by one rescan for one
 * that has. Overstating here is bounded and visible; refusing to answer at
 * all until every wallet rescans would be worse. */
static int wallet_coin_mature(const rpc_wops_coin* c, long tip){
    if (!c->is_coinbase) return 1;
    if (tip < 0) return 0;                         /* unknown tip: do not claim */
    return (tip - (long)c->height + 1) >= 100;
}

/* ---- getbalance: sum of the address index's entries for the resolved
 * address (param, or the wallet's own default address if omitted). ---- */
static int cmd_getbalance(const rj_val* params, const rpc_wallet* w, long* ec, const char** em, rj_val** result) {
    const char* addr_param = NULL;
    if (params && params->typ == RJ_ARR && params->nitems > 0) {
        addr_param = rpc_param_str(params, 0, ec, em);
        if (!addr_param) return 0;
    }
    /* No address argument = Core's shape: the WHOLE WALLET. Answer from the
     * rescan records + the live UTXO set, not the address index -- the index
     * is an extension that is off by default, which used to make a funded
     * wallet report 0.00000000. An explicit address still uses the index,
     * since that is the only thing that knows about addresses not ours. */
    if (!addr_param) {
        rpc_wops_coin* coins = malloc(WOP_COIN_CAP * sizeof *coins);
        if (!coins) { *ec = -32603; *em = "out of memory"; return 0; }
        int n = rpc_wops_wallet_coins(w ? w->seed : NULL, coins, WOP_COIN_CAP);
        if (n < 0) {
            free(coins);
            *ec = -4;
            *em = "no wallet rescan has completed, so this node does not know "
                  "what this wallet holds. Run rescanblockchain first; "
                  "answering 0.00000000 here would be indistinguishable from "
                  "a wallet that genuinely holds nothing";
            return 0;
        }
        long tip = rpc_chain_tip_height();
        unsigned long long sum = 0;
        for (int i = 0; i < n; i++)
            if (wallet_coin_mature(&coins[i], tip)) sum += coins[i].value;
        free(coins);
        char amt2[24]; rpc_amounts((long long)sum, amt2, sizeof amt2);
        *result = rj_numf("%s", amt2);   /* Core: amounts are JSON numbers */
        return 1;
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
    *result = rj_numf("%s", amt);       /* Core: amounts are JSON numbers */
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
    if (!addr_param) {
        rpc_wops_coin* coins = malloc(WOP_COIN_CAP * sizeof *coins);
        if (!coins) { rj_free(arr); *ec = -32603; *em = "out of memory"; return 0; }
        int n = rpc_wops_wallet_coins(w ? w->seed : NULL, coins, WOP_COIN_CAP);
        if (n < 0) {
            free(coins); rj_free(arr);
            *ec = -4;
            *em = "no wallet rescan has completed, so this node does not know "
                  "what this wallet holds. Run rescanblockchain first";
            return 0;
        }
        long tip = rpc_chain_tip_height();
        for (int i = 0; i < n; i++) {
            unsigned char spk[34]; unsigned long spkl = coins[i].spklen;
            if (spkl) memcpy(spk, coins[i].spk, spkl); else { spk[0]=0x00; spk[1]=0x14; memcpy(spk+2, coins[i].h160, 20); spkl = 22; }
            char txidhex[65]; unsigned char disp[32];
            for (int k = 0; k < 32; k++) disp[k] = coins[i].txid[31-k];
            bin_to_hex(txidhex, disp, 32);
            char scripthex[70]; bin_to_hex(scripthex, spk, spkl);
            char addr[96]; addr[0] = 0;
            wallet_script_to_address(addr, sizeof addr, spk, (long)spkl);
            char amt[24]; rpc_amounts((long long)coins[i].value, amt, sizeof amt);
            int confs = tip >= 0 ? (int)(tip - (long)coins[i].height + 1) : 0;
            int mature = wallet_coin_mature(&coins[i], tip);
            rj_val* o = rj_obj();
            rj_obj_set(o, "txid", rj_str(txidhex));
            rj_obj_set(o, "vout", rj_numf("%u", coins[i].vout));
            if (addr[0]) rj_obj_set(o, "address", rj_str(addr));
            rj_obj_set(o, "label", rj_str(""));
            rj_obj_set(o, "scriptPubKey", rj_str(scripthex));
            rj_obj_set(o, "amount", rj_numf("%s", amt));
            rj_obj_set(o, "confirmations", rj_numf("%d", confs));
            /* an immature coinbase is listed but NOT spendable, which is what
             * Core reports; dropping it entirely would hide a real coin. */
            rj_obj_set(o, "spendable", rj_bool(mature));
            rj_obj_set(o, "solvable", rj_bool(1));
            rj_obj_set(o, "safe", rj_bool(mature));
            rj_arr_push(arr, o);
        }
        free(coins);
        *result = arr;
        return 1;
    }
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
            rj_obj_set(o, "amount", rj_numf("%s", amt));
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

    /* Two ways to reach the UTXO set, and a refusal if neither is available.
     * null is NOT "I cannot say" here -- it means "that output is not
     * unspent", so a server that cannot look must never answer with it. */
    unsigned long long value = 0; unsigned long height = 0, is_coinbase = 0;
    const unsigned char* script = NULL; unsigned long slen = 0;
    unsigned char spkbuf[TXO_SPK_CAP];   /* per-call: the RPC server is threaded */
    long r;
    if (g_utxo_lst) {
        /* in-process handle (the standalone rpcd) */
        r = utxo_lsm_get(g_utxo_lst, g_utxo_u, txid_wire, (unsigned)vout,
                         &value, &height, &is_coinbase, &script, &slen);
        if (r != 1) r = 0;
    } else if (g_txo_query) {
        /* out of process: ask the download worker, which owns the live set.
         * The worker can be mid-rotation; a brief retry turns most transient
         * "did not answer" refusals into answers (2026-08-31: a diagnostic
         * read every busy refusal as "output absent"). */
        r = -1;
        for (int att = 0; att < 3 && r < 0; att++){
            if (att){ struct timespec ts = {0, 150*1000*1000}; nanosleep(&ts, NULL); }
            r = g_txo_query(txid_wire, (unsigned)vout, &value, &height, &is_coinbase,
                            spkbuf, sizeof spkbuf, &slen);
        }
        if (r == 1) script = spkbuf;
    } else {
        r = -1;
    }
    if (r < 0) {
        *ec = -1;
        *em = "gettxout cannot be answered right now: this server has no handle "
              "on the live UTXO set and the download worker that owns it did "
              "not answer. Returning null would claim the output is spent, "
              "which this node has not established";
        return 0;
    }
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
    /* a NUMBER, not a string: Core's ValueFromAmount emits UniValue VNUM and
     * every other amount in this file already uses rj_numf. gettxout was the
     * one holdout, which stayed invisible while it only ever returned null --
     * the first real diff against Core caught it. */
    rj_obj_set(o, "value", rj_numf("%s", amt));
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
/* Exposed below as rpc_amount_to_sat: the spend path in rpc_wallet_ops.c
 * parses the same BTC amount strings, and a second parser that rounded
 * differently would send a different number of satoshis than the caller
 * asked for. */
/* Core's MAX_MONEY: 21,000,000 BTC in satoshis. Nothing above this can ever
 * be a valid amount, so it is the natural place to stop parsing. */
#define CRT_MAX_MONEY 2100000000000000LL
#define CRT_MAX_WHOLE 21000000LL

/* Parse a decimal BTC amount into satoshis; -1 on anything invalid.
 *
 * SECURITY (audit 2026-08-29 finding 5a): `whole` used to accumulate without
 * a bound, so ~19 digits of unauthenticated JSON-RPC input overflowed a
 * signed long long -- undefined behaviour, and in practice a wrap to a
 * negative or arbitrary value. Callers then saw an amount that had passed
 * "parsing" and only sometimes tripped a `<= 0` check afterwards.
 *
 * The bound is applied DURING accumulation, not after: checking the result
 * cannot detect a wrap that has already happened. Core does the same thing in
 * ParseFixedPoint, and rejects rather than saturates -- an amount that is not
 * representable is a malformed request, not a request for the maximum. */
static long long crt_amount_to_sat(const char* s){
    long long whole=0, frac=0; int fdig=0, seen=0;
    const char* p=s; if (*p=='-') return -1;
    while (*p>='0'&&*p<='9'){
        if (whole > CRT_MAX_WHOLE) return -1;      /* refuse before it wraps */
        whole=whole*10+(*p-'0'); p++; seen=1;
    }
    if (*p=='.'){ p++; while (*p>='0'&&*p<='9'){ if (fdig>=8) return -1; frac=frac*10+(*p-'0'); fdig++; p++; seen=1; } }
    if (*p || !seen) return -1;
    while (fdig<8){ frac*=10; fdig++; }
    if (whole > CRT_MAX_WHOLE) return -1;
    { long long sat = whole*100000000LL + frac;
      if (sat > CRT_MAX_MONEY) return -1;          /* 21000000.00000001 etc */
      return sat; }
}

long long rpc_amount_to_sat(const char* s){ return crt_amount_to_sat(s); }
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
static void psbt_wr32(unsigned char* p, unsigned v);
static int psbt_version_arg(const rj_val* params, unsigned long idx, int* ver, long* ec, const char** em);
static char* psbt_wrap_version(const unsigned char* tx, long n, size_t nin, size_t nout, int ver);
static int cmd_createpsbt(const rj_val* params, long* ec, const char** em, rj_val** result){
    static unsigned char tx[131072]; long n; size_t nin, nout;
    if (!crt_build_unsigned(params, tx, &n, &nin, &nout, ec, em)) return 0;
    if (params->nitems >= 5 && params->items[4]->typ == RJ_NUM){                /* Core: tx version */
        long v = strtol(params->items[4]->str, 0, 10);
        if (v < 1 || v > 0x7fffffffL){ *ec = -8; *em = "Invalid parameter, version must be between 1 and 2147483647"; return 0; }
        psbt_wr32(tx, (unsigned)v); }
    int ver; if (!psbt_version_arg(params, 5, &ver, ec, em)) return 0;
    char* b64=psbt_wrap_version(tx,n,nin,nout,ver); if (!b64){ *ec=-7; *em="oom"; return 0; }
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
    int ver; if (!psbt_version_arg(params, 3, &ver, ec, em)) return 0;
    char* b64=psbt_wrap_version(utx,u,(size_t)n_in,(size_t)n_out,ver); if (!b64){ *ec=-7; *em="oom"; return 0; }
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
typedef struct {
    const unsigned char* op;      /* 36-byte outpoint */
    const unsigned char* ss;  unsigned long sslen;   /* scriptSig */
    const unsigned char* wit; unsigned long witlen;  /* serialized witness stack */
    unsigned witems;
    unsigned seq;
} crt_in_t;
static int crt_walk(const unsigned char* tx, unsigned long len, crt_in_t* ins, int cap, int* n_in_out, unsigned long* out_start, unsigned long* out_end, int* segwit_out);

/* ==== PSBT v2 (BIP370), 2026-09-01 ============================================
 * Every PSBT RPC works on a v0-SHAPED buffer: the global map begins with the
 * unsigned transaction, real (v0) or SYNTHESIZED from the v2 fields
 * (tx_version, per-input previous txid/index/sequence, required locktimes
 * folded per BIP370, per-output amount/script). The v2 per-input and
 * per-output keys stay inside their maps untouched, so every role that
 * copies "other" keys through keeps them, and psbt_v2_emit turns the result
 * back into the caller's version: strips the unsigned tx, re-adds the v2
 * globals, fills the v2 input/output keys a Creator implies, and sorts every
 * map by key -- Core's serialization order -- so a v2 that Core produced
 * comes back byte-identical. The validation messages are Core's
 * (psbt.h), prefixed "TX decode failed " the way DecodeBase64PSBT's caller
 * reports them. */
typedef struct {
    int version;                       /* 0 or 2 */
    unsigned tx_version;
    int has_fallback; unsigned fallback_locktime;
    int has_mod; unsigned char mod;
    int created;                       /* built from a tx here: sequences are written (Core's constructor sets them) */
    int locktime_conflict;             /* inputs' required locktimes cannot be satisfied together */
    unsigned long n_in, n_out;
} psbt_v2meta;
static char g_psbt_errbuf[192];
static const char* psbt_v2_fail(const char* what){ snprintf(g_psbt_errbuf, sizeof g_psbt_errbuf, "TX decode failed %s", what); return g_psbt_errbuf; }
static unsigned psbt_rd32(const unsigned char* p){ return (unsigned)p[0] | ((unsigned)p[1]<<8) | ((unsigned)p[2]<<16) | ((unsigned)p[3]<<24); }
static void psbt_wr32(unsigned char* p, unsigned v){ p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24); }
static int psbt_kv_cmp(const void* a, const void* b){
    const psbt_kv* x = a; const psbt_kv* y = b;
    unsigned long n = x->kl < y->kl ? x->kl : y->kl;
    int c = memcmp(x->k, y->k, n); if (c) return c;
    return x->kl < y->kl ? -1 : x->kl > y->kl ? 1 : 0;
}
/* Any PSBT -> v0-shaped buffer. Returns the length, or -1 with *err set. */
static long psbt_v2_normalize(const unsigned char* in, long inlen, unsigned char* out, long cap, psbt_v2meta* m, const char** err){
    memset(m, 0, sizeof *m);
    if (inlen < 5 || memcmp(in, "psbt\xff", 5)){ *err = "TX decode failed"; return -1; }
    long p = 5; static psbt_kv g[PSBT_MAXKV]; int gn = psbt_parse_map(in, inlen, &p, g, PSBT_MAXKV);
    long maps_start = p;
    const unsigned char* utx = NULL; unsigned long utxl = 0;
    int f_txver = 0, f_fb = 0, f_in = 0, f_out = 0, f_ver = 0, f_mod = 0; unsigned ver = 0, txver = 0, fb = 0; unsigned long cin = 0, cout = 0; unsigned char mod = 0;
    for (int i = 0; i < gn; i++){
        if (g[i].kl != 1) continue;
        switch (g[i].k[0]){
        case 0x00: utx = g[i].v; utxl = g[i].vl; break;
        case 0x02: if (g[i].vl != 4){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } txver = psbt_rd32(g[i].v); f_txver = 1; break;
        case 0x03: if (g[i].vl != 4){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } fb = psbt_rd32(g[i].v); f_fb = 1; break;
        case 0x04: { unsigned long cc; cin = srw_varint(g[i].v, &cc); if (cc != g[i].vl){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } f_in = 1; } break;
        case 0x05: { unsigned long cc; cout = srw_varint(g[i].v, &cc); if (cc != g[i].vl){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } f_out = 1; } break;
        case 0x06: if (g[i].vl != 1){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } mod = g[i].v[0]; f_mod = 1; break;
        case 0xfb: if (g[i].vl != 4){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } ver = psbt_rd32(g[i].v); f_ver = 1;
                   if (ver > 2){ *err = psbt_v2_fail("Unsupported version number"); return -1; } break;
        default: break;
        }
    }
    (void)f_ver;
    if (ver == 0){
        if (!utx){ *err = psbt_v2_fail("No unsigned transaction was provided"); return -1; }
        if (f_txver){ *err = psbt_v2_fail("PSBT_GLOBAL_TX_VERSION is not allowed in PSBTv0"); return -1; }
        if (f_fb){ *err = psbt_v2_fail("PSBT_GLOBAL_FALLBACK_LOCKTIME is not allowed in PSBTv0"); return -1; }
        if (f_in){ *err = psbt_v2_fail("PSBT_GLOBAL_INPUT_COUNT is not allowed in PSBTv0"); return -1; }
        if (f_out){ *err = psbt_v2_fail("PSBT_GLOBAL_OUTPUT_COUNT is not allowed in PSBTv0"); return -1; }
        if (f_mod){ *err = psbt_v2_fail("PSBT_GLOBAL_TX_MODIFIABLE is not allowed in PSBTv0"); return -1; }
        if (inlen > cap){ *err = "TX decode failed"; return -1; }
        memcpy(out, in, (size_t)inlen);
        m->version = 0; m->tx_version = psbt_rd32(utx);
        { unsigned long cc; long q = 4; m->n_in = srw_varint(utx + q, &cc); q += cc;
          for (unsigned long k = 0; k < m->n_in && (unsigned long)q < utxl; k++){ q += 36; unsigned long sl = srw_varint(utx + q, &cc); q += cc + sl + 4; }
          m->n_out = (unsigned long)q < utxl ? srw_varint(utx + q, &cc) : 0; }
        return inlen;
    }
    if (ver == 1){ *err = psbt_v2_fail("There is no PSBT version 1"); return -1; }
    if (!f_txver){ *err = psbt_v2_fail("PSBT_GLOBAL_TX_VERSION is required in PSBTv2"); return -1; }
    if (!f_in){ *err = psbt_v2_fail("PSBT_GLOBAL_INPUT_COUNT is required in PSBTv2"); return -1; }
    if (!f_out){ *err = psbt_v2_fail("PSBT_GLOBAL_OUTPUT_COUNT is required in PSBTv2"); return -1; }
    if (utx){ *err = psbt_v2_fail("PSBT_GLOBAL_UNSIGNED_TX is not allowed in PSBTv2"); return -1; }
    if (cin > PSBT_MAXIO || cout > PSBT_MAXIO){ *err = "TX decode failed PSBT too large"; return -1; }
    m->version = 2; m->tx_version = txver; m->has_fallback = f_fb; m->fallback_locktime = fb; m->has_mod = f_mod; m->mod = mod; m->n_in = cin; m->n_out = cout;
    /* inputs: previous txid/index required; sequence, required locktimes optional */
    static unsigned char tx[200000]; long t = 0;
    psbt_wr32(tx + t, txver); t += 4;
    t += crt_varint(tx + t, cin);
    int have_time = 1, have_height = 1; unsigned time_lock = 0, height_lock = 0;
    for (unsigned long i = 0; i < cin; i++){
        static psbt_kv kv[PSBT_MAXKV]; int n = psbt_parse_map(in, inlen, &p, kv, PSBT_MAXKV);
        const unsigned char* ptxid = NULL; int f_idx = 0; unsigned idx = 0, seq = 0xffffffffu; int f_tl = 0, f_hl = 0; unsigned tl = 0, hl = 0;
        for (int j = 0; j < n; j++){
            if (kv[j].kl != 1) continue;
            switch (kv[j].k[0]){
            case 0x0e: if (kv[j].vl != 32){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } ptxid = kv[j].v; break;
            case 0x0f: if (kv[j].vl != 4){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } idx = psbt_rd32(kv[j].v); f_idx = 1; break;
            case 0x10: if (kv[j].vl != 4){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } seq = psbt_rd32(kv[j].v); break;
            case 0x11: if (kv[j].vl != 4){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } tl = psbt_rd32(kv[j].v); f_tl = 1;
                       if (tl < 500000000u){ *err = psbt_v2_fail("Required time based locktime is invalid (less than 500000000)"); return -1; } break;
            case 0x12: if (kv[j].vl != 4){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } hl = psbt_rd32(kv[j].v); f_hl = 1;
                       if (hl >= 500000000u){ *err = psbt_v2_fail("Required height based locktime is invalid (greater than or equal to 500000000)"); return -1; }
                       if (hl == 0){ *err = psbt_v2_fail("Required height based locktime is invalid (0)"); return -1; } break;
            default: break;
            }
        }
        if (!ptxid){ *err = psbt_v2_fail("Previous TXID is required in PSBTv2"); return -1; }
        if (!f_idx){ *err = psbt_v2_fail("Previous output's index is required in PSBTv2"); return -1; }
        /* BIP370 locktime fold (Core ComputeTimeLock) */
        if (f_tl && !f_hl){ have_height = 0; if (!have_time) m->locktime_conflict = 1; }
        else if (!f_tl && f_hl){ have_time = 0; if (!have_height) m->locktime_conflict = 1; }
        if (f_tl && have_time && tl > time_lock) time_lock = tl;
        if (f_hl && have_height && hl > height_lock) height_lock = hl;
        if (t + 41 > (long)sizeof tx){ *err = "TX decode failed PSBT too large"; return -1; }
        memcpy(tx + t, ptxid, 32); t += 32; psbt_wr32(tx + t, idx); t += 4; tx[t++] = 0x00; psbt_wr32(tx + t, seq); t += 4;
    }
    t += crt_varint(tx + t, cout);
    for (unsigned long i = 0; i < cout; i++){
        static psbt_kv kv[PSBT_MAXKV]; int n = psbt_parse_map(in, inlen, &p, kv, PSBT_MAXKV);
        const unsigned char* amt = NULL; const unsigned char* sc = NULL; unsigned long scl = 0; int f_sc = 0;
        for (int j = 0; j < n; j++){
            if (kv[j].kl != 1) continue;
            if (kv[j].k[0] == 0x03){ if (kv[j].vl != 8){ *err = psbt_v2_fail("Size of value was not the stated size"); return -1; } amt = kv[j].v; }
            else if (kv[j].k[0] == 0x04){ sc = kv[j].v; scl = kv[j].vl; f_sc = 1; }
        }
        if (!amt){ *err = psbt_v2_fail("Output amount is required in PSBTv2"); return -1; }
        if (!f_sc){ *err = psbt_v2_fail("Output script is required in PSBTv2"); return -1; }
        if (t + 17 + (long)scl > (long)sizeof tx){ *err = "TX decode failed PSBT too large"; return -1; }
        memcpy(tx + t, amt, 8); t += 8; t += crt_varint(tx + t, scl); if (scl) memcpy(tx + t, sc, scl); t += scl;
    }
    unsigned locktime = 0;
    if (!m->locktime_conflict){
        if (have_height && height_lock > 0) locktime = height_lock;
        else if (have_time && time_lock > 0) locktime = time_lock;
        else locktime = f_fb ? fb : 0;
    }
    psbt_wr32(tx + t, locktime); t += 4;
    /* write: magic | global [unsigned tx, then every other global key except the v2 ones] | the maps verbatim */
    long o = 0;
    if (5 + 12 + t + (inlen - maps_start) + 64 > cap){ *err = "TX decode failed PSBT too large"; return -1; }
    memcpy(out, "psbt\xff", 5); o = 5;
    out[o++] = 0x01; out[o++] = 0x00; o += crt_varint(out + o, (unsigned long long)t); memcpy(out + o, tx, (size_t)t); o += t;
    for (int i = 0; i < gn; i++){
        if (g[i].kl == 1 && (g[i].k[0] == 0x00 || (g[i].k[0] >= 0x02 && g[i].k[0] <= 0x06) || g[i].k[0] == 0xfb)) continue;
        if (o + 20 + (long)g[i].kl + (long)g[i].vl > cap){ *err = "TX decode failed PSBT too large"; return -1; }
        o += crt_varint(out + o, g[i].kl); memcpy(out + o, g[i].k, g[i].kl); o += g[i].kl;
        o += crt_varint(out + o, g[i].vl); memcpy(out + o, g[i].v, g[i].vl); o += g[i].vl;
    }
    out[o++] = 0x00;
    memcpy(out + o, in + maps_start, (size_t)(inlen - maps_start)); o += inlen - maps_start;
    return o;
}
/* v0-shaped buffer -> the caller's version. Returns the length or -1. */
static long psbt_v2_emit(const unsigned char* v0, long v0len, unsigned char* out, long cap, const psbt_v2meta* m){
    if (m->version != 2){ if (v0len > cap) return -1; memcpy(out, v0, (size_t)v0len); return v0len; }
    long p = 5; static psbt_kv g[PSBT_MAXKV + 8]; int gn = psbt_parse_map(v0, v0len, &p, g, PSBT_MAXKV);
    const unsigned char* utx = NULL; unsigned long utxl = 0;
    for (int i = 0; i < gn; i++) if (g[i].kl == 1 && g[i].k[0] == 0x00){ utx = g[i].v; utxl = g[i].vl; }
    if (!utx) return -1;
    static crt_in_t uin[PSBT_MAXIO]; int n_in, sw; unsigned long ost, oen;
    if (!crt_walk(utx, utxl, uin, PSBT_MAXIO, &n_in, &ost, &oen, &sw)) return -1;
    unsigned long n_out; unsigned long cc; n_out = srw_varint(utx + ost, &cc);
    /* globals: drop the unsigned tx and any stale v2 globals, add the current ones, sort */
    static unsigned char kb[8][2], vb[8][9]; int kn = 0; static psbt_kv add[8]; int an = 0;
    static psbt_kv gg[PSBT_MAXKV + 8]; int ggn = 0;
    for (int i = 0; i < gn; i++){ if (g[i].kl == 1 && (g[i].k[0] == 0x00 || (g[i].k[0] >= 0x02 && g[i].k[0] <= 0x06) || g[i].k[0] == 0xfb)) continue; gg[ggn++] = g[i]; }
    #define PSBT_ADD1(T, VAL, VL) do{ kb[kn][0] = (T); add[an].k = kb[kn]; add[an].kl = 1; memcpy(vb[kn], (VAL), (VL)); add[an].v = vb[kn]; add[an].vl = (VL); an++; kn++; }while(0)
    { unsigned char v4[4]; psbt_wr32(v4, m->tx_version ? m->tx_version : psbt_rd32(utx)); PSBT_ADD1(0x02, v4, 4); }
    if (m->has_fallback){ unsigned char v4[4]; psbt_wr32(v4, m->fallback_locktime); PSBT_ADD1(0x03, v4, 4); }
    { unsigned char cs[9]; long l = crt_varint(cs, (unsigned long long)n_in); PSBT_ADD1(0x04, cs, (unsigned long)l); }
    { unsigned char cs[9]; long l = crt_varint(cs, (unsigned long long)n_out); PSBT_ADD1(0x05, cs, (unsigned long)l); }
    if (m->has_mod){ PSBT_ADD1(0x06, &m->mod, 1); }
    { unsigned char v4[4]; psbt_wr32(v4, 2); PSBT_ADD1(0xfb, v4, 4); }
    for (int i = 0; i < an; i++) gg[ggn++] = add[i];
    qsort(gg, (size_t)ggn, sizeof(psbt_kv), psbt_kv_cmp);
    long o = 0; memcpy(out, "psbt\xff", 5); o = 5;
    o += psbt_ser_map(out + o, gg, ggn);
    /* inputs: fill previous txid/index (+sequence for a PSBT created here), sort */
    static const unsigned char K0E = 0x0e, K0F = 0x0f, K10 = 0x10, K03 = 0x03, K04 = 0x04;
    for (int i = 0; i < n_in; i++){
        static psbt_kv kv[PSBT_MAXKV + 3]; int n = psbt_parse_map(v0, v0len, &p, kv, PSBT_MAXKV);
        int has_e = 0, has_f = 0, has_s = 0;
        for (int j = 0; j < n; j++) if (kv[j].kl == 1){ if (kv[j].k[0] == 0x0e) has_e = 1; else if (kv[j].k[0] == 0x0f) has_f = 1; else if (kv[j].k[0] == 0x10) has_s = 1; }
        if (!has_e){ kv[n].k = &K0E; kv[n].kl = 1; kv[n].v = uin[i].op; kv[n].vl = 32; n++; }
        if (!has_f){ kv[n].k = &K0F; kv[n].kl = 1; kv[n].v = uin[i].op + 32; kv[n].vl = 4; n++; }
        if (!has_s && m->created){ kv[n].k = &K10; kv[n].kl = 1; kv[n].v = uin[i].op + 37; kv[n].vl = 4; n++; }   /* empty scriptSig: the sequence follows the 1-byte length */
        qsort(kv, (size_t)n, sizeof(psbt_kv), psbt_kv_cmp);
        if (o + 40 > cap) return -1;
        o += psbt_ser_map(out + o, kv, n);
    }
    { const unsigned char* q = utx + ost + cc;
      for (unsigned long i = 0; i < n_out; i++){
        static psbt_kv kv[PSBT_MAXKV + 3]; int n = psbt_parse_map(v0, v0len, &p, kv, PSBT_MAXKV);
        const unsigned char* amt = q; unsigned long c2; unsigned long sl = srw_varint(q + 8, &c2); const unsigned char* sc = q + 8 + c2; q += 8 + c2 + sl;
        int has_a = 0, has_sc = 0;
        for (int j = 0; j < n; j++) if (kv[j].kl == 1){ if (kv[j].k[0] == 0x03) has_a = 1; else if (kv[j].k[0] == 0x04) has_sc = 1; }
        if (!has_a){ kv[n].k = &K03; kv[n].kl = 1; kv[n].v = amt; kv[n].vl = 8; n++; }
        if (!has_sc){ kv[n].k = &K04; kv[n].kl = 1; kv[n].v = sc; kv[n].vl = sl; n++; }
        qsort(kv, (size_t)n, sizeof(psbt_kv), psbt_kv_cmp);
        if (o + 40 + (long)sl > cap) return -1;
        o += psbt_ser_map(out + o, kv, n);
      } }
    return o;
}
/* Core's GetUniqueID for v2 hashes the unsigned tx with every sequence zeroed */
static int psbt_same_tx_seqblind(const unsigned char* a, const unsigned char* b, unsigned long len){
    static unsigned char ca[200000], cb[200000]; if (len > sizeof ca) return 0;
    memcpy(ca, a, len); memcpy(cb, b, len);
    for (int w = 0; w < 2; w++){ unsigned char* t = w ? cb : ca; unsigned long cc; long q = 4; unsigned long n_in = srw_varint(t + q, &cc); q += cc;
        for (unsigned long k = 0; k < n_in && (unsigned long)q + 41 <= len; k++){ q += 36; unsigned long sl = srw_varint(t + q, &cc); q += cc + sl; memset(t + q, 0, 4); q += 4; } }
    return memcmp(ca, cb, len) == 0;
}
/* decode + normalize a base64 PSBT into `out`; 0 with ec/em on failure */
static int psbt_load(const char* b64, unsigned char* out, long cap, long* outlen, psbt_v2meta* m, long* ec, const char** em){
    static unsigned char raw[400000]; long rl = 0;
    if (!crt_b64dec(b64, raw, sizeof raw, &rl) || rl < 5 || memcmp(raw, "psbt\xff", 5)){ *ec = -22; *em = "TX decode failed"; return 0; }
    const char* err = NULL; long n = psbt_v2_normalize(raw, rl, out, cap, m, &err);
    if (n < 0){ *ec = -22; *em = err ? err : "TX decode failed"; return 0; }
    *outlen = n; return 1;
}
/* v0-shaped bytes -> base64 in the caller's version (malloc'd) */
static char* psbt_b64_out(const unsigned char* v0, long v0len, const psbt_v2meta* m){
    static unsigned char ob[440000]; long n = psbt_v2_emit(v0, v0len, ob, sizeof ob, m);
    if (n < 0) return NULL;
    char* b = malloc((size_t)((n + 2) / 3) * 4 + 1); if (!b) return NULL;
    crt_b64(b, ob, n); return b;
}
/* psbt_version argument (Core: default 2, only 0 or 2) at `idx` */
static int psbt_version_arg(const rj_val* params, unsigned long idx, int* ver, long* ec, const char** em){
    *ver = 2;
    if (params && params->typ == RJ_ARR && params->nitems > idx && params->items[idx]->typ != RJ_NULL){
        if (params->items[idx]->typ != RJ_NUM){ *ec = -3; *em = "JSON value of type string is not of expected type number"; return 0; }
        long v = strtol(params->items[idx]->str, 0, 10);
        if (v != 0 && v != 2){ *ec = -8; *em = "The PSBT version can only be 2 or 0"; return 0; }
        *ver = (int)v;
    }
    return 1;
}
/* wrap an unsigned tx as a PSBT of the requested version (Core's Creator) */
static char* psbt_wrap_version(const unsigned char* tx, long n, size_t nin, size_t nout, int ver){
    char* b64 = psbt_wrap_unsigned(tx, n, nin, nout); if (!b64 || ver != 2) return b64;
    static unsigned char v0[400000]; long v0l = 0;
    if (!crt_b64dec(b64, v0, sizeof v0, &v0l)){ free(b64); return NULL; }
    free(b64);
    psbt_v2meta m; memset(&m, 0, sizeof m); m.version = 2; m.tx_version = psbt_rd32(tx);
    m.has_fallback = 1; m.fallback_locktime = psbt_rd32(tx + n - 4); m.created = 1;
    return psbt_b64_out(v0, v0l, &m);
}

static void psbt_path_str(char* out, unsigned long cap, const unsigned char* p, unsigned long n){
    /* Core's WriteHDKeypath: "m" then "/<i>" with an h suffix for hardened */
    unsigned long o = 0; o += (unsigned long)snprintf(out + o, cap - o, "m");
    for (unsigned long i = 0; i + 4 <= n && o + 16 < cap; i += 4){
        unsigned v = (unsigned)p[i] | ((unsigned)p[i+1]<<8) | ((unsigned)p[i+2]<<16) | ((unsigned)p[i+3]<<24);
        o += (unsigned long)snprintf(out + o, cap - o, "/%u%s", v & 0x7fffffffu, (v & 0x80000000u) ? "h" : "");
    }
}
static rj_val* psbt_hexval(const unsigned char* v, unsigned long n){ char* h = malloc(n*2+1); if (!h) return rj_str(""); bin_to_hex(h, v, n); rj_val* r = rj_str(h); free(h); return r; }
static rj_val* psbt_obj_arr(rj_val* o, const char* name){ rj_val* a = rj_obj_get(o, name); if (!a){ a = rj_arr(); rj_obj_set(o, name, a); } return a; }
/* decodepsbt input/output taproot + partial-signature fields, Core's names
 * (rpc/rawtransaction.cpp decodepsbt). Returns 1 if the key was consumed. */
static int psbt_decode_common(rj_val* o, const unsigned char* key, unsigned long kl, const unsigned char* val, unsigned long vl, int is_input){
    unsigned char t = key[0];
    if (is_input){
        if (t == 0x02 && kl >= 34){ rj_val* ps = rj_obj_get(o, "partial_signatures"); if (!ps){ ps = rj_obj(); rj_obj_set(o, "partial_signatures", ps); }
            char kh[140]; bin_to_hex(kh, key+1, kl-1); rj_obj_set(ps, kh, psbt_hexval(val, vl)); return 1; }
        if (t == 0x03 && vl == 4){ unsigned v = (unsigned)val[0] | ((unsigned)val[1]<<8); const char* nm = NULL;
            switch (v){ case 0: nm = "DEFAULT"; break; case 1: nm = "ALL"; break; case 2: nm = "NONE"; break; case 3: nm = "SINGLE"; break;
                        case 0x81: nm = "ALL|ANYONECANPAY"; break; case 0x82: nm = "NONE|ANYONECANPAY"; break; case 0x83: nm = "SINGLE|ANYONECANPAY"; break; default: break; }
            if (nm) rj_obj_set(o, "sighash", rj_str(nm)); return 1; }
        if (t == 0x06 && kl >= 34 && vl >= 4){ rj_val* a = psbt_obj_arr(o, "bip32_derivs"); rj_val* d = rj_obj();
            rj_obj_set(d, "pubkey", psbt_hexval(key+1, kl-1)); rj_obj_set(d, "master_fingerprint", psbt_hexval(val, 4));
            char ps[512]; psbt_path_str(ps, sizeof ps, val+4, vl-4); rj_obj_set(d, "path", rj_str(ps)); rj_arr_push(a, d); return 1; }
        if (t == 0x08){ rj_val* a = rj_arr(); const unsigned char* q = val; unsigned long cc; unsigned long cnt = srw_varint(q, &cc); q += cc;
            for (unsigned long z = 0; z < cnt && (unsigned long)(q - val) < vl; z++){ unsigned long l = srw_varint(q, &cc); q += cc; if ((unsigned long)(q - val) + l > vl) break; rj_arr_push(a, psbt_hexval(q, l)); q += l; }
            rj_obj_set(o, "final_scriptwitness", a); return 1; }
        if (t == 0x13 && (vl == 64 || vl == 65)){ rj_obj_set(o, "taproot_key_path_sig", psbt_hexval(val, vl)); return 1; }
        if (t == 0x14 && kl == 65){ rj_val* a = psbt_obj_arr(o, "taproot_script_path_sigs"); rj_val* d = rj_obj();
            rj_obj_set(d, "pubkey", psbt_hexval(key+1, 32)); rj_obj_set(d, "leaf_hash", psbt_hexval(key+33, 32)); rj_obj_set(d, "sig", psbt_hexval(val, vl)); rj_arr_push(a, d); return 1; }
        if (t == 0x15 && kl >= 34 && vl >= 1){ rj_val* a = psbt_obj_arr(o, "taproot_scripts"); rj_val* d = NULL;
            /* Core groups control blocks by (script, leaf_ver) */
            for (unsigned long z = 0; z < a->nitems; z++){ rj_val* e = a->items[z]; rj_val* sc = rj_obj_get(e, "script"); rj_val* lv = rj_obj_get(e, "leaf_ver");
                if (sc && sc->str && strlen(sc->str) == (vl-1)*2 && lv && (unsigned)strtoul(lv->str, 0, 10) == val[vl-1]){ char* h = malloc(vl*2); bin_to_hex(h, val, vl-1); int same = !strcmp(h, sc->str); free(h); if (same){ d = e; break; } } }
            if (!d){ d = rj_obj(); rj_obj_set(d, "script", psbt_hexval(val, vl-1)); rj_obj_set(d, "leaf_ver", rj_numf("%u", (unsigned)val[vl-1])); rj_obj_set(d, "control_blocks", rj_arr()); rj_arr_push(a, d); }
            rj_arr_push(rj_obj_get(d, "control_blocks"), psbt_hexval(key+1, kl-1)); return 1; }
        if (t == 0x17 && vl == 32){ rj_obj_set(o, "taproot_internal_key", psbt_hexval(val, 32)); return 1; }
        if (t == 0x18 && vl == 32){ rj_obj_set(o, "taproot_merkle_root", psbt_hexval(val, 32)); return 1; }
    } else {
        if (t == 0x02 && kl >= 34 && vl >= 4){ rj_val* a = psbt_obj_arr(o, "bip32_derivs"); rj_val* d = rj_obj();
            rj_obj_set(d, "pubkey", psbt_hexval(key+1, kl-1)); rj_obj_set(d, "master_fingerprint", psbt_hexval(val, 4));
            char ps[512]; psbt_path_str(ps, sizeof ps, val+4, vl-4); rj_obj_set(d, "path", rj_str(ps)); rj_arr_push(a, d); return 1; }
        if (t == 0x05 && vl == 32){ rj_obj_set(o, "taproot_internal_key", psbt_hexval(val, 32)); return 1; }
        if (t == 0x06){ rj_val* a = rj_arr(); const unsigned char* q = val;
            while ((unsigned long)(q - val) + 2 < vl){ unsigned char depth = q[0], lv = q[1]; unsigned long cc; unsigned long l = srw_varint(q+2, &cc); q += 2 + cc; if ((unsigned long)(q - val) + l > vl) break;
                rj_val* d = rj_obj(); rj_obj_set(d, "depth", rj_numf("%u", depth)); rj_obj_set(d, "leaf_ver", rj_numf("%u", lv)); rj_obj_set(d, "script", psbt_hexval(q, l)); rj_arr_push(a, d); q += l; }
            rj_obj_set(o, "taproot_tree", a); return 1; }
    }
    /* taproot bip32 derivs share a shape on both sides: 0x16 (input) / 0x07 (output) */
    if (((is_input && t == 0x16) || (!is_input && t == 0x07)) && kl == 33){
        unsigned long cc; unsigned long nlh = srw_varint(val, &cc); unsigned long q = cc + nlh * 32; if (q + 4 > vl) return 1;
        rj_val* a = psbt_obj_arr(o, "taproot_bip32_derivs"); rj_val* d = rj_obj();
        rj_obj_set(d, "pubkey", psbt_hexval(key+1, 32)); rj_obj_set(d, "master_fingerprint", psbt_hexval(val+q, 4));
        char ps[512]; psbt_path_str(ps, sizeof ps, val+q+4, vl-q-4); rj_obj_set(d, "path", rj_str(ps));
        rj_val* lh = rj_arr(); for (unsigned long z = 0; z < nlh; z++) rj_arr_push(lh, psbt_hexval(val+cc+z*32, 32)); rj_obj_set(d, "leaf_hashes", lh);
        rj_arr_push(a, d); return 1; }
    return 0;
}
/* MuSig2 (BIP373) in decodepsbt, Core's field names: musig2_participant_pubkeys
 * [{aggregate_pubkey, participant_pubkeys[]}], musig2_pubnonces /
 * musig2_partial_sigs [{participant_pubkey, aggregate_pubkey, [leaf_hash],
 * pubnonce|partial_sig}] */
static rj_val* psbt_arr_at(rj_val* o, const char* name){ rj_val* a=rj_obj_get(o,name); if(!a){ a=rj_arr(); rj_obj_set(o,name,a); a=rj_obj_get(o,name); } return a; }
static void psbt_musig_participants(rj_val* o, const unsigned char* agg, const unsigned char* val, unsigned long vl){
    rj_val* e=rj_obj(); psbt_field_hex(e,"aggregate_pubkey",agg,33);
    rj_val* parts=rj_arr(); for (unsigned long q=0;q+33<=vl;q+=33){ char h[67]; bin_to_hex(h,val+q,33); rj_arr_push(parts,rj_str(h)); }
    rj_obj_set(e,"participant_pubkeys",parts); rj_arr_push(psbt_arr_at(o,"musig2_participant_pubkeys"),e);
}
static void psbt_musig_signer_field(rj_val* o, unsigned char type, const unsigned char* key, unsigned long kl, const unsigned char* val, unsigned long vl){
    rj_val* e=rj_obj(); psbt_field_hex(e,"participant_pubkey",key+1,33); psbt_field_hex(e,"aggregate_pubkey",key+34,33);
    if (kl==99) psbt_field_hex(e,"leaf_hash",key+67,32);
    psbt_field_hex(e,type==0x1b?"pubnonce":"partial_sig",val,vl);
    rj_arr_push(psbt_arr_at(o,type==0x1b?"musig2_pubnonces":"musig2_partial_sigs"),e);
}
static int cmd_decodepsbt(const rj_val* params, long* ec, const char** em, rj_val** result){
    const char* b64 = rpc_param_str(params,0,ec,em); if (!b64) return 0;
    static unsigned char buf[400000]; long blen=0; psbt_v2meta vm;
    if (!psbt_load(b64, buf, sizeof buf, &blen, &vm, ec, em)) return 0;
    long p=5; const unsigned char* utx=NULL; unsigned long utxlen=0; int psbtver=vm.version;
    while (p<blen){ unsigned long cc; unsigned long kl=srw_varint(buf+p,&cc); p+=cc; if (kl==0) break;
        const unsigned char* key=buf+p; p+=kl;
        unsigned long vl=srw_varint(buf+p,&cc); p+=cc; const unsigned char* val=buf+p; p+=vl;
        if (kl>=1 && key[0]==0x00){ utx=val; utxlen=vl; }
    }
    rj_val* o=rj_obj();
    long n_in=0, n_out=0; rj_val* txo=NULL;
    if (utx){
        long e2; const char* m2;
        if (rpc_chain_decode_rawtx(utx,(long)utxlen,&txo,&e2,&m2)){
            rj_val* vin=rj_obj_get(txo,"vin"); rj_val* vout=rj_obj_get(txo,"vout");
            n_in = vin?(long)vin->nitems:0; n_out = vout?(long)vout->nitems:0;
            if (psbtver < 2) rj_obj_set(o,"tx",txo);                /* Core: the decoded tx only for v0 */
        }
    }
    rj_obj_set(o,"global_xpubs",rj_arr());
    if (psbtver >= 2){                                              /* Core's PSBTv2 globals, in its order */
        rj_obj_set(o,"tx_version",rj_numf("%u",vm.tx_version));
        if (vm.has_fallback) rj_obj_set(o,"fallback_locktime",rj_numf("%u",vm.fallback_locktime));
        rj_obj_set(o,"input_count",rj_numf("%lu",vm.n_in));
        rj_obj_set(o,"output_count",rj_numf("%lu",vm.n_out));
        if (vm.has_mod){ rj_obj_set(o,"inputs_modifiable",rj_bool(vm.mod&1)); rj_obj_set(o,"outputs_modifiable",rj_bool((vm.mod>>1)&1)); rj_obj_set(o,"has_sighash_single",rj_bool((vm.mod>>2)&1)); }
    }
    rj_obj_set(o,"psbt_version",rj_numf("%d",psbtver));
    rj_obj_set(o,"proprietary",rj_arr());
    rj_obj_set(o,"unknown",rj_obj());
    rj_val* ins=rj_arr();
    long long total_in = 0; int have_all_utxos = 1;                 /* Core: "fee" when every input's UTXO is known */
    static crt_in_t d_uin[PSBT_MAXIO]; int d_nin = 0; { int sw; unsigned long os, oe; if (!utx || !crt_walk(utx, utxlen, d_uin, PSBT_MAXIO, &d_nin, &os, &oe, &sw)) d_nin = 0; }
    for (long i=0;i<n_in && p<blen;i++){
        rj_val* io=rj_obj(); long long in_val = -1;
        while (p<blen){ unsigned long cc; unsigned long kl=srw_varint(buf+p,&cc); p+=cc; if (kl==0) break;
            const unsigned char* key=buf+p; p+=kl; unsigned long vl=srw_varint(buf+p,&cc); p+=cc; const unsigned char* val=buf+p; p+=vl;
            if (kl>=1){ switch (key[0]){
                    case 0x00: { rj_val* t2=NULL; long e3; const char* m3;
                        if (rpc_chain_decode_rawtx(val,(long)vl,&t2,&e3,&m3)){ rj_obj_set(io,"non_witness_utxo",t2);
                            /* this input's prevout value from the parent's vout[n] */
                            if (i < d_nin && in_val < 0){ unsigned long vo = (unsigned long)d_uin[i].op[32] | ((unsigned long)d_uin[i].op[33]<<8) | ((unsigned long)d_uin[i].op[34]<<16) | ((unsigned long)d_uin[i].op[35]<<24);
                                unsigned long q = 4; if (vl > 6 && val[4]==0 && val[5]==1) q = 6; unsigned long c2; unsigned long ni = srw_varint(val+q,&c2); q += c2;
                                for (unsigned long k = 0; k < ni && q < vl; k++){ q += 36; unsigned long sl = srw_varint(val+q,&c2); q += c2 + sl + 4; }
                                unsigned long no = srw_varint(val+q,&c2); q += c2;
                                for (unsigned long k = 0; k < no && q + 8 <= vl; k++){ long long v = 0; for (int b = 0; b < 8; b++) v |= ((long long)val[q+b]) << (8*b); unsigned long sl = srw_varint(val+q+8,&c2); if (k == vo) in_val = v; q += 8 + c2 + sl; } } }
                        break; }
                    case 0x01: if (vl >= 9){ long long v = 0; for (int b = 0; b < 8; b++) v |= ((long long)val[b]) << (8*b);
                        unsigned long c2; unsigned long sl = srw_varint(val+8,&c2);
                        if (8 + c2 + sl <= vl){ rj_val* wo = rj_obj(); char am[32]; rpc_amounts(v, am, sizeof am); rj_obj_set(wo,"amount",rj_numf("%s",am));
                            rj_obj_set(wo,"scriptPubKey",rpc_chain_script_pubkey_json(val+8+c2, sl)); rj_obj_set(io,"witness_utxo",wo); in_val = v; } }
                        break;
                    case 0x04: rj_obj_set(io,"redeem_script",rpc_chain_script_json_noaddr(val,vl)); break;      /* Core: ScriptToUniv object */
                    case 0x05: rj_obj_set(io,"witness_script",rpc_chain_script_json_noaddr(val,vl)); break;
                    case 0x07: { rj_val* fo = rj_obj(); char* a = rpc_chain_script_asm(val, vl, 1); rj_obj_set(fo,"asm",rj_str(a ? a : "")); free(a);
                                 char* hx = malloc(vl*2+1); if (hx){ bin_to_hex(hx,val,vl); rj_obj_set(fo,"hex",rj_str(hx)); free(hx); }
                                 rj_obj_set(io,"final_scriptSig",fo); break; }
                    case 0x0e: if (vl==32){ char hx[65]; for (int b=0;b<32;b++) sprintf(hx+2*b,"%02x",val[31-b]); rj_obj_set(io,"previous_txid",rj_str(hx)); } break;
                    case 0x0f: if (vl==4) rj_obj_set(io,"previous_vout",rj_numf("%u",psbt_rd32(val))); break;
                    case 0x10: if (vl==4) rj_obj_set(io,"sequence",rj_numf("%u",psbt_rd32(val))); break;
                    case 0x11: if (vl==4) rj_obj_set(io,"time_locktime",rj_numf("%u",psbt_rd32(val))); break;
                    case 0x12: if (vl==4) rj_obj_set(io,"height_locktime",rj_numf("%u",psbt_rd32(val))); break;
                    /* MuSig2 (BIP373), Core's decodepsbt shapes */
                    case 0x1a: if (kl==34 && vl%33==0) psbt_musig_participants(io,key+1,val,vl); break;
                    case 0x1b: case 0x1c: if ((kl==67||kl==99) && vl==(key[0]==0x1b?66:32)) psbt_musig_signer_field(io,key[0],key,kl,val,vl); break;
                    default: psbt_decode_common(io,key,kl,val,vl,1); break; } }
        }
        if (in_val < 0) have_all_utxos = 0; else total_in += in_val;
        rj_arr_push(ins,io);
    }
    rj_obj_set(o,"inputs",ins);
    rj_val* outs=rj_arr();
    rj_val* dvout = txo ? rj_obj_get(txo,"vout") : NULL;
    for (long i=0;i<n_out && p<blen;i++){
        rj_val* oo=rj_obj();
        if (psbtver >= 2 && dvout && (unsigned long)i < dvout->nitems){        /* Core: amount + ScriptToUniv(script) */
            rj_val* dv = dvout->items[i]; rj_val* val_ = rj_obj_get(dv,"value"); rj_val* spk = rj_obj_get(dv,"scriptPubKey");
            if (val_) rj_obj_set(oo,"amount",rj_clone(val_));
            if (spk) rj_obj_set(oo,"script",rj_clone(spk));
        }
        while (p<blen){ unsigned long cc; unsigned long kl=srw_varint(buf+p,&cc); p+=cc; if (kl==0) break;
            const unsigned char* key=buf+p; p+=kl; unsigned long vl=srw_varint(buf+p,&cc); p+=cc; const unsigned char* val=buf+p; p+=vl;
            if (kl>=1){ switch (key[0]){ case 0x00: rj_obj_set(oo,"redeem_script",rpc_chain_script_json_noaddr(val,vl)); break;
                                         case 0x01: rj_obj_set(oo,"witness_script",rpc_chain_script_json_noaddr(val,vl)); break;
                                         case 0x08: if (kl==34 && vl%33==0) psbt_musig_participants(oo,key+1,val,vl); break;
                                         default: psbt_decode_common(oo,key,kl,val,vl,0); break; } }
        }
        rj_arr_push(outs,oo);
    }
    rj_obj_set(o,"outputs",outs);
    if (have_all_utxos && n_in > 0 && utx){                          /* Core: fee = inputs - outputs, only when every UTXO is known */
        long long out_sum = 0; unsigned long cc; long q = 4; unsigned long ni = srw_varint(utx+q,&cc); q += cc;
        for (unsigned long k = 0; k < ni; k++){ q += 36; unsigned long sl = srw_varint(utx+q,&cc); q += cc + sl + 4; }
        unsigned long no = srw_varint(utx+q,&cc); q += cc;
        for (unsigned long k = 0; k < no; k++){ long long v = 0; for (int b = 0; b < 8; b++) v |= ((long long)utx[q+b]) << (8*b); out_sum += v; q += 8; unsigned long sl = srw_varint(utx+q,&cc); q += cc + sl; }
        char am[32]; rpc_amounts(total_in - out_sum, am, sizeof am); rj_obj_set(o,"fee",rj_numf("%s",am));
    }
    if (txo && psbtver >= 2) rj_free(txo);
    *result=o;
    return 1;
}

/* combinepsbt (Core rpc/rawtransaction.cpp): merge PSBTs for the SAME unsigned
 * tx by unioning each map's key-value pairs (dedup by key; first occurrence
 * wins). Returns the merged base64 PSBT. */
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
    psbt_v2meta vm0; memset(&vm0, 0, sizeof vm0);
    for (int pi=0; pi<np; pi++){
        if (arr->items[pi]->typ!=RJ_STR){ *ec=-22; *em="TX decode failed"; return 0; }
        psbt_v2meta vm;
        if (!psbt_load(arr->items[pi]->str, bufs[pi], sizeof bufs[pi], &blens[pi], &vm, ec, em)) return 0;
        if (pi == 0) vm0 = vm; else if (vm.version != vm0.version){ *ec=-8; *em="PSBTs not compatible (different transactions)"; return 0; }
        long p=5;
        psbt_kv g[PSBT_MAXKV]; int g_n=psbt_parse_map(bufs[pi],blens[pi],&p,g,PSBT_MAXKV);
        const unsigned char* utx=NULL; unsigned long utxl=0;
        for (int j=0;j<g_n;j++) if (g[j].kl>=1 && g[j].k[0]==0x00){ utx=g[j].v; utxl=g[j].vl; break; }
        if (!utx){ *ec=-22; *em="TX decode failed"; return 0; }
        if (!utx0){ utx0=utx; utx0len=utxl;
            unsigned long cc; long q=4; n_in=(long)srw_varint(utx+q,&cc); q+=cc;
            for (long k=0;k<n_in;k++){ q+=36; unsigned long sl=srw_varint(utx+q,&cc); q+=cc+sl+4; }
            n_out=(long)srw_varint(utx+q,&cc);
            if (n_in>PSBT_MAXIO||n_out>PSBT_MAXIO){ *ec=-22; *em="PSBT too large to combine"; return 0; }
            for (long k=0;k<n_in;k++) in_n[k]=0;
            for (long k=0;k<n_out;k++) out_n[k]=0;
        } else if (utxl!=utx0len || (vm0.version < 2 ? memcmp(utx,utx0,utxl) != 0 : !psbt_same_tx_seqblind(utx,utx0,utxl))){ *ec=-8; *em="PSBTs not compatible (different transactions)"; return 0; }
        gn=psbt_union(gkv,gn,PSBT_MAXKV,g,g_n);
        for (long k=0;k<n_in;k++){ psbt_kv m[PSBT_MAXKV]; int mn=psbt_parse_map(bufs[pi],blens[pi],&p,m,PSBT_MAXKV); in_n[k]=psbt_union(ikv[k],in_n[k],PSBT_MAXKV,m,mn); }
        for (long k=0;k<n_out;k++){ psbt_kv m[PSBT_MAXKV]; int mn=psbt_parse_map(bufs[pi],blens[pi],&p,m,PSBT_MAXKV); out_n[k]=psbt_union(okv[k],out_n[k],PSBT_MAXKV,m,mn); }
    }
    static unsigned char out[220000]; long n=0;
    out[n++]=0x70;out[n++]=0x73;out[n++]=0x62;out[n++]=0x74;out[n++]=0xff;
    n+=psbt_ser_map(out+n,gkv,gn);
    for (long k=0;k<n_in;k++)  n+=psbt_ser_map(out+n,ikv[k],in_n[k]);
    for (long k=0;k<n_out;k++) n+=psbt_ser_map(out+n,okv[k],out_n[k]);
    char* b64=psbt_b64_out(out,n,&vm0); if(!b64){ *ec=-7; *em="oom"; return 0; }
    *result=rj_str(b64); free(b64);
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
        { psbt_v2meta vm; if (!psbt_load(arr->items[pi]->str, bufs[pi], sizeof bufs[pi], &blens[pi], &vm, ec, em)) return 0;
          if (vm.version >= 2){ *ec=-8; *em="joinpsbts only operates on version 0 PSBTs"; return 0; } }
        long p=5; psbt_kv g[PSBT_MAXKV]; int gn=psbt_parse_map(bufs[pi],blens[pi],&p,g,PSBT_MAXKV);
        const unsigned char* utx=NULL; unsigned long utxl=0;
        for (int j=0;j<gn;j++) if (g[j].kl>=1 && g[j].k[0]==0x00){ utx=g[j].v; utxl=g[j].vl; break; }
        if (!utx){ *ec=-22; *em="TX decode failed"; return 0; }
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
    static unsigned char buf[400000]; long blen; psbt_v2meta vm;
    if (!psbt_load(params->items[0]->str, buf, sizeof buf, &blen, &vm, ec, em)) return 0;
    long p=5; psbt_kv g[PSBT_MAXKV]; int gn=psbt_parse_map(buf,blen,&p,g,PSBT_MAXKV);
    const unsigned char* utx=NULL;
    for (int j=0;j<gn;j++) if (g[j].kl>=1 && g[j].k[0]==0x00){ utx=g[j].v; break; }
    rj_val* out=rj_obj();
    if (!utx || vm.locktime_conflict){ rj_obj_set(out,"error",rj_str("PSBT cannot be made into a valid transaction")); *result=out; return 1; }

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
    if (!strcmp(s,"DEFAULT")) return 0x100;   /* Core: SIGHASH_DEFAULT -- ALL for ECDSA, the 64-byte default for taproot */
    int base=0, acp=0; const char* bar=strchr(s,'|');
    size_t bl = bar ? (size_t)(bar-s) : strlen(s);
    if (bl==3 && !strncmp(s,"ALL",3)) base=1;
    else if (bl==4 && !strncmp(s,"NONE",4)) base=2;
    else if (bl==6 && !strncmp(s,"SINGLE",6)) base=3;
    else return -1;
    if (bar){ if (!strcmp(bar+1,"ANYONECANPAY")) acp=0x80; else return -1; }
    return base|acp;
}
#include "miniscript_sign.h"
#define SRW_WITCAP 4200            /* per-input witness buffer: items + a witnessScript of up to 3600 bytes */
typedef struct { unsigned char txid_wire[32]; unsigned long vout; unsigned char spk[64]; unsigned long spklen;
                 unsigned long long amount; unsigned char redeem[128]; unsigned long redeemlen;
                 unsigned char wscript[3700]; unsigned long wscriptlen;   /* a P2WSH witnessScript is at most 3600 bytes (miniscript reaches it) */
                 /* taproot (2026-09-01): a script-path leaf + its control block, and/or the
                  * key-path tweak inputs. Fed by the PSBT layer through the prevtx object's
                  * internal keys tapLeafScript/tapControlBlock/tapMerkleRoot/tapInternalKey. */
                 unsigned char tapleaf[1024]; unsigned long tapleaflen;
                 unsigned char tapctrl[33+32*16]; unsigned long tapctrllen;
                 unsigned char tapmerkle[32]; int has_merkle;
                 unsigned char tapinternal[32]; int has_internal;
                 /* partial signatures already in the PSBT (TAP_SCRIPT_SIG / TAP_KEY_SIG), carried
                  * into the witness for the keys this call does not hold */
                 struct { unsigned char x[32], lh[32], sig[65]; int sl; } tap_psig[32]; int n_tap_psig;
                 unsigned char tap_keysig[65]; int tap_keysig_len;
                 ms_preimages_t pre;                                      /* PSBT hash preimages (miniscript satisfier) */
                 unsigned char pubs[64][33]; int npubs; } srw_prev_t;     /* pubkeys known without a key: pk_h() resolution */

/* ---- CHECKMULTISIG / taproot signing helpers (2026-09-01) ------------------
 * The raw signer used to sign P2PKH, P2WPKH and P2SH-P2WPKH only. It now
 * also signs: legacy P2SH multisig (redeemScript = OP_k <pubs> OP_n
 * OP_CHECKMULTISIG), P2WSH and P2SH-P2WSH (witnessScript = the same template
 * or a single <pub> OP_CHECKSIG), and P2TR key-path spends whose internal
 * key is a given key with no script tree (tr(KEY)) -- the BIP341 tweak is
 * TapTweak(P), the signing key P's private key tweaked, the signature BIP340
 * (bip340_sign.c). Signatures for a multisig are emitted in the script's key
 * order, at most k; fewer than k leaves the input incomplete. */
extern void sha256_full(unsigned char out[32], const void* msg, unsigned long len);
extern int  bip32_pubkey_decompress(const unsigned char pub33[33], unsigned char out65[65]);
extern int  bip32_xonly_tweak_add(const unsigned char x[32], const unsigned char t[32], unsigned char out_x[32]);
extern int  bip340_sign(unsigned char sig[64], const unsigned char* msg, unsigned long msglen, const unsigned char priv_be[32], const unsigned char aux[32]);
extern int  bip340_tweak_privkey(unsigned char out_priv[32], const unsigned char priv_be[32], const unsigned char tweak[32]);
extern int  wallet_ecdsa_sign(unsigned long long out_r[4], unsigned long long out_s[4], const unsigned char z[32], const unsigned char priv[32]);
extern int  der_signature_export(unsigned char* out, const unsigned long long r[4], const unsigned long long s[4]);
/* OP_k <pub>... OP_n OP_CHECKMULTISIG -> k, the key pointers/lengths, n; -1 if not that template */
static int srw_parse_multisig(const unsigned char* sc, unsigned long sl, int* k, const unsigned char* keys[20], int keylen[20]){
    if (sl < 4 || sc[sl-1] != 0xae) return -1;
    if (sc[0] < 0x51 || sc[0] > 0x60) return -1;
    int kk = sc[0] - 0x50;
    unsigned long tail; int n;
    if (sc[sl-2] >= 0x51 && sc[sl-2] <= 0x60){ n = sc[sl-2] - 0x50; tail = 2; }
    else if (sl >= 5 && sc[sl-3] == 0x01 && sc[sl-2] >= 17 && sc[sl-2] <= 20){ n = sc[sl-2]; tail = 3; }
    else return -1;
    unsigned long q = 1; int cnt = 0;
    while (q < sl - tail){
        unsigned l = sc[q];
        if ((l != 33 && l != 65) || q + 1 + l > sl - tail || cnt >= 20) return -1;
        keys[cnt] = sc + q + 1; keylen[cnt] = (int)l; cnt++; q += 1 + l;
    }
    if (cnt != n || kk < 1 || kk > n) return -1;
    *k = kk; return n;
}
/* the held key matching a script key (compressed or uncompressed), or -1 */
static const char* srw_sign_wsh(const srw_prev_t* P, unsigned char* wit, unsigned long* witlen, int* wititems,
                                const unsigned char* tx, const unsigned char hp[32], const unsigned char hs[32],
                                const unsigned char outpoint36[36], unsigned seq, const unsigned char ho[32], unsigned long locktime, int hashtype,
                                unsigned char (*kpriv)[32], unsigned char (*kpub)[33], const int* ncomp, int nkeys);
static int srw_tap_sighash(unsigned char z[32], const unsigned char* tx, unsigned long txlen,
                           unsigned long i, unsigned long n_in, const unsigned char* const* outpoints, const unsigned* seqs,
                           srw_prev_t* const* prev_of, unsigned long out_start, unsigned long out_end,
                           unsigned long locktime, int hashtype, const unsigned char* leafhash);
/* ---- taproot script path (2026-09-01) --------------------------------------
 * The leaf forms this node signs on its own: pk(KEY) -> <x> CHECKSIG, and
 * multi_a(k, K1..Kn) -> <x1> CHECKSIG <x2> CHECKSIGADD .. <k> NUMEQUAL. Any
 * other leaf is left to the miniscript satisfier (separate workstream). */
#define SRW_TAP_MAXKEYS 32
static int srw_tap_leaf_keys(const unsigned char* sc, unsigned long n, unsigned char (*keys)[32], int* k_of){
    /* returns the key count (>0) and the threshold in *k_of; 0 = not a form we sign */
    int nk = 0; unsigned long p = 0;
    if (n == 34 && sc[0] == 0x20 && sc[33] == 0xac){ memcpy(keys[0], sc+1, 32); *k_of = 1; return 1; }
    while (p + 34 <= n && nk < SRW_TAP_MAXKEYS && sc[p] == 0x20){
        unsigned char op = sc[p+33];
        if (nk == 0 ? op != 0xac : op != 0xba) return 0;
        memcpy(keys[nk++], sc+p+1, 32); p += 34;
    }
    if (nk < 1 || p >= n) return 0;
    int k;
    if (sc[p] >= 0x51 && sc[p] <= 0x60){ k = sc[p] - 0x50; p++; }
    else if (sc[p] == 0x01 && p + 1 < n){ k = sc[p+1]; p += 2; }
    else return 0;
    if (p + 1 != n || sc[p] != 0x9c || k < 1 || k > nk) return 0;
    *k_of = k; return nk;
}
static void srw_tapleaf_hash(unsigned char out[32], unsigned char ver, const unsigned char* sc, unsigned long n){
    unsigned char th[32]; sha256_full(th, "TapLeaf", 7);
    unsigned char* b = malloc(64 + 1 + 9 + n); unsigned long m = 0;
    memcpy(b, th, 32); m += 32; memcpy(b + m, th, 32); m += 32; b[m++] = ver;
    m += crt_varint(b + m, n); memcpy(b + m, sc, n); m += n;
    sha256_full(out, b, m); free(b);
}
static void srw_tapbranch(unsigned char out[32], const unsigned char* a, const unsigned char* b){
    unsigned char th[32]; sha256_full(th, "TapBranch", 9);
    unsigned char buf[128]; memcpy(buf, th, 32); memcpy(buf+32, th, 32);
    if (memcmp(a, b, 32) <= 0){ memcpy(buf+64, a, 32); memcpy(buf+96, b, 32); } else { memcpy(buf+64, b, 32); memcpy(buf+96, a, 32); }
    sha256_full(out, buf, 128);
}
static void srw_taptweak(unsigned char t[32], const unsigned char* xonly, const unsigned char* root /* NULL = no tree */){
    unsigned char th[32]; sha256_full(th, "TapTweak", 8);
    unsigned char tb[128]; memcpy(tb, th, 32); memcpy(tb+32, th, 32); memcpy(tb+64, xonly, 32);
    if (root){ memcpy(tb+96, root, 32); sha256_full(t, tb, 128); } else sha256_full(t, tb, 96);
}
/* Sign one P2TR script-path input. Builds the witness [sig..., script, control]
 * (multi_a: one slot per key, empty where we hold no key, at most k filled),
 * even when incomplete, so the PSBT layer can extract partial signatures.
 * Returns NULL or an error string ("Missing signatures: ..." is partial). */
static const char* srw_sign_tap_script(const srw_prev_t* P, const unsigned char* spk, unsigned char* wit, unsigned long* witlen, int* wititems,
                                       const unsigned char* tx, unsigned long txlen, unsigned long i, unsigned long n_in,
                                       const unsigned char* const* outpoints, const unsigned* seqs, srw_prev_t* const* prev_of,
                                       unsigned long out_start, unsigned long out_end, unsigned long locktime, int tht,
                                       unsigned char (*kpriv)[32], unsigned char (*kpub)[33], const int* ncomp, int nkeys){
    const unsigned char* ctrl = P->tapctrl; unsigned long cl = P->tapctrllen;
    unsigned char ver = ctrl[0] & 0xfe;
    unsigned char lh[32]; srw_tapleaf_hash(lh, ver, P->tapleaf, P->tapleaflen);
    unsigned char k[32]; memcpy(k, lh, 32);
    for (unsigned long q = 33; q + 32 <= cl; q += 32) srw_tapbranch(k, k, ctrl + q);
    unsigned char t[32], qx[32]; srw_taptweak(t, ctrl + 1, k);
    if (!bip32_xonly_tweak_add(ctrl + 1, t, qx) || memcmp(qx, spk + 2, 32)) return "tapControlBlock does not commit to this scriptPubKey";
    unsigned char keys[SRW_TAP_MAXKEYS][32]; int kth = 0;
    int nk = srw_tap_leaf_keys(P->tapleaf, P->tapleaflen, keys, &kth);
    unsigned char z[32];
    if (!srw_tap_sighash(z, tx, txlen, i, n_in, outpoints, seqs, prev_of, out_start, out_end, locktime, tht, lh))
        return "P2TR sighash needs scriptPubKey and amount for every input";
    if (nk <= 0){
        /* any other leaf is a miniscript (2026-09-01): the satisfier signs with the keys we hold,
         * the partial signatures the PSBT carries for this leaf, its preimages and the tx's timelocks */
        ms_psig_t ps[32]; int nps = 0;
        for (int q = 0; q < P->n_tap_psig && nps < 32; q++) if (!memcmp(P->tap_psig[q].lh, lh, 32)){ ps[nps].x = P->tap_psig[q].x; ps[nps].sig = P->tap_psig[q].sig; ps[nps].sl = P->tap_psig[q].sl; nps++; }
        const char* merr = NULL; unsigned long ml = 0; int mi = 0;
        unsigned long need = 3 + P->tapleaflen + 3 + cl; if (need + 64 > SRW_WITCAP) return "P2TR leaf too large for this node's witness buffer";
        int r = ms_sign_witness_tapleaf(P->tapleaf, P->tapleaflen, z, tht, seqs[i], locktime, kpriv, kpub, nkeys,
                                        (const unsigned char (*)[33])P->pubs, P->npubs, ps, nps, &P->pre, wit, SRW_WITCAP - need, &ml, &mi, &merr);
        if (r == 0) return "P2TR script-path: pk(), multi_a() and miniscript leaves are signed on this node; this leaf is none of those";
        if (r == -1) return merr;
        unsigned long o = ml;
        o += crt_varint(wit + o, P->tapleaflen); memcpy(wit + o, P->tapleaf, P->tapleaflen); o += P->tapleaflen;
        o += crt_varint(wit + o, cl); memcpy(wit + o, ctrl, cl); o += cl;
        *witlen = o; *wititems = mi + 2;
        return NULL;
    }
    static unsigned char sigs[SRW_TAP_MAXKEYS][65]; int sl[SRW_TAP_MAXKEYS]; int got = 0;
    for (int a = 0; a < nk; a++){
        sl[a] = 0;
        if (got >= kth) continue;
        for (int b = 0; b < nkeys; b++){
            if (!ncomp[b] || memcmp(kpub[b] + 1, keys[a], 32)) continue;
            unsigned char aux[32], ab[64]; memcpy(ab, z, 32); memcpy(ab+32, kpriv[b], 32); sha256d(aux, ab, 64);
            if (!bip340_sign(sigs[a], z, 32, kpriv[b], aux)) return "schnorr signing failed";
            sl[a] = 64; if (tht != 0){ sigs[a][64] = (unsigned char)tht; sl[a] = 65; }
            got++; break;
        }
    }
    for (int a = 0; a < nk && got < kth; a++){                       /* slots we could not sign: partials from the PSBT */
        if (sl[a]) continue;
        for (int q = 0; q < P->n_tap_psig; q++){
            if (memcmp(P->tap_psig[q].x, keys[a], 32) || memcmp(P->tap_psig[q].lh, lh, 32)) continue;
            memcpy(sigs[a], P->tap_psig[q].sig, (size_t)P->tap_psig[q].sl); sl[a] = P->tap_psig[q].sl; got++; break;
        }
    }
    unsigned long o = 0; int items = 0;
    if (nk == 1 && kth == 1){ if (sl[0]){ wit[o++] = (unsigned char)sl[0]; memcpy(wit+o, sigs[0], sl[0]); o += sl[0]; items++; } }
    else { for (int a = nk - 1; a >= 0; a--){ wit[o++] = (unsigned char)sl[a]; if (sl[a]){ memcpy(wit+o, sigs[a], sl[a]); o += sl[a]; } items++; } }
    o += crt_varint(wit + o, P->tapleaflen); memcpy(wit + o, P->tapleaf, P->tapleaflen); o += P->tapleaflen; items++;
    o += crt_varint(wit + o, cl); memcpy(wit + o, ctrl, cl); o += cl; items++;
    *witlen = o; *wititems = items;
    if (got < kth){ static char mbuf[64]; snprintf(mbuf, sizeof mbuf, "Missing signatures: have %d of %d", got, kth); return mbuf; }
    return NULL;
}

static int srw_key_index(const unsigned char* key, int klen, unsigned char (*kpub)[33], const int* ncomp, int nkeys){
    for (int h = 0; h < nkeys; h++){
        if (klen == 33){ if (ncomp[h] && !memcmp(key, kpub[h], 33)) return h; }
        else { unsigned char u[65]; if (!ncomp[h] && bip32_pubkey_decompress(kpub[h], u) && !memcmp(key, u, 65)) return h; }
    }
    return -1;
}
/* DER signature + hashtype byte for sighash z under held key h */
static int srw_ecdsa(unsigned char* der, const unsigned char z[32], const unsigned char priv[32], int hashtype){
    unsigned long long r[4], sv[4]; wallet_ecdsa_sign(r, sv, z, priv);
    int dl = der_signature_export(der, r, sv); der[dl++] = (unsigned char)hashtype; return dl;
}
/* the signatures we can produce for a multisig script (key order, at most k); returns how many */
static int srw_multisig_sigs(unsigned char (*sigs)[80], int* siglens, int k, const unsigned char* keys[], const int* keylen, int n,
                             const unsigned char z[32], unsigned char (*kpriv)[32], unsigned char (*kpub)[33], const int* ncomp, int nkeys, int hashtype){
    int got = 0;
    for (int i = 0; i < n && got < k; i++){
        int h = srw_key_index(keys[i], keylen[i], kpub, ncomp, nkeys);
        if (h < 0) continue;
        siglens[got] = srw_ecdsa(sigs[got], z, kpriv[h], hashtype); got++;
    }
    return got;
}
/* push data with a minimal length prefix (< 0x4c, else OP_PUSHDATA1/2) */
static unsigned long srw_push(unsigned char* o, const unsigned char* d, unsigned long n){
    unsigned long w = 0;
    if (n < 0x4c) o[w++] = (unsigned char)n;
    else if (n <= 0xff){ o[w++] = 0x4c; o[w++] = (unsigned char)n; }
    else { o[w++] = 0x4d; o[w++] = (unsigned char)n; o[w++] = (unsigned char)(n >> 8); }
    memcpy(o + w, d, n); return w + n;
}
/* BIP341 key-path sighash (ext_flag 0, no annex) for input i. prev_of[j] is
 * the prevtx of input j (all needed unless ANYONECANPAY). 1 ok / 0 missing data. */
static int srw_tap_sighash(unsigned char z[32], const unsigned char* tx, unsigned long txlen,
                           unsigned long i, unsigned long n_in, const unsigned char* const* outpoints, const unsigned* seqs,
                           srw_prev_t* const* prev_of, unsigned long out_start, unsigned long out_end,
                           unsigned long locktime, int hashtype, const unsigned char* leafhash /* NULL = key path */){
    int base = hashtype & 3, acp = hashtype & 0x80;
    if (hashtype != 0 && !(base == 1 || base == 2 || base == 3)) return 0;   /* DEFAULT, ALL, NONE, SINGLE (+ACP) */
    unsigned char* msg = malloc(300 + txlen); if (!msg) return 0; unsigned long m = 0;
    msg[m++] = 0x00;                                   /* epoch */
    msg[m++] = (unsigned char)hashtype;
    memcpy(msg + m, tx, 4); m += 4;                    /* nVersion */
    msg[m++] = (unsigned char)locktime; msg[m++] = (unsigned char)(locktime >> 8); msg[m++] = (unsigned char)(locktime >> 16); msg[m++] = (unsigned char)(locktime >> 24);
    if (!acp){
        for (unsigned long j = 0; j < n_in; j++) if (!prev_of[j]){ free(msg); return 0; }
        unsigned char* b = malloc(n_in * 36 + 64 * n_in + 16); if (!b){ free(msg); return 0; }
        unsigned long bl = 0;
        for (unsigned long j = 0; j < n_in; j++){ memcpy(b + bl, outpoints[j], 36); bl += 36; }
        sha256_full(msg + m, b, bl); m += 32;                                   /* sha_prevouts */
        bl = 0; for (unsigned long j = 0; j < n_in; j++){ unsigned long long a = prev_of[j]->amount; for (int q = 0; q < 8; q++) b[bl++] = (unsigned char)(a >> (8*q)); }
        sha256_full(msg + m, b, bl); m += 32;                                   /* sha_amounts */
        bl = 0; for (unsigned long j = 0; j < n_in; j++){ bl += crt_varint(b + bl, prev_of[j]->spklen); memcpy(b + bl, prev_of[j]->spk, prev_of[j]->spklen); bl += prev_of[j]->spklen; }
        sha256_full(msg + m, b, bl); m += 32;                                   /* sha_scriptpubkeys */
        bl = 0; for (unsigned long j = 0; j < n_in; j++){ unsigned sq = seqs[j]; b[bl++] = (unsigned char)sq; b[bl++] = (unsigned char)(sq >> 8); b[bl++] = (unsigned char)(sq >> 16); b[bl++] = (unsigned char)(sq >> 24); }
        sha256_full(msg + m, b, bl); m += 32;                                   /* sha_sequences */
        free(b);
    }
    unsigned long cc; unsigned long n_out = srw_varint(tx + out_start, &cc);
    const unsigned char* outs = tx + out_start + cc; unsigned long outs_len = out_end - (out_start + cc);
    if (base != 2 && base != 3){ sha256_full(msg + m, outs, outs_len); m += 32; }   /* sha_outputs */
    msg[m++] = leafhash ? 0x02 : 0x00;                 /* spend_type: ext_flag (1 = tapscript) * 2 + annex (never) */
    if (acp){
        if (!prev_of[i]){ free(msg); return 0; }
        memcpy(msg + m, outpoints[i], 36); m += 36;
        unsigned long long a = prev_of[i]->amount; for (int q = 0; q < 8; q++) msg[m++] = (unsigned char)(a >> (8*q));
        m += crt_varint(msg + m, prev_of[i]->spklen); memcpy(msg + m, prev_of[i]->spk, prev_of[i]->spklen); m += prev_of[i]->spklen;
        unsigned sq = seqs[i]; msg[m++] = (unsigned char)sq; msg[m++] = (unsigned char)(sq >> 8); msg[m++] = (unsigned char)(sq >> 16); msg[m++] = (unsigned char)(sq >> 24);
    } else { msg[m++] = (unsigned char)i; msg[m++] = (unsigned char)(i >> 8); msg[m++] = (unsigned char)(i >> 16); msg[m++] = (unsigned char)(i >> 24); }
    if (base == 3){                                    /* SINGLE: sha256 of this input's output */
        if (i >= n_out){ free(msg); return 0; }
        const unsigned char* q = outs; unsigned long left = outs_len;
        for (unsigned long oi = 0; ; oi++){
            if (left < 9){ free(msg); return 0; }
            unsigned long c2; unsigned long sl = srw_varint(q + 8, &c2); unsigned long olen = 8 + c2 + sl;
            if (olen > left){ free(msg); return 0; }
            if (oi == i){ sha256_full(msg + m, q, olen); m += 32; break; }
            q += olen; left -= olen;
        }
    }
    if (leafhash){                                     /* BIP342 extension: tapleaf_hash, key_version, codesep_pos */
        memcpy(msg + m, leafhash, 32); m += 32;
        msg[m++] = 0x00;
        msg[m++] = 0xff; msg[m++] = 0xff; msg[m++] = 0xff; msg[m++] = 0xff;
    }
    /* TaggedHash("TapSighash", msg) */
    unsigned char th[32]; sha256_full(th, "TapSighash", 10);
    unsigned char* pre = malloc(64 + m); if (!pre){ free(msg); return 0; }
    memcpy(pre, th, 32); memcpy(pre + 32, th, 32); memcpy(pre + 64, msg, m);
    sha256_full(z, pre, 64 + m);
    free(pre); free(msg);
    return 1;
}

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

/* sign a P2WSH input: witnessScript = CHECKMULTISIG template (witness: <> sigs... ws)
 * or <pub> OP_CHECKSIG (witness: sig ws). NULL on success, else the error. */
static const char* srw_sign_wsh(const srw_prev_t* P, unsigned char* wit, unsigned long* witlen, int* wititems,
                                const unsigned char* tx, const unsigned char hp[32], const unsigned char hs[32],
                                const unsigned char outpoint36[36], unsigned seq, const unsigned char ho[32], unsigned long locktime, int hashtype,
                                unsigned char (*kpriv)[32], unsigned char (*kpub)[33], const int* ncomp, int nkeys){
    const unsigned char* ws=P->wscript; unsigned long wl=P->wscriptlen;
    unsigned char z[32]; srw_bip143(z, tx, hp, hs, outpoint36, ws, wl, P->amount, seq, ho, locktime, hashtype);
    unsigned long o=0;
    if (wl==35 && ws[0]==33 && ws[34]==0xac){                                   /* <pub> CHECKSIG */
        int h=srw_key_index(ws+1,33,kpub,ncomp,nkeys); if (h<0) return "Keys not provided for this input";
        unsigned char der[80]; int dl=srw_ecdsa(der,z,kpriv[h],hashtype);
        wit[o++]=(unsigned char)dl; memcpy(wit+o,der,(size_t)dl); o+=dl;
        o+=crt_varint(wit+o,wl); memcpy(wit+o,ws,wl); o+=wl; *witlen=o; *wititems=2; return NULL;   /* witness items are varint-prefixed, not script pushes */
    }
    int k; const unsigned char* keys[20]; int kl[20]; int n=srw_parse_multisig(ws,wl,&k,keys,kl);
    if (n<0){
        /* miniscript (2026-09-01): the satisfier builds the witness from the keys we hold, the
         * PSBT's preimages and the tx's timelock fields; the witnessScript is appended here */
        const char* merr=NULL; unsigned long ml=0; int mi=0;
        int r=ms_sign_witness_v0(ws,wl,z,hashtype,seq,locktime,kpriv,kpub,ncomp,nkeys,(const unsigned char (*)[33])P->pubs,P->npubs,&P->pre,wit,SRW_WITCAP-(3+wl),&ml,&mi,&merr);
        if (r==1){ o=ml; o+=crt_varint(wit+o,wl); memcpy(wit+o,ws,wl); o+=wl; *witlen=o; *wititems=mi+1; return NULL; }
        if (r==-1) return merr;
        return "Unsupported witnessScript (CHECKMULTISIG, <pub> CHECKSIG or miniscript only)";
    }
    unsigned char sigs[20][80]; int sls[20];
    int got=srw_multisig_sigs(sigs,sls,k,keys,kl,n,z,kpriv,kpub,ncomp,nkeys,hashtype);
    wit[o++]=0x00;                                                              /* the empty dummy element */
    for (int q=0;q<got;q++){ wit[o++]=(unsigned char)sls[q]; memcpy(wit+o,sigs[q],(size_t)sls[q]); o+=sls[q]; }
    o+=crt_varint(wit+o,wl); memcpy(wit+o,ws,wl); o+=wl; *witlen=o; *wititems=2+got;
    if (got<k){ static char mbuf[64]; snprintf(mbuf,sizeof mbuf,"Missing signatures: have %d of %d",got,k); return mbuf; }
    return NULL;
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
    /* 512 keys: the wallet signer hands over its whole window for every
     * active output type (4 types x 2 chains x SRWW_WINDOW); the old cap of
     * 64 silently dropped the 49'/86' keys. Static: the RPC thread's stack
     * is small (see project_tls_thread_stacks). */
    #define SRW_MAX_KEYS 512
    int nk=(int)pk->nitems; if (nk>SRW_MAX_KEYS) nk=SRW_MAX_KEYS;
    static unsigned char kpriv[SRW_MAX_KEYS][32]; static unsigned char kpub[SRW_MAX_KEYS][33]; static unsigned char kh[SRW_MAX_KEYS][20]; static int ncomp[SRW_MAX_KEYS]; int nkeys=0;
    for (int i=0;i<(int)pk->nitems && nkeys<SRW_MAX_KEYS;i++){
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
            rj_val* ws=rj_obj_get(e,"witnessScript"); P->wscriptlen=0;
            if (ws&&ws->typ==RJ_STR){ size_t wl=strlen(ws->str); if (!(wl&1)&&wl/2<=sizeof P->wscript){ P->wscriptlen=(unsigned long)(wl/2); hex_to_bytes(P->wscript,ws->str,wl); } }
            P->tapleaflen=0; P->tapctrllen=0; P->has_merkle=0; P->has_internal=0;
            { rj_val* tl=rj_obj_get(e,"tapLeafScript"); rj_val* tc=rj_obj_get(e,"tapControlBlock");
              if (tl&&tl->typ==RJ_STR&&tc&&tc->typ==RJ_STR){ size_t a=strlen(tl->str), b=strlen(tc->str);
                  if (!(a&1)&&a/2<=sizeof P->tapleaf&&!(b&1)&&b/2>=33&&b/2<=sizeof P->tapctrl&&((b/2-33)%32)==0
                      &&hex_to_bytes(P->tapleaf,tl->str,a)&&hex_to_bytes(P->tapctrl,tc->str,b)){ P->tapleaflen=a/2; P->tapctrllen=b/2; } }
              rj_val* tm=rj_obj_get(e,"tapMerkleRoot"); if (tm&&tm->typ==RJ_STR&&strlen(tm->str)==64&&hex_to_bytes(P->tapmerkle,tm->str,64)) P->has_merkle=1;
              rj_val* ti=rj_obj_get(e,"tapInternalKey"); if (ti&&ti->typ==RJ_STR&&strlen(ti->str)==64&&hex_to_bytes(P->tapinternal,ti->str,64)) P->has_internal=1;
              P->n_tap_psig=0; P->tap_keysig_len=0;
              rj_val* tp=rj_obj_get(e,"tapPartialSigs");
              if (tp&&tp->typ==RJ_ARR){ for (unsigned long q=0;q<tp->nitems&&P->n_tap_psig<32;q++){ rj_val* d=tp->items[q]; if (d->typ!=RJ_OBJ) continue;
                  rj_val* px=rj_obj_get(d,"pubkey"); rj_val* pl=rj_obj_get(d,"leaf_hash"); rj_val* pg=rj_obj_get(d,"sig");
                  if (!px||!pl||!pg||px->typ!=RJ_STR||pl->typ!=RJ_STR||pg->typ!=RJ_STR||strlen(px->str)!=64||strlen(pl->str)!=64) continue;
                  size_t gl=strlen(pg->str); if (gl!=128&&gl!=130) continue;
                  int n2=P->n_tap_psig; if (!hex_to_bytes(P->tap_psig[n2].x,px->str,64)||!hex_to_bytes(P->tap_psig[n2].lh,pl->str,64)||!hex_to_bytes(P->tap_psig[n2].sig,pg->str,gl)) continue;
                  P->tap_psig[n2].sl=(int)(gl/2); P->n_tap_psig++; } }
              rj_val* tk=rj_obj_get(e,"tapKeySig"); if (tk&&tk->typ==RJ_STR&&(strlen(tk->str)==128||strlen(tk->str)==130)&&hex_to_bytes(P->tap_keysig,tk->str,strlen(tk->str))) P->tap_keysig_len=(int)(strlen(tk->str)/2); }
            /* "preimages": [{"hash":hex20|hex32,"preimage":hex32},...] -- what a PSBT's
             * PSBT_IN_*_PREIMAGES fields carry, for miniscript hash challenges */
            /* "pubkeys": [hex33,...] -- keys a descriptor names without a private key (pk_h needs them) */
            rj_val* pk2=rj_obj_get(e,"pubkeys"); P->npubs=0;
            if (pk2&&pk2->typ==RJ_ARR){ for (size_t q=0;q<pk2->nitems&&P->npubs<64;q++){ rj_val* v=pk2->items[q]; if (v->typ!=RJ_STR||strlen(v->str)!=66) continue; if (hex_to_bytes(P->pubs[P->npubs],v->str,66)) P->npubs++; } }
            rj_val* pm=rj_obj_get(e,"preimages"); P->pre.n=0;
            if (pm&&pm->typ==RJ_ARR){
                for (size_t q=0;q<pm->nitems&&P->pre.n<MS_PRE_MAX;q++){
                    rj_val* po=pm->items[q]; if (po->typ!=RJ_OBJ) continue;
                    rj_val* h=rj_obj_get(po,"hash"); rj_val* pr=rj_obj_get(po,"preimage");
                    if (!h||h->typ!=RJ_STR||!pr||pr->typ!=RJ_STR) continue;
                    size_t hl=strlen(h->str), pl=strlen(pr->str);
                    if ((hl!=40&&hl!=64)||pl!=64) continue;
                    int m=P->pre.n;
                    if (!hex_to_bytes(P->pre.hash[m],h->str,hl)||!hex_to_bytes(P->pre.pre[m],pr->str,pl)) continue;
                    P->pre.hlen[m]=(int)(hl/2); P->pre.n++;
                }
            }
            nprev++;
        }
    }
    int hashtype = (params->nitems>=4 && params->items[3]->typ==RJ_STR) ? srw_hashtype(params->items[3]->str) : 0x01;
    int ht_explicit = (params->nitems>=4 && params->items[3]->typ==RJ_STR);   /* taproot signs SIGHASH_DEFAULT unless one was asked for */
    if (hashtype<0){ *ec=-8; *em="Invalid sighash param"; return 0; }
    if (hashtype==0x100){ hashtype=0x01; ht_explicit=0; }                     /* "DEFAULT": ALL for ECDSA, no hashtype byte for taproot */

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
    static unsigned char ss[10000][1400]; unsigned long sslen[10000];      /* scriptSig per input (a 3-sig P2SH multisig is ~330 bytes) */
    static unsigned char witbuf[10000][SRW_WITCAP]; unsigned long witlen[10000]; int wititems[10000]; /* witness items (the count goes in front at assembly) */
    /* prevtx of every input, for the taproot sighash (which commits to all spent outputs) */
    static srw_prev_t* prev_of[10000];
    for (unsigned long i=0;i<n_in;i++){
        prev_of[i]=NULL;
        unsigned long vo=(unsigned long)in_outpoint[i][32]|((unsigned long)in_outpoint[i][33]<<8)|((unsigned long)in_outpoint[i][34]<<16)|((unsigned long)in_outpoint[i][35]<<24);
        for (int k=0;k<nprev;k++) if (prev[k].vout==vo && !memcmp(prev[k].txid_wire,in_outpoint[i],32)){ prev_of[i]=&prev[k]; break; }
    }
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
            } else if (sl==23 && spk[0]==0xa9&&spk[1]==0x14&&spk[22]==0x87 && P->redeemlen>0){     /* P2SH: P2SH-P2WSH or legacy multisig */
                unsigned char rh[20]; hash160(rh,P->redeem,P->redeemlen);
                if (memcmp(rh,spk+2,20)){ err="redeemScript does not match scriptPubKey"; }
                else if (P->redeemlen==34 && P->redeem[0]==0x00 && P->redeem[1]==0x20){                 /* P2SH-P2WSH */
                    if (!P->wscriptlen) err="witnessScript needed for P2SH-P2WSH";
                    else { unsigned char wh[32]; sha256_full(wh,P->wscript,P->wscriptlen);
                        if (memcmp(wh,P->redeem+2,32)) err="witnessScript does not match redeemScript";
                        else { err=srw_sign_wsh(P, witbuf[i], &witlen[i], &wititems[i], tx, bip_hp, bip_hs, in_outpoint[i], in_seq[i], bip_ho, locktime, hashtype, kpriv, kpub, ncomp, nkeys);
                               if (!err || strstr(err,"Missing signatures")){ sslen[i]=srw_push(ss[i],P->redeem,P->redeemlen); any_segwit=1; } } }
                } else {                                                                                  /* legacy P2SH multisig */
                    int k; const unsigned char* keys[20]; int kl[20]; int n=srw_parse_multisig(P->redeem,P->redeemlen,&k,keys,kl);
                    if (n<0) err="Unsupported redeemScript (CHECKMULTISIG, P2WPKH or P2WSH only)";
                    else if (!legacy_sighash(z,tx,txlen,i,P->redeem,P->redeemlen,hashtype,pre,(unsigned long)txlen+8192)) err="sighash failed";
                    else { unsigned char sigs[20][80]; int sls[20];
                        int got=srw_multisig_sigs(sigs,sls,k,keys,kl,n,z,kpriv,kpub,ncomp,nkeys,hashtype);
                        unsigned long o=0; ss[i][o++]=0x00;                                             /* CHECKMULTISIG's dummy */
                        for (int q=0;q<got;q++) o+=srw_push(ss[i]+o,sigs[q],(unsigned long)sls[q]);
                        o+=srw_push(ss[i]+o,P->redeem,P->redeemlen); sslen[i]=o;
                        if (got<k){ static char mbuf[64]; snprintf(mbuf,sizeof mbuf,"Missing signatures: have %d of %d",got,k); err=mbuf; } }
                }
            } else if (sl==34 && spk[0]==0x00 && spk[1]==0x20){                                          /* P2WSH */
                if (!P->wscriptlen) err="witnessScript needed for P2WSH";
                else { unsigned char wh[32]; sha256_full(wh,P->wscript,P->wscriptlen);
                    if (memcmp(wh,spk+2,32)) err="witnessScript does not match scriptPubKey";
                    else { err=srw_sign_wsh(P, witbuf[i], &witlen[i], &wititems[i], tx, bip_hp, bip_hs, in_outpoint[i], in_seq[i], bip_ho, locktime, hashtype, kpriv, kpub, ncomp, nkeys);
                           if (!err || strstr(err,"Missing signatures")) any_segwit=1; } }
            } else if (sl==34 && spk[0]==0x51 && spk[1]==0x20 && P->tapleaflen){                        /* P2TR script path: a leaf + control block were supplied */
                int tht = ht_explicit ? hashtype : 0x00;
                err=srw_sign_tap_script(P, spk, witbuf[i], &witlen[i], &wititems[i], tx, txlen, i, n_in, (const unsigned char* const*)in_outpoint, in_seq, prev_of, out_start, out_end, locktime, tht, kpriv, kpub, ncomp, nkeys);
                if (!err || strstr(err,"Missing signatures")) any_segwit=1;
            } else if (sl==34 && spk[0]==0x51 && spk[1]==0x20){                                          /* P2TR key path: tr(KEY) with no tree, or with the merkle root supplied */
                unsigned char tweak[32];
                for (int k=0;k<nkeys;k++){
                    if (!ncomp[k]) continue;
                    if (P->has_internal && memcmp(kpub[k]+1,P->tapinternal,32)) continue;
                    unsigned char t[32]; srw_taptweak(t,kpub[k]+1,P->has_merkle?P->tapmerkle:NULL);
                    unsigned char q[32]; if (bip32_xonly_tweak_add(kpub[k]+1,t,q) && !memcmp(q,spk+2,32)){ found=k; memcpy(tweak,t,32); break; }
                }
                if (found<0 && P->tap_keysig_len){                                                    /* already signed by another signer: carry it */
                    unsigned long o=0; witbuf[i][o++]=(unsigned char)P->tap_keysig_len; memcpy(witbuf[i]+o,P->tap_keysig,(size_t)P->tap_keysig_len); o+=P->tap_keysig_len;
                    witlen[i]=o; wititems[i]=1; any_segwit=1; }
                else if (found<0) err=P->has_merkle ? "Keys not provided for this input (a P2TR key path with a script tree needs its internal key)"
                                               : "Keys not provided for this input (a P2TR key path needs the internal key of tr(KEY) with no script tree)";
                else { int tht = ht_explicit ? hashtype : 0x00;
                    if (!srw_tap_sighash(z,tx,txlen,i,n_in,(const unsigned char* const*)in_outpoint,in_seq,prev_of,out_start,out_end,locktime,tht,NULL))
                        err="P2TR sighash needs scriptPubKey and amount for every input";
                    else { unsigned char dq[32], aux[32], sig[65];
                        if (!bip340_tweak_privkey(dq,kpriv[found],tweak)) err="taproot tweak failed";
                        else { unsigned char ab[64]; memcpy(ab,z,32); memcpy(ab+32,dq,32); sha256d(aux,ab,64);   /* deterministic aux, as the ECDSA nonce is */
                            if (!bip340_sign(sig,z,32,dq,aux)) err="schnorr signing failed";
                            else { int sl2=64; if (tht!=0){ sig[64]=(unsigned char)tht; sl2=65; }
                                unsigned long o=0; witbuf[i][o++]=(unsigned char)sl2; memcpy(witbuf[i]+o,sig,(size_t)sl2); o+=sl2; witlen[i]=o; wititems[i]=1; any_segwit=1; } } } }
            } else {
                err="Unsupported script type (bare multisig / P2TR script-path signing not implemented)";
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
/* ==== wallet-state RPCs over the transaction journal ======================
 * (wallet_txlog.c: BMCTX v1, append-only, crc-guarded records of every send
 * the wallet made.) VERIFICATION BOUND, stated plainly: there is no oracle
 * wallet to diff against, so these are verified by round-trip -- a journal
 * written through the REAL txlog_append is read back through these RPCs --
 * and the field set is the honest subset the journal actually holds:
 *   - only "send" category records exist (the journal records sends);
 *   - confirmations is 0 and no blockhash/blockheight fields are emitted
 *     (the journal does not track confirmations -- absent, never invented);
 *   - amounts follow Core's sign conventions (send amount and fee negative);
 *   - the journal stores txids in INTERNAL byte order; these RPCs emit
 *     display order like every other txid in the API. */
static void wsl_add_lastprocessedblock(rj_val* o);   /* defined below */
static int wsl_hexb(const char* h, unsigned char* out, int n){
    for (int i=0;i<n;i++){ int a=0,b=0; char c=h[i*2], d=h[i*2+1];
        if(c>='0'&&c<='9')a=c-'0'; else if(c>='a'&&c<='f')a=c-'a'+10; else return 0;
        if(d>='0'&&d<='9')b=d-'0'; else if(d>='a'&&d<='f')b=d-'a'+10; else return 0;
        out[i]=(unsigned char)((a<<4)|b); }
    return 1;
}
typedef struct { unsigned long long ts; unsigned char txid[32];
                 long long amount, fee; unsigned char dest[20];
                 unsigned long inputs; long rawlen; } wsl_rec_t;
static unsigned long wsl_crc(const char* s, long n){
    unsigned long h = 2166136261UL;
    for (long i=0;i<n;i++){ h ^= (unsigned char)s[i]; h *= 16777619UL; }
    return h;
}
/* parse the journal (default path in the daemon's cwd/datadir); crc-bad or
 * torn lines are skipped exactly as the tool-side reader philosophy demands
 * -- a torn record is absent data, not data. Returns records found. */
static int wsl_read(wsl_rec_t* recs, int cap){
    extern const char* rpc_wops_walletdir(void);
    char wdl[600]; snprintf(wdl, sizeof wdl, "%s/bmcwallet.dat.txlog", rpc_wops_walletdir()[0] ? rpc_wops_walletdir() : ".");
    const char* candidates[3] = { wdl, "bmcwallet.dat.txlog", "data/bmcwallet.dat.txlog" };
    FILE* f = 0;
    for (int i=0;i<3 && !f;i++) f = fopen(candidates[i], "r");
    if (!f) return 0;
    char line[600]; int n = 0;
    while (n < cap && fgets(line, sizeof line, f)){
        if (line[0]=='#' || line[0]=='\n' || !strncmp(line,"BMCTX",5)) continue;
        char txh[80], desth[48], crch[16];
        wsl_rec_t r;
        int got = sscanf(line, "%llu sent %79s %lld %lld %47s %lu %ld %15s",
                         &r.ts, txh, &r.amount, &r.fee, desth, &r.inputs, &r.rawlen, crch);
        if (got != 8 || strlen(txh)!=64 || strlen(desth)!=40) continue;
        /* crc over the 8-field prefix exactly as the writer computed it */
        { char pre[512];
          int pl = snprintf(pre, sizeof pre, "%llu sent %s %lld %lld %s %lu %ld",
                            r.ts, txh, r.amount, r.fee, desth, r.inputs, r.rawlen);
          char want[16]; snprintf(want, sizeof want, "%08lx", wsl_crc(pre, pl));
          if (strcmp(want, crch)) continue; }
        if (!wsl_hexb(txh, r.txid, 32) || !wsl_hexb(desth, r.dest, 20)) continue;
        recs[n++] = r;
    }
    fclose(f);
    return n;
}
#define WSL_MAX 4096
static rj_val* wsl_entry(const wsl_rec_t* r){
    rj_val* e = rj_obj();
    /* dest h160 -> its P2PKH address via the same helper every other RPC uses */
    { unsigned char spk[25];
      spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, r->dest, 20); spk[23]=0x88; spk[24]=0xac;
      char addr[128]; addr[0]=0;
      if (wallet_script_to_address(addr, sizeof addr, spk, 25) > 0 && addr[0])
          rj_obj_set(e, "address", rj_str(addr)); }
    rj_obj_set(e, "category", rj_str("send"));
    /* Core emits `vout` on every entry. The journal records a destination
     * but not which output index it landed at, so this is 0 -- the honest
     * value for "not recorded", and the same convention getpeerinfo uses
     * for counters this node does not track. */
    rj_obj_set(e, "vout", rj_numf("%d", 0));
    { char am[32]; rpc_amounts(-r->amount, am, sizeof am); rj_obj_set(e, "amount", rj_numf("%s", am)); }
    { char fe[32]; rpc_amounts(-r->fee, fe, sizeof fe); rj_obj_set(e, "fee", rj_numf("%s", fe)); }
    rj_obj_set(e, "confirmations", rj_numf("%d", 0));   /* journal tracks none */
    { char hx[65]; static const char* HD="0123456789abcdef";
      for (int k=0;k<32;k++){ unsigned char b=r->txid[31-k]; hx[k*2]=HD[b>>4]; hx[k*2+1]=HD[b&15]; }
      hx[64]=0; rj_obj_set(e, "txid", rj_str(hx)); }
    rj_obj_set(e, "time", rj_numf("%llu", r->ts));
    rj_obj_set(e, "timereceived", rj_numf("%llu", r->ts));
    { rj_val* wc = rj_arr(); rj_obj_set(e, "walletconflicts", wc); }
    { rj_val* mc = rj_arr(); rj_obj_set(e, "mempoolconflicts", mc); }
    rj_obj_set(e, "abandoned", rj_bool(0));
    /* NOT emitted, because the journal does not record them and inventing
     * them would be worse than their absence (oracle-diffed 2026-08-25
     * against a wallet-enabled Core):
     *   blockhash/blockheight/blockindex/blocktime -- the journal stores no
     *     confirmation data at all, which is the same reason confirmations
     *     is 0 above;
     *   wtxid -- the journal stores the txid only, and for a segwit send
     *     the wtxid is NOT derivable from it;
     *   label / parent_descs -- this store has no labels and no descriptor
     *     provenance.
     * Each becomes emittable if the journal format grows the field; that is
     * a store-format change, deliberately not smuggled in here. */
    return e;
}
/* listtransactions ("label" count skip): newest LAST like Core; count default
 * 10, skip from the end (Core semantics: the last `count` after skipping
 * `skip` most recent). */
static int cmd_listtransactions(const rj_val* params, long* ec, const char** em, rj_val** result){
    (void)ec; (void)em;
    long count = 10, skip = 0;
    if (params && params->typ==RJ_ARR){
        if (params->nitems>=2 && params->items[1]->typ==RJ_NUM) count = atol(params->items[1]->str);
        if (params->nitems>=3 && params->items[2]->typ==RJ_NUM) skip = atol(params->items[2]->str);
    }
    if (count < 0){ *ec=-8; *em="Negative count"; return 0; }
    if (skip < 0){ *ec=-8; *em="Negative from"; return 0; }
    static wsl_rec_t recs[WSL_MAX];
    int n = wsl_read(recs, WSL_MAX);
    long hi = n - skip;            /* exclusive end after skipping most recent */
    long lo = hi - count;
    if (lo < 0) lo = 0;
    rj_val* arr = rj_arr();
    for (long i = lo; i < hi; i++) rj_arr_push(arr, wsl_entry(&recs[i]));
    *result = arr;
    return 1;
}
static int cmd_gettransaction(const rj_val* params, long* ec, const char** em, rj_val** result){
    if (!params || params->typ!=RJ_ARR || params->nitems<1 || params->items[0]->typ!=RJ_STR ||
        strlen(params->items[0]->str)!=64){
        *ec=-8; *em="Invalid txid"; return 0; }
    unsigned char want[32];
    { unsigned char disp[32];
      if (!wsl_hexb(params->items[0]->str, disp, 32)){ *ec=-8; *em="Invalid txid"; return 0; }
      for (int i=0;i<32;i++) want[i] = disp[31-i]; }         /* display -> internal */
    static wsl_rec_t recs[WSL_MAX];
    int n = wsl_read(recs, WSL_MAX);
    for (int i = n-1; i >= 0; i--){
        if (memcmp(recs[i].txid, want, 32)) continue;
        rj_val* o = rj_obj();
        { char am[32]; rpc_amounts(-recs[i].amount, am, sizeof am); rj_obj_set(o, "amount", rj_numf("%s", am)); }
        { char fe[32]; rpc_amounts(-recs[i].fee, fe, sizeof fe); rj_obj_set(o, "fee", rj_numf("%s", fe)); }
        rj_obj_set(o, "confirmations", rj_numf("%d", 0));
        rj_obj_set(o, "txid", rj_str(params->items[0]->str));
        { rj_val* wc = rj_arr(); rj_obj_set(o, "walletconflicts", wc); }
        { rj_val* mc = rj_arr(); rj_obj_set(o, "mempoolconflicts", mc); }
        rj_obj_set(o, "time", rj_numf("%llu", recs[i].ts));
        rj_obj_set(o, "timereceived", rj_numf("%llu", recs[i].ts));
        /* ORACLE-DIFFED 2026-08-25: Core's gettransaction.details[] entries
         * are a REDUCED shape -- {address, category, amount, vout, label,
         * parent_descs, abandoned} -- NOT a copy of a listtransactions
         * entry. We had been pushing the full entry, which meant details[0]
         * carried six fields Core never puts there (txid, time,
         * timereceived, confirmations, walletconflicts, fee): those belong
         * to the top-level object, and repeating them there is a shape
         * Core consumers do not expect. */
        { rj_val* det = rj_arr();
          rj_val* d = rj_obj();
          { unsigned char spk[25];
            spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, recs[i].dest, 20);
            spk[23]=0x88; spk[24]=0xac;
            char addr[128]; addr[0]=0;
            if (wallet_script_to_address(addr, sizeof addr, spk, 25) > 0 && addr[0])
                rj_obj_set(d, "address", rj_str(addr)); }
          rj_obj_set(d, "category", rj_str("send"));
          { char am[32]; rpc_amounts(-(long long)recs[i].amount, am, sizeof am);
            rj_obj_set(d, "amount", rj_numf("%s", am)); }
          rj_obj_set(d, "vout", rj_numf("%d", 0));
          { char fe[32]; rpc_amounts(-(long long)recs[i].fee, fe, sizeof fe);
            rj_obj_set(d, "fee", rj_numf("%s", fe)); }   /* Core: sends only */
          rj_obj_set(d, "abandoned", rj_bool(0));
          rj_arr_push(det, d);
          rj_obj_set(o, "details", det); }
        /* bumpfee linkage (rpc_wallet_ops.c's bumped.dat sidecar): Core
         * reports replaced_by_txid / replaces_txid from mapWallet; ours
         * come from the sidecar the bump wrote. Absent = no field, like
         * Core omitting them for an unreplaced tx. */
        { extern int rpc_wops_bump_link(const char*, char*, size_t, char*, size_t);
          char rb[80], rp[80];
          if (rpc_wops_bump_link(params->items[0]->str, rb, sizeof rb, rp, sizeof rp)){
              if (rb[0]) rj_obj_set(o, "replaced_by_txid", rj_str(rb));
              if (rp[0]) rj_obj_set(o, "replaces_txid", rj_str(rp));
          } }
        wsl_add_lastprocessedblock(o);
        *result = o;
        return 1;
    }
    *ec = -5; *em = "Invalid or non-wallet transaction id";
    return 0;
}
/* Core stamps every wallet answer with the chain state it was computed
 * against (`lastprocessedblock`: hash + height), so a caller can tell a
 * stale reply from a current one. We can supply it honestly -- the chain
 * module owns the tip -- by asking the SAME dispatch a client would, which
 * keeps this a one-way dependency (wallet -> chain) with no new coupling.
 * Omitted entirely if the chain is not open, rather than reported as zero. */
static void wsl_add_lastprocessedblock(rj_val* o){
    rj_val* h = NULL; long ec; const char* em;
    if (rpc_chain_dispatch("getbestblockhash", NULL, &h, &ec, &em) != 1 || !h) return;
    rj_val* c = NULL;
    if (rpc_chain_dispatch("getblockcount", NULL, &c, &ec, &em) != 1 || !c){ rj_free(h); return; }
    rj_val* lpb = rj_obj();
    rj_obj_set(lpb, "hash", rj_str(h->str));
    rj_obj_set(lpb, "height", rj_numf("%s", c->str));
    rj_obj_set(o, "lastprocessedblock", lpb);
    rj_free(h); rj_free(c);
}

/* getwalletinfo -- ORACLE-DIFFED 2026-08-25 against a wallet-enabled Core.
 * The scratch oracle ran with disablewallet=1 until then, which is why this
 * shipped round-trip-verified only; enabling it (one config line -- the
 * binary always had wallet support) turned the hedge into a real diff, and
 * the diff found two things:
 *   1. Core's modern getwalletinfo carries NO balance fields at all --
 *      balance / unconfirmed_balance / immature_balance / paytxfee were
 *      removed when getbalances took over. We were emitting four fields
 *      Core does not have.
 *   2. Core emits blank / birthtime / flags / lastprocessedblock (plus
 *      keypoolsize_hd_internal for wallets using internal keys); we emitted
 *      none of them.
 * Names and shape now follow Core. Values stay ours and honest:
 * walletversion 1 and format "bmc" deliberately say this is our own store,
 * not a Core wallet, and descriptors=false because there is no descriptor
 * wallet here. birthtime/lastprocessedblock are omitted rather than faked --
 * this store records neither. */
static int cmd_getwalletinfo(const rpc_wallet* w, rj_val** result){
    static wsl_rec_t recs[WSL_MAX];
    int n = wsl_read(recs, WSL_MAX);
    rj_val* o = rj_obj();
    { extern const char* rpc_wops_active_wallet_name(void);
      const char* wn = rpc_wops_active_wallet_name();
      rj_obj_set(o, "walletname", rj_str(wn ? wn : "")); }
    rj_obj_set(o, "walletversion", rj_numf("%d", 1));
    rj_obj_set(o, "format", rj_str("bmc"));
    rj_obj_set(o, "txcount", rj_numf("%d", n));
    rj_obj_set(o, "keypoolsize", rj_numf("%d", 0));
    rj_obj_set(o, "private_keys_enabled", rj_bool(w && w->seed ? 1 : 0));
    { extern int rpc_wops_avoid_reuse(void);
      rj_obj_set(o, "avoid_reuse", rj_bool(rpc_wops_avoid_reuse() ? 1 : 0)); }
    rj_obj_set(o, "scanning", rj_bool(0));
    { extern int rpc_wops_watchonly(void);
      rj_obj_set(o, "descriptors", rj_bool(rpc_wops_watchonly() ? 1 : 0)); }
    rj_obj_set(o, "external_signer", rj_bool(0));
    rj_obj_set(o, "blank", rj_bool(w && w->seed ? 0 : 1));
    { rj_val* fl = rj_arr(); rj_obj_set(o, "flags", fl); }
    wsl_add_lastprocessedblock(o);
    *result = o;
    return 1;
}

/* getbalances -- where Core keeps balances now (the fields removed from
 * getwalletinfo above). mine.{trusted,untrusted_pending,immature,
 * nonmempool}: the injected UTXO set is by definition confirmed and
 * spendable, so it lands in `trusted`; the rest are zero because this node
 * tracks no wallet mempool -- stated, not guessed. */
static int cmd_getbalances(const rpc_wallet* w, rj_val** result){
    unsigned long long bal = 0;
    if (w) for (unsigned long i = 0; i < w->utxo_n; i++) bal += w->utxo_val[i];
    rj_val* o = rj_obj();
    rj_val* mine = rj_obj();
    { char am[32]; rpc_amounts((long long)bal, am, sizeof am);
      rj_obj_set(mine, "trusted", rj_numf("%s", am)); }
    rj_obj_set(mine, "untrusted_pending", rj_numf("%.8f", 0.0));
    rj_obj_set(mine, "immature", rj_numf("%.8f", 0.0));
    rj_obj_set(mine, "nonmempool", rj_numf("%.8f", 0.0));
    rj_obj_set(o, "mine", mine);
    wsl_add_lastprocessedblock(o);
    *result = o;
    return 1;
}

/* ==== signrawtransactionwithwallet ========================================
 * Core: sign whatever inputs of a raw tx the WALLET holds keys for, and
 * report per-input errors for the rest. That is exactly
 * signrawtransactionwithkey with the key list sourced from the wallet
 * instead of the caller, so this builds the key list and delegates rather
 * than growing a second signer that could drift from the first. The
 * delegate already handles legacy, P2SH, BIP143 v0 and P2SH-wrapped v0, so
 * nothing is lost by the reuse.
 *
 * BOUNDED KEY WINDOW. The wallet derives keys on demand, so "the wallet's
 * keys" is not a finite set. getnewaddress/getrawchangeaddress hand out
 * index 0, and the CLI can be asked for an explicit index, so the window is
 * indexes 0..SRWW_WINDOW-1 across both the receive and change branches.
 * An input funded beyond that window is NOT silently skipped -- it lands in
 * the `errors` array with complete:false, which is Core's own shape for an
 * input it could not sign. */
#define SRWW_WINDOW 20

static void srww_wif(char out[64], const unsigned char priv[32]){
    unsigned char pay[34];
    pay[0] = 0x80; memcpy(pay + 1, priv, 32); pay[33] = 0x01;   /* compressed */
    base58check_encode(out, pay, 34);
}

static int cmd_signrawtransactionwithwallet(const rj_val* params, const rpc_wallet* w,
                                            long* ec, const char** em, rj_val** result){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_STR){
        *ec = -8; *em = "Invalid parameters, expected a raw transaction hex string"; return 0; }
    if (!w || !w->seed){ *ec = -4; *em = "No wallet is loaded"; return 0; }

    /* [hexstring, [wif...], prevtxs, sighashtype] -- the delegate's shape.
     * Core's signrawtransactionwithwallet takes (hexstring, prevtxs,
     * sighashtype), so the caller's arg 1 is prevtxs and arg 2 is the
     * sighash type; they shift by one here. */
    rj_val* keys = rj_arr();
    { int mask = rpc_wops_active_types();
      for (int t = 0; t < 4; t++){
        if (!(mask & (1 << t))) continue;
        for (unsigned i = 0; i < SRWW_WINDOW; i++){
            for (int chain = 0; chain <= 1; chain++){
                unsigned idx[5]; rpc_wops_type_path(t, i, chain, idx);
                unsigned char k[32], c[32]; char wif[64];
                if (bip32_derive_path(k, c, w->seed, 64, idx, 5) != 1) continue;
                srww_wif(wif, k);
                rj_arr_push(keys, rj_str(wif));
            }
        }
      } }
    /* ...and every key addhdkey contributed. A wallet that WATCHES an added
     * key's outputs (they are in the rescan window) but cannot sign for them
     * would report coins as spendable and then fail at signing -- worse than
     * never having had the key. */
    { extern int rpc_wops_hdkey_privkeys(unsigned char (*out)[32], int cap, unsigned window);
      static unsigned char hk[8 * SRWW_WINDOW * 2][32];
      int nh = rpc_wops_hdkey_privkeys(hk, (int)(sizeof hk / sizeof hk[0]), SRWW_WINDOW);
      for (int i = 0; i < nh; i++){ char wif[64]; srww_wif(wif, hk[i]); rj_arr_push(keys, rj_str(wif)); }
      memset(hk, 0, sizeof hk); }
    /* ...and every key a PSBT's taproot bip32 origin names under OUR master
     * fingerprint (walletprocesspsbt forwards them as prevtx.tapBip32): a
     * script-path leaf key at an arbitrary path that no rescan window covers. */
    if (params->nitems >= 2 && params->items[1]->typ == RJ_ARR){
        extern int rpc_wops_master_fp(const void* seed, char out[9]);
        extern int bip32_derive_path(unsigned char k[32], unsigned char c[32], const unsigned char* seed, long seedlen, const unsigned* indexes, long n);
        char myfp[9]; if (!rpc_wops_master_fp(w->seed, myfp)) myfp[0] = 0;
        const rj_val* pv = params->items[1]; int added = 0;
        for (unsigned long i = 0; i < pv->nitems && added < 64; i++){
            const rj_val* e = pv->items[i]; if (e->typ != RJ_OBJ) continue;
            rj_val* tb = rj_obj_get(e, "tapBip32"); if (!tb || tb->typ != RJ_ARR) continue;
            for (unsigned long q = 0; q < tb->nitems && added < 64; q++){
                rj_val* d = tb->items[q]; if (d->typ != RJ_OBJ) continue;
                rj_val* fp = rj_obj_get(d, "fingerprint"); rj_val* pa = rj_obj_get(d, "path");
                if (!fp || fp->typ != RJ_STR || !myfp[0] || strcmp(fp->str, myfp) || !pa || pa->typ != RJ_ARR || pa->nitems > 32) continue;
                unsigned path[32]; int n = 0;
                for (unsigned long z = 0; z < pa->nitems; z++){ if (pa->items[z]->typ != RJ_NUM) break; path[n++] = (unsigned)strtoul(pa->items[z]->str, 0, 10); }
                if ((unsigned long)n != pa->nitems) continue;
                unsigned char k[32], c[32];
                if (bip32_derive_path(k, c, w->seed, 64, path, n) != 1) continue;
                char wif[64]; srww_wif(wif, k); rj_arr_push(keys, rj_str(wif)); added++;
                memset(k, 0, 32); memset(c, 0, 32);
            }
        }
    }
    rj_val* fwd = rj_arr();
    rj_arr_push(fwd, rj_str(params->items[0]->str));
    rj_arr_push(fwd, keys);
    /* prevtxs: the caller's, PLUS entries synthesized from the wallet's own
     * rescan records for any input outpoint the wallet owns. Core's wallet
     * knows its own outputs when signing; without this, signing a
     * fundrawtransaction result would demand the caller re-supply data the
     * wallet already has. Caller-provided entries come first, so an explicit
     * prevtx always wins over a synthesized one. */
    {
        rj_val* pv = (params->nitems >= 2 && params->items[1]->typ == RJ_ARR)
                     ? rj_clone(params->items[1]) : rj_arr();
        const char* hx = params->items[0]->str;
        size_t hl2 = strlen(hx);
        if (!(hl2 & 1) && hl2/2 >= 10 && hl2/2 <= 200000){
            static unsigned char txb[200000];
            if (hex_to_bytes(txb, hx, hl2)){
                unsigned long tl = (unsigned long)(hl2/2), q = 4, cc2;
                if (tl > 6 && txb[4] == 0x00 && txb[5] == 0x01) q = 6;
                unsigned long ni = srw_varint(txb + q, &cc2); q += cc2;
                extern int rpc_wops_own_coin_spk(const void*, const unsigned char*, unsigned int,
                                                 unsigned long long*, unsigned char*, unsigned long*,
                                                 unsigned char*, unsigned long*);
                for (unsigned long i = 0; i < ni && ni <= 10000; i++){
                    if (q + 36 > tl) break;
                    const unsigned char* op = txb + q;
                    unsigned int vo = (unsigned int)op[32] | ((unsigned int)op[33]<<8) |
                                      ((unsigned int)op[34]<<16) | ((unsigned int)op[35]<<24);
                    unsigned long long val; unsigned char cspk[34], crd[22]; unsigned long cspkl = 0, crdl = 0;
                    if (rpc_wops_own_coin_spk(w->seed, op, vo, &val, cspk, &cspkl, crd, &crdl)){
                        /* skip if the caller already supplied this outpoint */
                        char tid[65];
                        for (int k = 0; k < 32; k++){
                            static const char* H = "0123456789abcdef";
                            unsigned char b = op[31-k];
                            tid[k*2] = H[b>>4]; tid[k*2+1] = H[b&15];
                        }
                        tid[64] = 0;
                        int have = 0;
                        for (size_t j = 0; j < pv->nitems; j++){
                            rj_val* t = rj_obj_get(pv->items[j], "txid");
                            rj_val* v2 = rj_obj_get(pv->items[j], "vout");
                            if (t && v2 && !strcmp(t->str, tid) &&
                                (unsigned int)atol(v2->str) == vo){ have = 1; break; }
                        }
                        if (!have){
                            rj_val* e = rj_obj();
                            rj_obj_set(e, "txid", rj_str(tid));
                            rj_obj_set(e, "vout", rj_numf("%u", vo));
                            { char spkh[72]; bin_to_hex(spkh, cspk, cspkl);
                              rj_obj_set(e, "scriptPubKey", rj_str(spkh)); }
                            if (crdl){ char rdh[48]; bin_to_hex(rdh, crd, crdl); rj_obj_set(e, "redeemScript", rj_str(rdh)); }
                            { char am[32]; rpc_amounts((long long)val, am, sizeof am);
                              rj_obj_set(e, "amount", rj_numf("%s", am)); }
                            rj_arr_push(pv, e);
                        }
                    }
                    q += 36;
                    unsigned long sl2 = srw_varint(txb + q, &cc2); q += cc2 + sl2 + 4;
                    if (q > tl) break;
                }
            }
        }
        rj_arr_push(fwd, pv);
    }
    if (params->nitems >= 3 && params->items[2]->typ == RJ_STR)
        rj_arr_push(fwd, rj_str(params->items[2]->str));

    int rc = cmd_signrawtransactionwithkey(fwd, ec, em, result);
    rj_free(fwd);
    return rc;
}

/* ==== simulaterawtransaction =============================================
 * Core: the net balance change these transactions would cause for THIS
 * wallet. Computable here without any funding machinery, because both
 * halves are already known:
 *   - an input is ours if its outpoint is in the wallet's own UTXO list
 *     (rpc_wallet carries txid/vout/value), so its value leaves;
 *   - an output is ours if its scriptPubKey is one of our derived P2WPKH
 *     scripts, so its value arrives.
 * An input whose outpoint we do not hold contributes nothing -- it is not
 * our money either way -- which is the same treatment Core gives a
 * not-ours input. */

static int simraw_is_ours_spk(const rpc_wallet* w, const unsigned char* spk, unsigned long spklen){
    int mask = rpc_wops_active_types();
    for (int t = 0; t < 4; t++){
        if (!(mask & (1 << t))) continue;
        for (unsigned i = 0; i < SRWW_WINDOW; i++){
            for (int chain = 0; chain <= 1; chain++){
                unsigned idx[5]; rpc_wops_type_path(t, i, chain, idx);
                unsigned char k[32], c[32], pub[33], ospk[34], h20[20]; unsigned long ol;
                if (bip32_derive_path(k, c, w->seed, 64, idx, 5) != 1) continue;
                scalar_to_pubkey(pub, k);
                if (rpc_wops_type_spk(t, pub, ospk, &ol, h20) && ol == spklen && !memcmp(ospk, spk, ol)) return 1;
            }
        }
    }
    return 0;
}

static int cmd_simulaterawtransaction(const rj_val* params, const rpc_wallet* w,
                                      long* ec, const char** em, rj_val** result){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_ARR){
        *ec = -8; *em = "Invalid parameters, expected an array of raw transactions"; return 0; }
    if (!w || !w->seed){ *ec = -4; *em = "No wallet is loaded"; return 0; }
    const rj_val* list = params->items[0];
    long long delta = 0;
    for (size_t t = 0; t < list->nitems; t++){
        if (list->items[t]->typ != RJ_STR){ *ec = -22; *em = "TX decode failed"; return 0; }
        const char* hx = list->items[t]->str; size_t hl = strlen(hx);
        if ((hl & 1) || hl/2 < 10 || hl/2 > 400000){ *ec = -22; *em = "TX decode failed"; return 0; }
        unsigned long txlen = (unsigned long)(hl/2);
        unsigned char* tx = malloc(txlen);
        if (!tx){ *ec = -7; *em = "oom"; return 0; }
        if (!hex_to_bytes(tx, hx, hl)){ free(tx); *ec = -22; *em = "TX decode failed"; return 0; }

        unsigned long p = 4, cc;
        int segwit = (txlen > 6 && tx[4] == 0x00 && tx[5] == 0x01);
        if (segwit) p = 6;
        unsigned long n_in = srw_varint(tx + p, &cc); p += cc;
        if (n_in == 0 || n_in > 100000){ free(tx); *ec = -22; *em = "TX decode failed"; return 0; }
        for (unsigned long i = 0; i < n_in; i++){
            if (p + 36 > txlen){ free(tx); *ec = -22; *em = "TX decode failed"; return 0; }
            const unsigned char* op = tx + p;
            unsigned long vo = (unsigned long)op[32] | ((unsigned long)op[33]<<8) |
                               ((unsigned long)op[34]<<16) | ((unsigned long)op[35]<<24);
            /* rpc_wallet.utxo_txid is in DISPLAY order -- rpc_commands and
             * the transport test both render it forward with bin_to_hex to
             * produce the txid a caller sees. The outpoint in the raw tx is
             * in wire order, so it has to be reversed before comparing;
             * comparing them directly would silently never match and report
             * every spend of our own coins as a zero balance change. */
            unsigned char disp[32];
            for (int b = 0; b < 32; b++) disp[b] = op[31-b];
            for (unsigned long u = 0; u < w->utxo_n; u++)
                if (w->utxo_idx[u] == vo && !memcmp(w->utxo_txid[u], disp, 32)){
                    delta -= (long long)w->utxo_val[u]; break; }
            p += 36;
            unsigned long ssl = srw_varint(tx + p, &cc); p += cc + ssl + 4;
            if (p > txlen){ free(tx); *ec = -22; *em = "TX decode failed"; return 0; }
        }
        unsigned long n_out = srw_varint(tx + p, &cc); p += cc;
        if (n_out > 100000){ free(tx); *ec = -22; *em = "TX decode failed"; return 0; }
        for (unsigned long i = 0; i < n_out; i++){
            if (p + 8 > txlen){ free(tx); *ec = -22; *em = "TX decode failed"; return 0; }
            unsigned long long val = 0;
            for (int b = 0; b < 8; b++) val |= (unsigned long long)tx[p+b] << (8*b);
            p += 8;
            unsigned long sl = srw_varint(tx + p, &cc); p += cc;
            if (p + sl > txlen){ free(tx); *ec = -22; *em = "TX decode failed"; return 0; }
            if (simraw_is_ours_spk(w, tx + p, sl)) delta += (long long)val;
            p += sl;
        }
        free(tx);
    }
    rj_val* o = rj_obj();
    char am[32]; rpc_amounts(delta, am, sizeof am);
    rj_obj_set(o, "balance_change", rj_numf("%s", am));
    *result = o;
    return 1;
}

/* ==== combinerawtransaction ==============================================
 * Core merges SIGNATURE DATA across partially signed copies of the same
 * transaction, which for a multisig input means combining individual
 * signatures out of several scriptSigs -- that is the signature-combiner in
 * Core's ProduceSignature, which this node does not have.
 *
 * So this implements the case it can do exactly, and REFUSES the case it
 * cannot rather than doing it wrongly: for each input, if at most one of the
 * supplied transactions carries signature data, that one is taken. If two
 * carry DIFFERENT non-empty data for the same input, combining them requires
 * the merger, and silently keeping one would hand back a transaction missing
 * signatures that the caller supplied -- so it errors and points at
 * combinepsbt, which merges properly at the PSBT level. */


/* Walk a raw tx into inputs + the outputs/locktime tail. 0 on malformed. */
static int crt_walk(const unsigned char* tx, unsigned long len, crt_in_t* ins, int cap,
                    int* n_in_out, unsigned long* out_start, unsigned long* out_end,
                    int* segwit_out){
    if (len < 10) return 0;
    unsigned long p = 4, cc;
    int segwit = (len > 6 && tx[4] == 0x00 && tx[5] == 0x01);
    if (segwit) p = 6;
    unsigned long n_in = srw_varint(tx + p, &cc); p += cc;
    if (n_in == 0 || (int)n_in > cap) return 0;
    for (unsigned long i = 0; i < n_in; i++){
        if (p + 36 > len) return 0;
        ins[i].op = tx + p; p += 36;
        unsigned long sl = srw_varint(tx + p, &cc); p += cc;
        if (p + sl + 4 > len) return 0;
        ins[i].ss = tx + p; ins[i].sslen = sl; p += sl;
        ins[i].seq = (unsigned)tx[p] | ((unsigned)tx[p+1]<<8) |
                     ((unsigned)tx[p+2]<<16) | ((unsigned)tx[p+3]<<24);
        p += 4;
        ins[i].wit = NULL; ins[i].witlen = 0; ins[i].witems = 0;
    }
    *out_start = p;
    unsigned long n_out = srw_varint(tx + p, &cc); p += cc;
    for (unsigned long i = 0; i < n_out; i++){
        if (p + 8 > len) return 0;
        p += 8;
        unsigned long sl = srw_varint(tx + p, &cc); p += cc + sl;
        if (p > len) return 0;
    }
    *out_end = p;
    if (segwit){
        for (unsigned long i = 0; i < n_in; i++){
            const unsigned char* wstart = tx + p;
            unsigned long items = srw_varint(tx + p, &cc); p += cc;
            for (unsigned long k = 0; k < items; k++){
                unsigned long il = srw_varint(tx + p, &cc); p += cc + il;
                if (p > len) return 0;
            }
            ins[i].wit = wstart; ins[i].witlen = (unsigned long)(tx + p - wstart);
            ins[i].witems = (unsigned)items;
        }
    }
    if (p + 4 > len) return 0;
    *n_in_out = (int)n_in;
    *segwit_out = segwit;
    return 1;
}

#define CRT_MAXTX 16
#define CRT_MAXIN 1000

static int cmd_combinerawtransaction(const rj_val* params, long* ec, const char** em, rj_val** result){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_ARR || params->items[0]->nitems < 1){
        *ec = -8; *em = "Invalid parameter, expected an array of hex transactions"; return 0; }
    const rj_val* arr = params->items[0];
    if (arr->nitems > CRT_MAXTX){
        *ec = -8; *em = "Too many transactions to combine"; return 0; }
    static unsigned char bufs[CRT_MAXTX][200000]; unsigned long blen[CRT_MAXTX];
    static crt_in_t ins[CRT_MAXTX][CRT_MAXIN];
    int n_in[CRT_MAXTX], segwit[CRT_MAXTX];
    unsigned long ostart[CRT_MAXTX], oend[CRT_MAXTX];
    int np = (int)arr->nitems;
    for (int i = 0; i < np; i++){
        if (arr->items[i]->typ != RJ_STR){ *ec = -22; *em = "TX decode failed"; return 0; }
        const char* h = arr->items[i]->str; size_t hl = strlen(h);
        if ((hl & 1) || hl/2 < 10 || hl/2 > sizeof bufs[0]){ *ec = -22; *em = "TX decode failed"; return 0; }
        blen[i] = (unsigned long)(hl/2);
        if (!hex_to_bytes(bufs[i], h, hl)){ *ec = -22; *em = "TX decode failed"; return 0; }
        if (!crt_walk(bufs[i], blen[i], ins[i], CRT_MAXIN, &n_in[i], &ostart[i], &oend[i], &segwit[i])){
            *ec = -22; *em = "TX decode failed"; return 0; }
        if (i > 0){
            if (n_in[i] != n_in[0]){ *ec = -8; *em = "Input txids and vouts must match across all transactions"; return 0; }
            for (int k = 0; k < n_in[0]; k++)
                if (memcmp(ins[i][k].op, ins[0][k].op, 36)){
                    *ec = -8; *em = "Input txids and vouts must match across all transactions"; return 0; }
            if (oend[i] - ostart[i] != oend[0] - ostart[0] ||
                memcmp(bufs[i] + ostart[i], bufs[0] + ostart[0], oend[0] - ostart[0])){
                *ec = -8; *em = "Outputs must match across all transactions"; return 0; }
        }
    }
    /* pick the signature data per input */
    int pick[CRT_MAXIN];
    for (int k = 0; k < n_in[0]; k++){
        int chosen = -1;
        for (int i = 0; i < np; i++){
            if (ins[i][k].sslen == 0 && ins[i][k].witlen <= 1) continue;   /* empty */
            if (chosen < 0){ chosen = i; continue; }
            /* a second non-empty candidate: identical is fine, different is
             * the merge case this node cannot perform */
            const crt_in_t* a = &ins[chosen][k]; const crt_in_t* b = &ins[i][k];
            if (a->sslen == b->sslen && !memcmp(a->ss, b->ss, a->sslen) &&
                a->witlen == b->witlen &&
                (a->witlen == 0 || !memcmp(a->wit, b->wit, a->witlen))) continue;
            *ec = -22;
            *em = "two of these transactions carry DIFFERENT signatures for the same "
                  "input. Merging them needs the signature combiner (for multisig, "
                  "assembling separate signatures into one scriptSig), which this node "
                  "does not implement -- keeping one would silently discard the other. "
                  "Use combinepsbt, which merges partial signatures properly";
            return 0;
        }
        pick[k] = chosen < 0 ? 0 : chosen;
    }
    /* serialize: base tx 0's version/outputs/locktime, chosen input data */
    int any_wit = 0;
    for (int k = 0; k < n_in[0]; k++) if (ins[pick[k]][k].witlen > 1) any_wit = 1;
    static unsigned char out[220000]; long o = 0;
    memcpy(out, bufs[0], 4); o = 4;
    if (any_wit){ out[o++] = 0x00; out[o++] = 0x01; }
    o += crt_varint(out + o, (unsigned long long)n_in[0]);
    for (int k = 0; k < n_in[0]; k++){
        const crt_in_t* c = &ins[pick[k]][k];
        memcpy(out + o, c->op, 36); o += 36;
        o += crt_varint(out + o, (unsigned long long)c->sslen);
        memcpy(out + o, c->ss, c->sslen); o += c->sslen;
        unsigned sq = c->seq;
        out[o++] = (unsigned char)sq; out[o++] = (unsigned char)(sq>>8);
        out[o++] = (unsigned char)(sq>>16); out[o++] = (unsigned char)(sq>>24);
    }
    memcpy(out + o, bufs[0] + ostart[0], oend[0] - ostart[0]); o += (long)(oend[0] - ostart[0]);
    if (any_wit){
        for (int k = 0; k < n_in[0]; k++){
            const crt_in_t* c = &ins[pick[k]][k];
            if (c->witlen){ memcpy(out + o, c->wit, c->witlen); o += (long)c->witlen; }
            else out[o++] = 0x00;                    /* empty stack for this input */
        }
    }
    memcpy(out + o, bufs[0] + blen[0] - 4, 4); o += 4;   /* locktime */
    char* hx = malloc((size_t)o * 2 + 1);
    if (!hx){ *ec = -7; *em = "oom"; return 0; }
    bin_to_hex(hx, out, (size_t)o);
    *result = rj_str(hx); free(hx);
    return 1;
}

/* ==== finalizepsbt =======================================================
 * The Finalizer and Extractor roles (BIP174). For each input that carries
 * partial signatures, build PSBT_IN_FINAL_SCRIPTSIG / _SCRIPTWITNESS from
 * the signature(s) and the input's scriptPubKey, then drop the fields BIP174
 * says a finalized input must not keep (partial sigs, sighash type, redeem
 * and witness scripts, derivations).
 *
 * The script forms handled are the ones this node can build without a
 * script solver: P2PKH, P2WPKH, and P2SH-P2WPKH. An input of any other form
 * is LEFT ALONE and `complete` comes back false -- which is precisely what
 * Core does for an input it cannot finalize, not a shortcut. Nothing is
 * emitted that was not derived from data already in the PSBT. */
#define FIN_MAXIO 1000
#define FIN_MAXKV 128

/* find a key whose first byte is `type` */
static const psbt_kv* fin_find(const psbt_kv* kv, int n, unsigned char type){
    for (int i = 0; i < n; i++) if (kv[i].kl >= 1 && kv[i].k[0] == type) return &kv[i];
    return NULL;
}
static int fin_count(const psbt_kv* kv, int n, unsigned char type){
    int c = 0; for (int i = 0; i < n; i++) if (kv[i].kl >= 1 && kv[i].k[0] == type) c++;
    return c;
}

/* The scriptPubKey this input spends: from PSBT_IN_WITNESS_UTXO (value ||
 * script) or, for a legacy input, by indexing PSBT_IN_NON_WITNESS_UTXO's
 * outputs at the outpoint's vout. Returns 0 if neither is present. */
static int fin_spk(const psbt_kv* kv, int n, unsigned long vout,
                   const unsigned char** spk, unsigned long* spklen){
    const psbt_kv* w = fin_find(kv, n, 0x01);
    if (w && w->vl > 9){
        unsigned long cc;
        const unsigned char* p = w->v + 8;
        unsigned long sl = srw_varint(p, &cc);
        if (8 + cc + sl <= w->vl){ *spk = p + cc; *spklen = sl; return 1; }
    }
    const psbt_kv* nw = fin_find(kv, n, 0x00);
    if (nw && nw->vl > 10){
        const unsigned char* tx = nw->v; unsigned long len = nw->vl, cc;
        unsigned long p = 4;
        if (len > 6 && tx[4] == 0x00 && tx[5] == 0x01) p = 6;
        unsigned long n_in = srw_varint(tx + p, &cc); p += cc;
        for (unsigned long i = 0; i < n_in; i++){
            if (p + 36 > len) return 0;
            p += 36;
            unsigned long sl = srw_varint(tx + p, &cc); p += cc + sl + 4;
            if (p > len) return 0;
        }
        unsigned long n_out = srw_varint(tx + p, &cc); p += cc;
        if (vout >= n_out) return 0;
        for (unsigned long i = 0; i < n_out; i++){
            if (p + 8 > len) return 0;
            p += 8;
            unsigned long sl = srw_varint(tx + p, &cc); p += cc;
            if (p + sl > len) return 0;
            if (i == vout){ *spk = tx + p; *spklen = sl; return 1; }
            p += sl;
        }
    }
    return 0;
}

/* Build the final scriptSig/witness for one input. Returns 1 when it could,
 * filling ss/sslen and wit/witlen (witness = serialized stack incl. count).
 * Returns 0 when the form is not one this node can finalize -- the caller
 * then leaves the input untouched. */
static int fin_build(const psbt_kv* kv, int n, const unsigned char* spk, unsigned long spklen,
                     unsigned char* ss, unsigned long* sslen,
                     unsigned char* wit, unsigned long* witlen){
    *sslen = 0; *witlen = 0;
    /* P2TR key path with PSBT_IN_TAP_KEY_SIG (a MuSig2 aggregate lands here): witness = [sig] */
    if (spklen == 34 && spk[0] == 0x51 && spk[1] == 0x20){
        const psbt_kv* ks = fin_find(kv, n, 0x13);
        if (!ks || (ks->vl != 64 && ks->vl != 65)) return 0;
        wit[0] = 0x01; wit[1] = (unsigned char)ks->vl; memcpy(wit + 2, ks->v, ks->vl); *witlen = 2 + ks->vl;
        return 1;
    }
    if (fin_count(kv, n, 0x02) != 1) return 0;        /* exactly one partial sig */
    const psbt_kv* ps = fin_find(kv, n, 0x02);
    if (!ps || ps->kl != 34 || ps->vl < 9 || ps->vl > 73) return 0;  /* 0x02||pub33 */
    const unsigned char* pub = ps->k + 1;
    const unsigned char* sig = ps->v; unsigned long siglen = ps->vl;

    /* P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG */
    if (spklen == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14 &&
        spk[23] == 0x88 && spk[24] == 0xac){
        unsigned char h[20]; hash160(h, pub, 33);
        if (memcmp(h, spk + 3, 20)) return 0;
        unsigned long o = 0;
        ss[o++] = (unsigned char)siglen; memcpy(ss + o, sig, siglen); o += siglen;
        ss[o++] = 33; memcpy(ss + o, pub, 33); o += 33;
        *sslen = o;
        return 1;
    }
    /* P2WPKH: OP_0 <20>. scriptSig stays empty; witness is [sig, pubkey]. */
    if (spklen == 22 && spk[0] == 0x00 && spk[1] == 0x14){
        unsigned char h[20]; hash160(h, pub, 33);
        if (memcmp(h, spk + 2, 20)) return 0;
        unsigned long o = 0;
        wit[o++] = 0x02;
        wit[o++] = (unsigned char)siglen; memcpy(wit + o, sig, siglen); o += siglen;
        wit[o++] = 33; memcpy(wit + o, pub, 33); o += 33;
        *witlen = o;
        return 1;
    }
    /* P2SH-P2WPKH: OP_HASH160 <20> OP_EQUAL, with the redeemScript being the
     * v0 program. scriptSig is the single push of the redeemScript. */
    if (spklen == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87){
        const psbt_kv* rs = fin_find(kv, n, 0x04);
        if (!rs || rs->vl != 22 || rs->v[0] != 0x00 || rs->v[1] != 0x14) return 0;
        unsigned char rh[20]; hash160(rh, rs->v, 22);
        if (memcmp(rh, spk + 2, 20)) return 0;
        unsigned char h[20]; hash160(h, pub, 33);
        if (memcmp(h, rs->v + 2, 20)) return 0;
        ss[0] = 22; memcpy(ss + 1, rs->v, 22); *sslen = 23;
        unsigned long o = 0;
        wit[o++] = 0x02;
        wit[o++] = (unsigned char)siglen; memcpy(wit + o, sig, siglen); o += siglen;
        wit[o++] = 33; memcpy(wit + o, pub, 33); o += 33;
        *witlen = o;
        return 1;
    }
    return 0;
}

static int cmd_finalizepsbt(const rj_val* params, long* ec, const char** em, rj_val** result){
    const char* b64 = rpc_param_str(params, 0, ec, em); if (!b64) return 0;
    int extract = 1;
    if (params->nitems >= 2 && params->items[1]->typ == RJ_BOOL)
        extract = params->items[1]->str[0] == '1';
    static unsigned char buf[400000]; long blen = 0; psbt_v2meta vm;
    if (!psbt_load(b64, buf, sizeof buf, &blen, &vm, ec, em)) return 0;
    if (vm.locktime_conflict){ *ec = -22; *em = "PSBT cannot be made into a valid transaction"; return 0; }
    long p = 5;
    static psbt_kv gkv[FIN_MAXKV]; int gn = psbt_parse_map(buf, blen, &p, gkv, FIN_MAXKV);
    const psbt_kv* utxk = fin_find(gkv, gn, 0x00);
    if (!utxk){ *ec = -22; *em = "TX decode failed"; return 0; }
    const unsigned char* utx = utxk->v; unsigned long utxl = utxk->vl;

    /* walk the unsigned tx for the outpoints and the outputs/locktime tail */
    static crt_in_t uin[FIN_MAXIO];
    int n_in, sw; unsigned long ost, oen;
    if (!crt_walk(utx, utxl, uin, FIN_MAXIO, &n_in, &ost, &oen, &sw)){
        *ec = -22; *em = "TX decode failed"; return 0; }

    static psbt_kv ikv[FIN_MAXIO][FIN_MAXKV]; static int in_n[FIN_MAXIO];
    static unsigned char fss[FIN_MAXIO][256]; static unsigned long fsslen[FIN_MAXIO];
    static unsigned char fwit[FIN_MAXIO][4200]; static unsigned long fwitlen[FIN_MAXIO];   /* items + a witnessScript of up to 3600 bytes */
    for (int i = 0; i < n_in; i++) in_n[i] = psbt_parse_map(buf, blen, &p, ikv[i], FIN_MAXKV);
    unsigned long n_out;
    { unsigned long cc; n_out = srw_varint(utx + ost, &cc); }
    static psbt_kv okv[FIN_MAXIO][FIN_MAXKV]; static int out_n[FIN_MAXIO];
    for (unsigned long i = 0; i < n_out && i < FIN_MAXIO; i++)
        out_n[i] = psbt_parse_map(buf, blen, &p, okv[i], FIN_MAXKV);

    int complete = 1;
    for (int i = 0; i < n_in; i++){
        fsslen[i] = 0; fwitlen[i] = 0;
        /* already finalized? */
        const psbt_kv* f7 = fin_find(ikv[i], in_n[i], 0x07);
        const psbt_kv* f8 = fin_find(ikv[i], in_n[i], 0x08);
        if (f7 || f8){
            if (f7){ memcpy(fss[i], f7->v, f7->vl > 256 ? 256 : f7->vl); fsslen[i] = f7->vl > 256 ? 256 : f7->vl; }
            if (f8){ memcpy(fwit[i], f8->v, f8->vl > 4200 ? 4200 : f8->vl); fwitlen[i] = f8->vl > 4200 ? 4200 : f8->vl; }
            continue;
        }
        const unsigned char* spk; unsigned long spklen;
        unsigned long vout = (unsigned long)uin[i].op[32] | ((unsigned long)uin[i].op[33]<<8) |
                             ((unsigned long)uin[i].op[34]<<16) | ((unsigned long)uin[i].op[35]<<24);
        if (!fin_spk(ikv[i], in_n[i], vout, &spk, &spklen)){ complete = 0; continue; }
        if (!fin_build(ikv[i], in_n[i], spk, spklen, fss[i], &fsslen[i], fwit[i], &fwitlen[i])){
            fsslen[i] = 0; fwitlen[i] = 0; complete = 0; continue;
        }
    }

    if (complete && extract){
        /* Extractor: the network serialization */
        int any_wit = 0;
        for (int i = 0; i < n_in; i++) if (fwitlen[i] > 1) any_wit = 1;
        static unsigned char out[220000]; long o = 0;
        memcpy(out, utx, 4); o = 4;
        if (any_wit){ out[o++] = 0x00; out[o++] = 0x01; }
        o += crt_varint(out + o, (unsigned long long)n_in);
        for (int i = 0; i < n_in; i++){
            memcpy(out + o, uin[i].op, 36); o += 36;
            o += crt_varint(out + o, (unsigned long long)fsslen[i]);
            memcpy(out + o, fss[i], fsslen[i]); o += (long)fsslen[i];
            unsigned sq = uin[i].seq;
            out[o++]=(unsigned char)sq; out[o++]=(unsigned char)(sq>>8);
            out[o++]=(unsigned char)(sq>>16); out[o++]=(unsigned char)(sq>>24);
        }
        memcpy(out + o, utx + ost, oen - ost); o += (long)(oen - ost);
        if (any_wit)
            for (int i = 0; i < n_in; i++){
                if (fwitlen[i]){ memcpy(out + o, fwit[i], fwitlen[i]); o += (long)fwitlen[i]; }
                else out[o++] = 0x00;
            }
        memcpy(out + o, utx + utxl - 4, 4); o += 4;
        char* hx = malloc((size_t)o*2+1); if (!hx){ *ec=-7; *em="oom"; return 0; }
        bin_to_hex(hx, out, (size_t)o);
        rj_val* r = rj_obj();
        rj_obj_set(r, "hex", rj_str(hx));
        rj_obj_set(r, "complete", rj_bool(1));
        free(hx);
        *result = r;
        return 1;
    }

    /* not extracting: re-serialize the PSBT with the final fields set and
     * the now-forbidden ones dropped (BIP174: a finalized input keeps only
     * the UTXO, the final scriptSig/witness, and proprietary/unknown keys) */
    static unsigned char out[220000]; long o = 0;
    out[o++]=0x70; out[o++]=0x73; out[o++]=0x62; out[o++]=0x74; out[o++]=0xff;
    o += psbt_ser_map(out + o, gkv, gn);
    for (int i = 0; i < n_in; i++){
        psbt_kv keep[FIN_MAXKV]; int kn = 0;
        int finalized = fsslen[i] || fwitlen[i];
        for (int k = 0; k < in_n[i] && kn < FIN_MAXKV; k++){
            unsigned char t = ikv[i][k].kl ? ikv[i][k].k[0] : 0xff;
            if (finalized && (t==0x02||t==0x03||t==0x04||t==0x05||t==0x06||t==0x07||t==0x08))
                continue;
            keep[kn++] = ikv[i][k];
        }
        psbt_kv extra[2]; int en = 0;
        unsigned char k7 = 0x07, k8 = 0x08;
        if (finalized && fsslen[i]){ extra[en].k=&k7; extra[en].kl=1; extra[en].v=fss[i]; extra[en].vl=fsslen[i]; en++; }
        if (finalized && fwitlen[i]){ extra[en].k=&k8; extra[en].kl=1; extra[en].v=fwit[i]; extra[en].vl=fwitlen[i]; en++; }
        for (int k = 0; k < en && kn < FIN_MAXKV; k++) keep[kn++] = extra[k];
        o += psbt_ser_map(out + o, keep, kn);
    }
    for (unsigned long i = 0; i < n_out && i < FIN_MAXIO; i++)
        o += psbt_ser_map(out + o, okv[i], out_n[i]);
    char* b = psbt_b64_out(out, o, &vm); if (!b){ *ec=-7; *em="oom"; return 0; }
    rj_val* r = rj_obj();
    rj_obj_set(r, "psbt", rj_str(b));
    rj_obj_set(r, "complete", rj_bool(complete));
    free(b);
    *result = r;
    return 1;
}

/* ==== utxoupdatepsbt =====================================================
 * Fills PSBT_IN_WITNESS_UTXO for every input whose outpoint the UTXO set
 * knows and whose scriptPubKey is a witness program -- which is exactly what
 * the method is documented to do ("Updates all segwit inputs ... with data
 * from ... the UTXO set"). This node has no txindex and no mempool reachable
 * from here, so a non-witness input cannot be given its full previous
 * transaction; those inputs are left as they are.
 *
 * The `descriptors` argument would add redeem/witness scripts and BIP32
 * derivations. That is not implemented, so supplying it is an ERROR rather
 * than an argument quietly ignored -- a caller who passed descriptors and
 * got a PSBT back without them would reasonably believe they were applied. */
static int cmd_utxoupdatepsbt(const rj_val* params, long* ec, const char** em, rj_val** result){
    const char* b64 = rpc_param_str(params, 0, ec, em); if (!b64) return 0;
    if (params->nitems >= 2 && params->items[1]->typ == RJ_ARR && params->items[1]->nitems > 0){
        *ec = -8;
        *em = "the descriptors argument is not implemented by this node: it would add "
              "redeem/witness scripts and BIP32 derivations to the PSBT. Call without "
              "descriptors to fill witness UTXOs from the UTXO set";
        return 0;
    }
    static unsigned char buf[400000]; long blen = 0; psbt_v2meta vm;
    if (!psbt_load(b64, buf, sizeof buf, &blen, &vm, ec, em)) return 0;
    long p = 5;
    static psbt_kv gkv[FIN_MAXKV]; int gn = psbt_parse_map(buf, blen, &p, gkv, FIN_MAXKV);
    const psbt_kv* utxk = fin_find(gkv, gn, 0x00);
    if (!utxk){ *ec = -22; *em = "TX decode failed"; return 0; }
    static crt_in_t uin[FIN_MAXIO];
    int n_in, sw; unsigned long ost, oen;
    if (!crt_walk(utxk->v, utxk->vl, uin, FIN_MAXIO, &n_in, &ost, &oen, &sw)){
        *ec = -22; *em = "TX decode failed"; return 0; }
    static psbt_kv ikv[FIN_MAXIO][FIN_MAXKV]; static int in_n[FIN_MAXIO];
    for (int i = 0; i < n_in; i++) in_n[i] = psbt_parse_map(buf, blen, &p, ikv[i], FIN_MAXKV);
    unsigned long n_out; { unsigned long cc; n_out = srw_varint(utxk->v + ost, &cc); }
    static psbt_kv okv[FIN_MAXIO][FIN_MAXKV]; static int out_n[FIN_MAXIO];
    for (unsigned long i = 0; i < n_out && i < FIN_MAXIO; i++)
        out_n[i] = psbt_parse_map(buf, blen, &p, okv[i], FIN_MAXKV);

    static unsigned char wu[FIN_MAXIO][128]; static unsigned long wulen[FIN_MAXIO];
    for (int i = 0; i < n_in; i++){
        wulen[i] = 0;
        if (fin_find(ikv[i], in_n[i], 0x01) || fin_find(ikv[i], in_n[i], 0x00)) continue;
        if (!g_utxo_lst) continue;
        unsigned long vout = (unsigned long)uin[i].op[32] | ((unsigned long)uin[i].op[33]<<8) |
                             ((unsigned long)uin[i].op[34]<<16) | ((unsigned long)uin[i].op[35]<<24);
        unsigned long long value; unsigned long height, cb; const unsigned char* spk; unsigned long slen;
        if (utxo_lsm_get(g_utxo_lst, g_utxo_u, uin[i].op, (unsigned)vout,
                         &value, &height, &cb, &spk, &slen) != 1) continue;
        /* witness_utxo is only correct for a witness program; a legacy
         * prevout needs the whole previous transaction, which this node
         * cannot produce (no txindex). Leave those alone. */
        int is_wit = (slen == 22 && spk[0] == 0x00 && spk[1] == 0x14) ||
                     (slen == 34 && (spk[0] == 0x00 || spk[0] == 0x51) && spk[1] == 0x20);
        if (!is_wit || slen > 100) continue;
        unsigned long o = 0;
        for (int b = 0; b < 8; b++) wu[i][o++] = (unsigned char)(value >> (8*b));
        o += (unsigned long)crt_varint(wu[i] + o, (unsigned long long)slen);
        memcpy(wu[i] + o, spk, slen); o += slen;
        wulen[i] = o;
    }

    static unsigned char out[220000]; long o = 0;
    out[o++]=0x70; out[o++]=0x73; out[o++]=0x62; out[o++]=0x74; out[o++]=0xff;
    o += psbt_ser_map(out + o, gkv, gn);
    static unsigned char K1 = 0x01;
    for (int i = 0; i < n_in; i++){
        psbt_kv keep[FIN_MAXKV]; int kn = 0;
        for (int k = 0; k < in_n[i] && kn < FIN_MAXKV; k++) keep[kn++] = ikv[i][k];
        if (wulen[i] && kn < FIN_MAXKV){
            keep[kn].k = &K1; keep[kn].kl = 1; keep[kn].v = wu[i]; keep[kn].vl = wulen[i]; kn++;
        }
        o += psbt_ser_map(out + o, keep, kn);
    }
    for (unsigned long i = 0; i < n_out && i < FIN_MAXIO; i++)
        o += psbt_ser_map(out + o, okv[i], out_n[i]);
    char* b = psbt_b64_out(out, o, &vm); if (!b){ *ec=-7; *em="oom"; return 0; }
    *result = rj_str(b); free(b);
    return 1;
}

/* ==== walletprocesspsbt ==================================================
 * The Signer role (BIP174), by DELEGATION: extract the PSBT's unsigned tx,
 * synthesize prevtxs from the PSBT's own utxo fields, and run the whole
 * thing through cmd_signrawtransactionwithwallet -- the Core-validated
 * signing path every wallet spend already uses. The signed transaction's
 * per-input scriptSig/witness then splice back into the PSBT as FINAL
 * fields (the finalize=true default, which is also Core's), with the
 * BIP174 field-drop discipline finalizepsbt established. finalize=false
 * extracts PARTIAL_SIG entries instead, for the two script forms this
 * wallet actually signs (P2WPKH witness [sig,pub]; P2PKH scriptSig
 * push-sig push-pub) and refuses others by name. bip32derivs is accepted
 * and ignored: this node adds no derivation metadata (the PSBT remains
 * valid without it; stated rather than silently half-done). */
/* The Signer is pluggable: walletprocesspsbt signs with the wallet's keys,
 * descriptorprocesspsbt with the private keys the given descriptors carry.
 * Both go through the same extract / synthesize-prevtxs / sign / splice
 * path, so the two cannot drift in what they hand back. `fwd` is the
 * signrawtransaction argument list [hex, prevtxs, sighashtype?]. */
typedef int (*psbt_signer_fn)(rj_val* fwd, void* ctx, long* ec, const char** em, rj_val** sres);
/* ==== MuSig2 (BIP327 crypto, BIP373 PSBT fields) =========================
 * Everything MuSig2 in the PSBT signer lives between these markers.
 *
 * Fields: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS 0x1a (key = agg33, value =
 * participants 33*n), PSBT_IN_MUSIG2_PUB_NONCE 0x1b and
 * PSBT_IN_MUSIG2_PARTIAL_SIG 0x1c (key = part33 || agg33 [|| leaf_hash],
 * value = 66-byte pubnonce / 32-byte partial sig), PSBT_OUT_MUSIG2_
 * PARTICIPANT_PUBKEYS 0x08. As in Core, 0x1a is keyed by the UNTWEAKED
 * aggregate while 0x1b/0x1c are keyed by the key that is actually in the
 * script (after BIP32 derivation of the synthetic xpub and the taproot
 * tweak) -- "plain_pub" below.
 *
 * Flow (Core's SignMuSig2, key path only -- leaf scripts are not signed
 * here): for every aggregate on a P2TR input: if every participant's
 * partial signature is present, aggregate into the BIP340 signature and
 * set PSBT_IN_TAP_KEY_SIG; else, for every participant whose private key
 * this signer holds: with every pubnonce present and our secret nonce for
 * this session still in memory, produce our partial signature; with our
 * pubnonce absent, generate a nonce (getrandom + BIP327 derivation from
 * the key, the aggregate and the sighash) and publish it. Secret nonces
 * live only in this process, keyed by Core's session id (aggregate ||
 * participant || sighash || pubnonce), and are erased the moment they are
 * used -- a PSBT never carries one, and a lost session simply means that
 * participant restarts round 1. */
#include "musig2.h"
#include <sys/random.h>
extern int  bip32_ckdpub_step_pub(const unsigned char Kpar[33], const unsigned char ccpar[32], unsigned index, unsigned char Kout[33], unsigned char ccout[32]);
extern void hmac_sha512(unsigned char out[64], const void* key, long long keylen, const void* data, long long datalen);
typedef int (*psbt_keyfn)(void* sctx, const unsigned char pub33[33], unsigned char priv[32]);

#define MU_SESSIONS 64
typedef struct { unsigned char id[32]; unsigned char secnonce[97]; int used; } mu_sess_t;
static mu_sess_t g_mu_sess[MU_SESSIONS]; static int g_mu_sess_next = 0;
static void mu_session_id(unsigned char id[32], const unsigned char plain[33], const unsigned char part[33],
                          const unsigned char sighash[32], const unsigned char pubnonce[66]){
    unsigned char b[33+33+32+66]; memcpy(b, plain, 33); memcpy(b+33, part, 33); memcpy(b+66, sighash, 32); memcpy(b+98, pubnonce, 66);
    sha256_full(id, b, sizeof b);
}
static void mu_session_put(const unsigned char id[32], const unsigned char secnonce[97]){
    mu_sess_t* e = &g_mu_sess[g_mu_sess_next]; g_mu_sess_next = (g_mu_sess_next + 1) % MU_SESSIONS;
    memcpy(e->id, id, 32); memcpy(e->secnonce, secnonce, 97); e->used = 1;
}
static mu_sess_t* mu_session_get(const unsigned char id[32]){
    for (int i = 0; i < MU_SESSIONS; i++) if (g_mu_sess[i].used && !memcmp(g_mu_sess[i].id, id, 32)) return &g_mu_sess[i];
    return NULL;
}
static void mu_session_erase(mu_sess_t* e){ memset(e, 0, sizeof *e); }
/* exported for tests: forget every session (simulates a restart) */
void rpc_musig2_forget_sessions(void){ memset(g_mu_sess, 0, sizeof g_mu_sess); g_mu_sess_next = 0; }

static unsigned long mu_rd_varint(const unsigned char* p, unsigned long* cc){ return srw_varint(p, cc); }
/* value + scriptPubKey of an input's witness_utxo; 0 if absent */
static int mu_witness_utxo(const psbt_kv* kv, int n, unsigned long long* amount, const unsigned char** spk, unsigned long* spklen){
    const psbt_kv* wu = fin_find(kv, n, 0x01);
    if (!wu || wu->vl < 9) return 0;
    unsigned long long a = 0; for (int k = 0; k < 8; k++) a |= (unsigned long long)wu->v[k] << (8*k);
    unsigned long cc; unsigned long sl = mu_rd_varint(wu->v + 8, &cc);
    if (8 + cc + sl > wu->vl) return 0;
    *amount = a; *spk = wu->v + 8 + cc; *spklen = sl; return 1;
}
static void mu_taptweak(unsigned char t[32], const unsigned char x[32], const unsigned char* root){
    unsigned char th[32]; sha256_full(th, "TapTweak", 8);
    unsigned char b[128]; memcpy(b, th, 32); memcpy(b+32, th, 32); memcpy(b+64, x, 32); unsigned long n = 96;
    if (root){ memcpy(b+96, root, 32); n = 128; }
    sha256_full(t, b, n);
}
/* BIP32 unhardened derivation of the synthetic musig() xpub along `path`,
 * applying each step's scalar as a plain tweak to the key aggregation.
 * -> 1 ok / 0 hardened step or derivation failure. */
static int mu_apply_derivation(musig2_keyagg_t* ka, const unsigned char agg33[33], const unsigned* path, int plen){
    static const unsigned char MUSIG_CC[32] = { 0x86,0x80,0x87,0xca,0x02,0xa6,0xf9,0x74,0xc4,0x59,0x89,0x24,0xc3,0x6b,0x57,0x76,
                                                0x2d,0x32,0xcb,0x45,0x71,0x71,0x67,0xe3,0x00,0x62,0x2c,0x71,0x67,0xe3,0x89,0x65 };
    unsigned char K[33], cc[32]; memcpy(K, agg33, 33); memcpy(cc, MUSIG_CC, 32);
    for (int i = 0; i < plen; i++){
        if (path[i] >= 0x80000000u) return 0;
        unsigned char data[37]; memcpy(data, K, 33);
        data[33] = (unsigned char)(path[i] >> 24); data[34] = (unsigned char)(path[i] >> 16); data[35] = (unsigned char)(path[i] >> 8); data[36] = (unsigned char)path[i];
        unsigned char I[64]; hmac_sha512(I, cc, 32, data, 37);
        if (!musig2_tweak(ka, I, 0)) return 0;
        unsigned char K2[33], cc2[32];
        if (bip32_ckdpub_step_pub(K, cc, path[i], K2, cc2) != 1) return 0;
        memcpy(K, K2, 33); memcpy(cc, cc2, 32);
    }
    return 1;
}
#define MU_MAX_PART MUSIG2_MAX_KEYS
#define MU_EXTRA 4
static unsigned char g_mu_kbuf[FIN_MAXIO][MU_EXTRA][100]; static unsigned char g_mu_vbuf[FIN_MAXIO][MU_EXTRA][80]; static int g_mu_extra_n[FIN_MAXIO];
static int mu_append(psbt_kv* kv, int* n, int i, const unsigned char* k, unsigned long kl, const unsigned char* v, unsigned long vl){
    if (*n >= FIN_MAXKV || g_mu_extra_n[i] >= MU_EXTRA || kl > 100 || vl > 80) return 0;
    int e = g_mu_extra_n[i]++;
    memcpy(g_mu_kbuf[i][e], k, kl); memcpy(g_mu_vbuf[i][e], v, vl);
    kv[*n].k = g_mu_kbuf[i][e]; kv[*n].kl = kl; kv[*n].v = g_mu_vbuf[i][e]; kv[*n].vl = vl; (*n)++;
    return 1;
}
/* One aggregate on one input. Returns 1 when it produced the final
 * signature (wit = [sig]), 0 otherwise (nonce/partial-sig rounds or nothing
 * to do). */
static int mu_process_aggregate(psbt_kv* kv, int* kn, int i, const psbt_kv* agg_kv,
                                const unsigned char* utx, unsigned long utxl, crt_in_t* uin, int n_in,
                                unsigned long ost, unsigned long oen, srw_prev_t* const* prev_of, int tht,
                                psbt_keyfn keyfn, void* sctx, unsigned char* wit, unsigned long* witlen){
    const unsigned char* agg33 = agg_kv->k + 1;
    int np = (int)(agg_kv->vl / 33); if (np < 1 || np > MU_MAX_PART || agg_kv->vl % 33) return 0;
    unsigned char parts[MU_MAX_PART][33]; for (int p = 0; p < np; p++) memcpy(parts[p], agg_kv->v + 33*p, 33);
    musig2_keyagg_t ka; if (!musig2_key_agg(&ka, parts, np)) return 0;
    unsigned char plain_agg[33]; musig2_agg_plain(plain_agg, &ka);
    if (memcmp(plain_agg, agg33, 33)) return 0;                      /* the field's aggregate must be the participants' */
    unsigned long long amount; const unsigned char* spk; unsigned long spklen;
    if (!mu_witness_utxo(kv, *kn, &amount, &spk, &spklen)) return 0;
    if (spklen != 34 || spk[0] != 0x51 || spk[1] != 0x20) return 0;  /* key path of a P2TR output only */
    const psbt_kv* ik = fin_find(kv, *kn, 0x17); const psbt_kv* mr = fin_find(kv, *kn, 0x18);
    if (ik && ik->vl != 32) return 0;
    if (mr && mr->vl != 32) return 0;
    const unsigned char* script_x = ik ? ik->v : spk + 2;          /* the key the aggregate must reach before the taptweak */
    unsigned char ax[32]; musig2_agg_xonly(ax, &ka);
    if (memcmp(ax, script_x, 32)){
        /* derived aggregate: find the tap bip32 derivation of script_x whose fingerprint is ours */
        unsigned char fp[20]; hash160(fp, agg33, 33);
        int done = 0;
        for (int q = 0; q < *kn && !done; q++){
            if (kv[q].kl != 33 || kv[q].k[0] != 0x16 || memcmp(kv[q].k + 1, script_x, 32)) continue;
            unsigned long cc; unsigned long nl = mu_rd_varint(kv[q].v, &cc); unsigned long o = cc + 32 * nl;
            if (o + 4 > kv[q].vl || memcmp(kv[q].v + o, fp, 4)) continue;
            o += 4; int plen = (int)((kv[q].vl - o) / 4); if (plen < 1 || plen > 32) continue;
            unsigned path[32]; for (int t = 0; t < plen; t++){ const unsigned char* z = kv[q].v + o + 4*t; path[t] = (unsigned)z[0] | ((unsigned)z[1]<<8) | ((unsigned)z[2]<<16) | ((unsigned)z[3]<<24); }
            if (!mu_apply_derivation(&ka, agg33, path, plen)) return 0;
            musig2_agg_xonly(ax, &ka);
            if (memcmp(ax, script_x, 32)) return 0;
            done = 1;
        }
        if (!done) return 0;
    }
    if (ik){                                                          /* taproot tweak (BIP341), x-only */
        unsigned char t[32]; mu_taptweak(t, script_x, mr ? mr->v : NULL);
        if (!musig2_tweak(&ka, t, 1)) return 0;
        musig2_agg_xonly(ax, &ka);
        if (memcmp(ax, spk + 2, 32)) return 0;                        /* must land on the output key */
    }
    unsigned char plain[33]; musig2_agg_plain(plain, &ka);          /* the 0x1b/0x1c "aggregate_pubkey" */

    /* collect pubnonces / partial sigs for (plain, no leaf) in participant order */
    unsigned char pn[MU_MAX_PART][66]; int has_pn[MU_MAX_PART]; int n_pn = 0;
    unsigned char ps[MU_MAX_PART][32]; int has_ps[MU_MAX_PART]; int n_ps = 0;
    for (int p = 0; p < np; p++){
        has_pn[p] = has_ps[p] = 0;
        for (int q = 0; q < *kn; q++){
            if (kv[q].kl != 67 || memcmp(kv[q].k + 1, parts[p], 33) || memcmp(kv[q].k + 34, plain, 33)) continue;
            if (kv[q].k[0] == 0x1b && kv[q].vl == 66 && !has_pn[p]){ memcpy(pn[p], kv[q].v, 66); has_pn[p] = 1; n_pn++; }
            if (kv[q].k[0] == 0x1c && kv[q].vl == 32 && !has_ps[p]){ memcpy(ps[p], kv[q].v, 32); has_ps[p] = 1; n_ps++; }
        }
    }
    /* sighash (BIP341 key path, SIGHASH_DEFAULT unless one was asked for) */
    unsigned char z[32];
    { const unsigned char* ops[FIN_MAXIO]; unsigned seqs[FIN_MAXIO];
      for (int j = 0; j < n_in; j++){ ops[j] = uin[j].op; seqs[j] = uin[j].seq; }
      unsigned long locktime = (unsigned long)utx[utxl-4] | ((unsigned long)utx[utxl-3]<<8) | ((unsigned long)utx[utxl-2]<<16) | ((unsigned long)utx[utxl-1]<<24);
      if (!srw_tap_sighash(z, utx, utxl, (unsigned long)i, (unsigned long)n_in, ops, seqs, prev_of, ost, oen, locktime, tht, NULL)) return 0; }

    if (n_ps == np && n_pn == np){                                    /* round 3: aggregate */
        unsigned char aggnonce[66]; if (!musig2_nonce_agg(aggnonce, pn, np)) return 0;
        musig2_session_t ss; if (!musig2_session(&ss, &ka, aggnonce, z, 32)) return 0;
        unsigned char sig[65]; if (!musig2_partial_sig_agg(sig, &ss, &ka, ps, np)) return 0;
        unsigned long sl = 64; if (tht){ sig[64] = (unsigned char)tht; sl = 65; }
        unsigned char k13 = 0x13;
        if (!fin_find(kv, *kn, 0x13)) mu_append(kv, kn, i, &k13, 1, sig, sl);
        wit[0] = 0x01; wit[1] = (unsigned char)sl; memcpy(wit + 2, sig, sl); *witlen = 2 + sl;
        return 1;
    }
    if (!keyfn) return 0;
    for (int p = 0; p < np; p++){
        unsigned char priv[32];
        if (has_ps[p] || !keyfn(sctx, parts[p], priv)) continue;
        if (n_pn == np){                                              /* round 2: our partial signature */
            unsigned char id[32]; mu_session_id(id, plain, parts[p], z, pn[p]);
            mu_sess_t* se = mu_session_get(id); if (!se) continue;      /* not our nonce, or a session this process never had */
            unsigned char aggnonce[66]; if (!musig2_nonce_agg(aggnonce, pn, np)) continue;
            musig2_session_t ss; if (!musig2_session(&ss, &ka, aggnonce, z, 32)) continue;
            unsigned char psig[32]; int ok = musig2_partial_sign(psig, se->secnonce, priv, &ka, &ss);
            mu_session_erase(se);                                     /* never twice with the same nonce */
            if (!ok) continue;
            unsigned char k[67]; k[0] = 0x1c; memcpy(k+1, parts[p], 33); memcpy(k+34, plain, 33);
            mu_append(kv, kn, i, k, 67, psig, 32);
        } else if (!has_pn[p]){                                       /* round 1: our nonce */
            unsigned char rnd[32]; if (getrandom(rnd, 32, 0) != 32) continue;
            unsigned char aggx[32]; musig2_keyagg_t k0; if (!musig2_key_agg(&k0, parts, np)) continue; musig2_agg_xonly(aggx, &k0);
            unsigned char sec[97], pub[66];
            if (!musig2_nonce_gen(sec, pub, rnd, priv, parts[p], aggx, z, 32, NULL, 0)) continue;
            unsigned char id[32]; mu_session_id(id, plain, parts[p], z, pub); mu_session_put(id, sec);
            memset(sec, 0, sizeof sec);
            unsigned char k[67]; k[0] = 0x1b; memcpy(k+1, parts[p], 33); memcpy(k+34, plain, 33);
            mu_append(kv, kn, i, k, 67, pub, 66);
        }
        memset(priv, 0, 32);
    }
    return 0;
}
/* The stage: runs over every input before the raw signer is delegated to.
 * mu_witlen[i] != 0 marks an input this stage finished (wit = [sig]). */
static void psbt_musig_stage(psbt_kv (*ikv)[FIN_MAXKV], int* in_n, int n_in,
                             const unsigned char* utx, unsigned long utxl, crt_in_t* uin,
                             unsigned long ost, unsigned long oen, const char* sht,
                             psbt_keyfn keyfn, void* sctx,
                             unsigned char (*mu_wit)[80], unsigned long* mu_witlen){
    int any = 0;
    for (int i = 0; i < n_in; i++){ mu_witlen[i] = 0; g_mu_extra_n[i] = 0; if (fin_find(ikv[i], in_n[i], 0x1a)) any = 1; }
    if (!any) return;
    int tht = 0;
    if (sht){ int h = srw_hashtype(sht); if (h < 0) return; tht = h; }
    static srw_prev_t prev[FIN_MAXIO]; static srw_prev_t* prev_of[FIN_MAXIO];
    for (int j = 0; j < n_in; j++){
        prev_of[j] = NULL; unsigned long long a; const unsigned char* spk; unsigned long sl;
        if (!mu_witness_utxo(ikv[j], in_n[j], &a, &spk, &sl) || sl > sizeof prev[j].spk) continue;
        memset(&prev[j], 0, sizeof prev[j]); prev[j].amount = a; memcpy(prev[j].spk, spk, sl); prev[j].spklen = sl; prev_of[j] = &prev[j];
    }
    for (int i = 0; i < n_in; i++){
        for (int q = 0; q < in_n[i]; q++){
            const psbt_kv* a = &ikv[i][q];
            if (a->kl != 34 || a->k[0] != 0x1a) continue;
            if (mu_process_aggregate(ikv[i], &in_n[i], i, a, utx, utxl, uin, n_in, ost, oen, prev_of, tht, keyfn, sctx, mu_wit[i], &mu_witlen[i])) break;
        }
    }
}
/* network serialization of utx with the given final scriptSigs/witnesses */
static char* mu_extract_hex(const unsigned char* utx, unsigned long utxl, crt_in_t* uin, int n_in, unsigned long ost, unsigned long oen,
                            unsigned char (*fss)[256], const unsigned long* fsslen, unsigned char (*fwit)[256], const unsigned long* fwitlen){
    int any_wit = 0; for (int i = 0; i < n_in; i++) if (fwitlen[i] > 1) any_wit = 1;
    unsigned char* out = malloc(utxl + 16 + (unsigned long)n_in * 600); if (!out) return NULL; long o = 0;
    memcpy(out, utx, 4); o = 4;
    if (any_wit){ out[o++] = 0x00; out[o++] = 0x01; }
    o += crt_varint(out + o, (unsigned long long)n_in);
    for (int i = 0; i < n_in; i++){
        memcpy(out + o, uin[i].op, 36); o += 36;
        o += crt_varint(out + o, (unsigned long long)fsslen[i]); memcpy(out + o, fss[i], fsslen[i]); o += (long)fsslen[i];
        unsigned sq = uin[i].seq; out[o++]=(unsigned char)sq; out[o++]=(unsigned char)(sq>>8); out[o++]=(unsigned char)(sq>>16); out[o++]=(unsigned char)(sq>>24);
    }
    memcpy(out + o, utx + ost, oen - ost); o += (long)(oen - ost);
    if (any_wit) for (int i = 0; i < n_in; i++){ if (fwitlen[i]){ memcpy(out + o, fwit[i], fwitlen[i]); o += (long)fwitlen[i]; } else out[o++] = 0x00; }
    memcpy(out + o, utx + utxl - 4, 4); o += 4;
    char* hx = malloc((size_t)o*2+1); if (hx) bin_to_hex(hx, out, (size_t)o);
    free(out); return hx;
}
/* ==== end MuSig2 ========================================================= */

static int psbt_process(const char* b64, int sign, const char* sht, int finalize,
                        psbt_signer_fn signer, void* sctx, psbt_keyfn keyfn,
                        long* ec, const char** em, rj_val** result){

    static unsigned char buf[400000]; long blen = 0; psbt_v2meta vm;
    if (!psbt_load(b64, buf, sizeof buf, &blen, &vm, ec, em)) return 0;
    if (vm.locktime_conflict){ *ec = -22; *em = "PSBT cannot be made into a valid transaction"; return 0; }
    long p = 5;
    static psbt_kv gkv[FIN_MAXKV]; int gn = psbt_parse_map(buf, blen, &p, gkv, FIN_MAXKV);
    const psbt_kv* utxk = fin_find(gkv, gn, 0x00);
    if (!utxk){ *ec = -22; *em = "TX decode failed"; return 0; }
    const unsigned char* utx = utxk->v; unsigned long utxl = utxk->vl;

    static crt_in_t uin[FIN_MAXIO];
    int n_in, sw; unsigned long ost, oen;
    if (!crt_walk(utx, utxl, uin, FIN_MAXIO, &n_in, &ost, &oen, &sw)){
        *ec = -22; *em = "TX decode failed"; return 0; }
    static psbt_kv ikv[FIN_MAXIO][FIN_MAXKV]; static int in_n[FIN_MAXIO];
    for (int i = 0; i < n_in; i++) in_n[i] = psbt_parse_map(buf, blen, &p, ikv[i], FIN_MAXKV);
    unsigned long n_out;
    { unsigned long q = oen; unsigned long cc; (void)q; (void)cc; }
    /* output count from the unsigned tx's own outputs section */
    { unsigned long cc; n_out = srw_varint(utx + ost, &cc); }
    static psbt_kv okv[FIN_MAXIO][FIN_MAXKV]; static int out_n[FIN_MAXIO];
    for (unsigned long i = 0; i < n_out && i < FIN_MAXIO; i++)
        out_n[i] = psbt_parse_map(buf, blen, &p, okv[i], FIN_MAXKV);

    if (!sign){
        /* the Updater-only call: nothing this node would update -- return
         * the PSBT as supplied, complete unknown -> false */
        rj_val* r = rj_obj();
        rj_obj_set(r, "psbt", rj_str(b64));
        rj_obj_set(r, "complete", rj_bool(0));
        *result = r;
        return 1;
    }

    /* MuSig2 (BIP327/BIP373): nonces, partial signatures, or the final
     * key-path signature for aggregates this signer participates in */
    static unsigned char mu_wit[FIN_MAXIO][80]; static unsigned long mu_witlen[FIN_MAXIO];
    psbt_musig_stage(ikv, in_n, n_in, utx, utxl, uin, ost, oen, sht, keyfn, sctx, mu_wit, mu_witlen);

    /* taproot fields per input (2026-09-01): leaves (0x15), bip32 origins
     * (0x16), internal key (0x17), merkle root (0x18). Signing runs in
     * ROUNDS: round 0 offers every input its key path (internal key + root),
     * round r>=1 offers leaf r-1; each input keeps the first round that
     * signed it (a complete signature beats a partial one). The rounds are
     * re-assembled into one transaction below. */
    typedef struct { const unsigned char* leaf[8]; unsigned long leaflen[8]; const unsigned char* ctrl[8]; unsigned long ctrllen[8]; int nleaf;
                     const unsigned char* internal; const unsigned char* merkle;
                     struct { unsigned char fp[4]; unsigned path[32]; int n; } deriv[8]; int nderiv;
                     const unsigned char* keysig; unsigned long keysiglen;
                     const unsigned char* psig_k[32]; const unsigned char* psig_v[32]; unsigned long psig_vl[32]; int npsig; } ptap_t;
    static ptap_t ptap[FIN_MAXIO]; int max_leaf = 0;
    for (int i = 0; i < n_in; i++){
        ptap_t* T = &ptap[i]; memset(T, 0, sizeof *T);
        for (int k2 = 0; k2 < in_n[i]; k2++){
            const psbt_kv* kv = &ikv[i][k2]; if (!kv->kl) continue;
            switch (kv->k[0]){
            case 0x15: if (kv->kl >= 34 && ((kv->kl - 34) % 32) == 0 && kv->vl >= 2 && T->nleaf < 8){
                           T->ctrl[T->nleaf] = kv->k + 1; T->ctrllen[T->nleaf] = kv->kl - 1;
                           T->leaf[T->nleaf] = kv->v; T->leaflen[T->nleaf] = kv->vl - 1; T->nleaf++; } break;
            case 0x16: if (kv->kl == 33 && T->nderiv < 8){
                           unsigned long cc; unsigned long nlh = srw_varint(kv->v, &cc); unsigned long q = cc + nlh * 32;
                           if (q + 4 <= kv->vl && ((kv->vl - q - 4) % 4) == 0 && (kv->vl - q - 4) / 4 <= 32){
                               memcpy(T->deriv[T->nderiv].fp, kv->v + q, 4); q += 4; int n = 0;
                               while (q + 4 <= kv->vl){ T->deriv[T->nderiv].path[n++] = (unsigned)kv->v[q] | ((unsigned)kv->v[q+1]<<8) | ((unsigned)kv->v[q+2]<<16) | ((unsigned)kv->v[q+3]<<24); q += 4; }
                               T->deriv[T->nderiv].n = n; T->nderiv++; } } break;
            case 0x17: if (kv->vl == 32) T->internal = kv->v; break;
            case 0x18: if (kv->vl == 32) T->merkle = kv->v; break;
            case 0x13: if (kv->vl == 64 || kv->vl == 65){ T->keysig = kv->v; T->keysiglen = kv->vl; } break;
            case 0x14: if (kv->kl == 65 && (kv->vl == 64 || kv->vl == 65) && T->npsig < 32){ T->psig_k[T->npsig] = kv->k + 1; T->psig_v[T->npsig] = kv->v; T->psig_vl[T->npsig] = kv->vl; T->npsig++; } break;
            default: break;
            }
        }
        if (T->nleaf > max_leaf) max_leaf = T->nleaf;
    }
    static unsigned char in_spk[FIN_MAXIO][128]; static unsigned long in_spklen[FIN_MAXIO];
    static unsigned char rec_ss[FIN_MAXIO][4096]; static unsigned long rec_sslen[FIN_MAXIO];
    static unsigned char rec_wit[FIN_MAXIO][4096]; static unsigned long rec_witlen[FIN_MAXIO]; static unsigned rec_witems[FIN_MAXIO];
    static int rec_state[FIN_MAXIO];   /* 0 unsigned, 1 partial, 2 complete */
    for (int i = 0; i < n_in; i++){ in_spklen[i] = 0; rec_sslen[i] = rec_witlen[i] = 0; rec_witems[i] = 0; rec_state[i] = 0; }
    /* inputs the MuSig2 stage finished are complete before any round: their
     * witness is the aggregated key-path signature, and the delegate's
     * "keys not provided" for them is ignored by the per-input record */
    for (int i = 0; i < n_in; i++) if (mu_witlen[i] && mu_witlen[i] <= sizeof rec_wit[i]){
        memcpy(rec_wit[i], mu_wit[i], mu_witlen[i]); rec_witlen[i] = mu_witlen[i]; rec_witems[i] = 1; rec_state[i] = 2; }
    rj_val* sres = NULL;
    for (int round = 0; round <= max_leaf; round++){
    if (sres){ rj_free(sres); sres = NULL; }
    /* prevtxs from the PSBT's own utxo fields (witness_utxo first, else
     * index the non-witness parent at the outpoint's vout); an input with
     * neither is left to the delegate's wallet-coin synthesis */
    rj_val* pv = rj_arr();
    for (int i = 0; i < n_in; i++){
        const unsigned char* spk = NULL; unsigned long spklen = 0;
        unsigned long long amount = 0;
        const psbt_kv* wu = fin_find(ikv[i], in_n[i], 0x01);
        if (wu && wu->vl >= 9){
            for (int k2 = 0; k2 < 8; k2++) amount |= (unsigned long long)wu->v[k2] << (8*k2);
            unsigned long cc; unsigned long sl = srw_varint(wu->v + 8, &cc);
            if (8 + cc + sl <= wu->vl){ spk = wu->v + 8 + cc; spklen = sl; }
        } else {
            const psbt_kv* nwu = fin_find(ikv[i], in_n[i], 0x00);
            if (nwu){
                unsigned long vo = (unsigned long)uin[i].op[32] | ((unsigned long)uin[i].op[33]<<8)
                                 | ((unsigned long)uin[i].op[34]<<16) | ((unsigned long)uin[i].op[35]<<24);
                static crt_in_t pin[FIN_MAXIO]; int pn, psw; unsigned long pos, pen;
                if (crt_walk(nwu->v, nwu->vl, pin, FIN_MAXIO, &pn, &pos, &pen, &psw)){
                    unsigned long cc; unsigned long no = srw_varint(nwu->v + pos, &cc);
                    unsigned long q = pos + cc;
                    for (unsigned long oi = 0; oi < no && oi <= vo; oi++){
                        unsigned long long val = 0;
                        for (int k2 = 0; k2 < 8; k2++) val |= (unsigned long long)nwu->v[q+k2] << (8*k2);
                        q += 8;
                        unsigned long sl = srw_varint(nwu->v + q, &cc); q += cc;
                        if (oi == vo){ amount = val; spk = nwu->v + q; spklen = sl; break; }
                        q += sl;
                    }
                }
            }
        }
        if (!spk || spklen == 0 || spklen > 128) continue;
        rj_val* e = rj_obj();
        char tid[65];
        for (int k2 = 0; k2 < 32; k2++){
            static const char* H = "0123456789abcdef";
            unsigned char b2 = uin[i].op[31-k2];
            tid[k2*2] = H[b2>>4]; tid[k2*2+1] = H[b2&15];
        }
        tid[64] = 0;
        rj_obj_set(e, "txid", rj_str(tid));
        { unsigned long vo = (unsigned long)uin[i].op[32] | ((unsigned long)uin[i].op[33]<<8)
                           | ((unsigned long)uin[i].op[34]<<16) | ((unsigned long)uin[i].op[35]<<24);
          rj_obj_set(e, "vout", rj_numf("%lu", vo)); }
        { char* sh = malloc(spklen*2+1);
          if (sh){ bin_to_hex(sh, spk, spklen); rj_obj_set(e, "scriptPubKey", rj_str(sh)); free(sh); } }
        { char am[32]; rpc_amounts((long long)amount, am, sizeof am);
          rj_obj_set(e, "amount", rj_numf("%s", am)); }
        if (spklen <= sizeof in_spk[i]){ memcpy(in_spk[i], spk, spklen); in_spklen[i] = spklen; }
        { const ptap_t* T = &ptap[i]; char hx[2*(33+32*16)+1];
          if (T->internal){ bin_to_hex(hx, T->internal, 32); rj_obj_set(e, "tapInternalKey", rj_str(hx)); }
          if (T->merkle){ bin_to_hex(hx, T->merkle, 32); rj_obj_set(e, "tapMerkleRoot", rj_str(hx)); }
          if (round >= 1 && round - 1 < T->nleaf && T->leaflen[round-1] <= 1024){
              char* lh = malloc(T->leaflen[round-1]*2+1);
              if (lh){ bin_to_hex(lh, T->leaf[round-1], T->leaflen[round-1]); rj_obj_set(e, "tapLeafScript", rj_str(lh)); free(lh); }
              bin_to_hex(hx, T->ctrl[round-1], T->ctrllen[round-1]); rj_obj_set(e, "tapControlBlock", rj_str(hx)); }
          if (T->keysig){ char kh[131]; bin_to_hex(kh, T->keysig, T->keysiglen); rj_obj_set(e, "tapKeySig", rj_str(kh)); }
          if (T->npsig){ rj_val* arr = rj_arr();
              for (int q = 0; q < T->npsig; q++){ rj_val* d = rj_obj(); char h1[65], h2[65], h3[131]; bin_to_hex(h1, T->psig_k[q], 32); bin_to_hex(h2, T->psig_k[q] + 32, 32); bin_to_hex(h3, T->psig_v[q], T->psig_vl[q]);
                  rj_obj_set(d, "pubkey", rj_str(h1)); rj_obj_set(d, "leaf_hash", rj_str(h2)); rj_obj_set(d, "sig", rj_str(h3)); rj_arr_push(arr, d); }
              rj_obj_set(e, "tapPartialSigs", arr); }
          if (T->nderiv){ rj_val* arr = rj_arr();
              for (int q = 0; q < T->nderiv; q++){ rj_val* d = rj_obj(); char fp[9]; bin_to_hex(fp, T->deriv[q].fp, 4); rj_obj_set(d, "fingerprint", rj_str(fp));
                  rj_val* pa = rj_arr(); for (int z = 0; z < T->deriv[q].n; z++) rj_arr_push(pa, rj_numf("%u", T->deriv[q].path[z]));
                  rj_obj_set(d, "path", pa); rj_arr_push(arr, d); }
              rj_obj_set(e, "tapBip32", arr); } }
        /* the PSBT's own redeem/witness scripts (0x04/0x05) and hash preimages
         * (0x0a ripemd160, 0x0b sha256, 0x0c hash160, 0x0d hash256): what a
         * miniscript input needs beyond keys (2026-09-01) */
        { const psbt_kv* rs = fin_find(ikv[i], in_n[i], 0x04);
          if (rs && rs->vl && rs->vl <= 128){ char* h = malloc(rs->vl*2+1); if (h){ bin_to_hex(h, rs->v, rs->vl); rj_obj_set(e, "redeemScript", rj_str(h)); free(h); } }
          const psbt_kv* wsf = fin_find(ikv[i], in_n[i], 0x05);
          if (wsf && wsf->vl && wsf->vl <= 3700){ char* h = malloc(wsf->vl*2+1); if (h){ bin_to_hex(h, wsf->v, wsf->vl); rj_obj_set(e, "witnessScript", rj_str(h)); free(h); } }
          rj_val* pa = NULL;
          for (int k2 = 0; k2 < in_n[i]; k2++){
              const psbt_kv* kv = &ikv[i][k2];
              if (kv->kl < 1 || kv->k[0] < 0x0a || kv->k[0] > 0x0d) continue;
              unsigned long hl = kv->kl - 1; if ((hl != 20 && hl != 32) || kv->vl != 32) continue;
              if (!pa) pa = rj_arr();
              rj_val* po = rj_obj(); char hh[65], ph[65];
              bin_to_hex(hh, kv->k + 1, hl); bin_to_hex(ph, kv->v, 32);
              rj_obj_set(po, "hash", rj_str(hh)); rj_obj_set(po, "preimage", rj_str(ph));
              rj_arr_push(pa, po);
          }
          if (pa) rj_obj_set(e, "preimages", pa); }
        rj_arr_push(pv, e);
    }

    /* delegate the signing */
    char* uhex = malloc(utxl*2+1);
    if (!uhex){ rj_free(pv); *ec = -7; *em = "oom"; return 0; }
    bin_to_hex(uhex, utx, utxl);
    rj_val* fwd = rj_arr();
    rj_arr_push(fwd, rj_str(uhex));
    free(uhex);
    rj_arr_push(fwd, pv);
    if (sht) rj_arr_push(fwd, rj_str(sht));
    int rc = signer(fwd, sctx, ec, em, &sres);
    rj_free(fwd);
    if (!rc) return 0;
    rj_val* rhex = rj_obj_get(sres, "hex");
    if (!rhex || !rhex->str){ rj_free(sres); *ec = -22; *em = "signing produced no transaction"; return 0; }
    /* record what this round signed, per input */
    { static unsigned char rbuf[200000]; unsigned long rhl = strlen(rhex->str);
      if ((rhl & 1) || rhl/2 > sizeof rbuf || !hex_to_bytes(rbuf, rhex->str, rhl)){ rj_free(sres); *ec = -22; *em = "TX decode failed"; return 0; }
      static crt_in_t rin[FIN_MAXIO]; int rn, rsw; unsigned long rost, roen;
      if (!crt_walk(rbuf, rhl/2, rin, FIN_MAXIO, &rn, &rost, &roen, &rsw) || rn != n_in){ rj_free(sres); *ec = -22; *em = "signed transaction shape mismatch"; return 0; }
      rj_val* errs = rj_obj_get(sres, "errors");
      for (int i = 0; i < n_in; i++){
          int signed_i = (rin[i].sslen > 0) || (rin[i].witlen > 0 && rin[i].witems > 0);
          if (!signed_i) continue;
          int partial = 0, failed = 0;
          if (errs && errs->typ == RJ_ARR){
              char tid[65]; for (int k2 = 0; k2 < 32; k2++){ static const char* H = "0123456789abcdef"; unsigned char b2 = uin[i].op[31-k2]; tid[k2*2] = H[b2>>4]; tid[k2*2+1] = H[b2&15]; } tid[64] = 0;
              unsigned long vo = (unsigned long)uin[i].op[32] | ((unsigned long)uin[i].op[33]<<8) | ((unsigned long)uin[i].op[34]<<16) | ((unsigned long)uin[i].op[35]<<24);
              for (unsigned long q = 0; q < errs->nitems; q++){
                  rj_val* eo = errs->items[q]; rj_val* et = rj_obj_get(eo, "txid"); rj_val* ev = rj_obj_get(eo, "vout"); rj_val* ee = rj_obj_get(eo, "error");
                  if (!et || !ev || et->typ != RJ_STR || strcmp(et->str, tid) || strtoul(ev->str, 0, 10) != vo) continue;
                  if (ee && ee->str && strstr(ee->str, "Missing signatures")) partial = 1; else failed = 1;
              }
          }
          if (failed) continue;
          int st = partial ? 1 : 2;
          if (st <= rec_state[i]) continue;
          if (rin[i].sslen > sizeof rec_ss[i] || rin[i].witlen > sizeof rec_wit[i]) continue;
          memcpy(rec_ss[i], rin[i].ss, rin[i].sslen); rec_sslen[i] = rin[i].sslen;
          memcpy(rec_wit[i], rin[i].wit, rin[i].witlen); rec_witlen[i] = rin[i].witlen; rec_witems[i] = rin[i].witems;
          rec_state[i] = st;
      }
    }
    { int all = 1; for (int i = 0; i < n_in; i++) if (rec_state[i] != 2) all = 0; if (all) break; }
    }   /* rounds */
    if (!sres){ *ec = -22; *em = "signing produced no transaction"; return 0; }

    /* re-assemble one transaction from the per-input records */
    static unsigned char sbuf[200000]; unsigned long shl = 0;
    int complete = 1, anywit = 0;
    for (int i = 0; i < n_in; i++){ if (rec_state[i] != 2) complete = 0; if (rec_witlen[i]) anywit = 1; }
    { unsigned long o = 0; memcpy(sbuf + o, utx, 4); o += 4;
      if (anywit){ sbuf[o++] = 0x00; sbuf[o++] = 0x01; }
      o += crt_varint(sbuf + o, (unsigned long long)n_in);
      for (int i = 0; i < n_in; i++){
          if (o + 36 + 9 + rec_sslen[i] + 4 > sizeof sbuf){ rj_free(sres); *ec = -22; *em = "transaction too large"; return 0; }
          memcpy(sbuf + o, uin[i].op, 36); o += 36;
          o += crt_varint(sbuf + o, rec_sslen[i]); memcpy(sbuf + o, rec_ss[i], rec_sslen[i]); o += rec_sslen[i];
          unsigned sq = uin[i].seq; sbuf[o++] = (unsigned char)sq; sbuf[o++] = (unsigned char)(sq>>8); sbuf[o++] = (unsigned char)(sq>>16); sbuf[o++] = (unsigned char)(sq>>24);
      }
      if (o + (oen - ost) + 4 > sizeof sbuf){ rj_free(sres); *ec = -22; *em = "transaction too large"; return 0; }
      memcpy(sbuf + o, utx + ost, oen - ost); o += oen - ost;
      if (anywit){ for (int i = 0; i < n_in; i++){
          if (o + rec_witlen[i] + 1 > sizeof sbuf){ rj_free(sres); *ec = -22; *em = "transaction too large"; return 0; }
          if (rec_witlen[i]){ memcpy(sbuf + o, rec_wit[i], rec_witlen[i]); o += rec_witlen[i]; } else sbuf[o++] = 0x00; } }
      memcpy(sbuf + o, utx + utxl - 4, 4); o += 4;
      shl = o * 2; }
    static char shexbuf[400001]; bin_to_hex(shexbuf, sbuf, shl/2);
    static crt_in_t sin[FIN_MAXIO];
    int sn, ssw; unsigned long sost, soen;
    if (!crt_walk(sbuf, shl/2, sin, FIN_MAXIO, &sn, &sost, &soen, &ssw) || sn != n_in){
        rj_free(sres); *ec = -22; *em = "signed transaction shape mismatch"; return 0; }

    static unsigned char fss[FIN_MAXIO][4096]; static unsigned long fsslen[FIN_MAXIO];
    static unsigned char fwit[FIN_MAXIO][6000]; static unsigned long fwitlen[FIN_MAXIO];
    #define PX_MAX (SRW_TAP_MAXKEYS + 2)
    static unsigned char px_k[FIN_MAXIO][PX_MAX][67]; static unsigned long px_kl[FIN_MAXIO][PX_MAX];
    static unsigned char px_v[FIN_MAXIO][PX_MAX][80]; static unsigned long px_vl[FIN_MAXIO][PX_MAX]; static int px_n[FIN_MAXIO];
    for (int i = 0; i < n_in; i++){
        fsslen[i] = fwitlen[i] = 0; px_n[i] = 0;
        int signed_i = (sin[i].sslen > 0) || (sin[i].witlen > 0 && sin[i].witems > 0);
        if (!signed_i) continue;
        int is_p2tr = in_spklen[i] == 34 && in_spk[i][0] == 0x51 && in_spk[i][1] == 0x20;
        if (finalize && rec_state[i] == 2){
            if (sin[i].sslen > 0 && sin[i].sslen <= sizeof fss[i]){ memcpy(fss[i], sin[i].ss, sin[i].sslen); fsslen[i] = sin[i].sslen; }
            if (sin[i].witlen > 0 && sin[i].witlen <= sizeof fwit[i]){ memcpy(fwit[i], sin[i].wit, sin[i].witlen); fwitlen[i] = sin[i].witlen; }
        } else if (is_p2tr){
            /* taproot partials: key path -> PSBT_IN_TAP_KEY_SIG (0x13); script
             * path -> one PSBT_IN_TAP_SCRIPT_SIG (0x14 | xonly | leafhash) per
             * signature present in the witness [sigs..., script, control] */
            const unsigned char* it[SRW_TAP_MAXKEYS + 2]; unsigned long il[SRW_TAP_MAXKEYS + 2]; int nit = 0;
            { const unsigned char* q = sin[i].wit; unsigned long cc; unsigned long cnt = srw_varint(q, &cc); q += cc;
              for (unsigned long z = 0; z < cnt && nit < SRW_TAP_MAXKEYS + 2; z++){ il[nit] = srw_varint(q, &cc); q += cc; it[nit] = q; q += il[nit]; nit++; } }
            if (nit == 1 && (il[0] == 64 || il[0] == 65)){
                px_k[i][0][0] = 0x13; px_kl[i][0] = 1; memcpy(px_v[i][0], it[0], il[0]); px_vl[i][0] = il[0]; px_n[i] = 1;
            } else if (nit >= 3 && il[nit-1] >= 33){
                unsigned char keys[SRW_TAP_MAXKEYS][32]; int kth = 0;
                int nk = srw_tap_leaf_keys(it[nit-2], il[nit-2], keys, &kth);
                unsigned char lh[32]; srw_tapleaf_hash(lh, it[nit-1][0] & 0xfe, it[nit-2], il[nit-2]);
                for (int a = 0; a < nk && px_n[i] < PX_MAX; a++){
                    int idx = (nk == 1 && kth == 1) ? 0 : (nk - 1 - a);
                    if (idx >= nit - 2 || (il[idx] != 64 && il[idx] != 65)) continue;
                    int n2 = px_n[i]; px_k[i][n2][0] = 0x14; memcpy(px_k[i][n2]+1, keys[a], 32); memcpy(px_k[i][n2]+33, lh, 32); px_kl[i][n2] = 65;
                    memcpy(px_v[i][n2], it[idx], il[idx]); px_vl[i][n2] = il[idx]; px_n[i]++;
                }
            }
        } else {
            /* PARTIAL_SIG extraction: P2WPKH witness [sig, pub] or P2PKH
             * scriptSig push(sig) push(pub) */
            const unsigned char* sig = NULL; unsigned long sigl = 0;
            const unsigned char* pub = NULL; unsigned long publ = 0;
            if (sin[i].witems == 2 && sin[i].witlen > 2){
                const unsigned char* q = sin[i].wit; unsigned long cc;
                unsigned long c0 = srw_varint(q, &cc); q += cc;   /* count (=2) */
                (void)c0;
                sigl = srw_varint(q, &cc); q += cc; sig = q; q += sigl;
                publ = srw_varint(q, &cc); q += cc; pub = q;
            } else if (sin[i].sslen > 2){
                const unsigned char* q = sin[i].ss;
                sigl = q[0]; sig = q + 1;
                if (1 + sigl < sin[i].sslen){ publ = q[1+sigl]; pub = q + 2 + sigl; }
            }
            if (!sig || !pub || sigl > 79 || (publ != 33 && publ != 65)){
                /* a partially signed multisig under finalize=true: nothing
                 * final to write and no per-key partial this node can name
                 * without verifying each signature -- the input is left as
                 * supplied and the result says complete=false */
                if (rec_state[i] == 1 && finalize) continue;
                rj_free(sres); *ec = -8;
                *em = "finalize=false: partial-signature extraction is supported only for "
                      "P2WPKH, P2PKH and P2TR inputs on this node";
                return 0;
            }
            px_k[i][0][0] = 0x02; memcpy(px_k[i][0]+1, pub, publ); px_kl[i][0] = 1 + publ;
            memcpy(px_v[i][0], sig, sigl); px_vl[i][0] = sigl; px_n[i] = 1;
        }
    }

    static unsigned char out[220000]; long o = 0;
    out[o++]=0x70; out[o++]=0x73; out[o++]=0x62; out[o++]=0x74; out[o++]=0xff;
    o += psbt_ser_map(out + o, gkv, gn);
    for (int i = 0; i < n_in; i++){
        psbt_kv keep[FIN_MAXKV]; int kn = 0;
        int finalized = fsslen[i] || fwitlen[i];
        for (int k2 = 0; k2 < in_n[i] && kn < FIN_MAXKV; k2++){
            unsigned char t = ikv[i][k2].kl ? ikv[i][k2].k[0] : 0xff;
            if (finalized && (t==0x02||t==0x03||t==0x04||t==0x05||t==0x06||t==0x07||t==0x08||(t>=0x13&&t<=0x1c)))
                continue;
            /* a partial we produce replaces the same key already present */
            { int dup = 0; for (int q = 0; q < px_n[i]; q++) if (ikv[i][k2].kl == px_kl[i][q] && !memcmp(ikv[i][k2].k, px_k[i][q], px_kl[i][q])) dup = 1; if (dup) continue; }
            keep[kn++] = ikv[i][k2];
        }
        static psbt_kv extra[PX_MAX + 2]; int en = 0;
        static unsigned char k7 = 0x07, k8 = 0x08;
        if (fsslen[i]){ extra[en].k=&k7; extra[en].kl=1; extra[en].v=fss[i]; extra[en].vl=fsslen[i]; en++; }
        if (fwitlen[i]){ extra[en].k=&k8; extra[en].kl=1; extra[en].v=fwit[i]; extra[en].vl=fwitlen[i]; en++; }
        for (int q = 0; q < px_n[i]; q++){ extra[en].k=px_k[i][q]; extra[en].kl=px_kl[i][q]; extra[en].v=px_v[i][q]; extra[en].vl=px_vl[i][q]; en++; }
        for (int k2 = 0; k2 < en && kn < FIN_MAXKV; k2++) keep[kn++] = extra[k2];
        o += psbt_ser_map(out + o, keep, kn);
    }
    for (unsigned long i = 0; i < n_out && i < FIN_MAXIO; i++)
        o += psbt_ser_map(out + o, okv[i], out_n[i]);

    char* b = psbt_b64_out(out, o, &vm);
    if (!b){ rj_free(sres); *ec=-7; *em="oom"; return 0; }
    rj_val* r = rj_obj();
    rj_obj_set(r, "psbt", rj_str(b));
    rj_obj_set(r, "complete", rj_bool(complete));
    if (complete && finalize) rj_obj_set(r, "hex", rj_str(shexbuf));
    free(b);
    rj_free(sres);
    *result = r;
    return 1;
}

static int wallet_psbt_signer(rj_val* fwd, void* ctx, long* ec, const char** em, rj_val** sres){
    return cmd_signrawtransactionwithwallet(fwd, (const rpc_wallet*)ctx, ec, em, sres);
}
/* MuSig2 key oracle for the wallet: the same window of HD keys the wallet
 * signer hands to the raw signer, plus the imported HD keys */
static int wallet_musig_keyfn(void* vctx, const unsigned char pub33[33], unsigned char priv[32]){
    const rpc_wallet* w = (const rpc_wallet*)vctx; if (!w || !w->seed) return 0;
    int mask = rpc_wops_active_types();
    for (int t = 0; t < 4; t++){
        if (!(mask & (1 << t))) continue;
        for (unsigned i = 0; i < SRWW_WINDOW; i++) for (int chain = 0; chain <= 1; chain++){
            unsigned idx[5]; rpc_wops_type_path(t, i, chain, idx);
            unsigned char k[32], c[32], pub[33];
            if (bip32_derive_path(k, c, w->seed, 64, idx, 5) != 1) continue;
            scalar_to_pubkey(pub, k);
            if (!memcmp(pub, pub33, 33)){ memcpy(priv, k, 32); return 1; }
        }
    }
    { extern int rpc_wops_hdkey_privkeys(unsigned char (*out)[32], int cap, unsigned window);
      static unsigned char hk[256][32]; int nh = rpc_wops_hdkey_privkeys(hk, 256, SRWW_WINDOW);
      for (int i = 0; i < nh; i++){ unsigned char pub[33]; scalar_to_pubkey(pub, hk[i]); if (!memcmp(pub, pub33, 33)){ memcpy(priv, hk[i], 32); return 1; } } }
    return 0;
}
int rpc_cmd_walletprocesspsbt(const rj_val* params, const rpc_wallet* w,
                              long* ec, const char** em, rj_val** result){
    const char* b64 = rpc_param_str(params, 0, ec, em); if (!b64) return 0;
    int sign = 1, finalize = 1;
    if (params->nitems >= 2 && params->items[1]->typ == RJ_BOOL) sign = params->items[1]->str[0]=='1';
    const char* sht = (params->nitems >= 3 && params->items[2]->typ == RJ_STR) ? params->items[2]->str : NULL;
    if (params->nitems >= 5 && params->items[4]->typ == RJ_BOOL) finalize = params->items[4]->str[0]=='1';
    if (!w || !w->seed){ *ec = -4; *em = "No wallet is loaded"; return 0; }
    return psbt_process(b64, sign, sht, finalize, wallet_psbt_signer, (void*)w, wallet_musig_keyfn, ec, em, result);
}

/* ==== descriptorprocesspsbt ==============================================
 * Core's wallet-less Signer: the private keys come from the descriptors
 * themselves (WIF keys, or xprv-derived at the index whose expansion IS an
 * input's scriptPubKey). For every prevtx the PSBT supplied, the descriptor
 * and index that produce its script are found by expansion, that
 * descriptor's private keys at that index go to signrawtransactionwithkey,
 * and a sh() descriptor's redeemScript is supplied alongside. Inputs no
 * descriptor covers stay unsigned and the result reports complete=false,
 * as Core does. The script forms that can be signed are the raw signer's:
 * P2PKH, P2WPKH, P2SH-P2WPKH. */
#include "descriptor.h"
typedef struct { descr_t* d; long lo, hi; } dpp_desc_t;
typedef struct { dpp_desc_t* v; int n; } dpp_ctx_t;
static void dpp_wif(char* out, const unsigned char priv[32], int compressed){
    unsigned char pay[34]; pay[0] = 0x80; memcpy(pay+1, priv, 32); pay[33] = 1;   /* the raw signer reads the 0x80 form on every chain */
    base58check_encode(out, pay, compressed ? 34 : 33);
}
static int dpp_signer(rj_val* fwd, void* vctx, long* ec, const char** em, rj_val** sres){
    dpp_ctx_t* c = (dpp_ctx_t*)vctx;
    rj_val* keys = rj_arr();
    rj_val* pv = (fwd->nitems >= 2 && fwd->items[1]->typ == RJ_ARR) ? rj_clone(fwd->items[1]) : rj_arr();
    int nkeys = 0;
    for (unsigned long i = 0; i < pv->nitems; i++){
        rj_val* e = pv->items[i]; rj_val* sh = rj_obj_get(e, "scriptPubKey");
        if (!sh || sh->typ != RJ_STR) continue;
        unsigned char spk[128]; size_t shl = strlen(sh->str);
        if ((shl & 1) || shl/2 > sizeof spk || !hex_to_bytes(spk, sh->str, shl)) continue;
        int done = 0;
        for (int di = 0; di < c->n && !done; di++){
            descr_t* d = c->v[di].d;
            for (long idx = c->v[di].lo; idx <= c->v[di].hi && !done; idx++){
                descr_spk_t sp[4]; int n = descr_expand(d, idx, sp, 4);
                for (int q = 0; q < n && !done; q++){
                    if (sp[q].len != (int)(shl/2) || memcmp(sp[q].spk, spk, (size_t)sp[q].len)) continue;
                    done = 1;
                    rj_val* pubs = rj_arr();
                    for (int k = 0; k < d->nk && nkeys < 64; k++){
                        unsigned char priv[32]; int comp = 1;
                        { unsigned char pub[65]; int pl; if (descr_key_pub_at(d, k, idx, pub, &pl) && pl == 33){ char ph[67]; bin_to_hex(ph, pub, 33); rj_arr_push(pubs, rj_str(ph)); } }
                        if (!descr_key_priv_at(d, k, idx, priv, &comp)) continue;
                        char wif[64]; dpp_wif(wif, priv, comp); rj_arr_push(keys, rj_str(wif)); nkeys++;
                    }
                    if (pubs->nitems && !rj_obj_get(e, "pubkeys")) rj_obj_set(e, "pubkeys", pubs); else rj_free(pubs);
                    unsigned char inner[1400]; int which = 0;
                    int il = descr_inner_script_at(d, idx, inner, (int)sizeof inner, &which);
                    if (il > 0 && which == 1 && !rj_obj_get(e, "redeemScript")){
                        char* h = malloc((size_t)il * 2 + 1);
                        if (h){ bin_to_hex(h, inner, (size_t)il); rj_obj_set(e, "redeemScript", rj_str(h)); free(h); }
                    }
                    if (il > 0 && (which == 2 || which == 3) && !rj_obj_get(e, "witnessScript")){
                        char* h = malloc((size_t)il * 2 + 1);
                        if (h){ bin_to_hex(h, inner, (size_t)il); rj_obj_set(e, "witnessScript", rj_str(h)); free(h); }
                        if (which == 3 && !rj_obj_get(e, "redeemScript")){          /* sh(wsh(...)): redeemScript = 0 <sha256(ws)> */
                            unsigned char rd[34]; rd[0] = 0x00; rd[1] = 0x20; sha256_full(rd + 2, inner, (unsigned long)il);
                            char rh[69]; bin_to_hex(rh, rd, 34); rj_obj_set(e, "redeemScript", rj_str(rh));
                        }
                    }
                }
            }
        }
    }
    rj_val* f2 = rj_arr();
    rj_arr_push(f2, rj_str(fwd->items[0]->str));
    rj_arr_push(f2, keys);
    rj_arr_push(f2, pv);
    if (fwd->nitems >= 3 && fwd->items[2]->typ == RJ_STR) rj_arr_push(f2, rj_str(fwd->items[2]->str));
    int rc = cmd_signrawtransactionwithkey(f2, ec, em, sres);
    rj_free(f2);
    return rc;
}
/* MuSig2 key oracle for descriptorprocesspsbt: any key of any supplied
 * descriptor, at any index of its range (a participant's key is handed in
 * as its own descriptor, e.g. tr(<xprv>/0/*) or pk(<WIF>)) */
static int dpp_musig_keyfn(void* vctx, const unsigned char pub33[33], unsigned char priv[32]){
    dpp_ctx_t* c = (dpp_ctx_t*)vctx;
    for (int di = 0; di < c->n; di++){
        descr_t* d = c->v[di].d;
        for (long idx = c->v[di].lo; idx <= c->v[di].hi; idx++)
            for (int k = 0; k < d->nk; k++){
                unsigned char pub[65]; int pl = 0;
                if (!descr_key_pub_at(d, k, idx, pub, &pl) || pl != 33 || memcmp(pub, pub33, 33)) continue;
                int comp = 1; if (descr_key_priv_at(d, k, idx, priv, &comp)) return 1;
            }
    }
    return 0;
}
/* descriptorprocesspsbt's Updater step for musig() (2026-09-01): for every
 * input whose witness_utxo is a tr(musig(...)) / rawtr(musig(...)) expansion
 * of one of the descriptors, add what Core's UpdatePSBTInput adds and the
 * MuSig2 signer consumes: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1a, keyed by
 * the untweaked, underived aggregate; the sorted participants), a
 * PSBT_IN_TAP_BIP32_DERIVATION (0x16) for the derived key with fingerprint
 * hash160(aggregate)[0..4] and the musig() path (only when there is one),
 * and PSBT_IN_TAP_INTERNAL_KEY (0x17) for tr(). Fields already present are
 * left alone. Returns a malloc'd base64 PSBT, or NULL when nothing changed. */
static char* dpp_musig_update(const char* b64, dpp_desc_t* dv, int nd){
    static unsigned char buf[200000]; long blen = 0;
    if (!crt_b64dec(b64, buf, sizeof buf, &blen) || blen < 5 || memcmp(buf, "psbt\xff", 5)) return NULL;
    long p = 5;
    static psbt_kv gkv[FIN_MAXKV]; int gn = psbt_parse_map(buf, blen, &p, gkv, FIN_MAXKV);
    const psbt_kv* utxk = fin_find(gkv, gn, 0x00); if (!utxk) return NULL;
    static crt_in_t uin[FIN_MAXIO]; int n_in, sw; unsigned long ost, oen;
    if (!crt_walk(utxk->v, utxk->vl, uin, FIN_MAXIO, &n_in, &ost, &oen, &sw)) return NULL;
    static psbt_kv ikv[FIN_MAXIO][FIN_MAXKV]; static int in_n[FIN_MAXIO];
    for (int i = 0; i < n_in; i++) in_n[i] = psbt_parse_map(buf, blen, &p, ikv[i], FIN_MAXKV);
    unsigned long n_out; { unsigned long cc; n_out = srw_varint(utxk->v + ost, &cc); }
    static psbt_kv okv[FIN_MAXIO][FIN_MAXKV]; static int out_n[FIN_MAXIO];
    for (unsigned long i = 0; i < n_out && i < FIN_MAXIO; i++) out_n[i] = psbt_parse_map(buf, blen, &p, okv[i], FIN_MAXKV);
    /* new field storage: at most one aggregate per input */
    static unsigned char k1a[FIN_MAXIO][34], v1a[FIN_MAXIO][33 * MUSIG2_MAX_KEYS], k16[FIN_MAXIO][33], v16[FIN_MAXIO][1 + 4 + 4 * 40], k17[FIN_MAXIO], v17[FIN_MAXIO][32];
    static unsigned char k16p[FIN_MAXIO][MUSIG2_MAX_KEYS][33], v16p[FIN_MAXIO][MUSIG2_MAX_KEYS][5 + 4 * (DESCR_MAX_PATH * 2 + 1)];
    int changed = 0;
    for (int i = 0; i < n_in; i++){
        unsigned long long amount; const unsigned char* spk; unsigned long spklen;
        if (!mu_witness_utxo(ikv[i], in_n[i], &amount, &spk, &spklen)) continue;
        if (spklen != 34 || spk[0] != 0x51 || spk[1] != 0x20) continue;
        if (fin_find(ikv[i], in_n[i], 0x1a)) continue;                        /* already updated */
        for (int di = 0; di < nd; di++){
            descr_t* d = dv[di].d; int kx = descr_top_key(d);
            if (kx < 0 || d->keys[kx].kind != DK_MUSIG) continue;
            int is_tr = d->nodes[d->root].type == DN_TR;
            if (is_tr && d->nodes[d->root].child[0] >= 0) continue;           /* key-path musig with a script tree: not updated here */
            int hit = 0;
            for (long idx = dv[di].lo; idx <= dv[di].hi && !hit; idx++){
                descr_spk_t sp[4]; if (descr_expand(d, idx, sp, 4) != 1 || sp[0].len != 34 || memcmp(sp[0].spk, spk, 34)) continue;
                unsigned char agg[33], parts[MUSIG2_MAX_KEYS][33], der[33]; int np = 0, plen = 0; unsigned path[40];
                if (!descr_musig_info(d, kx, idx, agg, parts, &np, der, path, &plen)) break;
                hit = 1;
                k1a[i][0] = 0x1a; memcpy(k1a[i] + 1, agg, 33); memcpy(v1a[i], parts, (size_t)np * 33);
                if (in_n[i] + 3 > FIN_MAXKV) break;
                ikv[i][in_n[i]].k = k1a[i]; ikv[i][in_n[i]].kl = 34; ikv[i][in_n[i]].v = v1a[i]; ikv[i][in_n[i]].vl = (unsigned long)np * 33; in_n[i]++;
                if (plen > 0){
                    k16[i][0] = 0x16; memcpy(k16[i] + 1, der + 1, 32);
                    unsigned char fp[20]; hash160(fp, agg, 33);
                    v16[i][0] = 0; memcpy(v16[i] + 1, fp, 4);
                    for (int t = 0; t < plen; t++){ unsigned char* z = v16[i] + 5 + 4 * t; z[0] = (unsigned char)path[t]; z[1] = (unsigned char)(path[t] >> 8); z[2] = (unsigned char)(path[t] >> 16); z[3] = (unsigned char)(path[t] >> 24); }
                    int dup = 0; for (int q = 0; q < in_n[i]; q++) if (ikv[i][q].kl == 33 && ikv[i][q].k[0] == 0x16 && !memcmp(ikv[i][q].k + 1, der + 1, 32)) dup = 1;
                    if (!dup){ ikv[i][in_n[i]].k = k16[i]; ikv[i][in_n[i]].kl = 33; ikv[i][in_n[i]].v = v16[i]; ikv[i][in_n[i]].vl = 5 + 4 * (unsigned long)plen; in_n[i]++; }
                }
                if (is_tr && !fin_find(ikv[i], in_n[i], 0x17)){
                    k17[i] = 0x17; memcpy(v17[i], der + 1, 32);
                    ikv[i][in_n[i]].k = &k17[i]; ikv[i][in_n[i]].kl = 1; ikv[i][in_n[i]].v = v17[i]; ikv[i][in_n[i]].vl = 32; in_n[i]++;
                }
                /* one TAP_BIP32_DERIVATION per participant, as Core's UpdatePSBTInput writes them: the
                 * key's origin when it has one, else the xpub's own fingerprint + path, else the bare
                 * key's hash160 prefix with an empty path -- what lets every signer find its key */
                const descr_key_t* mk = &d->keys[kx];
                for (int q = 0; q < mk->musig_n && in_n[i] + 1 <= FIN_MAXKV; q++){
                    const descr_key_t* pkey = &d->keys[mk->musig_parts[q]];
                    unsigned char ppub[65]; int ppl = 0;
                    if (!descr_key_pub_at(d, mk->musig_parts[q], idx, ppub, &ppl) || ppl != 33) continue;
                    unsigned char* kk = k16p[i][q]; unsigned char* vv = v16p[i][q];
                    kk[0] = 0x16; memcpy(kk + 1, ppub + 1, 32);
                    int dup = 0; for (int z = 0; z < in_n[i]; z++) if (ikv[i][z].kl == 33 && ikv[i][z].k[0] == 0x16 && !memcmp(ikv[i][z].k + 1, ppub + 1, 32)) dup = 1;
                    if (dup) continue;
                    unsigned pp[DESCR_MAX_PATH * 2 + 1]; int pn = 0;
                    vv[0] = 0;
                    if (pkey->has_origin){ memcpy(vv + 1, pkey->origin_fp, 4); for (int z = 0; z < pkey->origin_len && pn < DESCR_MAX_PATH * 2; z++) pp[pn++] = pkey->origin[z]; }
                    else { unsigned char h[20]; hash160(h, pkey->pub, (pkey->kind == DK_XPUB || pkey->kind == DK_XPRV) ? 33 : pkey->publen); memcpy(vv + 1, h, 4); }
                    if (pkey->kind == DK_XPUB || pkey->kind == DK_XPRV){
                        for (int z = 0; z < pkey->pathlen && pn < DESCR_MAX_PATH * 2; z++) pp[pn++] = pkey->path[z];
                        if (pkey->ranged && pn < DESCR_MAX_PATH * 2) pp[pn++] = (unsigned)idx | (pkey->range_hard ? 0x80000000u : 0);
                    }
                    for (int z = 0; z < pn; z++){ unsigned char* w = vv + 5 + 4 * z; w[0] = (unsigned char)pp[z]; w[1] = (unsigned char)(pp[z] >> 8); w[2] = (unsigned char)(pp[z] >> 16); w[3] = (unsigned char)(pp[z] >> 24); }
                    ikv[i][in_n[i]].k = kk; ikv[i][in_n[i]].kl = 33; ikv[i][in_n[i]].v = vv; ikv[i][in_n[i]].vl = 5 + 4 * (unsigned long)pn; in_n[i]++;
                }
                changed = 1;
            }
            if (hit) break;
        }
    }
    if (!changed) return NULL;
    static unsigned char out[220000]; long o = 0;
    memcpy(out, "psbt\xff", 5); o = 5;
    o += psbt_ser_map(out + o, gkv, gn);
    for (int i = 0; i < n_in; i++) o += psbt_ser_map(out + o, ikv[i], in_n[i]);
    for (unsigned long i = 0; i < n_out && i < FIN_MAXIO; i++) o += psbt_ser_map(out + o, okv[i], out_n[i]);
    char* b = malloc((size_t)((o + 2) / 3) * 4 + 1); if (!b) return NULL;
    crt_b64(b, out, o);
    return b;
}
#define DPP_MAX_DESCS 16
int rpc_cmd_descriptorprocesspsbt(const rj_val* params, long* ec, const char** em, rj_val** result){
    const char* b64 = rpc_param_str(params, 0, ec, em); if (!b64) return 0;
    if (params->nitems < 2 || params->items[1]->typ != RJ_ARR){ *ec = -8; *em = "descriptors must be an array of descriptor strings or {desc,range} objects"; return 0; }
    const char* sht = (params->nitems >= 3 && params->items[2]->typ == RJ_STR) ? params->items[2]->str : NULL;
    int finalize = 1;
    if (params->nitems >= 5 && params->items[4]->typ == RJ_BOOL) finalize = params->items[4]->str[0]=='1';
    const rj_val* da = params->items[1];
    static descr_t descs[DPP_MAX_DESCS]; static dpp_desc_t dv[DPP_MAX_DESCS]; int nd = 0;
    static char perr[300];
    if (da->nitems > DPP_MAX_DESCS){ *ec = -8; *em = "Too many descriptors"; return 0; }
    for (unsigned long i = 0; i < da->nitems; i++){
        const rj_val* o = da->items[i]; const char* ds = NULL; long lo = 0, hi = 1000;
        if (o->typ == RJ_STR) ds = o->str;
        else if (o->typ == RJ_OBJ){
            rj_val* dv0 = rj_obj_get(o, "desc"); if (dv0 && dv0->typ == RJ_STR) ds = dv0->str;
            rj_val* rv = rj_obj_get(o, "range");
            if (rv && rv->typ == RJ_NUM) hi = strtol(rv->str, NULL, 10);
            else if (rv && rv->typ == RJ_ARR && rv->nitems == 2 && rv->items[0]->typ == RJ_NUM && rv->items[1]->typ == RJ_NUM){
                lo = strtol(rv->items[0]->str, NULL, 10); hi = strtol(rv->items[1]->str, NULL, 10); }
        }
        if (!ds){ *ec = -8; *em = "Descriptor needs to be provided in scan object"; return 0; }
        char e[256];
        if (!descr_parse(ds, &descs[nd], e, sizeof e)){ snprintf(perr, sizeof perr, "%s", e); *ec = -5; *em = perr; return 0; }
        if (!descs[nd].ranged){ lo = 0; hi = 0; }
        if (lo < 0 || hi < lo || hi - lo > 100000){ *ec = -8; *em = "Invalid range"; return 0; }
        dv[nd].d = &descs[nd]; dv[nd].lo = lo; dv[nd].hi = hi; nd++;
    }
    dpp_ctx_t ctx = { dv, nd };
    char* upd = dpp_musig_update(b64, dv, nd);          /* the Updater role for musig() descriptors (BIP390/BIP373) */
    int rc = psbt_process(upd ? upd : b64, 1, sht, finalize, dpp_signer, &ctx, dpp_musig_keyfn, ec, em, result);
    free(upd);
    return rc;
}

/* The wallet/util subset rpc_commands.c dispatches itself. At file scope
 * so `help` can enumerate it alongside the other modules' tables --
 * one list, no second copy to fall out of step. */
static const char* const WALLET_METHODS[] = {
        "getnewaddress","getrawchangeaddress","validateaddress","getaddressinfo",
        "gettxout","listunspent","getbalance","decoderawtransaction",
        "signmessagewithprivkey","verifymessage","createrawtransaction","signrawtransactionwithkey","createpsbt","decodepsbt","converttopsbt","combinepsbt","joinpsbts","analyzepsbt",
        "listtransactions","gettransaction","getwalletinfo","getbalances",
        "signrawtransactionwithwallet","simulaterawtransaction",
        "combinerawtransaction","finalizepsbt","utxoupdatepsbt",
        "descriptorprocesspsbt",
    /* Control, plus the three singletons Core files elsewhere */
    "help","logging","getrpcinfo","getmemoryinfo","getopenrpcinfo","rpc.discover",
    "exportasmap","enumeratesigners",
        /* createrawtransaction / signraw / sendraw are wired by the server card
         * which owns the tx-store lookup; the pure-wallet subset is dispatched
         * here. */
    NULL
};

/* ==== Core's Control category, plus the three singletons (2026-08-25) ====
 * These live here because rpc_commands.c is the only translation unit that
 * can see every module's method table, which `help` needs. */

/* Every method this node serves, merged from the four tables and sorted.
 * Built from the tables themselves, so a method added to a dispatcher shows
 * up here automatically and a hand-maintained second list cannot drift. */
#define CTL_MAXM 512
static int ctl_all_methods(const char* out[CTL_MAXM]){
    int n = 0;
    const char* m;
    for (int i = 0; (m = rpc_wallet_method_at(i)) != NULL && n < CTL_MAXM; i++) out[n++] = m;
    for (int i = 0; (m = rpc_wops_method_at(i))   != NULL && n < CTL_MAXM; i++) out[n++] = m;
    for (int i = 0; (m = rpc_node_method_at(i))   != NULL && n < CTL_MAXM; i++) out[n++] = m;
    for (int i = 0; (m = rpc_chain_method_at(i))  != NULL && n < CTL_MAXM; i++) out[n++] = m;
    /* insertion sort; n is ~150 and this runs once per help call */
    for (int i = 1; i < n; i++){
        const char* k = out[i]; int j = i - 1;
        while (j >= 0 && strcmp(out[j], k) > 0){ out[j+1] = out[j]; j--; }
        out[j+1] = k;
    }
    /* de-duplicate: a name could legitimately appear in two tables */
    int w = 0;
    for (int i = 0; i < n; i++){
        if (w > 0 && !strcmp(out[w-1], out[i])) continue;
        out[w++] = out[i];
    }
    return w;
}

/* help ( "command" )
 * Core answers with per-method usage text grouped by category. This node
 * carries neither -- the usage strings are ~150 hand-written blocks that
 * would have to be kept in step with the implementations by hand, and a
 * usage string that has drifted from its method is worse than none. What it
 * does have is the authoritative list of what it serves, taken from the
 * dispatch tables themselves. */
static int cmd_help(const rj_val* params, long* ec, const char** em, rj_val** result){
    const char* want = NULL;
    if (params && params->typ == RJ_ARR && params->nitems >= 1 &&
        params->items[0]->typ == RJ_STR && params->items[0]->str[0])
        want = params->items[0]->str;
    if (want){
        static char line[256];
        if (!rpc_known_method(want)){
            /* Core's exact text for an unknown command */
            snprintf(line, sizeof line, "help: unknown command: %s", want);
            *result = rj_str(line);
            return 1;
        }
        snprintf(line, sizeof line,
                 "%s\n\nThis node serves %s, but does not carry Bitcoin Core's "
                 "per-method usage text. Consult Core's own `help %s` for the "
                 "argument and result shapes; where this node diverges from "
                 "them it is recorded in docs/RPC_LIVE_NODE.md.", want, want, want);
        *result = rj_str(line);
        return 1;
    }
    const char* all[CTL_MAXM];
    int n = ctl_all_methods(all);
    /* header + one line each */
    size_t cap = 512 + (size_t)n * 40;
    char* buf = malloc(cap);
    if (!buf){ *ec = -7; *em = "oom"; return 0; }
    int o = snprintf(buf, cap,
        "== Methods served by this node (%d) ==\n"
        "This list is generated from the dispatch tables, so it is exactly what\n"
        "will be answered. Per-method usage text is not carried here; see\n"
        "Core's own help for argument shapes and docs/RPC_LIVE_NODE.md for the\n"
        "places this node deliberately diverges or refuses.\n\n", n);
    for (int i = 0; i < n && o < (int)cap - 2; i++)
        o += snprintf(buf + o, cap - (size_t)o, "%s\n", all[i]);
    *result = rj_str(buf);
    free(buf);
    return 1;
}

/* getrpcinfo -- Core reports the commands currently executing and the log
 * path. This node's RPC server accepts and services ONE connection at a time
 * on a single thread (rpc_server.c), so at the moment getrpcinfo runs it is
 * necessarily the only active command: the single-element array is the
 * complete truth here, not a simplification. */
static int cmd_getrpcinfo(rj_val** result){
    rj_val* cmds = rj_arr();
    rj_val* c = rj_obj();
    rj_obj_set(c, "method", rj_str("getrpcinfo"));
    rj_obj_set(c, "duration", rj_numf("%d", 0));
    rj_arr_push(cmds, c);
    rj_val* o = rj_obj();
    rj_obj_set(o, "active_commands", cmds);
    /* The daemon opens its log as the bare relative name "bitcoind.log" from
     * the datadir it runs in (daemon/main.c), so resolving it against the
     * cwd is the real path, not a guess. */
    { char cwd[1024];
      if (getcwd(cwd, sizeof cwd)){
          char path[1200];
          snprintf(path, sizeof path, "%s/bitcoind.log", cwd);
          rj_obj_set(o, "logpath", rj_str(path));
      } }
    *result = o;
    return 1;
}

/* logging ( ["include"] ["exclude"] )
 * node_log.asm emits eight fixed kinds (INFO HSHK HDRS BLOCK CONS STORE
 * ERROR SERVE) and has no runtime gate: every event is written
 * unconditionally, by design -- the logger holds no global mutable state so
 * it can link anywhere. The read form therefore reports this node's real
 * kinds, all true because they really are all emitted. The mutating form is
 * refused rather than accepted-and-ignored: a caller who turned a category
 * "off" and kept seeing it in the log would be worse off than one told the
 * switch does not exist. Note these are NOT Core's category names, because
 * they are not Core's categories. */
static int cmd_logging(const rj_val* params, long* ec, const char** em, rj_val** result){
    if (params && params->typ == RJ_ARR && params->nitems >= 1){
        *ec = -1;
        *em = "this node's logger (node_log.asm) has no runtime category gate: "
              "its eight kinds are always emitted, deliberately, so that it "
              "holds no global mutable state and can link anywhere. Call "
              "logging with no arguments to see them; there is nothing to "
              "switch on or off";
        return 0;
    }
    static const char* KINDS[] = { "info","hshk","hdrs","block","cons","store","error","serve" };
    rj_val* o = rj_obj();
    for (int i = 0; i < 8; i++) rj_obj_set(o, KINDS[i], rj_bool(1));
    *result = o;
    return 1;
}

/* getmemoryinfo ( "mode" )
 * Core's default mode reports its SECURE ALLOCATOR's locked pool. This node
 * has no secure allocator, so those six numbers describe nothing here and
 * are refused rather than zeroed. Mode "mallocinfo" is real: glibc's
 * malloc_info(3) emits the same XML Core forwards. */
static int cmd_getmemoryinfo(const rj_val* params, long* ec, const char** em, rj_val** result){
    const char* mode = "stats";
    if (params && params->typ == RJ_ARR && params->nitems >= 1 &&
        params->items[0]->typ == RJ_STR) mode = params->items[0]->str;
    if (!strcmp(mode, "mallocinfo")){
        char* buf = NULL; size_t len = 0;
        FILE* f = open_memstream(&buf, &len);
        if (!f){ *ec = -7; *em = "oom"; return 0; }
        int r = malloc_info(0, f);
        fclose(f);
        if (r != 0){ free(buf); *ec = -1; *em = "malloc_info failed"; return 0; }
        *result = rj_str(buf ? buf : "");
        free(buf);
        return 1;
    }
    if (!strcmp(mode, "stats")){
        *ec = -1;
        *em = "getmemoryinfo \"stats\" reports Bitcoin Core's SECURE ALLOCATOR "
              "locked-page pool. This node has no secure allocator, so those "
              "numbers would describe nothing. Use mode \"mallocinfo\", which "
              "returns glibc's real malloc_info(3) XML";
        return 0;
    }
    *ec = -8; *em = "mode must be \"stats\" or \"mallocinfo\"";
    return 0;
}

static int ctl_unsupported(const char* msg, long* ec, const char** em){
    *ec = -1; *em = msg; return 0;
}

const char* rpc_wallet_method_at(int i){
    int n = 0;
    while (WALLET_METHODS[n]) n++;
    return (i >= 0 && i < n) ? WALLET_METHODS[i] : NULL;
}

int rpc_known_method(const char* method) {
    for (int i = 0; WALLET_METHODS[i]; i++) if (!strcmp(method, WALLET_METHODS[i])) return 1;
    if (rpc_wops_known_method(method)) return 1;
    if (rpc_node_known_method(method)) return 1;
    return rpc_chain_known_method(method);
}

int rpc_dispatch(const char* method, const rj_val* params,
                 const rpc_wallet* w,
                 rj_val** result, long* err_code, const char** err_msg) {
    *err_code = 0; *err_msg = NULL; *result = NULL;
    if (!strcmp(method, "getnewaddress") || !strcmp(method, "getrawchangeaddress")) {
        if (!w->seed) {
            /* a WATCH-ONLY wallet (multi-wallet, 2026-08-27) hands out the
             * next unused address of its first imported descriptor -- the
             * same derivation deriveaddresses answers, so getnewaddress and
             * deriveaddresses can never disagree */
            extern int rpc_wops_watchonly(void);
            extern int rpc_wops_watch_newaddress(char*, long, long*, const char**);
            if (rpc_wops_watchonly()){
                char a[128];
                int r = rpc_wops_watch_newaddress(a, sizeof a, err_code, err_msg);
                if (r != 1) return 0;
                *result = rj_str(a);
                return 1;
            }
            *err_code = 32603; *err_msg = "wallet seed not configured"; return 0;
        }
        return cmd_getnewaddr(method, params, w, err_code, err_msg, result);
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
    if (!strcmp(method, "listtransactions"))
        return cmd_listtransactions(params, err_code, err_msg, result);
    if (!strcmp(method, "gettransaction"))
        return cmd_gettransaction(params, err_code, err_msg, result);
    if (!strcmp(method, "getwalletinfo"))
        return cmd_getwalletinfo(w, result);
    if (!strcmp(method, "getbalances"))
        return cmd_getbalances(w, result);
    if (!strcmp(method, "signrawtransactionwithkey"))
        return cmd_signrawtransactionwithkey(params, err_code, err_msg, result);
    if (!strcmp(method, "signrawtransactionwithwallet"))
        return cmd_signrawtransactionwithwallet(params, w, err_code, err_msg, result);
    if (!strcmp(method, "simulaterawtransaction"))
        return cmd_simulaterawtransaction(params, w, err_code, err_msg, result);
    if (!strcmp(method, "help"))
        return cmd_help(params, err_code, err_msg, result);
    if (!strcmp(method, "getrpcinfo"))
        return cmd_getrpcinfo(result);
    if (!strcmp(method, "logging"))
        return cmd_logging(params, err_code, err_msg, result);
    if (!strcmp(method, "getmemoryinfo"))
        return cmd_getmemoryinfo(params, err_code, err_msg, result);
    if (!strcmp(method, "getopenrpcinfo") || !strcmp(method, "rpc.discover"))
        return ctl_unsupported(
            "this node publishes no OpenRPC service description: that document "
            "restates every method's argument and result schema, which would be "
            "a second specification to keep in step with the implementations by "
            "hand. `help` lists what is served, generated from the dispatch "
            "tables themselves", err_code, err_msg);
    if (!strcmp(method, "exportasmap"))
        return ctl_unsupported(
            "this node uses no asmap: peer diversity is not bucketed by AS, so "
            "there is no mapping to export", err_code, err_msg);
    if (!strcmp(method, "enumeratesigners")){
        extern int rpc_signer_enumerate(rj_val**, long*, const char**);
        return rpc_signer_enumerate(result, err_code, err_msg);
    }
    if (!strcmp(method, "combinerawtransaction"))
        return cmd_combinerawtransaction(params, err_code, err_msg, result);
    if (!strcmp(method, "finalizepsbt"))
        return cmd_finalizepsbt(params, err_code, err_msg, result);
    if (!strcmp(method, "utxoupdatepsbt"))
        return cmd_utxoupdatepsbt(params, err_code, err_msg, result);
    if (!strcmp(method, "descriptorprocesspsbt"))
        return rpc_cmd_descriptorprocesspsbt(params, err_code, err_msg, result);
    /* the rest of Core's Wallet category (rpc_wallet_ops.c) -- labels, wallet
     * inventory, output locks, message signing, descriptor reporting, and the
     * lifecycle methods a single-seed wallet cannot honour. */
    {
        int r = rpc_wops_dispatch(method, params, w, result, err_code, err_msg);
        if (r >= 0) return r;
    }
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

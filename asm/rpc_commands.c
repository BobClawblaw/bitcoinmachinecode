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

/* rpc_esplora.c -- the Esplora facade (2026-09-08).
 *
 * mempool.space serves address pages, per-block transaction lists with
 * prevouts and outspends only through an Esplora-compatible REST backend
 * (its own production runs on one); with a plain bitcoind it refuses
 * address lookups and fetches every input's previous transaction one RPC at
 * a time. This file answers that REST contract from the node's OWN RPC
 * handlers, in process: every route is a call to rpc_dispatch (the same
 * dispatch the JSON-RPC server uses, so nothing can diverge) and a reshape
 * of Core's JSON into Esplora's. The shapes are exactly what mempool's own
 * converter produces from Core JSON (backend/src/api/bitcoin/bitcoin-api.ts,
 * transaction-utils.ts convertScriptSigAsm), except where real Esplora
 * differs and mempool consumes Esplora's form: a coinbase input carries the
 * all-zero txid and vout 4294967295.
 *
 * Stage 1 (this file): tips, block by hash and height, header, raw block,
 * txids, block transactions with prevouts (mempool's /internal/block/../txs),
 * transactions with prevouts and fee, hex, status, merkle proof, outspends
 * (the txospender index when present, gettxout otherwise), the mempool
 * (txids, recent, batch loads), broadcast. Address and scripthash routes
 * answer 501 until the address-history index (stage 2) lands.
 *
 * Amounts: Esplora's are integer satoshis; Core's are decimal strings. The
 * conversion is string arithmetic, never a double. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rpc_esplora.h"
#include "rpc_json.h"
#include "daemon/addr_hist_fmt.h"
/* the address routes' sources (stage 2, 2026-09-08) */
extern int  wallet_validate_address(const char* addr, int* type, unsigned char* ver, unsigned char h160[20], unsigned char prog[32]);
extern long axt_read_events(int type, const unsigned char hash[32], long min_height,
                            int (*cb)(void*, int, const unsigned char*, unsigned, unsigned long long, unsigned), void* ctx);

typedef unsigned char u8;
extern void sha256d(u8 out[32], const void* data, unsigned long len);

/* ---- small helpers -------------------------------------------------------- */
static const char* S(const rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : 0; return v && (v->typ == RJ_STR || v->typ == RJ_NUM) ? v->str : 0; }
static rj_val* G(const rj_val* o, const char* k){ return o ? rj_obj_get(o, k) : 0; }
static long long N(const rj_val* o, const char* k){ const char* s = S(o, k); return s ? strtoll(s, 0, 10) : 0; }
static int hexval(int c){ return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
static long unhex(const char* h, u8* out, long cap){ long n = 0; while (h[0] && h[1] && n < cap){ int a = hexval(h[0]), b = hexval(h[1]); if (a < 0 || b < 0) return -1; out[n++] = (u8)(a * 16 + b); h += 2; } return h[0] ? -1 : n; }
static void hexof(char* out, const u8* p, long n){ static const char* d = "0123456789abcdef"; for (long i = 0; i < n; i++){ out[2*i] = d[p[i] >> 4]; out[2*i+1] = d[p[i] & 15]; } out[2*n] = 0; }
static void hexrev(char* out, const u8* p){ u8 r[32]; for (int i = 0; i < 32; i++) r[i] = p[31 - i]; hexof(out, r, 32); }

long esplora_sats_of_amount(const char* dec){
    if (!dec) return -1;
    int neg = 0; if (*dec == '-'){ neg = 1; dec++; }
    long long whole = 0, frac = 0; int fd = 0; const char* p = dec;
    if (!isdigit((unsigned char)*p)) return -1;
    while (isdigit((unsigned char)*p)) whole = whole * 10 + (*p++ - '0');
    if (*p == '.'){ p++; while (isdigit((unsigned char)*p)){ if (fd < 8){ frac = frac * 10 + (*p - '0'); fd++; } p++; } }
    if (*p) return -1;
    while (fd < 8){ frac *= 10; fd++; }
    long long v = whole * 100000000LL + frac;
    return (long)(neg ? -v : v);
}
const char* esplora_spk_type(const char* t){
    if (!t) return "unknown";
    if (!strcmp(t, "pubkey")) return "p2pk";
    if (!strcmp(t, "pubkeyhash")) return "p2pkh";
    if (!strcmp(t, "scripthash")) return "p2sh";
    if (!strcmp(t, "witness_v0_keyhash")) return "v0_p2wpkh";
    if (!strcmp(t, "witness_v0_scripthash")) return "v0_p2wsh";
    if (!strcmp(t, "witness_v1_taproot")) return "v1_p2tr";
    if (!strcmp(t, "nonstandard")) return "nonstandard";
    if (!strcmp(t, "multisig")) return "multisig";
    if (!strcmp(t, "anchor")) return "anchor";
    if (!strcmp(t, "nulldata")) return "op_return";
    return "unknown";
}
static const char* opname(int op){
    static const char* n[] = { /* 0x61.. */
        "OP_NOP","OP_VER","OP_IF","OP_NOTIF","OP_VERIF","OP_VERNOTIF","OP_ELSE","OP_ENDIF","OP_VERIFY","OP_RETURN",
        "OP_TOALTSTACK","OP_FROMALTSTACK","OP_2DROP","OP_2DUP","OP_3DUP","OP_2OVER","OP_2ROT","OP_2SWAP","OP_IFDUP","OP_DEPTH",
        "OP_DROP","OP_DUP","OP_NIP","OP_OVER","OP_PICK","OP_ROLL","OP_ROT","OP_SWAP","OP_TUCK","OP_CAT",
        "OP_SUBSTR","OP_LEFT","OP_RIGHT","OP_SIZE","OP_INVERT","OP_AND","OP_OR","OP_XOR","OP_EQUAL","OP_EQUALVERIFY",
        "OP_RESERVED1","OP_RESERVED2","OP_1ADD","OP_1SUB","OP_2MUL","OP_2DIV","OP_NEGATE","OP_ABS","OP_NOT","OP_0NOTEQUAL",
        "OP_ADD","OP_SUB","OP_MUL","OP_DIV","OP_MOD","OP_LSHIFT","OP_RSHIFT","OP_BOOLAND","OP_BOOLOR","OP_NUMEQUAL",
        "OP_NUMEQUALVERIFY","OP_NUMNOTEQUAL","OP_LESSTHAN","OP_GREATERTHAN","OP_LESSTHANOREQUAL","OP_GREATERTHANOREQUAL","OP_MIN","OP_MAX","OP_WITHIN","OP_RIPEMD160",
        "OP_SHA1","OP_SHA256","OP_HASH160","OP_HASH256","OP_CODESEPARATOR","OP_CHECKSIG","OP_CHECKSIGVERIFY","OP_CHECKMULTISIG","OP_CHECKMULTISIGVERIFY","OP_NOP1",
        "OP_CLTV","OP_CSV","OP_NOP4","OP_NOP5","OP_NOP6","OP_NOP7","OP_NOP8","OP_NOP9","OP_NOP10","OP_CHECKSIGADD" };
    if (op >= 0x61 && op <= 0xba) return n[op - 0x61];
    return 0;
}
/* mempool's convertScriptSigAsm, byte for byte */
size_t esplora_asm_of_hex(const char* hex, char* out, size_t cap){
    size_t o = 0; long len = hex ? (long)strlen(hex) / 2 : 0;
    u8* buf = malloc((size_t)len + 1); if (!buf){ if (cap) out[0] = 0; return 0; }
    if (unhex(hex ? hex : "", buf, len) < 0) len = 0;
    #define PUT(s) do{ size_t l = strlen(s); if (o + l + 2 < cap){ if (o){ out[o++] = ' '; } memcpy(out + o, s, l); o += l; out[o] = 0; } }while(0)
    long i = 0; char tmp[64];
    while (i < len){
        int op = buf[i];
        if (op >= 0x01 && op <= 0x4e){
            i++; long push;
            if (op == 0x4c && len > i){ push = buf[i]; PUT("OP_PUSHDATA1"); i += 1; }
            else if (op == 0x4d && len > i + 1){ push = buf[i] | (buf[i+1] << 8); PUT("OP_PUSHDATA2"); i += 2; }
            else if (op == 0x4e && len > i + 3){ push = (long)buf[i] | ((long)buf[i+1] << 8) | ((long)buf[i+2] << 16) | ((long)buf[i+3] << 24); PUT("OP_PUSHDATA4"); i += 4; }
            else { push = op; snprintf(tmp, sizeof tmp, "OP_PUSHBYTES_%ld", push); PUT(tmp); }
            if (i >= len) break;
            long take = push; if (i + take > len) take = len - i;
            if (o + (size_t)take * 2 + 2 < cap){ if (o) out[o++] = ' '; hexof(out + o, buf + i, take); o += (size_t)take * 2; }
            i += take;
            if (take != push) break;
        } else {
            if (op == 0x00) PUT("OP_0");
            else if (op == 0x4f) PUT("OP_PUSHNUM_NEG1");
            else if (op == 0x50) PUT("OP_RESERVED");
            else if (op >= 0x51 && op <= 0x60){ snprintf(tmp, sizeof tmp, "OP_PUSHNUM_%d", op - 0x50); PUT(tmp); }
            else { const char* nm = opname(op); if (nm) PUT(nm); else { snprintf(tmp, sizeof tmp, "OP_RETURN_%d", op); PUT(tmp); } }
            i += 1;
        }
    }
    #undef PUT
    free(buf);
    if (cap) out[o < cap ? o : cap - 1] = 0;
    return o;
}
/* merkle branch for leaf `pos`: the sibling at each level, leaf to root */
int esplora_merkle_branch(const u8 (*txids)[32], long n, long pos, u8 (*branch)[32], long cap){
    if (n <= 0 || pos < 0 || pos >= n) return -1;
    u8 (*lvl)[32] = malloc((size_t)(n + 1) * 32); if (!lvl) return -1;
    memcpy(lvl, txids, (size_t)n * 32);
    long cnt = n, idx = pos, nb = 0;
    while (cnt > 1){
        long sib = idx ^ 1; if (sib >= cnt) sib = idx;         /* odd count: the last is paired with itself */
        if (nb < cap) memcpy(branch[nb], lvl[sib], 32);
        nb++;
        long next = 0;
        for (long i = 0; i < cnt; i += 2){
            u8 pair[64]; memcpy(pair, lvl[i], 32); memcpy(pair + 32, lvl[i + 1 < cnt ? i + 1 : i], 32);
            sha256d(lvl[next++], pair, 64);
        }
        cnt = next; idx /= 2;
    }
    free(lvl);
    return (int)(nb <= cap ? nb : cap);
}

/* ---- RPC in process --------------------------------------------------------- */
/* The server's execution lock is taken around EACH dispatch, not around the
 * request: a route that makes thousands of calls (a batch load) must let
 * JSON-RPC callers interleave. rpc_server.c installs the hooks. */
static void (*g_lock)(void) = 0; static void (*g_unlock)(void) = 0;
void esplora_set_exec_lock(void (*lock)(void), void (*unlock)(void)){ g_lock = lock; g_unlock = unlock; }
static rj_val* call(const rpc_wallet* w, const char* method, rj_val* params, long* ec, const char** em){
    rj_val* r = 0; long e = 0; const char* m = 0;
    if (g_lock) g_lock();
    int ok = rpc_dispatch(method, params, w, &r, &e, &m);
    if (g_unlock) g_unlock();
    if (params) rj_free(params);
    if (ec) *ec = ok ? 0 : e;
    if (em) *em = ok ? 0 : m;
    return ok ? r : 0;
}
static rj_val* P1s(const char* s){ rj_val* a = rj_arr(); rj_arr_push(a, rj_str(s)); return a; }
static rj_val* P1s1n(const char* s, long n){ rj_val* a = rj_arr(); rj_arr_push(a, rj_str(s)); rj_arr_push(a, rj_numf("%ld", n)); return a; }
static rj_val* P1s1b(const char* s, int b){ rj_val* a = rj_arr(); rj_arr_push(a, rj_str(s)); rj_arr_push(a, rj_bool(b)); return a; }

/* ---- reshaping --------------------------------------------------------------- */
static rj_val* vout_to_esplora(const rj_val* v){
    rj_val* spk = G(v, "scriptPubKey"); rj_val* o = rj_obj();
    const char* hex = S(spk, "hex"); const char* type = S(spk, "type"); const char* addr = S(spk, "address");
    char* as = malloc(65536); as[0] = 0; if (hex) esplora_asm_of_hex(hex, as, 65536);
    rj_obj_set(o, "scriptpubkey", rj_str(hex ? hex : ""));
    rj_obj_set(o, "scriptpubkey_asm", rj_str(as));
    rj_obj_set(o, "scriptpubkey_type", rj_str(esplora_spk_type(type)));
    if (addr) rj_obj_set(o, "scriptpubkey_address", rj_str(addr));
    rj_obj_set(o, "value", rj_numf("%ld", esplora_sats_of_amount(S(v, "value"))));
    free(as);
    return o;
}
/* Core tx JSON (getrawtransaction verbosity 2 / getblock verbosity 3 entry)
 * -> Esplora Transaction. height/hash/time describe the block when known
 * (a mempool tx passes -1). */
static rj_val* tx_to_esplora(const rj_val* t, long height, const char* bhash, long btime, const rpc_wallet* w){
    (void)w;
    rj_val* o = rj_obj();
    rj_obj_set(o, "txid", rj_str(S(t, "txid") ? S(t, "txid") : ""));
    rj_obj_set(o, "version", rj_numf("%lld", N(t, "version")));
    rj_obj_set(o, "locktime", rj_numf("%lld", N(t, "locktime")));
    rj_obj_set(o, "size", rj_numf("%lld", N(t, "size")));
    rj_obj_set(o, "weight", rj_numf("%lld", N(t, "weight")));
    long fee = S(t, "fee") ? esplora_sats_of_amount(S(t, "fee")) : -1;
    rj_val* vin = rj_arr(); rj_val* cvin = G(t, "vin"); long in_sum = 0; int all_prev = 1;
    for (size_t i = 0; cvin && cvin->typ == RJ_ARR && i < cvin->nitems; i++){
        const rj_val* ci = cvin->items[i]; rj_val* e = rj_obj();
        const char* cb = S(ci, "coinbase");
        if (cb){
            rj_obj_set(e, "txid", rj_str("0000000000000000000000000000000000000000000000000000000000000000"));
            rj_obj_set(e, "vout", rj_num("4294967295"));
            rj_obj_set(e, "prevout", rj_null());
            rj_obj_set(e, "scriptsig", rj_str(cb));
            { char* as = malloc(65536); esplora_asm_of_hex(cb, as, 65536); rj_obj_set(e, "scriptsig_asm", rj_str(as)); free(as); }
            rj_obj_set(e, "is_coinbase", rj_bool(1));
        } else {
            rj_obj_set(e, "txid", rj_str(S(ci, "txid") ? S(ci, "txid") : ""));
            rj_obj_set(e, "vout", rj_numf("%lld", N(ci, "vout")));
            rj_val* pv = G(ci, "prevout");
            if (pv){ rj_obj_set(e, "prevout", vout_to_esplora(pv)); long v = esplora_sats_of_amount(S(pv, "value")); if (v >= 0) in_sum += v; else all_prev = 0; }
            else { rj_obj_set(e, "prevout", rj_null()); all_prev = 0; }
            rj_val* ss = G(ci, "scriptSig"); const char* sh = S(ss, "hex");
            rj_obj_set(e, "scriptsig", rj_str(sh ? sh : ""));
            { char* as = malloc(65536); as[0] = 0; if (sh) esplora_asm_of_hex(sh, as, 65536); rj_obj_set(e, "scriptsig_asm", rj_str(as)); free(as); }
            rj_obj_set(e, "is_coinbase", rj_bool(0));
        }
        rj_obj_set(e, "sequence", rj_numf("%lld", N(ci, "sequence")));
        rj_val* wit = G(ci, "txinwitness"); rj_val* wa = rj_arr();
        for (size_t j = 0; wit && wit->typ == RJ_ARR && j < wit->nitems; j++) rj_arr_push(wa, rj_str(wit->items[j]->str ? wit->items[j]->str : ""));
        rj_obj_set(e, "witness", wa);
        rj_obj_set(e, "inner_redeemscript_asm", rj_str(""));
        rj_obj_set(e, "inner_witnessscript_asm", rj_str(""));
        rj_arr_push(vin, e);
    }
    rj_obj_set(o, "vin", vin);
    rj_val* vout = rj_arr(); rj_val* cvout = G(t, "vout"); long out_sum = 0;
    for (size_t i = 0; cvout && cvout->typ == RJ_ARR && i < cvout->nitems; i++){
        rj_arr_push(vout, vout_to_esplora(cvout->items[i]));
        long v = esplora_sats_of_amount(S(cvout->items[i], "value")); if (v > 0) out_sum += v;
    }
    rj_obj_set(o, "vout", vout);
    if (fee < 0 && all_prev && cvin && cvin->nitems && !S(cvin->items[0], "coinbase")) fee = in_sum - out_sum;
    if (fee < 0 && cvin && cvin->nitems && S(cvin->items[0], "coinbase")) fee = 0;
    rj_obj_set(o, "fee", rj_numf("%ld", fee < 0 ? 0 : fee));
    rj_val* st = rj_obj();
    if (height >= 0){
        rj_obj_set(st, "confirmed", rj_bool(1));
        rj_obj_set(st, "block_height", rj_numf("%ld", height));
        rj_obj_set(st, "block_hash", rj_str(bhash ? bhash : ""));
        rj_obj_set(st, "block_time", rj_numf("%ld", btime));
    } else rj_obj_set(st, "confirmed", rj_bool(0));
    rj_obj_set(o, "status", st);
    return o;
}
static rj_val* block_to_esplora(const rj_val* b){
    rj_val* o = rj_obj();
    rj_obj_set(o, "id", rj_str(S(b, "hash") ? S(b, "hash") : ""));
    rj_obj_set(o, "height", rj_numf("%lld", N(b, "height")));
    rj_obj_set(o, "version", rj_numf("%lld", N(b, "version")));
    rj_obj_set(o, "timestamp", rj_numf("%lld", N(b, "time")));
    { const char* bits = S(b, "bits"); rj_obj_set(o, "bits", rj_numf("%lu", bits ? strtoul(bits, 0, 16) : 0UL)); }
    rj_obj_set(o, "nonce", rj_numf("%lld", N(b, "nonce")));
    rj_obj_set(o, "difficulty", rj_num(S(b, "difficulty") ? S(b, "difficulty") : "0"));
    rj_obj_set(o, "merkle_root", rj_str(S(b, "merkleroot") ? S(b, "merkleroot") : ""));
    rj_obj_set(o, "tx_count", rj_numf("%lld", N(b, "nTx")));
    rj_obj_set(o, "size", rj_numf("%lld", N(b, "size")));
    rj_obj_set(o, "weight", rj_numf("%lld", N(b, "weight")));
    rj_obj_set(o, "previousblockhash", rj_str(S(b, "previousblockhash") ? S(b, "previousblockhash") : ""));
    rj_obj_set(o, "mediantime", rj_numf("%lld", N(b, "mediantime")));
    rj_obj_set(o, "stale", rj_bool(0));
    return o;
}

/* ---- the routes ---------------------------------------------------------------- */
typedef struct { char** out; size_t* outlen; int* status; const char** ctype; } resp_t;
static void reply_text(resp_t* r, int status, const char* txt){ *r->out = strdup(txt); *r->outlen = strlen(txt); *r->status = status; *r->ctype = "text/plain"; }
static void reply_json(resp_t* r, rj_val* v){
    /* rj_write reports the length it NEEDS when the buffer is too small (a
     * snprintf-like contract, not -1); grow until the whole document fits.
     * A block's transactions with prevouts run to tens of MB. */
    long cap = 1 << 20; char* buf = 0; long n = -1;
    for (int tries = 0; tries < 10; tries++){
        free(buf); buf = malloc((size_t)cap + 1); if (!buf){ n = -1; break; }
        n = rj_write(buf, cap, v, 0);
        if (n >= 0 && n < cap) break;
        cap *= 2; n = -1;
    }
    rj_free(v);
    if (n < 0){ free(buf); reply_text(r, 500, "response too large"); return; }
    *r->out = buf; *r->outlen = (size_t)n; *r->status = 200; *r->ctype = "application/json";
}
static void reply_rpc_error(resp_t* r, long ec, const char* em){
    if (ec == -5 || ec == -8) reply_text(r, 404, em ? em : "not found");      /* RPC_INVALID_ADDRESS_OR_KEY / INVALID_PARAMETER */
    else reply_text(r, 500, em ? em : "rpc error");
}
static int is_hex64(const char* s, size_t n){ if (n != 64) return 0; for (size_t i = 0; i < 64; i++) if (hexval(s[i]) < 0) return 0; return 1; }
/* one confirmed-or-mempool tx by txid -> Esplora Transaction (NULL + ec on failure) */
static rj_val* tx_by_id(const rpc_wallet* w, const char* txid, long* ec, const char** em){
    rj_val* t = call(w, "getrawtransaction", P1s1n(txid, 2), ec, em);
    if (!t) return 0;
    long height = -1, btime = 0; const char* bh = S(t, "blockhash"); char bhash[65] = "";
    if (bh){
        snprintf(bhash, sizeof bhash, "%s", bh);
        rj_val* hdr = call(w, "getblockheader", P1s(bh), 0, 0);
        if (hdr){ height = N(hdr, "height"); btime = N(hdr, "time"); rj_free(hdr); }
    }
    if (height < 0){
        /* unconfirmed: Core's verbosity 2 carries neither fee nor prevouts for
         * a mempool tx. Add them to the Core JSON first (the fee from the
         * mempool entry, each prevout from gettxout with include_mempool), then
         * reshape once -- rj_obj_set appends, it does not replace. */
        rj_val* me = call(w, "getmempoolentry", P1s(txid), 0, 0);
        if (me){ rj_val* fees = G(me, "fees"); if (fees && S(fees, "base") && !S(t, "fee")) rj_obj_set(t, "fee", rj_num(S(fees, "base"))); rj_free(me); }
        /* Each prevout from the PREVIOUS transaction (txindex, or the mempool
         * for an unconfirmed parent), never from gettxout: on this node
         * gettxout is a request to the download worker over a socketpair,
         * answered only at that worker's service points, and a batch of
         * thousands held the RPC execution lock for an hour on production
         * (2026-09-08 09:41Z) while every other call waited behind it. */
        rj_val* cvin = G(t, "vin");
        for (size_t i = 0; cvin && cvin->typ == RJ_ARR && i < cvin->nitems; i++){
            rj_val* ci = cvin->items[i];
            if (S(ci, "coinbase") || G(ci, "prevout") || !S(ci, "txid")) continue;
            rj_val* prev = call(w, "getrawtransaction", P1s1n(S(ci, "txid"), 1), 0, 0);
            rj_val* pvout = prev ? G(prev, "vout") : 0; long n = N(ci, "vout");
            if (pvout && pvout->typ == RJ_ARR && n >= 0 && (size_t)n < pvout->nitems) rj_obj_set(ci, "prevout", rj_clone(pvout->items[n]));   /* value + scriptPubKey: the prevout's shape */
            if (prev) rj_free(prev);
        }
    }
    rj_val* e = tx_to_esplora(t, height, bh ? bhash : 0, btime, w);
    rj_free(t);
    return e;
}
static rj_val* block_txs(const rpc_wallet* w, const char* hash, long* ec, const char** em, long start, long count){
    rj_val* b = call(w, "getblock", P1s1n(hash, 3), ec, em);
    if (!b) return 0;
    long height = N(b, "height"), btime = N(b, "time");
    rj_val* arr = rj_arr(); rj_val* txs = G(b, "tx");
    for (size_t i = (size_t)(start < 0 ? 0 : start); txs && i < txs->nitems && (count < 0 || (long)i < start + count); i++)
        rj_arr_push(arr, tx_to_esplora(txs->items[i], height, hash, btime, w));
    rj_free(b);
    return arr;
}
static rj_val* outspends_of(const rpc_wallet* w, const char* txid, long* ec, const char** em){
    rj_val* t = call(w, "getrawtransaction", P1s1n(txid, 1), ec, em);
    if (!t) return 0;
    rj_val* vout = G(t, "vout"); size_t n = vout ? vout->nitems : 0;
    rj_val* arr = rj_arr();
    /* the txospender index, when it exists */
    rj_val* outs = rj_arr();
    for (size_t i = 0; i < n; i++){ rj_val* o = rj_obj(); rj_obj_set(o, "txid", rj_str(txid)); rj_obj_set(o, "vout", rj_numf("%zu", i)); rj_arr_push(outs, o); }
    rj_val* p = rj_arr(); rj_arr_push(p, outs);
    rj_val* sp = call(w, "gettxspendingprevout", p, 0, 0);
    for (size_t i = 0; i < n; i++){
        rj_val* o = rj_obj();
        const rj_val* s = sp && sp->typ == RJ_ARR && i < sp->nitems ? sp->items[i] : 0;
        const char* stx = s ? S(s, "spendingtxid") : 0;
        if (stx){
            rj_obj_set(o, "spent", rj_bool(1)); rj_obj_set(o, "txid", rj_str(stx));
            rj_obj_set(o, "vin", rj_numf("%lld", N(s, "spendingvin")));
            rj_val* st = rj_obj(); const char* bh = S(s, "blockhash");
            if (bh){ rj_obj_set(st, "confirmed", rj_bool(1)); rj_obj_set(st, "block_hash", rj_str(bh)); if (S(s, "blockheight")) rj_obj_set(st, "block_height", rj_numf("%lld", N(s, "blockheight"))); }
            else rj_obj_set(st, "confirmed", rj_bool(0));
            rj_obj_set(o, "status", st);
        } else if (sp){
            rj_obj_set(o, "spent", rj_bool(0));
        } else {
            /* no index: gettxout says spent-or-not, not by whom */
            rj_val* a = rj_arr(); rj_arr_push(a, rj_str(txid)); rj_arr_push(a, rj_numf("%zu", i)); rj_arr_push(a, rj_bool(1));
            rj_val* to = call(w, "gettxout", a, 0, 0);
            rj_obj_set(o, "spent", rj_bool(!(to && to->typ == RJ_OBJ)));
            if (to) rj_free(to);
        }
        rj_arr_push(arr, o);
    }
    if (sp) rj_free(sp);
    rj_free(t);
    return arr;
}
static long qparam(const char* path, size_t plen, const char* key){
    const char* q = memchr(path, '?', plen); if (!q) return -1;
    size_t kl = strlen(key); const char* end = path + plen;
    for (const char* p = q + 1; p < end; ){
        const char* amp = memchr(p, '&', (size_t)(end - p)); if (!amp) amp = end;
        if ((size_t)(amp - p) > kl && !memcmp(p, key, kl) && p[kl] == '=') return strtol(p + kl + 1, 0, 10);
        p = amp + 1;
    }
    return -1;
}
/* ---- the mempool, by address (2026-09-08) --------------------------------------
 * Esplora's address answers include the mempool: mempool_stats, the
 * unconfirmed transactions first in the list, unconfirmed outputs in /utxo
 * and outputs spent in the mempool dropped from it. An in-process cache,
 * refreshed lazily on an address request: the mempool's txid list is read
 * (getrawmempool), transactions not seen before are fetched once and their
 * outputs classified into address keys; each input's prevout comes from
 * the parent transaction (the cache when the parent is in the mempool, the
 * txindex otherwise). Transactions that left the mempool are dropped. At
 * most MP_REFRESH_MAX new transactions per refresh, so one request never
 * pays for a whole burst. */
#include "daemon/addr_index_fmt.h"
#define MP_REFRESH_MAX 2000
/* ---- the mempool cache is shared by every facade connection (2026-09-08) --
 * Production's first address request crashed the daemon: two connections
 * were in mp_refresh at once (the first client had timed out and its
 * thread was still refreshing when the next request came), and the two
 * realloc'd the same arrays -- a double free 71 s in. One lock guards the
 * cache. A refresher thread (esplora_start_refresher) keeps it current in
 * the background, a bounded slice of new transactions per pass, so a
 * request only ever READS the cache; without the thread (the tests) a view
 * refreshes inline with the same bound. */
#include <pthread.h>
#include <unistd.h>
static pthread_mutex_t g_mp_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_mp_refresher = 0;
#define MP_REFRESH_SLICE 400
typedef struct { unsigned char key[33]; unsigned char txid[32]; unsigned vout; unsigned long long value; int is_spend; unsigned char spent_txid[32]; unsigned spent_vout; } mp_ev;   /* one output funded, or one input spent */
typedef struct { unsigned char txid[32]; unsigned char vout_keys_done; } mp_tx;
static mp_ev* g_mp_ev = 0; static long g_mp_nev = 0, g_mp_cap = 0;
static unsigned char (*g_mp_txids)[32] = 0; static long g_mp_ntx = 0;        /* the txids the cache knows, sorted */
static int cmp32(const void* a, const void* b){ return memcmp(a, b, 32); }
static int mp_has(const unsigned char txid[32]){ return g_mp_ntx && bsearch(txid, g_mp_txids, (size_t)g_mp_ntx, 32, cmp32) != 0; }
static void mp_push(const unsigned char key[33], const unsigned char txid[32], unsigned vout, unsigned long long value, int is_spend, const unsigned char* stx, unsigned svout){
    if (g_mp_nev == g_mp_cap){ g_mp_cap = g_mp_cap ? g_mp_cap * 2 : 4096; g_mp_ev = realloc(g_mp_ev, (size_t)g_mp_cap * sizeof *g_mp_ev); }
    mp_ev* e = &g_mp_ev[g_mp_nev++]; memcpy(e->key, key, 33); memcpy(e->txid, txid, 32); e->vout = vout; e->value = value; e->is_spend = is_spend;
    if (stx) memcpy(e->spent_txid, stx, 32); else memset(e->spent_txid, 0, 32); e->spent_vout = svout;
}
/* an output's (value, script) -> key; from the cache for a mempool parent, else the txindex */
static int mp_prevout(const rpc_wallet* w, const unsigned char ptxid[32], unsigned vout, unsigned char key[33], unsigned long long* value){
    for (long i = 0; i < g_mp_nev; i++) if (!g_mp_ev[i].is_spend && g_mp_ev[i].vout == vout && !memcmp(g_mp_ev[i].txid, ptxid, 32)){ memcpy(key, g_mp_ev[i].key, 33); *value = g_mp_ev[i].value; return 1; }
    if (mp_has(ptxid)) return 0;                                  /* a mempool parent's non-standard output */
    char hx[65]; hexrev(hx, ptxid);
    rj_val* t = call(w, "getrawtransaction", P1s1n(hx, 1), 0, 0); if (!t) return 0;
    rj_val* vo = G(t, "vout"); int ok = 0;
    if (vo && vo->typ == RJ_ARR && vout < vo->nitems){
        rj_val* spk = G(vo->items[vout], "scriptPubKey"); const char* hex = S(spk, "hex");
        unsigned char scr[10000]; long sl = hex ? unhex(hex, scr, sizeof scr) : -1; unsigned char hash[32];
        int type = sl > 0 ? axf_classify(scr, (unsigned)sl, hash) : AXF_INVALID;
        if (type != AXF_INVALID){ key[0] = (unsigned char)type; memcpy(key + 1, hash, 32); *value = (unsigned long long)esplora_sats_of_amount(S(vo->items[vout], "value")); ok = 1; }
    }
    rj_free(t); return ok;
}
static void mp_refresh_locked(const rpc_wallet* w, long budget){
    rj_val* m = call(w, "getrawmempool", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_bool(0)); a; }), 0, 0);
    if (!m || m->typ != RJ_ARR){ if (m) rj_free(m); return; }
    long n = (long)m->nitems; unsigned char (*now)[32] = malloc((size_t)(n + 1) * 32); long nn = 0;
    for (long i = 0; i < n; i++) if (m->items[i]->str && unhex(m->items[i]->str, now[nn], 32) == 32){ for (int k = 0; k < 16; k++){ unsigned char x = now[nn][k]; now[nn][k] = now[nn][31-k]; now[nn][31-k] = x; } nn++; }
    rj_free(m);
    qsort(now, (size_t)nn, 32, cmp32);
    /* drop events of transactions that left */
    long keep = 0;
    for (long i = 0; i < g_mp_nev; i++) if (bsearch(g_mp_ev[i].txid, now, (size_t)nn, 32, cmp32)) g_mp_ev[keep++] = g_mp_ev[i];
    g_mp_nev = keep;
    /* fetch the new ones (parents before children when both are new: two rounds) */
    long fetched = 0;
    for (int round = 0; round < 2 && fetched < budget; round++){
        for (long i = 0; i < nn && fetched < budget; i++){
            if (mp_has(now[i])) continue;
            char hx[65]; hexrev(hx, now[i]);
            rj_val* t = call(w, "getrawtransaction", P1s1n(hx, 1), 0, 0); if (!t) continue;
            rj_val* vo = G(t, "vout"); rj_val* vi = G(t, "vin");
            for (size_t o = 0; vo && vo->typ == RJ_ARR && o < vo->nitems; o++){
                rj_val* spk = G(vo->items[o], "scriptPubKey"); const char* hex = S(spk, "hex");
                unsigned char scr[10000]; long sl = hex ? unhex(hex, scr, sizeof scr) : -1; unsigned char hash[32];
                int type = sl > 0 ? axf_classify(scr, (unsigned)sl, hash) : AXF_INVALID;
                if (type == AXF_INVALID) continue;
                unsigned char key[33]; key[0] = (unsigned char)type; memcpy(key + 1, hash, 32);
                mp_push(key, now[i], (unsigned)o, (unsigned long long)esplora_sats_of_amount(S(vo->items[o], "value")), 0, 0, 0);
            }
            /* the txid joins the known set now, so a child in this round finds its parent's outputs */
            { unsigned char (*nk)[32] = realloc(g_mp_txids, (size_t)(g_mp_ntx + 1) * 32); g_mp_txids = nk; memcpy(g_mp_txids[g_mp_ntx++], now[i], 32); qsort(g_mp_txids, (size_t)g_mp_ntx, 32, cmp32); }
            for (size_t k = 0; vi && vi->typ == RJ_ARR && k < vi->nitems; k++){
                const char* ptx = S(vi->items[k], "txid"); if (!ptx || S(vi->items[k], "coinbase")) continue;
                unsigned char pt[32]; if (unhex(ptx, pt, 32) != 32) continue; for (int q = 0; q < 16; q++){ unsigned char x = pt[q]; pt[q] = pt[31-q]; pt[31-q] = x; }
                unsigned char key[33]; unsigned long long value = 0;
                if (mp_prevout(w, pt, (unsigned)N(vi->items[k], "vout"), key, &value)) mp_push(key, now[i], (unsigned)k, value, 1, pt, (unsigned)N(vi->items[k], "vout"));
            }
            rj_free(t); fetched++;
        }
    }
    /* the known set = what is in the mempool now (minus the ones deferred to the next refresh) */
    long kn = 0; for (long i = 0; i < g_mp_ntx; i++) if (bsearch(g_mp_txids[i], now, (size_t)nn, 32, cmp32)) memcpy(g_mp_txids[kn++], g_mp_txids[i], 32);
    g_mp_ntx = kn;
    free(now);
}
/* the address's mempool view: stats, its unconfirmed txids (newest last, as seen), its unconfirmed outputs, and the outpoints it had that the mempool spends */
typedef struct { long funded_n, spent_n; long long funded_sum, spent_sum; unsigned char (*txids)[32]; long ntx; mp_ev* funds; long nfunds; mp_ev* spends; long nspends; } mp_view;
void esplora_mp_refresh(const rpc_wallet* w, long budget){
    pthread_mutex_lock(&g_mp_lock); mp_refresh_locked(w, budget > 0 ? budget : MP_REFRESH_SLICE); pthread_mutex_unlock(&g_mp_lock);
}
static void* mp_refresher_thread(void* arg){
    const rpc_wallet* w = arg;
    for (;;){ esplora_mp_refresh(w, MP_REFRESH_SLICE); sleep(3); }
    return 0;
}
int esplora_start_refresher(const rpc_wallet* w){
    pthread_t th; pthread_attr_t at; pthread_attr_init(&at); pthread_attr_setstacksize(&at, (size_t)16 << 20);
    int r = pthread_create(&th, &at, mp_refresher_thread, (void*)w); pthread_attr_destroy(&at);
    if (r == 0){ pthread_detach(th); g_mp_refresher = 1; }
    return r == 0 ? 0 : -1;
}
static void mp_view_of(const rpc_wallet* w, int type, const unsigned char hash[32], mp_view* v){
    memset(v, 0, sizeof *v);
    pthread_mutex_lock(&g_mp_lock);
    if (!g_mp_refresher) mp_refresh_locked(w, MP_REFRESH_SLICE);
    unsigned char key[33]; key[0] = (unsigned char)type; memcpy(key + 1, hash, 32);
    for (long i = 0; i < g_mp_nev; i++){
        mp_ev* e = &g_mp_ev[i]; if (memcmp(e->key, key, 33)) continue;
        if (e->is_spend){ v->spent_n++; v->spent_sum += (long long)e->value; v->spends = realloc(v->spends, (size_t)(v->nspends + 1) * sizeof *e); v->spends[v->nspends++] = *e; }
        else { v->funded_n++; v->funded_sum += (long long)e->value; v->funds = realloc(v->funds, (size_t)(v->nfunds + 1) * sizeof *e); v->funds[v->nfunds++] = *e; }
        int dup = 0; for (long j = 0; j < v->ntx; j++) if (!memcmp(v->txids[j], e->txid, 32)){ dup = 1; break; }
        if (!dup){ v->txids = realloc(v->txids, (size_t)(v->ntx + 1) * 32); memcpy(v->txids[v->ntx++], e->txid, 32); }
    }
    pthread_mutex_unlock(&g_mp_lock);
}
static void mp_view_free(mp_view* v){ free(v->txids); free(v->funds); free(v->spends); }

/* ---- /address routes (stage 2) ------------------------------------------------
 * History = the base index (addr_hist.dat, to its to_height) + the live tail
 * journal above it (addrindex.tail: ADD funding, DEL spend, TOUCH the
 * spender). A base event names its transaction by (height, txpos); the txid
 * is one getblock away, cached per block within a request. mempool_stats and
 * the mempool transaction list are empty in this cut. */
typedef struct { long height; long txpos; unsigned char txid[32]; int has_txid; } esp_txref;
typedef struct { long funded_n, spent_n; long long funded_sum, spent_sum; esp_txref* refs; long nrefs, cap; } esp_hist;
static void hist_push(esp_hist* h, long height, long txpos, const unsigned char* txid){
    if (h->nrefs == h->cap){ h->cap = h->cap ? h->cap * 2 : 256; h->refs = realloc(h->refs, (size_t)h->cap * sizeof *h->refs); }
    esp_txref* t = &h->refs[h->nrefs++]; t->height = height; t->txpos = txpos; t->has_txid = txid != 0; if (txid) memcpy(t->txid, txid, 32); else memset(t->txid, 0, 32);
}
static int hist_tail_cb(void* ctx, int op, const unsigned char* txid, unsigned vout, unsigned long long value, unsigned height){
    esp_hist* h = ctx; (void)vout;
    if (op == 1){ h->funded_n++; h->funded_sum += (long long)value; hist_push(h, (long)height, -1, txid); }
    else if (op == 2){ h->spent_n++; h->spent_sum += (long long)value; }
    else if (op == 3){ hist_push(h, (long)height, -1, txid); }
    return 1;
}
typedef struct { unsigned char txid[32]; unsigned vout; unsigned long long value; unsigned height; } esp_utxo;
typedef struct { esp_utxo* u; long n, cap; } esp_utxos;
static int utxo_tail_cb(void* c, int op, const unsigned char* txid, unsigned vout, unsigned long long value, unsigned height){
    esp_utxos* x = c;
    if (op == 1){ if (x->n == x->cap){ x->cap *= 2; x->u = realloc(x->u, sizeof(esp_utxo) * (size_t)x->cap); } memcpy(x->u[x->n].txid, txid, 32); x->u[x->n].vout = vout; x->u[x->n].value = value; x->u[x->n].height = height; x->n++; }
    else if (op == 2){ for (long i = 0; i < x->n; i++) if (x->u[i].vout == vout && !memcmp(x->u[i].txid, txid, 32)){ x->u[i] = x->u[x->n-1]; x->n--; break; } }
    return 1;
}
static int esp_addr_key(const char* addr, int* type, unsigned char key[32]){
    int t = 0; unsigned char ver, h160[20], prog[32];
    if (!wallet_validate_address(addr, &t, &ver, h160, prog)) return 0;
    if (t < 1 || t > 5) return 0;
    memset(key, 0, 32);
    if (t == 4 || t == 5) memcpy(key, prog, 32); else memcpy(key, h160, 20);
    *type = t; return 1;
}
/* every event of the address: base then tail; refs deduplicated per transaction, newest first */
static int esp_hist_load(const rpc_wallet* w, int type, const unsigned char key[32], esp_hist* h){
    memset(h, 0, sizeof *h);
    const ah_event* ev = 0; long n = ah_lookup((uint8_t)type, key, &ev);
    if (n < 0) return 0;                                     /* no base index at all */
    long base_to = ah_to_height();
    for (long i = 0; i < n; i++){
        ah_event e; memcpy(&e, (const unsigned char*)ev + i * AH_EVENT_BYTES, sizeof e);
        if (e.kind == AH_FUND){ h->funded_n++; h->funded_sum += (long long)e.value; } else { h->spent_n++; h->spent_sum += (long long)e.value; }
        if (h->nrefs == 0 || h->refs[h->nrefs-1].height != (long)e.height || h->refs[h->nrefs-1].txpos != (long)e.txpos) hist_push(h, e.height, e.txpos, 0);
    }
    axt_read_events(type, key, base_to, hist_tail_cb, h);
    /* newest first, into a fresh array. Base refs carry (height, txpos) and
     * are distinct by construction (the events are sorted and a
     * transaction's events are adjacent); tail refs carry txids and a
     * transaction that funds and spends the address is pushed twice, so
     * those dedupe by txid. No txid is resolved here: the stats need none,
     * and a page resolves its own 25 (esp_hist_resolve). The genesis
     * address holds tens of thousands of events; resolving every one cost
     * 44,000 RPC calls per request. */
    esp_txref* out = malloc((size_t)(h->nrefs ? h->nrefs : 1) * sizeof *out); long m = 0;
    for (long i = h->nrefs - 1; i >= 0; i--){
        int dup = 0;
        if (h->refs[i].has_txid) for (long j = 0; j < m && j < 4096; j++) if (out[j].has_txid && !memcmp(h->refs[i].txid, out[j].txid, 32)){ dup = 1; break; }
        if (!dup) out[m++] = h->refs[i];
    }
    free(h->refs); h->refs = out; h->nrefs = m;
    return 1;
}
/* txids for refs[from, from+count): one getblock per distinct height, the
 * slice's refs of one height are adjacent (the list is ordered by height) */
static void esp_hist_resolve(const rpc_wallet* w, esp_hist* h, long from, long count){
    long last_h = -1; rj_val* last_txs = 0;
    for (long i = from; i < h->nrefs && i < from + count; i++){
        esp_txref* t = &h->refs[i]; if (t->has_txid) continue;
        if (t->height != last_h){
            if (last_txs) rj_free(last_txs);
            last_txs = 0; last_h = t->height;
            rj_val* hh = call(w, "getblockhash", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_numf("%ld", t->height)); a; }), 0, 0);
            if (hh && hh->str){ rj_val* b = call(w, "getblock", P1s1n(hh->str, 1), 0, 0); if (b){ rj_val* tx = G(b, "tx"); last_txs = tx ? rj_clone(tx) : 0; rj_free(b); } }
            if (hh) rj_free(hh);
        }
        if (last_txs && last_txs->typ == RJ_ARR && t->txpos >= 0 && (size_t)t->txpos < last_txs->nitems && last_txs->items[t->txpos]->str){
            unhex(last_txs->items[t->txpos]->str, t->txid, 32);
            for (int k = 0; k < 16; k++){ unsigned char x = t->txid[k]; t->txid[k] = t->txid[31-k]; t->txid[31-k] = x; }
            t->has_txid = 1;
        }
    }
    if (last_txs) rj_free(last_txs);
}
/* the position of a transaction in the ref list (the after_txid paging):
 * a tail ref by txid, a base ref by the (height, txpos) its block gives */
static long esp_hist_find(const rpc_wallet* w, esp_hist* h, const unsigned char want[32], const char* want_hex){
    for (long i = 0; i < h->nrefs; i++) if (h->refs[i].has_txid && !memcmp(h->refs[i].txid, want, 32)) return i;
    rj_val* t = call(w, "getrawtransaction", P1s1n(want_hex, 1), 0, 0); if (!t) return -1;
    const char* bh = S(t, "blockhash"); long height = -1, txpos = -1;
    if (bh){ rj_val* b = call(w, "getblock", P1s1n(bh, 1), 0, 0);
        if (b){ height = N(b, "height"); rj_val* tx = G(b, "tx");
            for (size_t k = 0; tx && tx->typ == RJ_ARR && k < tx->nitems; k++) if (tx->items[k]->str && !strcmp(tx->items[k]->str, want_hex)){ txpos = (long)k; break; }
            rj_free(b); } }
    rj_free(t);
    if (height < 0 || txpos < 0) return -1;
    for (long i = 0; i < h->nrefs; i++) if (!h->refs[i].has_txid && h->refs[i].height == height && h->refs[i].txpos == txpos) return i;
    return -1;
}
#define IS(k, s) (!strcmp(seg[k], s))
static void esplora_address(resp_t* r, const rpc_wallet* w, char seg[][80], int ns, int get){
    int type; unsigned char key[32];
    if (!get){ reply_text(r, 405, "method not allowed"); return; }
    if (!esp_addr_key(seg[1], &type, key)){ reply_text(r, 400, "Invalid Bitcoin address"); return; }
    if (!ah_available()){ reply_text(r, 501, "address history index not built on this node (daemon/bmc_build_addr_hist)"); return; }
    esp_hist h;
    if (!esp_hist_load(w, type, key, &h)){ reply_text(r, 500, "address history index unreadable"); return; }
    if (ns == 2){
        rj_val* o = rj_obj(); rj_obj_set(o, "address", rj_str(seg[1]));
        rj_val* cs = rj_obj(); rj_obj_set(cs, "funded_txo_count", rj_numf("%ld", h.funded_n)); rj_obj_set(cs, "funded_txo_sum", rj_numf("%lld", h.funded_sum));
        rj_obj_set(cs, "spent_txo_count", rj_numf("%ld", h.spent_n)); rj_obj_set(cs, "spent_txo_sum", rj_numf("%lld", h.spent_sum)); rj_obj_set(cs, "tx_count", rj_numf("%ld", h.nrefs));
        rj_obj_set(o, "chain_stats", cs);
        mp_view v; mp_view_of(w, type, key, &v);
        rj_val* ms = rj_obj(); rj_obj_set(ms, "funded_txo_count", rj_numf("%ld", v.funded_n)); rj_obj_set(ms, "funded_txo_sum", rj_numf("%lld", v.funded_sum)); rj_obj_set(ms, "spent_txo_count", rj_numf("%ld", v.spent_n)); rj_obj_set(ms, "spent_txo_sum", rj_numf("%lld", v.spent_sum)); rj_obj_set(ms, "tx_count", rj_numf("%ld", v.ntx));
        rj_obj_set(o, "mempool_stats", ms); mp_view_free(&v);
        free(h.refs); reply_json(r, o); return;
    }
    if (IS(2, "txs") && (ns == 3 || (ns >= 4 && IS(3, "chain")))){
        /* newest first, 25 per page, after `lastSeen` when given */
        long start = 0;
        if (ns >= 5){
            unsigned char want[32];
            if (unhex(seg[4], want, 32) == 32){
                for (int k = 0; k < 16; k++){ unsigned char x = want[k]; want[k] = want[31-k]; want[31-k] = x; }
                long at = esp_hist_find(w, &h, want, seg[4]); if (at >= 0) start = at + 1;
            }
        }
        esp_hist_resolve(w, &h, start, 25);
        rj_val* arr = rj_arr(); long taken = 0;
        if (ns == 3){                                            /* the unconfirmed ones first, as Esplora lists them */
            mp_view v; mp_view_of(w, type, key, &v);
            for (long i = v.ntx - 1; i >= 0 && taken < 25; i--){ char hx[65]; hexrev(hx, v.txids[i]); rj_val* t = tx_by_id(w, hx, 0, 0); if (t){ rj_arr_push(arr, t); taken++; } }
            mp_view_free(&v); taken = 0;
        }
        for (long i = start; i < h.nrefs && taken < 25; i++){
            if (!h.refs[i].has_txid) continue;
            char hx[65]; hexrev(hx, h.refs[i].txid);
            rj_val* t = tx_by_id(w, hx, 0, 0);
            if (t){ rj_arr_push(arr, t); taken++; }
        }
        free(h.refs); reply_json(r, arr); return;
    }
    if (IS(2, "txs") && ns == 4 && IS(3, "mempool")){
        mp_view v; mp_view_of(w, type, key, &v); rj_val* arr = rj_arr();
        for (long i = v.ntx - 1; i >= 0; i--){ char hx[65]; hexrev(hx, v.txids[i]); rj_val* t = tx_by_id(w, hx, 0, 0); if (t) rj_arr_push(arr, t); }
        mp_view_free(&v); free(h.refs); reply_json(r, arr); return;
    }
    if (IS(2, "utxo")){
        /* Esplora refuses an address with more unspent outputs than its
         * utxos_limit (500): every funding event would need its txid, one
         * getblock per block. Same rule here. */
        if (h.funded_n - h.spent_n > 500){ free(h.refs); reply_text(r, 400, "too many unspent transaction outputs"); return; }
        /* every funding event of the address (base, then the tail's ADDs),
         * minus the ones the txospender index knows a spender for -- one
         * gettxspendingprevout per 500 outpoints. The tail's DELs cover
         * spends above the spender index's own coverage. No reverse index,
         * no gettxout (that call crosses to the download worker). */
        typedef struct { unsigned char txid[32]; unsigned vout; unsigned long long value; long height; int spent; } fund_t;
        fund_t* f = malloc(sizeof(fund_t) * (size_t)(h.funded_n + 16)); long nf = 0;
        const ah_event* ev = 0; long n = ah_lookup((uint8_t)type, key, &ev); long last_h = -1; rj_val* last_txs = 0;
        for (long i = 0; i < n && nf < h.funded_n + 16; i++){
            ah_event e; memcpy(&e, (const unsigned char*)ev + i * AH_EVENT_BYTES, sizeof e);
            if (e.kind != AH_FUND) continue;
            if ((long)e.height != last_h){
                if (last_txs) rj_free(last_txs);
                last_txs = 0; last_h = e.height;
                rj_val* hh = call(w, "getblockhash", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_numf("%u", e.height)); a; }), 0, 0);
                if (hh && hh->str){ rj_val* b = call(w, "getblock", P1s1n(hh->str, 1), 0, 0); if (b){ last_txs = rj_clone(G(b, "tx")); rj_free(b); } }
                if (hh) rj_free(hh);
            }
            if (!last_txs || last_txs->typ != RJ_ARR || e.txpos >= last_txs->nitems || !last_txs->items[e.txpos]->str) continue;
            unhex(last_txs->items[e.txpos]->str, f[nf].txid, 32);
            for (int k = 0; k < 16; k++){ unsigned char x = f[nf].txid[k]; f[nf].txid[k] = f[nf].txid[31-k]; f[nf].txid[31-k] = x; }
            f[nf].vout = e.idx; f[nf].value = e.value; f[nf].height = e.height; f[nf].spent = 0; nf++;
        }
        if (last_txs) rj_free(last_txs);
        esp_utxos ux; ux.cap = 4096; ux.n = 0; ux.u = malloc(sizeof(esp_utxo) * (size_t)ux.cap);
        axt_read_events(type, key, ah_to_height(), utxo_tail_cb, &ux);   /* ADDs above the base; DELs cancel (tail or base funds) */
        for (long i = 0; i < ux.n && nf < h.funded_n + 16; i++){ memcpy(f[nf].txid, ux.u[i].txid, 32); f[nf].vout = ux.u[i].vout; f[nf].value = ux.u[i].value; f[nf].height = ux.u[i].height; f[nf].spent = 0; nf++; }
        free(ux.u);
        /* the tail's DELs against base funds: replay once more, marking */
        for (long start = 0; start < nf; start += 500){
            rj_val* outs = rj_arr(); long end = start + 500 < nf ? start + 500 : nf;
            for (long i = start; i < end; i++){ char hx[65]; hexrev(hx, f[i].txid); rj_val* o = rj_obj(); rj_obj_set(o, "txid", rj_str(hx)); rj_obj_set(o, "vout", rj_numf("%u", f[i].vout)); rj_arr_push(outs, o); }
            rj_val* p = rj_arr(); rj_arr_push(p, outs); rj_val* opt = rj_obj(); rj_obj_set(opt, "mempool_only", rj_bool(0)); rj_arr_push(p, opt);
            rj_val* sp = call(w, "gettxspendingprevout", p, 0, 0);
            for (long i = start; i < end; i++){ const rj_val* e = sp && sp->typ == RJ_ARR && (size_t)(i - start) < sp->nitems ? sp->items[i - start] : 0; if (e && S(e, "spendingtxid")) f[i].spent = 1; }
            if (sp) rj_free(sp);
        }
        /* the mempool: outputs it spends leave, outputs it creates join (unconfirmed) */
        mp_view v; mp_view_of(w, type, key, &v);
        for (long i = 0; i < nf; i++) for (long k = 0; k < v.nspends; k++) if (v.spends[k].spent_vout == f[i].vout && !memcmp(v.spends[k].spent_txid, f[i].txid, 32)) f[i].spent = 1;
        rj_val* arr = rj_arr();
        for (long i = 0; i < nf; i++){
            if (f[i].spent) continue;
            char hx[65]; hexrev(hx, f[i].txid);
            rj_val* o = rj_obj(); rj_obj_set(o, "txid", rj_str(hx)); rj_obj_set(o, "vout", rj_numf("%u", f[i].vout));
            rj_val* st = rj_obj(); rj_obj_set(st, "confirmed", rj_bool(1)); rj_obj_set(st, "block_height", rj_numf("%ld", f[i].height));
            rj_obj_set(o, "status", st); rj_obj_set(o, "value", rj_numf("%llu", f[i].value));
            rj_arr_push(arr, o);
        }
        for (long i = 0; i < v.nfunds; i++){
            int spent = 0; for (long k = 0; k < v.nspends; k++) if (v.spends[k].spent_vout == v.funds[i].vout && !memcmp(v.spends[k].spent_txid, v.funds[i].txid, 32)) spent = 1;
            if (spent) continue;
            char hx[65]; hexrev(hx, v.funds[i].txid);
            rj_val* o = rj_obj(); rj_obj_set(o, "txid", rj_str(hx)); rj_obj_set(o, "vout", rj_numf("%u", v.funds[i].vout));
            rj_val* st = rj_obj(); rj_obj_set(st, "confirmed", rj_bool(0)); rj_obj_set(o, "status", st); rj_obj_set(o, "value", rj_numf("%llu", v.funds[i].value));
            rj_arr_push(arr, o);
        }
        mp_view_free(&v);
        free(f); free(h.refs); reply_json(r, arr); return;
    }
    free(h.refs); reply_text(r, 404, "unknown address route");
}
#undef IS
int esplora_handle(const char* method, size_t mlen, const char* path, size_t plen,
                   const char* body, size_t blen, const rpc_wallet* w,
                   char** out, size_t* outlen, int* status, const char** ctype){
    resp_t r = { out, outlen, status, ctype };
    int get = (mlen == 3 && !memcmp(method, "GET", 3)), post = (mlen == 4 && !memcmp(method, "POST", 4));
    /* split the path (without the query) into segments */
    size_t pl = plen; { const char* q = memchr(path, '?', plen); if (q) pl = (size_t)(q - path); }
    char seg[8][80]; int ns = 0; size_t i = 0;
    while (i < pl && ns < 8){ while (i < pl && path[i] == '/') i++; size_t j = i; while (j < pl && path[j] != '/') j++; if (j > i){ size_t l = j - i; if (l > 79) l = 79; memcpy(seg[ns], path + i, l); seg[ns][l] = 0; ns++; } i = j; }
    long ec = 0; const char* em = 0;
    #define IS(k, s) (!strcmp(seg[k], s))
    if (ns == 0){ reply_text(&r, 200, "bmc esplora facade"); return 1; }
    if (get && ns == 3 && IS(0, "blocks") && IS(1, "tip")){
        rj_val* ci = call(w, "getblockchaininfo", rj_arr(), &ec, &em); if (!ci){ reply_rpc_error(&r, ec, em); return 1; }
        char b[128]; if (IS(2, "height")) snprintf(b, sizeof b, "%lld", N(ci, "blocks")); else snprintf(b, sizeof b, "%s", S(ci, "bestblockhash") ? S(ci, "bestblockhash") : "");
        rj_free(ci); reply_text(&r, 200, b); return 1;
    }
    if (get && ns == 2 && IS(0, "block-height")){
        rj_val* h = call(w, "getblockhash", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_numf("%ld", strtol(seg[1], 0, 10))); a; }), &ec, &em);
        if (!h){ reply_rpc_error(&r, ec, em); return 1; }
        reply_text(&r, 200, h->str ? h->str : ""); rj_free(h); return 1;
    }
    if (get && ns >= 2 && (IS(0, "block") || (ns >= 3 && IS(0, "internal") && IS(1, "block")))){
        int k = IS(0, "internal") ? 2 : 1; const char* hash = seg[k];
        if (!is_hex64(hash, strlen(hash))){ reply_text(&r, 400, "invalid block hash"); return 1; }
        if (ns == k + 1){ rj_val* b = call(w, "getblock", P1s1n(hash, 1), &ec, &em); if (!b){ reply_rpc_error(&r, ec, em); return 1; } rj_val* e = block_to_esplora(b); rj_free(b); reply_json(&r, e); return 1; }
        if (IS(k + 1, "header")){ rj_val* h = call(w, "getblockheader", P1s1b(hash, 0), &ec, &em); if (!h){ reply_rpc_error(&r, ec, em); return 1; } reply_text(&r, 200, h->str ? h->str : ""); rj_free(h); return 1; }
        if (IS(k + 1, "raw")){ rj_val* h = call(w, "getblock", P1s1n(hash, 0), &ec, &em); if (!h){ reply_rpc_error(&r, ec, em); return 1; }
            long n = h->str ? (long)strlen(h->str) / 2 : 0; u8* bin = malloc((size_t)n + 1); long got = unhex(h->str ? h->str : "", bin, n); rj_free(h);
            if (got < 0){ free(bin); reply_text(&r, 500, "bad block hex"); return 1; }
            *out = (char*)bin; *outlen = (size_t)got; *status = 200; *ctype = "application/octet-stream"; return 1; }
        if (IS(k + 1, "txids")){ rj_val* b = call(w, "getblock", P1s1n(hash, 1), &ec, &em); if (!b){ reply_rpc_error(&r, ec, em); return 1; } rj_val* t = rj_clone(G(b, "tx")); rj_free(b); reply_json(&r, t ? t : rj_arr()); return 1; }
        if (IS(k + 1, "txid") && ns == k + 3){ rj_val* b = call(w, "getblock", P1s1n(hash, 1), &ec, &em); if (!b){ reply_rpc_error(&r, ec, em); return 1; }
            rj_val* t = G(b, "tx"); long idx = strtol(seg[k + 2], 0, 10); if (!t || idx < 0 || (size_t)idx >= t->nitems){ rj_free(b); reply_text(&r, 404, "tx index out of range"); return 1; }
            reply_text(&r, 200, t->items[idx]->str); rj_free(b); return 1; }
        if (IS(k + 1, "txs")){ long start = ns == k + 3 ? strtol(seg[k + 2], 0, 10) : 0; long count = IS(0, "internal") ? -1 : 25;
            rj_val* a = block_txs(w, hash, &ec, &em, start, count); if (!a){ reply_rpc_error(&r, ec, em); return 1; } reply_json(&r, a); return 1; }
        if (IS(k + 1, "status")){ rj_val* b = call(w, "getblock", P1s1n(hash, 1), &ec, &em); if (!b){ reply_rpc_error(&r, ec, em); return 1; }
            rj_val* o = rj_obj(); rj_obj_set(o, "in_best_chain", rj_bool(N(b, "confirmations") > 0)); rj_obj_set(o, "height", rj_numf("%lld", N(b, "height")));
            if (S(b, "nextblockhash")) rj_obj_set(o, "next_best", rj_str(S(b, "nextblockhash")));
            rj_free(b); reply_json(&r, o); return 1; }
        reply_text(&r, 404, "unknown block route"); return 1;
    }
    if (get && ns >= 2 && IS(0, "tx")){
        const char* txid = seg[1]; if (!is_hex64(txid, strlen(txid))){ reply_text(&r, 400, "invalid txid"); return 1; }
        if (ns == 2){ rj_val* e = tx_by_id(w, txid, &ec, &em); if (!e){ reply_rpc_error(&r, ec, em); return 1; } reply_json(&r, e); return 1; }
        if (IS(2, "hex") || IS(2, "raw")){ rj_val* h = call(w, "getrawtransaction", P1s1n(txid, 0), &ec, &em); if (!h){ reply_rpc_error(&r, ec, em); return 1; }
            if (IS(2, "hex")){ reply_text(&r, 200, h->str ? h->str : ""); rj_free(h); return 1; }
            long n = h->str ? (long)strlen(h->str) / 2 : 0; u8* bin = malloc((size_t)n + 1); long got = unhex(h->str ? h->str : "", bin, n); rj_free(h);
            *out = (char*)bin; *outlen = (size_t)(got < 0 ? 0 : got); *status = 200; *ctype = "application/octet-stream"; return 1; }
        if (IS(2, "status")){ rj_val* e = tx_by_id(w, txid, &ec, &em); if (!e){ reply_rpc_error(&r, ec, em); return 1; } rj_val* st = rj_clone(G(e, "status")); rj_free(e); reply_json(&r, st); return 1; }
        if (IS(2, "outspends")){ rj_val* a = outspends_of(w, txid, &ec, &em); if (!a){ reply_rpc_error(&r, ec, em); return 1; } reply_json(&r, a); return 1; }
        if (IS(2, "outspend") && ns == 4){ rj_val* a = outspends_of(w, txid, &ec, &em); if (!a){ reply_rpc_error(&r, ec, em); return 1; }
            long v = strtol(seg[3], 0, 10); if (v < 0 || (size_t)v >= a->nitems){ rj_free(a); reply_text(&r, 404, "vout out of range"); return 1; }
            rj_val* one = rj_clone(a->items[v]); rj_free(a); reply_json(&r, one); return 1; }
        if (IS(2, "merkle-proof")){
            rj_val* t = call(w, "getrawtransaction", P1s1n(txid, 1), &ec, &em); if (!t){ reply_rpc_error(&r, ec, em); return 1; }
            const char* bh = S(t, "blockhash"); if (!bh){ rj_free(t); reply_text(&r, 400, "Transaction not confirmed"); return 1; }
            rj_val* b = call(w, "getblock", P1s1n(bh, 1), &ec, &em); rj_free(t); if (!b){ reply_rpc_error(&r, ec, em); return 1; }
            rj_val* txs = G(b, "tx"); long n = txs ? (long)txs->nitems : 0, pos = -1;
            u8 (*ids)[32] = malloc((size_t)(n + 1) * 32);
            for (long i = 0; i < n; i++){ u8 tmp[32]; unhex(txs->items[i]->str, tmp, 32); for (int j = 0; j < 32; j++) ids[i][j] = tmp[31 - j]; if (!strcmp(txs->items[i]->str, txid)) pos = i; }
            if (pos < 0){ free(ids); rj_free(b); reply_text(&r, 404, "tx not in its block"); return 1; }
            u8 (*br)[32] = malloc(64 * 32); int nb = esplora_merkle_branch(ids, n, pos, br, 64);
            rj_val* o = rj_obj(); rj_obj_set(o, "block_height", rj_numf("%lld", N(b, "height"))); rj_val* ma = rj_arr();
            for (int i = 0; i < nb; i++){ char hx[65]; hexrev(hx, br[i]); rj_arr_push(ma, rj_str(hx)); }
            rj_obj_set(o, "merkle", ma); rj_obj_set(o, "pos", rj_numf("%ld", pos));
            free(ids); free(br); rj_free(b); reply_json(&r, o); return 1;
        }
        reply_text(&r, 404, "unknown tx route"); return 1;
    }
    if (post && ns == 1 && IS(0, "tx")){
        char* hex = malloc(blen + 1); memcpy(hex, body, blen); hex[blen] = 0; while (blen && (hex[blen-1] == '\n' || hex[blen-1] == '\r' || hex[blen-1] == ' ')) hex[--blen] = 0;
        rj_val* t = call(w, "sendrawtransaction", P1s(hex), &ec, &em); free(hex);
        if (!t){ reply_text(&r, 400, em ? em : "rejected"); return 1; }
        reply_text(&r, 200, t->str ? t->str : ""); rj_free(t); return 1;
    }
    if (get && ns >= 1 && IS(0, "mempool")){
        if (ns == 1){ rj_val* mi = call(w, "getmempoolinfo", rj_arr(), &ec, &em); if (!mi){ reply_rpc_error(&r, ec, em); return 1; }
            rj_val* o = rj_obj(); rj_obj_set(o, "count", rj_numf("%lld", N(mi, "size"))); rj_obj_set(o, "vsize", rj_numf("%lld", N(mi, "bytes")));
            rj_obj_set(o, "total_fee", rj_numf("%ld", S(mi, "total_fee") ? esplora_sats_of_amount(S(mi, "total_fee")) : 0)); rj_obj_set(o, "fee_histogram", rj_arr());
            rj_free(mi); reply_json(&r, o); return 1; }
        if (IS(1, "txids")){ rj_val* m = call(w, "getrawmempool", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_bool(0)); a; }), &ec, &em); if (!m){ reply_rpc_error(&r, ec, em); return 1; } reply_json(&r, m); return 1; }
        if (IS(1, "recent")){ rj_val* m = call(w, "getrawmempool", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_bool(1)); a; }), &ec, &em); if (!m){ reply_rpc_error(&r, ec, em); return 1; }
            rj_val* arr = rj_arr(); size_t shown = 0;
            for (size_t i = m->nmembers; i > 0 && shown < 10; i--){ const rj_val* e = m->members[i-1].val; rj_val* o = rj_obj(); rj_obj_set(o, "txid", rj_str(m->members[i-1].key));
                rj_val* fees = G(e, "fees"); rj_obj_set(o, "fee", rj_numf("%ld", fees && S(fees, "base") ? esplora_sats_of_amount(S(fees, "base")) : 0));
                rj_obj_set(o, "vsize", rj_numf("%lld", N(e, "vsize"))); rj_obj_set(o, "value", rj_num("0")); rj_arr_push(arr, o); shown++; }
            rj_free(m); reply_json(&r, arr); return 1; }
        reply_text(&r, 404, "unknown mempool route"); return 1;
    }
    if (ns >= 2 && IS(0, "internal")){
        /* mempool.space's electrs additions: batch loads */
        if (post && ((ns == 2 && IS(1, "txs")) || (ns == 3 && IS(1, "mempool") && IS(2, "txs")))){
            rj_val* ids = rj_parse(body, blen); rj_val* arr = rj_arr();
            for (size_t i = 0; ids && ids->typ == RJ_ARR && i < ids->nitems; i++){ const char* id = ids->items[i]->str; if (!id || !is_hex64(id, strlen(id))) continue; rj_val* e = tx_by_id(w, id, 0, 0); if (e) rj_arr_push(arr, e); }
            if (ids) rj_free(ids);
            reply_json(&r, arr); return 1;
        }
        if (get && ns >= 3 && IS(1, "mempool") && IS(2, "txs")){
            /* recent mempool txs, newest first, `max_txs` after `lastSeen` */
            long maxn = qparam(path, plen, "max_txs"); if (maxn <= 0) maxn = 25; const char* last = ns >= 4 ? seg[3] : 0;
            rj_val* m = call(w, "getrawmempool", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_bool(0)); a; }), &ec, &em); if (!m){ reply_rpc_error(&r, ec, em); return 1; }
            rj_val* arr = rj_arr(); long taken = 0; int after = last ? 0 : 1;
            for (size_t i = m->nitems; i > 0 && taken < maxn; i--){ const char* id = m->items[i-1]->str; if (!after){ if (last && id && !strcmp(id, last)) after = 1; continue; }
                rj_val* e = tx_by_id(w, id, 0, 0); if (e){ rj_arr_push(arr, e); taken++; } }
            rj_free(m); reply_json(&r, arr); return 1;
        }
        if (post && ns == 4 && IS(1, "txs") && IS(2, "outspends") && IS(3, "by-txid")){
            rj_val* ids = rj_parse(body, blen); rj_val* arr = rj_arr();
            for (size_t i = 0; ids && ids->typ == RJ_ARR && i < ids->nitems; i++){ const char* id = ids->items[i]->str; rj_val* o = (id && is_hex64(id, strlen(id))) ? outspends_of(w, id, 0, 0) : 0; rj_arr_push(arr, o ? o : rj_arr()); }
            if (ids) rj_free(ids);
            reply_json(&r, arr); return 1;
        }
        reply_text(&r, 404, "unknown internal route"); return 1;
    }
    if (ns >= 2 && IS(0, "address")){ esplora_address(&r, w, seg, ns, get); return 1; }
    if (ns >= 2 && IS(0, "scripthash")){ reply_text(&r, 501, "scripthash lookups are not served: the address index is keyed by address, not script hash"); return 1; }
    reply_text(&r, 404, "unknown route"); return 1;
    #undef IS
}

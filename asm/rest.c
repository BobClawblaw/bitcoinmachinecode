/* rest.c -- Bitcoin Core's REST interface (src/rest.cpp), 2026-09-08.
 *
 * Fourteen unauthenticated routes under /rest/, enabled by rest=1 and served
 * on the JSON-RPC listener exactly as Core serves them: the same paths, the
 * three formats by suffix (.json, .hex, .bin), Core's status codes and its
 * error texts (text/plain, message + CRLF). Every route is a reshaping of a
 * JSON-RPC result the node already produces; the RPC lock is taken per
 * dispatch, never for a whole request. The differential proof is
 * validation/rest_regtest_diff.sh against Core's own /rest/. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "rest.h"
#include "rpc_json.h"
typedef unsigned char u8;
extern int rpc_dispatch(const char* method, const rj_val* params, const rpc_wallet* w, rj_val** result, long* ec, const char** em);

/* ---- small helpers (the facade has its own copies; both are static) -------- */
static const char* S(const rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : 0; return v && (v->typ == RJ_STR || v->typ == RJ_NUM) ? v->str : 0; }
static rj_val* G(const rj_val* o, const char* k){ return o ? rj_obj_get(o, k) : 0; }
static long long N(const rj_val* o, const char* k){ const char* s = S(o, k); return s ? strtoll(s, 0, 10) : 0; }
static int hexval(int c){ return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
static long unhex(const char* h, u8* out, long cap){ long n = 0; while (h[0] && h[1] && n < cap){ int a = hexval(h[0]), b = hexval(h[1]); if (a < 0 || b < 0) return -1; out[n++] = (u8)(a * 16 + b); h += 2; } return n; }
static void hexof(char* out, const u8* p, long n){ static const char* d = "0123456789abcdef"; for (long i = 0; i < n; i++){ out[2*i] = d[p[i] >> 4]; out[2*i+1] = d[p[i] & 15]; } out[2*n] = 0; }
static int is_hex64(const char* s){ if (strlen(s) != 64) return 0; for (int i = 0; i < 64; i++) if (hexval(s[i]) < 0) return 0; return 1; }
static void hash_le(u8 out[32], const char* hex){ u8 t[32]; unhex(hex, t, 32); for (int i = 0; i < 32; i++) out[i] = t[31 - i]; }   /* display hex -> internal bytes */
static void (*g_lock)(void) = 0; static void (*g_unlock)(void) = 0;
void rest_set_exec_lock(void (*lock)(void), void (*unlock)(void)){ g_lock = lock; g_unlock = unlock; }
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
static rj_val* P1s1n(const char* s, long n){ rj_val* a = rj_arr(); rj_arr_push(a, rj_str(s)); rj_arr_push(a, rj_numf("%ld", n)); return a; }
static rj_val* P1s1b(const char* s, int b){ rj_val* a = rj_arr(); rj_arr_push(a, rj_str(s)); rj_arr_push(a, rj_bool(b)); return a; }
static void obj_del(rj_val* o, const char* k){
    for (size_t i = 0; o && o->typ == RJ_OBJ && i < o->nmembers; i++) if (!strcmp(o->members[i].key, k)){
        rj_free(o->members[i].val); free(o->members[i].key);
        memmove(&o->members[i], &o->members[i + 1], (o->nmembers - i - 1) * sizeof o->members[0]); o->nmembers--; return; }
}

/* ---- the reply ---------------------------------------------------------------- */
typedef struct { char** out; size_t* outlen; int* status; const char** ctype; } resp_t;
static void rerr(resp_t* r, int status, const char* msg){          /* RESTERR: text/plain, message + CRLF */
    size_t n = strlen(msg); char* b = malloc(n + 3); memcpy(b, msg, n); b[n] = '\r'; b[n+1] = '\n'; b[n+2] = 0;
    *r->out = b; *r->outlen = n + 2; *r->status = status; *r->ctype = "text/plain";
}
static void rerrf(resp_t* r, int status, const char* fmt, const char* a, const char* b){ char m[512]; snprintf(m, sizeof m, fmt, a, b); rerr(r, status, m); }
static void rjson(resp_t* r, rj_val* v){                          /* UniValue::write() + "\n" */
    long n = 0; char* b = rj_write_alloc(v, 0, &n); rj_free(v);
    if (!b){ rerr(r, 500, "response too large"); return; }
    b = realloc(b, (size_t)n + 2); b[n] = '\n'; b[n + 1] = 0;
    *r->out = b; *r->outlen = (size_t)n + 1; *r->status = 200; *r->ctype = "application/json";
}
static void rhex(resp_t* r, const u8* p, long n){                 /* HexStr + "\n" */
    char* b = malloc((size_t)n * 2 + 2); hexof(b, p, n); b[2*n] = '\n'; b[2*n+1] = 0;
    *r->out = b; *r->outlen = (size_t)n * 2 + 1; *r->status = 200; *r->ctype = "text/plain";
}
static void rbin(resp_t* r, u8* p, long n){ *r->out = (char*)p; *r->outlen = (size_t)n; *r->status = 200; *r->ctype = "application/octet-stream"; }
enum { RF_UNDEF, RF_BIN, RF_HEX, RF_JSON };
static const char* FMTS_ALL = "output format not found (available: .bin, .hex, .json)";
static const char* FMTS_JSON = "output format not found (available: json)";
/* ParseDataFormat: strip the query, then a known ".suffix" */
static int parse_fmt(const char* uri, size_t ulen, char* param, size_t cap){
    const char* q = memchr(uri, '?', ulen); size_t pl = q ? (size_t)(q - uri) : ulen;
    if (pl >= cap) pl = cap - 1;
    memcpy(param, uri, pl); param[pl] = 0;
    char* dot = strrchr(param, '.'); if (!dot) return RF_UNDEF;
    int rf = !strcmp(dot + 1, "bin") ? RF_BIN : !strcmp(dot + 1, "hex") ? RF_HEX : !strcmp(dot + 1, "json") ? RF_JSON : RF_UNDEF;
    if (rf != RF_UNDEF) *dot = 0;
    return rf;
}
static int qget(const char* path, size_t plen, const char* key, char* out, size_t cap){
    const char* q = memchr(path, '?', plen); if (!q) return 0;
    size_t kl = strlen(key); const char* p = q + 1; const char* end = path + plen;
    while (p < end){ const char* amp = memchr(p, '&', (size_t)(end - p)); if (!amp) amp = end;
        if ((size_t)(amp - p) > kl && !memcmp(p, key, kl) && p[kl] == '='){ size_t vl = (size_t)(amp - p) - kl - 1; if (vl >= cap) vl = cap - 1; memcpy(out, p + kl + 1, vl); out[vl] = 0; return 1; }
        p = amp + 1; }
    return 0;
}
static int split(char* s, char* parts[], int max){ int n = 0; char* p = s; while (*p && n < max){ char* sl = strchr(p, '/'); if (sl) *sl = 0; parts[n++] = p; if (!sl) break; p = sl + 1; } return n; }
/* Core's ToIntegral<size_t>: decimal digits only, no sign, no space */
static int to_ulong(const char* s, unsigned long* out){ if (!*s) return 0; unsigned long v = 0; for (; *s; s++){ if (*s < '0' || *s > '9') return 0; if (v > (~0UL - 9) / 10) return 0; v = v * 10 + (unsigned long)(*s - '0'); } *out = v; return 1; }
static long put_cs(u8* p, unsigned long v){ if (v < 253){ p[0] = (u8)v; return 1; } if (v <= 0xffff){ p[0] = 253; p[1] = v & 255; p[2] = v >> 8; return 3; } if (v <= 0xffffffffUL){ p[0] = 254; for (int i = 0; i < 4; i++) p[1+i] = (u8)(v >> (8*i)); return 5; } p[0] = 255; for (int i = 0; i < 8; i++) p[1+i] = (u8)(v >> (8*i)); return 9; }
static void rpc_fail(resp_t* r, long ec, const char* em, const char* hash){
    if (ec == -5 || ec == -8) rerrf(r, 404, "%s not found", hash, "");
    else rerr(r, 500, em ? em : "rpc error");
}
/* the 80-byte header from getblockheader's verbose object (one call per header, not two) */
static void raw_header(u8 out[80], const rj_val* h){
    unsigned long v = (unsigned long)N(h, "version"); for (int i = 0; i < 4; i++) out[i] = (u8)(v >> (8*i));
    const char* prev = S(h, "previousblockhash"); if (prev) hash_le(out + 4, prev); else memset(out + 4, 0, 32);
    hash_le(out + 36, S(h, "merkleroot") ? S(h, "merkleroot") : "0000000000000000000000000000000000000000000000000000000000000000");
    unsigned long t = (unsigned long)N(h, "time"); for (int i = 0; i < 4; i++) out[68+i] = (u8)(t >> (8*i));
    unsigned long bits = strtoul(S(h, "bits") ? S(h, "bits") : "0", 0, 16); for (int i = 0; i < 4; i++) out[72+i] = (u8)(bits >> (8*i));
    unsigned long nonce = (unsigned long)N(h, "nonce"); for (int i = 0; i < 4; i++) out[76+i] = (u8)(nonce >> (8*i));
}
/* the scriptPubKey object Core's ScriptToUniv(include_hex, include_address) gives: asm, desc, hex, address?, type */
static rj_val* spk_of(const rj_val* spk){
    rj_val* o = rj_obj(); const char* k[] = { "asm", "desc", "hex", "address", "type" };
    for (int i = 0; i < 5; i++){ const rj_val* v = G(spk, k[i]); if (v) rj_obj_set(o, k[i], rj_clone(v)); }
    return o;
}

/* ---- the routes ------------------------------------------------------------------ */
static void r_tx(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul){
    char hash[300]; int rf = parse_fmt(uri, ul, hash, sizeof hash);
    if (!is_hex64(hash)){ rerrf(r, 400, "Invalid hash: %s%s", hash, ""); return; }
    if (rf == RF_UNDEF){ rerr(r, 404, FMTS_ALL); return; }
    long ec; const char* em;
    if (rf == RF_JSON){
        rj_val* t = call(w, "getrawtransaction", P1s1n(hash, 1), &ec, &em); if (!t){ rpc_fail(r, ec, em, hash); return; }
        obj_del(t, "in_active_chain"); obj_del(t, "confirmations"); obj_del(t, "blocktime"); obj_del(t, "time");   /* TxToUniv's fields */
        { rj_val* hx = G(t, "hex"); if (hx){ rj_val* c = rj_clone(hx); obj_del(t, "hex"); rj_obj_set(t, "hex", c); } }   /* ...in its order: blockhash, then hex last */
        rjson(r, t); return;
    }
    rj_val* h = call(w, "getrawtransaction", P1s1n(hash, 0), &ec, &em); if (!h){ rpc_fail(r, ec, em, hash); return; }
    long n = h->str ? (long)strlen(h->str) / 2 : 0; u8* bin = malloc((size_t)n + 1); long got = unhex(h->str ? h->str : "", bin, n); rj_free(h);
    if (got < 0){ free(bin); rerr(r, 500, "bad transaction hex"); return; }
    if (rf == RF_HEX){ rhex(r, bin, got); free(bin); } else rbin(r, bin, got);
}
/* block_json_verbosity: 3 = TxVerbosity::SHOW_DETAILS_AND_PREVOUT (/rest/block/), 1 = SHOW_TXID (notxdetails), 0 = no JSON (blockpart) */
static void r_block(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul, int json_verbosity, int part, unsigned long off, unsigned long size){
    char hash[300]; int rf = parse_fmt(uri, ul, hash, sizeof hash);
    if (!is_hex64(hash)){ rerrf(r, 400, "Invalid hash: %s%s", hash, ""); return; }
    if (rf == RF_UNDEF){ rerr(r, 404, FMTS_ALL); return; }
    long ec; const char* em;
    if (rf == RF_JSON){
        if (!json_verbosity){ rerr(r, 400, "JSON output is not supported for this request type"); return; }
        rj_val* b = call(w, "getblock", P1s1n(hash, json_verbosity), &ec, &em); if (!b){ rpc_fail(r, ec, em, hash); return; }
        rjson(r, b); return;
    }
    rj_val* h = call(w, "getblock", P1s1n(hash, 0), &ec, &em); if (!h){ rpc_fail(r, ec, em, hash); return; }
    long n = h->str ? (long)strlen(h->str) / 2 : 0; u8* bin = malloc((size_t)n + 1); long got = unhex(h->str ? h->str : "", bin, n); rj_free(h);
    if (got < 0){ free(bin); rerr(r, 500, "bad block hex"); return; }
    u8* p = bin; long len = got;
    if (part){
        if (off > (unsigned long)got || size > (unsigned long)got - off){ free(bin); char m[400]; snprintf(m, sizeof m, "Bad block part offset/size %lu/%lu for %s", off, size, hash); rerr(r, 400, m); return; }
        p = bin + off; len = (long)size;
    }
    if (rf == RF_HEX){ rhex(r, p, len); free(bin); } else { if (part){ u8* q = malloc((size_t)len + 1); memcpy(q, p, (size_t)len); free(bin); rbin(r, q, len); } else rbin(r, bin, len); }
}
static void r_blockpart(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul, const char* path, size_t plen){
    char v[64]; unsigned long off, size;
    if (!qget(path, plen, "offset", v, sizeof v) || !to_ulong(v, &off)){ rerr(r, 400, "Block part offset missing or invalid"); return; }
    if (!qget(path, plen, "size", v, sizeof v) || !to_ulong(v, &size)){ rerr(r, 400, "Block part size missing or invalid"); return; }
    r_block(r, w, uri, ul, 0, 1, off, size);
}
/* the active-chain walk from a hash: up to count verbose headers; an unknown
 * hash or one off the active chain yields nothing (Core: an empty list, 200) */
static long walk_headers(const rpc_wallet* w, const char* hash, unsigned long count, rj_val*** out){
    rj_val** hs = malloc(sizeof *hs * (count ? count : 1)); long n = 0; char cur[65]; snprintf(cur, sizeof cur, "%s", hash);
    while ((unsigned long)n < count){
        rj_val* h = call(w, "getblockheader", P1s1b(cur, 1), 0, 0); if (!h) break;
        if (N(h, "confirmations") < 0){ rj_free(h); break; }
        hs[n++] = h;
        const char* nx = S(h, "nextblockhash"); if (!nx) break; snprintf(cur, sizeof cur, "%s", nx);
    }
    *out = hs; return n;
}
static int count_arg(resp_t* r, const char* raw, unsigned long* count){
    if (!to_ulong(raw, count) || *count < 1 || *count > 2000){ char m[300]; snprintf(m, sizeof m, "Header count is invalid or out of acceptable range (1-2000): %s", raw); rerr(r, 400, m); return 0; }
    return 1;
}
static void r_headers(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul, const char* path, size_t plen){
    char param[400]; int rf = parse_fmt(uri, ul, param, sizeof param); char* parts[4]; int np = split(param, parts, 4);
    char raw_count[64]; const char* hash;
    if (np == 2){ hash = parts[1]; snprintf(raw_count, sizeof raw_count, "%s", parts[0]); }
    else if (np == 1){ hash = parts[0]; if (!qget(path, plen, "count", raw_count, sizeof raw_count)) snprintf(raw_count, sizeof raw_count, "5"); }
    else { rerr(r, 400, "Invalid URI format. Expected /rest/headers/<hash>.<ext>?count=<count>"); return; }
    unsigned long count; if (!count_arg(r, raw_count, &count)) return;
    if (!is_hex64(hash)){ rerrf(r, 400, "Invalid hash: %s%s", hash, ""); return; }
    if (rf == RF_UNDEF){ rerr(r, 404, FMTS_ALL); return; }
    rj_val** hs; long n = walk_headers(w, hash, count, &hs);
    if (rf == RF_JSON){ rj_val* a = rj_arr(); for (long i = 0; i < n; i++) rj_arr_push(a, hs[i]); free(hs); rjson(r, a); return; }
    u8* buf = malloc((size_t)n * 80 + 1); for (long i = 0; i < n; i++){ raw_header(buf + i * 80, hs[i]); rj_free(hs[i]); } free(hs);
    if (rf == RF_HEX){ rhex(r, buf, n * 80); free(buf); } else rbin(r, buf, n * 80);
}
static void r_blockhash_by_height(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul){
    char hs[300]; int rf = parse_fmt(uri, ul, hs, sizeof hs); unsigned long height;
    if (!to_ulong(hs, &height) || height > 0x7fffffffUL){ char m[400]; snprintf(m, sizeof m, "Invalid height: %s", hs); rerr(r, 400, m); return; }
    long ec; const char* em;
    rj_val* h = call(w, "getblockhash", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_numf("%lu", height)); a; }), &ec, &em);
    if (!h){ rerr(r, 404, "Block height out of range"); return; }
    if (rf == RF_JSON){ rj_val* o = rj_obj(); rj_obj_set(o, "blockhash", rj_str(h->str)); rj_free(h); rjson(r, o); return; }
    if (rf == RF_HEX){ char* b = malloc(70); int n = snprintf(b, 70, "%s\n", h->str); rj_free(h); *r->out = b; *r->outlen = (size_t)n; *r->status = 200; *r->ctype = "text/plain"; return; }
    if (rf == RF_BIN){ u8* b = malloc(32); hash_le(b, h->str); rj_free(h); rbin(r, b, 32); return; }
    rj_free(h); rerr(r, 404, FMTS_ALL);
}
static void r_chaininfo(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul){
    char p[64]; int rf = parse_fmt(uri, ul, p, sizeof p);
    if (rf != RF_JSON){ rerr(r, 404, FMTS_JSON); return; }
    long ec; const char* em; rj_val* ci = call(w, "getblockchaininfo", rj_arr(), &ec, &em); if (!ci){ rerr(r, 500, em ? em : "rpc error"); return; }
    rjson(r, ci);
}
static void r_deploymentinfo(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul){
    char hash[300]; int rf = parse_fmt(uri, ul, hash, sizeof hash);
    if (rf != RF_JSON){ rerr(r, 404, FMTS_JSON); return; }
    long ec; const char* em; rj_val* params = rj_arr();
    if (hash[0]){
        if (!is_hex64(hash)){ rj_free(params); rerrf(r, 400, "Invalid hash: %s%s", hash, ""); return; }
        rj_val* h = call(w, "getblockheader", P1s1b(hash, 1), &ec, &em); if (!h){ rj_free(params); rerr(r, 400, "Block not found"); return; } rj_free(h);
        rj_arr_push(params, rj_str(hash));
    }
    rj_val* d = call(w, "getdeploymentinfo", params, &ec, &em); if (!d){ rerr(r, 500, em ? em : "rpc error"); return; }
    rjson(r, d);
}
static void r_mempool(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul, const char* path, size_t plen){
    char p[64]; int rf = parse_fmt(uri, ul, p, sizeof p);
    if (strcmp(p, "contents") && strcmp(p, "info")){ rerr(r, 400, "Invalid URI format. Expected /rest/mempool/<info|contents>.json"); return; }
    if (rf != RF_JSON){ rerr(r, 404, FMTS_JSON); return; }
    long ec; const char* em;
    if (!strcmp(p, "info")){ rj_val* m = call(w, "getmempoolinfo", rj_arr(), &ec, &em); if (!m){ rerr(r, 500, em ? em : "rpc error"); return; } rjson(r, m); return; }
    char verbose[16] = "true", seq[16] = "false";
    if (qget(path, plen, "verbose", verbose, sizeof verbose) && strcmp(verbose, "true") && strcmp(verbose, "false")){ rerr(r, 400, "The \"verbose\" query parameter must be either \"true\" or \"false\"."); return; }
    if (qget(path, plen, "mempool_sequence", seq, sizeof seq) && strcmp(seq, "true") && strcmp(seq, "false")){ rerr(r, 400, "The \"mempool_sequence\" query parameter must be either \"true\" or \"false\"."); return; }
    if (!strcmp(verbose, "true") && !strcmp(seq, "true")){ rerr(r, 400, "Verbose results cannot contain mempool sequence values. (hint: set \"verbose=false\")"); return; }
    if (!strcmp(seq, "true")){ rerr(r, 400, "mempool_sequence is not available on this node (it keeps no mempool sequence number)"); return; }   /* an explicit refusal, not a made-up counter */
    rj_val* m = call(w, "getrawmempool", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_bool(!strcmp(verbose, "true"))); a; }), &ec, &em);
    if (!m){ rerr(r, 500, em ? em : "rpc error"); return; }
    rjson(r, m);
}
static void r_blockfilter(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul){
    char param[400]; int rf = parse_fmt(uri, ul, param, sizeof param); char* parts[4]; int np = split(param, parts, 4);
    if (np != 2){ rerr(r, 400, "Invalid URI format. Expected /rest/blockfilter/<filtertype>/<blockhash>"); return; }
    const char* type = parts[0]; const char* hash = parts[1];
    if (!is_hex64(hash)){ rerrf(r, 400, "Invalid hash: %s%s", hash, ""); return; }
    if (strcmp(type, "basic")){ rerrf(r, 400, "Unknown filtertype %s%s", type, ""); return; }
    long ec; const char* em;
    rj_val* f = call(w, "getblockfilter", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_str(hash)); rj_arr_push(a, rj_str(type)); a; }), &ec, &em);
    if (!f){
        if (em && strstr(em, "not enabled")){ rerrf(r, 400, "Index is not enabled for filtertype %s%s", type, ""); return; }
        if (ec == -5){ rerrf(r, 404, "%s not found", hash, ""); return; }
        rerr(r, 404, "Filter not found. Block filters are still in the process of being indexed."); return;
    }
    const char* fh = S(f, "filter"); if (!fh){ rj_free(f); rerr(r, 404, "Filter not found. This error is unexpected and indicates index corruption."); return; }
    if (rf == RF_JSON){ rj_val* o = rj_obj(); rj_obj_set(o, "filter", rj_str(fh)); rj_free(f); rjson(r, o); return; }
    if (rf == RF_UNDEF){ rj_free(f); rerr(r, 404, FMTS_ALL); return; }
    long fl = (long)strlen(fh) / 2; u8* buf = malloc((size_t)fl + 64); buf[0] = 0; hash_le(buf + 1, hash); long n = 33 + put_cs(buf + 33, (unsigned long)fl);
    long got = unhex(fh, buf + n, fl); rj_free(f); if (got < 0){ free(buf); rerr(r, 500, "bad filter hex"); return; } n += got;
    if (rf == RF_HEX){ rhex(r, buf, n); free(buf); } else rbin(r, buf, n);
}
static void r_blockfilterheaders(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul, const char* path, size_t plen){
    char param[400]; int rf = parse_fmt(uri, ul, param, sizeof param); char* parts[4]; int np = split(param, parts, 4);
    char raw_count[64]; const char* hash; const char* type;
    if (np == 3){ type = parts[0]; hash = parts[2]; snprintf(raw_count, sizeof raw_count, "%s", parts[1]); }
    else if (np == 2){ type = parts[0]; hash = parts[1]; if (!qget(path, plen, "count", raw_count, sizeof raw_count)) snprintf(raw_count, sizeof raw_count, "5"); }
    else { rerr(r, 400, "Invalid URI format. Expected /rest/blockfilterheaders/<filtertype>/<blockhash>.<ext>?count=<count>"); return; }
    unsigned long count; if (!count_arg(r, raw_count, &count)) return;
    if (!is_hex64(hash)){ rerrf(r, 400, "Invalid hash: %s%s", hash, ""); return; }
    if (strcmp(type, "basic")){ rerrf(r, 400, "Unknown filtertype %s%s", type, ""); return; }
    rj_val** hs; long n = walk_headers(w, hash, count, &hs);
    u8* buf = malloc((size_t)(n ? n : 1) * 32); rj_val* arr = rj_arr(); long got = 0;
    for (long i = 0; i < n; i++){
        long ec; const char* em;
        rj_val* f = call(w, "getblockfilter", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_str(S(hs[i], "hash"))); rj_arr_push(a, rj_str(type)); a; }), &ec, &em);
        const char* fh = f ? S(f, "header") : 0;
        if (!fh){ if (f) rj_free(f); for (long k = i; k < n; k++) rj_free(hs[k]); free(hs); free(buf); rj_free(arr);
            if (em && strstr(em, "not enabled")){ rerrf(r, 400, "Index is not enabled for filtertype %s%s", type, ""); return; }
            rerr(r, 404, "Filter not found. Block filters are still in the process of being indexed."); return; }
        rj_arr_push(arr, rj_str(fh)); hash_le(buf + got * 32, fh); got++; rj_free(f); rj_free(hs[i]);
    }
    free(hs);
    if (rf == RF_JSON){ free(buf); rjson(r, arr); return; }
    rj_free(arr);
    if (rf == RF_HEX){ rhex(r, buf, got * 32); free(buf); return; }
    if (rf == RF_BIN){ rbin(r, buf, got * 32); return; }
    free(buf); rerr(r, 404, FMTS_ALL);
}
static void r_spenttxouts(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul){
    char param[400]; int rf = parse_fmt(uri, ul, param, sizeof param); char* parts[4]; int np = split(param, parts, 4);
    if (np != 1){ rerr(r, 400, "Invalid URI format. Expected /rest/spenttxouts/<hash>.<ext>"); return; }
    const char* hash = parts[0];
    if (!is_hex64(hash)){ rerrf(r, 400, "Invalid hash: %s%s", hash, ""); return; }
    long ec; const char* em; rj_val* b = call(w, "getblock", P1s1n(hash, 3), &ec, &em); if (!b){ rpc_fail(r, ec, em, hash); return; }
    rj_val* txs = G(b, "tx");
    if (!txs || txs->typ != RJ_ARR || !txs->nitems){ rj_free(b); rerr(r, 404, "block has no transactions"); return; }
    /* every non-coinbase input must carry its prevout, else the undo data is missing */
    for (size_t t = 1; t < txs->nitems; t++){ rj_val* vin = G(txs->items[t], "vin");
        for (size_t i = 0; vin && vin->typ == RJ_ARR && i < vin->nitems; i++) if (!G(vin->items[i], "prevout")){ rj_free(b); rerrf(r, 404, "%s undo not available", hash, ""); return; } }
    if (rf == RF_JSON){
        rj_val* res = rj_arr(); rj_arr_push(res, rj_arr());                     /* the coinbase: no prevouts */
        for (size_t t = 1; t < txs->nitems; t++){ rj_val* per = rj_arr(); rj_val* vin = G(txs->items[t], "vin");
            for (size_t i = 0; vin && i < vin->nitems; i++){ const rj_val* pv = G(vin->items[i], "prevout"); rj_val* o = rj_obj();
                rj_obj_set(o, "value", rj_clone(G(pv, "value"))); rj_obj_set(o, "scriptPubKey", spk_of(G(pv, "scriptPubKey"))); rj_arr_push(per, o); }
            rj_arr_push(res, per); }
        rj_free(b); rjson(r, res); return;
    }
    if (rf == RF_UNDEF){ rj_free(b); rerr(r, 404, FMTS_ALL); return; }
    /* SerializeBlockUndo: compactsize(ntx), compactsize(0) for the coinbase, then per tx compactsize(nin) + CTxOut(int64 value, script) each */
    size_t cap = 1 << 16; u8* buf = malloc(cap); long n = 0;
    #define NEED(k) do { if ((size_t)n + (k) + 16 > cap){ while ((size_t)n + (k) + 16 > cap) cap *= 2; buf = realloc(buf, cap); } } while (0)
    n += put_cs(buf + n, txs->nitems); n += put_cs(buf + n, 0);
    for (size_t t = 1; t < txs->nitems; t++){ rj_val* vin = G(txs->items[t], "vin"); size_t nin = vin && vin->typ == RJ_ARR ? vin->nitems : 0;
        NEED(9); n += put_cs(buf + n, nin);
        for (size_t i = 0; i < nin; i++){ const rj_val* pv = G(vin->items[i], "prevout"); const char* hex = S(G(pv, "scriptPubKey"), "hex"); long sl = hex ? (long)strlen(hex) / 2 : 0;
            long long sats = 0; { const char* v = S(pv, "value"); if (v){ long long ip = 0, fp = 0; int nd = 0; const char* q = v; while (*q && *q != '.') ip = ip * 10 + (*q++ - '0'); if (*q == '.'){ q++; while (*q && nd < 8){ fp = fp * 10 + (*q++ - '0'); nd++; } while (nd++ < 8) fp *= 10; } sats = ip * 100000000LL + fp; } }
            NEED((size_t)sl + 24); for (int k = 0; k < 8; k++) buf[n++] = (u8)((unsigned long long)sats >> (8*k));
            n += put_cs(buf + n, (unsigned long)sl); long got = hex ? unhex(hex, buf + n, sl) : 0; if (got > 0) n += got; } }
    #undef NEED
    rj_free(b);
    if (rf == RF_HEX){ rhex(r, buf, n); free(buf); } else rbin(r, buf, n);
}
/* /rest/getutxos[/checkmempool]/<txid>-<n>/...: the outpoints from the URI (json/any) or, for bin/hex, from a POST body */
static void r_getutxos(resp_t* r, const rpc_wallet* w, const char* uri, size_t ul, const char* body, size_t blen){
    char param[2048]; int rf = parse_fmt(uri, ul, param, sizeof param);
    char* parts[32]; int np = param[0] ? split(param + (param[0] == '/'), parts, 32) : 0;
    int checkmempool = 0, from_uri = 0; u8 (*ops)[36] = calloc(16, 36); int nop = 0;
    if (np > 0){
        int i0 = 0; if (!strcmp(parts[0], "checkmempool")){ checkmempool = 1; i0 = 1; }
        for (int i = i0; i < np; i++){
            char* dash = strchr(parts[i], '-'); if (!dash || strchr(dash + 1, '-')){ free(ops); rerr(r, 400, "Parse error"); return; }
            *dash = 0; unsigned long vout;
            if (!is_hex64(parts[i]) || !to_ulong(dash + 1, &vout) || vout > 0xffffffffUL){ free(ops); rerr(r, 400, "Parse error"); return; }
            if (nop < 16){ hash_le(ops[nop], parts[i]); for (int k = 0; k < 4; k++) ops[nop][32 + k] = (u8)(vout >> (8*k)); }
            nop++;
        }
        if (nop > 0) from_uri = 1; else { free(ops); rerr(r, 400, "Error: empty request"); return; }
    }
    if (blen == 0 && np == 0){ free(ops); rerr(r, 400, "Error: empty request"); return; }
    u8* raw = 0; long rawlen = 0;
    if (rf == RF_HEX && blen){ raw = malloc(blen / 2 + 1); rawlen = unhex(body, raw, (long)blen / 2); if (rawlen < 0) rawlen = 0; }
    else if (rf == RF_BIN && blen){ raw = malloc(blen); memcpy(raw, body, blen); rawlen = (long)blen; }
    if ((rf == RF_HEX || rf == RF_BIN) && rawlen > 0){
        if (from_uri){ free(raw); free(ops); rerr(r, 400, "Combination of URI scheme inputs and raw post data is not allowed"); return; }
        /* Core's parse, as it actually runs (rest.cpp rest_getutxos): the body
         * is pushed into the stream as a std::string, which PREFIXES its
         * compactsize length; `>> fCheckMemPool` then reads that prefix's
         * first byte (never zero for a non-empty body) and `>> vOutPoints`
         * reads the count from the body's own first byte. Any non-empty body
         * therefore checks the mempool, and the outpoint vector starts at
         * byte 0. Trailing bytes are ignored, a short vector is a parse
         * error. Matched byte for byte by the regtest differential. */
        long p = 0; checkmempool = 1; unsigned long cnt = raw[p++];
        if (cnt == 253){ if (rawlen < p + 2){ free(raw); free(ops); rerr(r, 400, "Parse error"); return; } cnt = raw[p] | (raw[p+1] << 8); p += 2; }
        else if (cnt >= 254){ free(raw); free(ops); rerr(r, 400, "Parse error"); return; }
        if (rawlen < p + (long)cnt * 36){ free(raw); free(ops); rerr(r, 400, "Parse error"); return; }
        for (unsigned long i = 0; i < cnt; i++){ if (nop < 16) memcpy(ops[nop], raw + p + i * 36, 36); nop++; }
        free(raw);
    } else if (rf == RF_JSON){ if (!from_uri){ free(ops); rerr(r, 400, "Error: empty request"); return; } }
    else if (rf == RF_UNDEF){ free(ops); rerr(r, 404, FMTS_ALL); return; }
    if (nop > 15){ char m[128]; snprintf(m, sizeof m, "Error: max outpoints exceeded (max: %d, tried: %d)", 15, nop); free(ops); rerr(r, 400, m); return; }
    long ec; const char* em; rj_val* ci = call(w, "getblockchaininfo", rj_arr(), &ec, &em); if (!ci){ free(ops); rerr(r, 500, em ? em : "rpc error"); return; }
    long long height = N(ci, "blocks"); const char* tip = S(ci, "bestblockhash"); char tiphex[65]; snprintf(tiphex, sizeof tiphex, "%s", tip ? tip : "");
    rj_free(ci);
    rj_val* utxos = rj_arr(); u8 bitmap[2] = {0, 0}; char bits[17] = ""; long hits = 0;
    u8* bin = malloc(4096 + (size_t)nop * 10100); long bn = 0;
    for (int i = 0; i < nop; i++){
        char txid[65]; u8 t[32]; for (int k = 0; k < 32; k++) t[k] = ops[i][31 - k]; hexof(txid, t, 32);
        unsigned long vout = ops[i][32] | (ops[i][33] << 8) | (ops[i][34] << 16) | ((unsigned long)ops[i][35] << 24);
        rj_val* o = call(w, "gettxout", (rj_val*)({ rj_val* a = rj_arr(); rj_arr_push(a, rj_str(txid)); rj_arr_push(a, rj_numf("%lu", vout)); rj_arr_push(a, rj_bool(checkmempool)); a; }), 0, 0);
        int hit = o && o->typ == RJ_OBJ;
        bits[i] = hit ? '1' : '0'; bits[i+1] = 0; if (hit) bitmap[i / 8] |= (u8)(1 << (i % 8));
        if (hit){
            hits++;
            long long conf = N(o, "confirmations"); unsigned long h = conf <= 0 ? 0x7fffffffUL : (unsigned long)(height - conf + 1);   /* MEMPOOL_HEIGHT for an unconfirmed coin */
            rj_val* u = rj_obj(); rj_obj_set(u, "height", rj_numf("%lu", h)); rj_obj_set(u, "value", rj_clone(G(o, "value"))); rj_obj_set(u, "scriptPubKey", spk_of(G(o, "scriptPubKey"))); rj_arr_push(utxos, u);
            /* CCoin: u32 nTxVerDummy=0, u32 nHeight, CTxOut(int64 value, script) */
            for (int k = 0; k < 4; k++) bin[bn++] = 0;
            for (int k = 0; k < 4; k++) bin[bn++] = (u8)(h >> (8*k));
            long long sats = 0; { const char* v = S(o, "value"); if (v){ long long ip = 0, fp = 0; int nd = 0; const char* q = v; while (*q && *q != '.') ip = ip * 10 + (*q++ - '0'); if (*q == '.'){ q++; while (*q && nd < 8){ fp = fp * 10 + (*q++ - '0'); nd++; } while (nd++ < 8) fp *= 10; } sats = ip * 100000000LL + fp; } }
            for (int k = 0; k < 8; k++) bin[bn++] = (u8)((unsigned long long)sats >> (8*k));
            const char* hex = S(G(o, "scriptPubKey"), "hex"); long sl = hex ? (long)strlen(hex) / 2 : 0; if (sl > 10000) sl = 10000;
            bn += put_cs(bin + bn, (unsigned long)sl); long got = hex ? unhex(hex, bin + bn, sl) : 0; if (got > 0) bn += got;
        }
        if (o) rj_free(o);
    }
    free(ops);
    if (rf == RF_JSON){
        free(bin); rj_val* res = rj_obj(); rj_obj_set(res, "chainHeight", rj_numf("%lld", height)); rj_obj_set(res, "chaintipHash", rj_str(tiphex));
        rj_obj_set(res, "bitmap", rj_str(bits)); rj_obj_set(res, "utxos", utxos); rjson(r, res); return;
    }
    rj_free(utxos);
    /* int32 height, uint256 tip, vector<u8> bitmap, vector<CCoin> */
    long nb = (nop + 7) / 8; u8* out = malloc(64 + (size_t)bn); long n = 0;
    for (int k = 0; k < 4; k++) out[n++] = (u8)((unsigned long)height >> (8*k));
    hash_le(out + n, tiphex); n += 32;
    n += put_cs(out + n, (unsigned long)nb); for (long k = 0; k < nb; k++) out[n++] = bitmap[k];
    n += put_cs(out + n, (unsigned long)hits); memcpy(out + n, bin, (size_t)bn); n += bn; free(bin);
    if (rf == RF_HEX){ rhex(r, out, n); free(out); } else rbin(r, out, n);
}

/* ---- the dispatcher: Core's uri_prefixes table, in its order --------------------- */
int rest_is_path(const char* path, size_t plen){ return plen >= 6 && !memcmp(path, "/rest/", 6); }
int rest_handle(const char* method, size_t mlen, const char* path, size_t plen,
                const char* body, size_t blen, const rpc_wallet* w,
                char** out, size_t* outlen, int* status, const char** ctype){
    (void)method; (void)mlen;
    resp_t r = { out, outlen, status, ctype }; *out = 0; *outlen = 0; *status = 404; *ctype = "text/plain";
    static const struct { const char* prefix; int id; } tab[] = {
        {"/rest/tx/", 1}, {"/rest/block/notxdetails/", 2}, {"/rest/block/", 3}, {"/rest/blockpart/", 4},
        {"/rest/blockfilter/", 5}, {"/rest/blockfilterheaders/", 6}, {"/rest/chaininfo", 7}, {"/rest/mempool/", 8},
        {"/rest/headers/", 9}, {"/rest/getutxos", 10}, {"/rest/deploymentinfo/", 11}, {"/rest/deploymentinfo", 11},
        {"/rest/blockhashbyheight/", 12}, {"/rest/spenttxouts/", 13} };
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++){
        size_t pl = strlen(tab[i].prefix); if (plen < pl || memcmp(path, tab[i].prefix, pl)) continue;
        const char* uri = path + pl; size_t ul = plen - pl;
        switch (tab[i].id){
        case 1: r_tx(&r, w, uri, ul); return 1;
        case 2: r_block(&r, w, uri, ul, 1, 0, 0, 0); return 1;
        case 3: r_block(&r, w, uri, ul, 3, 0, 0, 0); return 1;
        case 4: r_blockpart(&r, w, uri, ul, path, plen); return 1;
        case 5: r_blockfilter(&r, w, uri, ul); return 1;
        case 6: r_blockfilterheaders(&r, w, uri, ul, path, plen); return 1;
        case 7: r_chaininfo(&r, w, uri, ul); return 1;
        case 8: r_mempool(&r, w, uri, ul, path, plen); return 1;
        case 9: r_headers(&r, w, uri, ul, path, plen); return 1;
        case 10: r_getutxos(&r, w, uri, ul, body, blen); return 1;
        case 11: r_deploymentinfo(&r, w, uri, ul); return 1;
        case 12: r_blockhash_by_height(&r, w, uri, ul); return 1;
        case 13: r_spenttxouts(&r, w, uri, ul); return 1;
        }
    }
    *out = strdup(""); *outlen = 0; *status = 404; *ctype = "text/plain";   /* Core's HTTP server: an unregistered path is a bare 404 */
    return 1;
}

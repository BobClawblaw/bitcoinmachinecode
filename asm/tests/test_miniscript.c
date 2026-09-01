/* tests/test_miniscript.c -- the miniscript engine against Core's own
 * src/test/miniscript_tests.cpp:
 *   - every literal Test() vector (tests/miniscript_vectors.h, 97 of them), in
 *     BOTH the P2WSH and the tapscript context: parse/validity per context,
 *     type properties (non-malleable, needs-signature, timelock mix), script
 *     bytes, script size, script -> miniscript -> script round trip, and the
 *     ops / stack / witness-size / execution-stack figures Core asserts;
 *   - the programmatic cases (21-key multi_a, the 99/110/200-key and_b chains,
 *     the 998/999-deep stack-limit chains);
 *   - the misc unit cases: non-minimal pushes and VERIFYs are not miniscript,
 *     thresh bounds, multi ops/stack, MINIMALIF, duplicate keys, the first
 *     insane sub, signed numbers;
 *   - TestSatisfy: for every valid vector, random subsets of its keys and
 *     preimages under nine (nLockTime, nSequence) contexts; every produced
 *     witness is run through THIS node's script interpreter with a mock
 *     signature checker (bitcoin_interp.asm, the consensus engine), and the
 *     malleable/non-malleable relations Core checks hold.
 * Keys in the vectors are the pubkeys of private keys 1..255 (Core's
 * TestData), which is what lets pk_h() hashes resolve on decode. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../miniscript.h"
#include "miniscript_vectors.h"
typedef unsigned char u8;
extern void hash160(u8 out[20], const void* in, long long len);
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
extern void sha256d(u8 out[32], const void* data, unsigned long len);
extern void ripemd160(u8 out[20], const void* in, long long len);
extern void scalar_to_pubkey(u8 pub[33], const u8 k[32]);
extern int  pubkey_parse(const u8* pub, unsigned long publen, uint64_t qx[4], uint64_t qy[4]);

static int fails = 0, checks = 0;
static void ck(const char* what, int cond){ checks++; if (!cond){ fails++; printf("  FAIL %s\n", what); } }
static void ckm(const char* what, const char* ms, int cond){ checks++; if (!cond){ fails++; printf("  FAIL %s: %s\n", what, ms); } }
static void hex(char* o, const u8* b, size_t n){ for (size_t i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", b[i]); o[2 * n] = 0; }
static int unhex(const char* s, u8* out, size_t cap){ size_t n = strlen(s); if (n & 1 || n / 2 > cap) return -1; for (size_t i = 0; i < n / 2; i++){ unsigned v; if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1; out[i] = (u8)v; } return (int)(n / 2); }

/* ---- the key table: 255 test keys plus whatever the vectors mention ---- */
typedef struct { u8 pub[33]; u8 h33[20], h32[20]; u8 ecdsa[72]; u8 schnorr[65]; } tkey_t;
static tkey_t* K; static int nK, capK;
static int key_add(const u8 pub[33]){
    for (int i = 0; i < nK; i++) if (!memcmp(K[i].pub, pub, 33)) return i;
    if (nK == capK){ capK = capK ? capK * 2 : 512; K = realloc(K, (size_t)capK * sizeof(tkey_t)); }
    tkey_t* k = &K[nK]; memset(k, 0, sizeof *k); memcpy(k->pub, pub, 33);
    hash160(k->h33, pub, 33); hash160(k->h32, pub + 1, 32);
    /* mock signatures: distinct per key, sized like real ones (Core's test uses real ones only for equality) */
    for (int i = 0; i < 72; i++) k->ecdsa[i] = (u8)(0x30 + i * 7 + pub[1 + (i % 32)]); k->ecdsa[71] = 1;
    for (int i = 0; i < 65; i++) k->schnorr[i] = (u8)(0x40 + i * 11 + pub[1 + (i % 32)]); k->schnorr[64] = 1;
    return nK++;
}
static int find_pub(const u8* b, size_t n){
    u8 pub[33];
    if (n == 33) memcpy(pub, b, 33); else if (n == 32){ pub[0] = 2; memcpy(pub + 1, b, 32); } else return -1;
    uint64_t qx[4], qy[4]; if (!pubkey_parse(pub, 33, qx, qy)) return -1;
    return key_add(pub);
}
/* ms_ctx_t callbacks */
typedef struct { int tap; } tctx_t;
static int t_key_from_str(void* u, const char* s, size_t n, int* key, char* err, size_t errcap){
    tctx_t* c = u; (void)err; (void)errcap; u8 b[65];
    if (n != 66 && !(c->tap && n == 64)) return 0;      /* under tapscript our own to_string prints x-only keys */
    char tmp[67]; memcpy(tmp, s, n); tmp[n] = 0; if (unhex(tmp, b, 65) != (int)(n / 2)) return 0;
    int k = find_pub(b, n / 2); if (k < 0) return 0; *key = k; return 1;
}
static int t_key_from_bytes(void* u, const u8* b, size_t n, int* key){
    tctx_t* c = u; if (c->tap ? n != 32 : n != 33) return 0;
    int k = find_pub(b, n); if (k < 0) return 0; *key = k; return 1;
}
static int t_key_from_hash(void* u, const u8 h[20], int* key){
    tctx_t* c = u;
    for (int i = 0; i < nK; i++) if (!memcmp(c->tap ? K[i].h32 : K[i].h33, h, 20)){ *key = i; return 1; }
    return 0;
}
static int t_key_bytes(void* u, int key, u8 out[33], int* n){ tctx_t* c = u; if (c->tap){ memcpy(out, K[key].pub + 1, 32); *n = 32; } else { memcpy(out, K[key].pub, 33); *n = 33; } return 1; }
static int t_key_hash(void* u, int key, u8 out[20]){ tctx_t* c = u; memcpy(out, c->tap ? K[key].h32 : K[key].h33, 20); return 1; }
static int t_key_to_str(void* u, int key, char* out, size_t cap){ tctx_t* c = u; if (cap < 67) return 0; if (c->tap) hex(out, K[key].pub + 1, 32); else hex(out, K[key].pub, 33); return 1; }
static int t_key_cmp(void* u, int a, int b){ (void)u; return memcmp(K[a].pub, K[b].pub, 33); }
static void mkctx(ms_ctx_t* ctx, tctx_t* u, int tap){
    u->tap = tap; memset(ctx, 0, sizeof *ctx); ctx->user = u;
    ctx->key_from_str = t_key_from_str; ctx->key_from_bytes = t_key_from_bytes; ctx->key_from_hash = t_key_from_hash;
    ctx->key_bytes = t_key_bytes; ctx->key_hash = t_key_hash; ctx->key_to_str = t_key_to_str; ctx->key_cmp = t_key_cmp;
}

/* ---- the interpreter (bitcoin_interp.asm) with a mock signature checker ---- */
#define ELEM_SIZE 528
#define MAX_STACK 1000
struct script_state {
    uint8_t* main_elems; size_t main_sp; uint8_t* alt_elems; size_t alt_sp;
    uint8_t* script; size_t script_len; int sigversion; uint64_t flags;
    uint8_t* work; size_t work_cap; uint64_t* error_out; void* checksig_ctx;
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t, const uint8_t*, size_t, const void*);
    uint32_t tx_locktime, in_sequence, tx_version;
};
extern int script_eval(struct script_state* st);
#define F_NULLDUMMY (1<<4)
#define F_MINIMALDATA (1<<6)
#define F_CLTV (1<<9)
#define F_CSV (1<<10)
#define F_MINIMALIF (1<<13)
#define ERR_OP_COUNT 7
#define ERR_STACK_SIZE 8
static uint64_t mock_checksig(void* ctx, const uint8_t* sig, size_t siglen, const uint8_t* pub, size_t publen, const void* slice){
    (void)ctx; (void)slice;
    int k = find_pub(pub, publen); if (k < 0) return 0;
    if (publen == 32) return siglen == 65 && !memcmp(sig, K[k].schnorr, 65);
    return siglen == 72 && !memcmp(sig, K[k].ecdsa, 72);
}
static uint8_t g_main[MAX_STACK * ELEM_SIZE], g_alt[MAX_STACK * ELEM_SIZE];
/* run witness (varint-prefixed elements) + script; 1 ok / 0 with *err */
static int run_script(const u8* wit, size_t witlen, int nel, const u8* script, size_t slen, int tap, uint32_t locktime, uint32_t seq, uint64_t* err){
    if (nel > MAX_STACK) { *err = ERR_STACK_SIZE; return 0; }
    memset(g_main, 0, (size_t)(nel ? nel : 1) * ELEM_SIZE);
    size_t o = 0;
    for (int i = 0; i < nel; i++){
        uint32_t l = wit[o++]; if (l == 0xfd){ l = (uint32_t)wit[o] | ((uint32_t)wit[o + 1] << 8); o += 2; }
        if (l > 520){ *err = 6; return 0; }
        uint8_t* rec = g_main + (size_t)i * ELEM_SIZE; ((uint32_t*)rec)[0] = l; memcpy(rec + 4, wit + o, l); o += l;
    }
    (void)witlen;
    struct script_state st; memset(&st, 0, sizeof st);
    st.main_elems = g_main; st.main_sp = (size_t)nel; st.alt_elems = g_alt; st.alt_sp = 0;
    st.script = (uint8_t*)script; st.script_len = slen; st.sigversion = tap ? 2 : 1;
    st.flags = F_NULLDUMMY | F_MINIMALDATA | F_CLTV | F_CSV | F_MINIMALIF;
    st.error_out = err; st.checksig_fn = mock_checksig; st.tx_locktime = locktime; st.in_sequence = seq; st.tx_version = 2;
    *err = 0;
    if (!script_eval(&st)) return 0;
    if (st.main_sp != 1){ *err = 2; return 0; }               /* CLEANSTACK */
    uint8_t* top = g_main; uint32_t l = ((uint32_t*)top)[0];
    int truthy = 0; for (uint32_t i = 0; i < l; i++) if (top[4 + i]){ if (i == l - 1 && top[4 + i] == 0x80) break; truthy = 1; break; }
    if (!truthy){ *err = 2; return 0; }
    return 1;
}

/* ---- the satisfier context: challenges ---- */
typedef struct { int type; uint32_t num; } chal_t;   /* type: 0 PK, 1 SHA256, 2 RIPEMD160, 3 HASH256, 4 HASH160 */
typedef struct { chal_t* v; int n; } chals_t;
static uint32_t le32(const u8* p){ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static int chal_has(const chals_t* c, int type, uint32_t num){ for (int i = 0; i < c->n; i++) if (c->v[i].type == type && c->v[i].num == num) return 1; return 0; }
static void chal_add(chals_t* c, int type, uint32_t num){ if (chal_has(c, type, num)) return; c->v = realloc(c->v, (size_t)(c->n + 1) * sizeof(chal_t)); c->v[c->n].type = type; c->v[c->n].num = num; c->n++; }
typedef struct { const chals_t* sup; int tap; uint32_t locktime, seq; } satu_t;
/* the 32-byte preimages are the private keys 1..255 (Core's TestData) */
static int preimage_for(int frag, const u8* hash, u8 out[32]){
    for (int i = 1; i <= 255; i++){
        u8 pre[32] = { 0 }; pre[31] = (u8)i; u8 h[32];
        if (frag == MS_SHA256) sha256_full(h, pre, 32); else if (frag == MS_HASH256) sha256d(h, pre, 32);
        else if (frag == MS_RIPEMD160) ripemd160(h, pre, 32); else hash160(h, pre, 32);
        if (!memcmp(h, hash, frag == MS_SHA256 || frag == MS_HASH256 ? 32 : 20)){ memcpy(out, pre, 32); return 1; }
    }
    return 0;
}
static int s_sign(void* u, int key, u8* sig, size_t* siglen, size_t cap){
    satu_t* s = u; (void)cap;
    if (!chal_has(s->sup, 0, le32(K[key].pub + 29))) return MS_AVAIL_NO;
    if (s->tap){ memcpy(sig, K[key].schnorr, 65); *siglen = 65; } else { memcpy(sig, K[key].ecdsa, 72); *siglen = 72; }
    return MS_AVAIL_YES;
}
static int s_older(void* u, uint32_t k){
    satu_t* s = u; uint32_t seq = s->seq;
    if (seq & 0x80000000u) return 0;
    if ((k & (1u << 22)) != (seq & (1u << 22))) return 0;
    return (k & 0xffff) <= (seq & 0xffff);
}
static int s_after(void* u, uint32_t k){
    satu_t* s = u;
    if ((k < 500000000u) != (s->locktime < 500000000u)) return 0;
    if (k > s->locktime) return 0;
    return s->seq != 0xffffffffu;
}
static int s_preimage(void* u, int frag, const u8* hash, u8 out[32]){
    satu_t* s = u; int type = frag == MS_SHA256 ? 1 : frag == MS_RIPEMD160 ? 2 : frag == MS_HASH256 ? 3 : 4;
    if (!chal_has(s->sup, type, le32(hash))) return MS_AVAIL_NO;
    return preimage_for(frag, hash, out) ? MS_AVAIL_YES : MS_AVAIL_NO;
}
static void find_challenges(const ms_tree_t* t, int root, chals_t* out, int* has_timelock){
    *has_timelock = 0;
    for (int i = 0; i <= root; i++){   /* every node in the pool belongs to this tree in the vector test (one tree per pool) */
        const ms_node_t* n = &t->nodes[i];
        for (int q = 0; q < n->nkeys; q++) chal_add(out, 0, le32(K[t->keys[n->keys_off + q]].pub + 29));
        switch (n->frag){
        case MS_OLDER: case MS_AFTER: *has_timelock = 1; break;
        case MS_SHA256: chal_add(out, 1, le32(n->data)); break;
        case MS_RIPEMD160: chal_add(out, 2, le32(n->data)); break;
        case MS_HASH256: chal_add(out, 3, le32(n->data)); break;
        case MS_HASH160: chal_add(out, 4, le32(n->data)); break;
        default: break;
        }
    }
}
static uint64_t rng = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void){ rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (uint32_t)rng; }

static void test_satisfy(const char* ms, ms_tree_t* t, int root, const ms_ctx_t* ctx, int tap, const u8* script, size_t slen){
    chals_t all = { 0 }; int has_tl; find_challenges(t, root, &all, &has_tl);
    static const uint32_t LT[3] = { 0, 499999999u, 0xffffffffu };
    static const uint32_t SQ[3] = { 0xffffffffu, 0x0000ffffu, 0x0040ffffu };
    uint32_t stack_bound = 0; int has_ss = ms_get_stack_size(t, root, &stack_bound);
    uint32_t wit_bound = 0; int has_ws = ms_get_witness_size(t, root, &wit_bound);
    for (int lt = 0; lt < 3; lt++) for (int sq = 0; sq < 3; sq++) for (int iter = 0; iter < 2; iter++){
        /* shuffle the challenge list */
        for (int i = all.n - 1; i > 0; i--){ int j = (int)(rnd() % (uint32_t)(i + 1)); chal_t tmp = all.v[i]; all.v[i] = all.v[j]; all.v[j] = tmp; }
        chals_t sup = { 0 }; satu_t su = { &sup, tap, LT[lt], SQ[sq] };
        ms_sat_ctx_t sc = { &su, s_sign, s_older, s_after, s_preimage };
        int prev_mal = 0, prev_nonmal = 0;
        for (int add = -1; add < all.n; add++){
            if (add >= 0) chal_add(&sup, all.v[add].type, all.v[add].num);
            ms_witness_t wm = { 0 }, wn = { 0 };
            int mal = ms_satisfy(t, ctx, &sc, root, 0, &wm) == MS_AVAIL_YES;
            int nonmal = ms_satisfy(t, ctx, &sc, root, 1, &wn) == MS_AVAIL_YES;
            if (nonmal){
                ckm("nonmal: witness element count within the stack bound", ms, has_ss && (uint32_t)wn.nelems <= stack_bound);
                ckm("nonmal implies mal, with the same witness", ms, mal && wm.len == wn.len && !memcmp(wm.buf, wn.buf, wn.len));
                ckm("nonmal: serialized witness within the witness-size bound", ms, has_ws && wn.len <= wit_bound);
                uint64_t err; int res = run_script(wn.buf, wn.len, wn.nelems, script, slen, tap, LT[lt], SQ[sq], &err);
                if (ms_valid_satisfactions(t, root)) ckm("nonmal witness verifies under the interpreter", ms, res);
                ckm("nonmal witness verifies, or fails only on the op/stack limits it exceeds", ms,
                    res || (!ms_check_ops_limit(t, root) && err == ERR_OP_COUNT) || (!ms_check_stack_size(t, root) && err == ERR_STACK_SIZE));
            }
            if (mal && (!nonmal || wm.len != wn.len || memcmp(wm.buf, wn.buf, wm.len))){
                uint64_t err; int res = run_script(wm.buf, wm.len, wm.nelems, script, slen, tap, LT[lt], SQ[sq], &err);
                ckm("malleable witness verifies, or fails only on op/stack limits", ms, res || err == ERR_OP_COUNT || err == ERR_STACK_SIZE);
            }
            if (ms_is_sane(t, root)) ckm("sane: malleable and non-malleable satisfiability agree", ms, mal == nonmal);
            ckm("adding a satisfied condition never loses the malleable satisfaction", ms, mal >= prev_mal);
            if (ms_is_sane(t, root) || add < 0 || all.v[add].type == 0) ckm("adding a key never loses the non-malleable satisfaction", ms, nonmal >= prev_nonmal);
            prev_mal = mal; prev_nonmal = nonmal;
            ms_witness_free(&wm); ms_witness_free(&wn);
        }
        if (!has_tl){
            int satisfiable = !ms_is_not_satisfiable(t, root);
            ckm("with every key and preimage a satisfiable script is satisfied", ms, prev_mal == satisfiable);
            if (ms_is_sane(t, root)) ckm("...non-malleably when sane", ms, prev_nonmal == satisfiable);
        }
        free(sup.v);
    }
    free(all.v);
}

/* ---- one Core Test() vector in one context ---- */
static void test_vec(const char* ms, const char* hexscript, int mode, int tap, int ops, int stack, int wit, int exec){
    ms_tree_t t; ms_tree_init(&t, tap); tctx_t u; ms_ctx_t ctx; mkctx(&ctx, &u, tap);
    char err[256]; int root = ms_parse(&t, &ctx, ms, strlen(ms), err, sizeof err);
    int expect_invalid = mode == 0 || ((mode & 16) && !tap) || ((mode & 32) && tap);
    char what[200]; snprintf(what, sizeof what, "[%s] %.150s", tap ? "tap" : "wsh", ms);
    if (expect_invalid){ ck(what, root < 0 || !ms_is_valid(&t, root)); ms_tree_free(&t); return; }
    if (root < 0){ ck(what, 0); printf("    unparseable\n"); ms_tree_free(&t); return; }
    ckm("valid", what, ms_is_valid(&t, root));
    ckm("valid top level", what, ms_is_valid_top(&t, root));
    static u8 script[400000]; int sl = ms_to_script(&t, &ctx, root, script, sizeof script);
    ckm("to_script", what, sl >= 0);
    if (sl < 0){ ms_tree_free(&t); return; }
    ckm("script size matches", what, (size_t)sl == ms_script_size(&t, root));
    if (strcmp(hexscript, "?")){ char* h = malloc((size_t)sl * 2 + 1); hex(h, script, (size_t)sl); if (strcmp(h, hexscript)){ ckm("script bytes", what, 0); printf("    got  %s\n    want %s\n", h, hexscript); } else checks++; free(h); }
    ckm("non-malleable flag", what, ms_is_nonmalleable(&t, root) == !!(mode & 2));
    ckm("needs-signature flag", what, ms_needs_signature(&t, root) == !!(mode & 4));
    ckm("timelock-mix flag", what, ms_check_timelocks_mix(&t, root) == !(mode & 8));
    /* decode -> re-encode round trip */
    ms_tree_t t2; ms_tree_init(&t2, tap); int r2 = ms_decode(&t2, &ctx, script, (size_t)sl);
    ckm("script decodes back to a miniscript", what, r2 >= 0);
    if (r2 >= 0){
        static u8 s2[400000]; int l2 = ms_to_script(&t2, &ctx, r2, s2, sizeof s2);
        ckm("round trip miniscript->script->miniscript->script", what, l2 == sl && !memcmp(s2, script, (size_t)sl));
        /* and the textual round trip of the decoded tree parses to the same script */
        char* txt = malloc(400000); if (ms_to_string(&t2, &ctx, r2, txt, 400000)){
            ms_tree_t t3; ms_tree_init(&t3, tap); int r3 = ms_parse(&t3, &ctx, txt, strlen(txt), err, sizeof err);
            static u8 s3[400000]; int l3 = r3 >= 0 ? ms_to_script(&t3, &ctx, r3, s3, sizeof s3) : -1;
            ckm("to_string -> parse -> script matches", what, l3 == sl && !memcmp(s3, script, (size_t)sl));
            ms_tree_free(&t3);
        } free(txt);
    }
    ms_tree_free(&t2);
    uint32_t v;
    if (ops != -1){ ckm("ops figure", what, ms_get_ops(&t, root, &v) && (int)v == ops); if (ms_get_ops(&t, root, &v) && (int)v != ops) printf("    ops %u want %d\n", v, ops); }
    if (stack != -1){ ckm("stack figure", what, ms_get_stack_size(&t, root, &v) && (int)v == stack); if (ms_get_stack_size(&t, root, &v) && (int)v != stack) printf("    stack %u want %d\n", v, stack); }
    if (wit != -1){ ckm("witness-size figure", what, ms_get_witness_size(&t, root, &v) && (int)v == wit); if (ms_get_witness_size(&t, root, &v) && (int)v != wit) printf("    wit %u want %d\n", v, wit); }
    if (exec != -1){ ckm("exec-stack figure", what, ms_get_exec_stack_size(&t, root, &v) && (int)v == exec); if (ms_get_exec_stack_size(&t, root, &v) && (int)v != exec) printf("    exec %u want %d\n", v, exec); }
    test_satisfy(what, &t, root, &ctx, tap, script, (size_t)sl);
    ms_tree_free(&t);
}
static void test_both(const char* ms, const char* hexscript, const char* taphex, int mode, int ops, int stack, int wit, int tapwit, int exec){
    test_vec(ms, hexscript, mode, 0, ops, stack, wit, exec);
    test_vec(ms, !strcmp(taphex, "=") ? hexscript : taphex, mode, 1, ops, stack, tapwit, exec);
}
static int parse_ok(const char* ms, int tap, ms_tree_t* t, int* root){ tctx_t u; ms_ctx_t c; mkctx(&c, &u, tap); ms_tree_init(t, tap); char e[256]; *root = ms_parse(t, &c, ms, strlen(ms), e, sizeof e); return *root >= 0; }
static int decode_ok(const char* hexs, int tap){ u8 b[512]; int n = unhex(hexs, b, sizeof b); tctx_t u; ms_ctx_t c; mkctx(&c, &u, tap); ms_tree_t t; ms_tree_init(&t, tap); int r = ms_decode(&t, &c, b, (size_t)n); ms_tree_free(&t); return r >= 0; }

int main(void){
    /* Core's TestData: keys 1..255 */
    for (int i = 1; i <= 255; i++){ u8 priv[32] = { 0 }; priv[31] = (u8)i; u8 pub[33]; scalar_to_pubkey(pub, priv); key_add(pub); }
    printf("== %zu Core miniscript_tests.cpp vectors, P2WSH and tapscript ==\n", (size_t)MS_NVECS);
    for (size_t i = 0; i < MS_NVECS; i++){ const ms_vec_t* v = &MS_VECS[i]; test_both(v->ms, v->hex, v->taphex, v->mode, v->ops, v->stack, v->wit, v->tapwit, v->exec); }

    printf("== programmatic vectors ==\n");
    { /* 21-key multi_a under tapscript only */
        char* ms = malloc(4096); strcpy(ms, "multi_a(1,");
        for (int i = 0; i < 21; i++){ char h[67]; hex(h, K[i].pub, 33); strcat(ms, h); if (i < 20) strcat(ms, ","); }
        strcat(ms, ")");
        test_both(ms, "?", "2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac20c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ba20f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ba20e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13ba202f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4ba20fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ba205cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bcba202f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ba20acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbeba20a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7ba20774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cbba20d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85aba20f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8ba20499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4ba20d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080eba20e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0aba20defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34ba205601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7ccba202b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6cba204ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97ba20352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5ba519c",
                  1 | 2 | 4 | 16, 22, 21, -1, -1, 22);
        free(ms);
    }
    { /* and_b chains of 99 / 110 / 200 keys: ops > 201, stack > 100, script > 3600 bytes -- tapscript only */
        static const int PK[3] = { 99, 110, 200 };
        for (int c = 0; c < 3; c++){
            int n = PK[c]; char* ms = malloc(200000); ms[0] = 0; size_t o = 0;
            for (int i = 0; i < n - 1; i++){ char h[67]; hex(h, K[i].pub, 33); o += (size_t)sprintf(ms + o, "and_b(pk(%s),a:", h); }
            { char h[67]; hex(h, K[n - 1].pub, 33); o += (size_t)sprintf(ms + o, "pk(%s)", h); }
            for (int i = 0; i < n - 1; i++) ms[o++] = ')'; ms[o] = 0;
            test_both(ms, "?", "?", 1 | 2 | 4 | 16, n + (n - 1) * 3, n, -1, -1, n + 1);
            free(ms);
        }
    }
    { /* execution stack: 998 nested and_b(older(1),a:...) reach 1000 during execution; 999 exceed it */
        for (int count = 998; count <= 999; count++){
            char* ms = malloc(64000); size_t o = 0;
            for (int i = 0; i < count; i++) o += (size_t)sprintf(ms + o, "and_b(older(1),a:");
            { char h[67]; hex(h, K[0].pub, 33); o += (size_t)sprintf(ms + o, "pk(%s)", h); }
            for (int i = 0; i < count; i++) ms[o++] = ')'; ms[o] = 0;
            ms_tree_t t; int root;
            ck(count == 998 ? "998-deep chain parses under tapscript" : "999-deep chain parses under tapscript", parse_ok(ms, 1, &t, &root));
            if (root >= 0) ck(count == 998 ? "998-deep chain stays within the execution stack" : "999-deep chain exceeds the execution stack (detected)", ms_check_stack_size(&t, root) == (count == 998));
            ms_tree_free(&t);
            test_both(ms, "?", "?", 1 | 2 | 4 | 16, 4 * count + 1, 1, -1, -1, 1 + count + 1);
            free(ms);
        }
    }

    printf("== misc unit cases ==\n");
    ck("tapscript: 'ac519c' (no pubkey) is not miniscript", !decode_ok("ac519c", 1));
    ck("tapscript: multi_a with no key before CHECKSIGADD is not miniscript", !decode_ok("ba20c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ba519c", 1));
    ck("tapscript: multi_a with no key before CHECKSIG is not miniscript", !decode_ok("ac2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac20c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ba519c", 1));
    ck("a script with a non-minimal push is not miniscript (wsh)", !decode_ok("0000210232780000feff00ffffffffffff21ff005f00ae21ae00000000060602060406564c2102320000060900fe00005f00ae21ae00100000060606060606000000000000000000000000000000000000000000000000000000000000000000", 0));
    ck("a script with a non-minimal push is not miniscript (tap)", !decode_ok("0000210232780000feff00ffffffffffff21ff005f00ae21ae00000000060602060406564c2102320000060900fe00005f00ae21ae00100000060606060606000000000000000000000000000000000000000000000000000000000000000000", 1));
    ck("a non-minimal VERIFY (<key> CHECKSIG VERIFY 1) is not miniscript (wsh)", !decode_ok("2103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7ac6951", 0));
    ck("a non-minimal VERIFY is not miniscript (tap)", !decode_ok("2103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7ac6951", 1));
    {
        ms_tree_t t; int root; uint32_t v;
        ck("multi(1,k,k,k) parses", parse_ok("multi(1,03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)", 0, &t, &root));
        ck("multi: ops = 3 keys + CMS = 4", ms_get_ops(&t, root, &v) && v == 4);
        ck("multi: stack = 1 sig + dummy = 2", ms_get_stack_size(&t, root, &v) && v == 2);
        ms_tree_free(&t);
        ck("MINIMALIF: thresh over a d: wrapper is invalid under P2WSH", parse_ok("thresh(3,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),sc:pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),sdv:older(32))", 0, &t, &root) && !ms_is_valid(&t, root));
        ms_tree_free(&t);
        static const char* DUPS[4] = {
            "and_v(v:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))",
            "or_b(c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),ac:pk_h(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))",
            "or_i(and_b(pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),s:pk(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556)),and_b(older(1),s:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)))",
            "thresh(2,pkh(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),s:pk(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),a:and_b(dv:older(1),s:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)))" };
        for (int i = 0; i < 4; i++){ char w[64]; snprintf(w, sizeof w, "duplicate keys (%d) parse but are not sane", i + 1);
            ck(w, parse_ok(DUPS[i], 0, &t, &root) && !ms_is_sane(&t, root) && !ms_check_duplicate_key(&t, root)); ms_tree_free(&t); }
        ck("no duplicates: sane", parse_ok("pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)", 0, &t, &root) && ms_check_duplicate_key(&t, root) && ms_is_sane(&t, root));
        ms_tree_free(&t);
        ck("insane script parses, valid, not sane", parse_ok("or_i(and_b(after(1),a:after(1000000000)),pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204))", 0, &t, &root) && ms_is_valid(&t, root) && !ms_is_sane(&t, root));
        { int sub = ms_find_insane_sub(&t, root); char txt[512] = ""; tctx_t u; ms_ctx_t c; mkctx(&c, &u, 0); if (sub >= 0) ms_to_string(&t, &c, sub, txt, sizeof txt);
          ck("the first insane sub is the deepest one (the timelock mix)", sub >= 0 && !strcmp(txt, "and_b(after(1),a:after(1000000000))")); if (sub >= 0 && strcmp(txt, "and_b(after(1),a:after(1000000000))")) printf("    got %s\n", txt); }
        ms_tree_free(&t);
        ck("after(-1) rejected", !parse_ok("after(-1)", 0, &t, &root)); ms_tree_free(&t);
        ck("after(+1) rejected", !parse_ok("after(+1)", 0, &t, &root)); ms_tree_free(&t);
        ck("thresh(-1,...) rejected", !parse_ok("thresh(-1,pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204))", 0, &t, &root)); ms_tree_free(&t);
        ck("multi(+1,...) rejected", !parse_ok("multi(+1,03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)", 0, &t, &root)); ms_tree_free(&t);
    }
    printf("\n%s (%d failures of %d checks)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails, checks);
    return fails ? 1 : 0;
}

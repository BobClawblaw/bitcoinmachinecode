/* miniscript.c -- Miniscript engine (see miniscript.h): Core's
 * script/miniscript.h algorithms, node by node, without recursion. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "miniscript.h"

typedef unsigned char u8;

/* ---- limits (Core: consensus/consensus.h, policy/policy.h) --------------- */
#define MAX_OPS_PER_SCRIPT            201
#define MAX_STANDARD_P2WSH_STACK_ITEMS 100
#define MAX_STACK_SIZE                1000
#define MAX_STANDARD_P2WSH_SCRIPT_SIZE 3600
#define MAX_PUBKEYS_PER_MULTISIG      20
#define MAX_PUBKEYS_PER_MULTI_A       999
#define LOCKTIME_THRESHOLD            500000000u
#define SEQUENCE_LOCKTIME_TYPE_FLAG   (1u << 22)
#define SEQUENCE_LOCKTIME_MASK        0x0000ffffu

size_t ms_max_script_size(int tapscript){
    /* MAX_STANDARD_TX_WEIGHT - TX_BODY_LEEWAY_WEIGHT - MAX_TAPSCRIPT_SAT_SIZE, minus its own compact size */
    if (tapscript) return 400000 - 378 - 70135 - 5;
    return MAX_STANDARD_P2WSH_SCRIPT_SIZE;
}

/* ---- opcodes --------------------------------------------------------------- */
enum { OP_0 = 0x00, OP_PUSHDATA1 = 0x4c, OP_PUSHDATA2 = 0x4d, OP_PUSHDATA4 = 0x4e, OP_1NEGATE = 0x4f, OP_1 = 0x51, OP_16 = 0x60,
       OP_IF = 0x63, OP_NOTIF = 0x64, OP_ELSE = 0x67, OP_ENDIF = 0x68, OP_VERIFY = 0x69, OP_TOALTSTACK = 0x6b, OP_FROMALTSTACK = 0x6c,
       OP_IFDUP = 0x73, OP_DUP = 0x76, OP_SWAP = 0x7c, OP_SIZE = 0x82, OP_EQUAL = 0x87, OP_EQUALVERIFY = 0x88, OP_0NOTEQUAL = 0x92,
       OP_ADD = 0x93, OP_BOOLAND = 0x9a, OP_BOOLOR = 0x9b, OP_NUMEQUAL = 0x9c, OP_NUMEQUALVERIFY = 0x9d,
       OP_RIPEMD160 = 0xa6, OP_SHA256 = 0xa8, OP_HASH160 = 0xa9, OP_HASH256 = 0xaa,
       OP_CHECKSIG = 0xac, OP_CHECKSIGVERIFY = 0xad, OP_CHECKMULTISIG = 0xae, OP_CHECKMULTISIGVERIFY = 0xaf,
       OP_CHECKLOCKTIMEVERIFY = 0xb1, OP_CHECKSEQUENCEVERIFY = 0xb2, OP_CHECKSIGADD = 0xba };

/* ---- the type algebra ------------------------------------------------------ */
static uint32_t T(const char* s){
    uint32_t r = 0;
    for (; *s; s++) switch (*s){
        case 'B': r |= MST_B; break; case 'V': r |= MST_V; break; case 'K': r |= MST_K; break; case 'W': r |= MST_W; break;
        case 'z': r |= MST_z; break; case 'o': r |= MST_o; break; case 'n': r |= MST_n; break; case 'd': r |= MST_d; break;
        case 'u': r |= MST_u; break; case 'e': r |= MST_e; break; case 'f': r |= MST_f; break; case 's': r |= MST_s; break;
        case 'm': r |= MST_m; break; case 'x': r |= MST_x; break; case 'g': r |= MST_g; break; case 'h': r |= MST_h; break;
        case 'i': r |= MST_i; break; case 'j': r |= MST_j; break; case 'k': r |= MST_k; break; default: break;
    }
    return r;
}
/* "x << s": x has every property in s */
#define HAS(x, s) ((T(s) & ~(x)) == 0)
#define IF(s, c) ((c) ? T(s) : 0u)

void ms_type_string(uint32_t typ, char out[24]){
    static const char map[19] = { 'B','V','K','W','z','o','n','d','u','e','f','s','m','x','g','h','i','j','k' };
    int o = 0;
    for (int b = 0; b < 19; b++) if (typ & (1u << b)) out[o++] = map[b];
    out[o] = 0;
}

static uint32_t compute_type(int frag, uint32_t x, uint32_t y, uint32_t z, const uint32_t* subt, uint32_t k, int nsubs, int tap){
    switch (frag){
    case MS_PK_K: return T("Konudemsxk");
    case MS_PK_H: return T("Knudemsxk");
    case MS_OLDER: return IF("g", k & SEQUENCE_LOCKTIME_TYPE_FLAG) | IF("h", !(k & SEQUENCE_LOCKTIME_TYPE_FLAG)) | T("Bzfmxk");
    case MS_AFTER: return IF("i", k >= LOCKTIME_THRESHOLD) | IF("j", k < LOCKTIME_THRESHOLD) | T("Bzfmxk");
    case MS_SHA256: case MS_RIPEMD160: case MS_HASH256: case MS_HASH160: return T("Bonudmk");
    case MS_JUST_1: return T("Bzufmxk");
    case MS_JUST_0: return T("Bzudemsxk");
    case MS_WRAP_A: return IF("W", HAS(x, "B")) | (x & T("ghijk")) | (x & T("udfems")) | T("x");
    case MS_WRAP_S: return IF("W", HAS(x, "Bo")) | (x & T("ghijk")) | (x & T("udfemsx"));
    case MS_WRAP_C: return IF("B", HAS(x, "K")) | (x & T("ghijk")) | (x & T("ondfem")) | T("us");
    case MS_WRAP_D: return IF("B", HAS(x, "Vz")) | IF("o", HAS(x, "z")) | IF("e", HAS(x, "f")) | (x & T("ghijk")) | (x & T("ms")) | IF("u", tap) | T("ndx");
    case MS_WRAP_V: return IF("V", HAS(x, "B")) | (x & T("ghijk")) | (x & T("zonms")) | T("fx");
    case MS_WRAP_J: return IF("B", HAS(x, "Bn")) | IF("e", HAS(x, "f")) | (x & T("ghijk")) | (x & T("oums")) | T("ndx");
    case MS_WRAP_N: return (x & T("ghijk")) | (x & T("Bzondfems")) | T("ux");
    case MS_AND_V: {
        uint32_t r = 0;
        if (HAS(x, "V")) r |= (y & T("KVB"));
        r |= (x & T("n")); if (HAS(x, "z")) r |= (y & T("n"));
        if (HAS(x | y, "z")) r |= ((x | y) & T("o"));
        r |= (x & y & T("mz"));
        r |= ((x | y) & T("s"));
        r |= IF("f", HAS(y, "f") || HAS(x, "s"));
        r |= (y & T("ux"));
        r |= ((x | y) & T("ghij"));
        r |= IF("k", HAS(x & y, "k") && !((HAS(x, "g") && HAS(y, "h")) || (HAS(x, "h") && HAS(y, "g")) || (HAS(x, "i") && HAS(y, "j")) || (HAS(x, "j") && HAS(y, "i"))));
        return r; }
    case MS_AND_B: {
        uint32_t r = 0;
        if (HAS(y, "W")) r |= (x & T("B"));
        if (HAS(x | y, "z")) r |= ((x | y) & T("o"));
        r |= (x & T("n")); if (HAS(x, "z")) r |= (y & T("n"));
        if (HAS(x & y, "s")) r |= (x & y & T("e"));
        r |= (x & y & T("dzm"));
        r |= IF("f", HAS(x & y, "f") || HAS(x, "sf") || HAS(y, "sf"));
        r |= ((x | y) & T("s"));
        r |= T("ux");
        r |= ((x | y) & T("ghij"));
        r |= IF("k", HAS(x & y, "k") && !((HAS(x, "g") && HAS(y, "h")) || (HAS(x, "h") && HAS(y, "g")) || (HAS(x, "i") && HAS(y, "j")) || (HAS(x, "j") && HAS(y, "i"))));
        return r; }
    case MS_OR_B: {
        uint32_t r = 0;
        r |= IF("B", HAS(x, "Bd") && HAS(y, "Wd"));
        if (HAS(x | y, "z")) r |= ((x | y) & T("o"));
        if (HAS(x | y, "s") && HAS(x & y, "e")) r |= (x & y & T("m"));
        r |= (x & y & T("zse"));
        r |= T("dux");
        r |= ((x | y) & T("ghij"));
        r |= (x & y & T("k"));
        return r; }
    case MS_OR_D: {
        uint32_t r = 0;
        if (HAS(x, "Bdu")) r |= (y & T("B"));
        if (HAS(y, "z")) r |= (x & T("o"));
        if (HAS(x, "e") && HAS(x | y, "s")) r |= (x & y & T("m"));
        r |= (x & y & T("zs"));
        r |= (y & T("ufde"));
        r |= T("x");
        r |= ((x | y) & T("ghij"));
        r |= (x & y & T("k"));
        return r; }
    case MS_OR_C: {
        uint32_t r = 0;
        if (HAS(x, "Bdu")) r |= (y & T("V"));
        if (HAS(y, "z")) r |= (x & T("o"));
        if (HAS(x, "e") && HAS(x | y, "s")) r |= (x & y & T("m"));
        r |= (x & y & T("zs"));
        r |= T("fx");
        r |= ((x | y) & T("ghij"));
        r |= (x & y & T("k"));
        return r; }
    case MS_OR_I: {
        uint32_t r = 0;
        r |= (x & y & T("VBKufs"));
        r |= IF("o", HAS(x & y, "z"));
        if (HAS(x | y, "f")) r |= ((x | y) & T("e"));
        if (HAS(x | y, "s")) r |= (x & y & T("m"));
        r |= ((x | y) & T("d"));
        r |= T("x");
        r |= ((x | y) & T("ghij"));
        r |= (x & y & T("k"));
        return r; }
    case MS_ANDOR: {
        uint32_t r = 0;
        if (HAS(x, "Bdu")) r |= (y & z & T("BKV"));
        r |= (x & y & z & T("z"));
        if (HAS(x | (y & z), "z")) r |= ((x | (y & z)) & T("o"));
        r |= (y & z & T("u"));
        if (HAS(x, "s") || HAS(y, "f")) r |= (z & T("f"));
        r |= (z & T("d"));
        if (HAS(x, "s") || HAS(y, "f")) r |= (z & T("e"));
        if (HAS(x, "e") && HAS(x | y | z, "s")) r |= (x & y & z & T("m"));
        r |= (z & (x | y) & T("s"));
        r |= T("x");
        r |= ((x | y | z) & T("ghij"));
        r |= IF("k", HAS(x & y & z, "k") && !((HAS(x, "g") && HAS(y, "h")) || (HAS(x, "h") && HAS(y, "g")) || (HAS(x, "i") && HAS(y, "j")) || (HAS(x, "j") && HAS(y, "i"))));
        return r; }
    case MS_MULTI: return T("Bnudemsk");
    case MS_MULTI_A: return T("Budemsk");
    case MS_THRESH: {
        int all_e = 1, all_m = 1; uint32_t args = 0, num_s = 0; uint32_t acc_tl = T("k");
        for (int i = 0; i < nsubs; i++){
            uint32_t t = subt[i];
            if (!HAS(t, i ? "Wdu" : "Bdu")) return 0;
            if (!HAS(t, "e")) all_e = 0;
            if (!HAS(t, "m")) all_m = 0;
            if (HAS(t, "s")) num_s++;
            args += HAS(t, "z") ? 0 : HAS(t, "o") ? 1 : 2;
            uint32_t kk = IF("k", HAS(acc_tl & t, "k") && ((k <= 1) ||
                        ((k > 1) && !((HAS(acc_tl, "g") && HAS(t, "h")) || (HAS(acc_tl, "h") && HAS(t, "g")) ||
                                      (HAS(acc_tl, "i") && HAS(t, "j")) || (HAS(acc_tl, "j") && HAS(t, "i"))))));
            acc_tl = ((acc_tl | t) & T("ghij")) | kk;
        }
        return T("Bdu") | IF("z", args == 0) | IF("o", args == 1) | IF("e", all_e && num_s == (uint32_t)nsubs) |
               IF("m", all_e && all_m && num_s >= (uint32_t)nsubs - k) | IF("s", num_s >= (uint32_t)nsubs - k + 1) | acc_tl; }
    }
    return 0;
}

/* ---- script numbers ---------------------------------------------------------- */
static int num_bytes(int64_t v){          /* CScriptNum serialization length of v > 0 */
    int n = 0; uint64_t a = (uint64_t)(v < 0 ? -v : v);
    while (a){ n++; a >>= 8; }
    if (n == 0) return 0;
    uint64_t top = (uint64_t)(v < 0 ? -v : v) >> (8 * (n - 1));
    if (top & 0x80) n++;
    return n;
}
static int push_num_size(int64_t v){ if (v == 0 || (v >= 1 && v <= 16)) return 1; return 1 + num_bytes(v); }
static int push_num(u8* out, size_t cap, size_t o, int64_t v){
    if (v == 0){ if (o + 1 > cap) return -1; out[o++] = OP_0; return (int)o; }
    if (v >= 1 && v <= 16){ if (o + 1 > cap) return -1; out[o++] = (u8)(OP_1 + v - 1); return (int)o; }
    int n = num_bytes(v); if (o + 1 + (size_t)n > cap) return -1;
    out[o++] = (u8)n;
    uint64_t a = (uint64_t)(v < 0 ? -v : v);
    for (int i = 0; i < n; i++){ out[o + i] = (u8)(a & 0xff); a >>= 8; }
    if (v < 0) out[o + n - 1] |= 0x80;
    return (int)(o + n);
}
static int push_data(u8* out, size_t cap, size_t o, const u8* d, size_t n){
    if (n < 0x4c){ if (o + 1 + n > cap) return -1; out[o++] = (u8)n; }
    else if (n <= 0xff){ if (o + 2 + n > cap) return -1; out[o++] = OP_PUSHDATA1; out[o++] = (u8)n; }
    else { if (o + 3 + n > cap) return -1; out[o++] = OP_PUSHDATA2; out[o++] = (u8)n; out[o++] = (u8)(n >> 8); }
    memcpy(out + o, d, n); return (int)(o + n);
}

/* ---- pools ------------------------------------------------------------------- */
void ms_tree_init(ms_tree_t* t, int tapscript){ memset(t, 0, sizeof *t); t->growable = 1; t->tapscript = tapscript; }
void ms_tree_free(ms_tree_t* t){ if (t->growable){ free(t->nodes); free(t->subs); free(t->keys); } memset(t, 0, sizeof *t); }
void ms_tree_reset(ms_tree_t* t){ t->nn = 0; t->ns = 0; t->nk = 0; }

static int grow(void** p, int32_t* cap, int32_t need, size_t esz, int growable){
    if (need <= *cap) return 1;
    if (!growable) return 0;
    int32_t nc = *cap ? *cap : 64; while (nc < need) nc *= 2;
    void* q = realloc(*p, (size_t)nc * esz); if (!q) return 0;
    *p = q; *cap = nc; return 1;
}
static int32_t subs_push(ms_tree_t* t, const int32_t* v, int n){
    if (!grow((void**)&t->subs, &t->scap, t->ns + n, sizeof(int32_t), t->growable)) return -1;
    int32_t off = t->ns; memcpy(t->subs + off, v, (size_t)n * sizeof(int32_t)); t->ns += n; return off;
}
static int32_t keys_push(ms_tree_t* t, const int32_t* v, int n){
    if (!grow((void**)&t->keys, &t->kcap, t->nk + n, sizeof(int32_t), t->growable)) return -1;
    int32_t off = t->nk; memcpy(t->keys + off, v, (size_t)n * sizeof(int32_t)); t->nk += n; return off;
}
#define SUB(t, n, i) ((t)->subs[(n)->subs_off + (i)])
#define NODE(t, i) (&(t)->nodes[i])

/* MaxInt: valid flag folded into the sign (-1 = invalid) */
static int32_t mx_add(int32_t a, int32_t b){ if (a < 0 || b < 0) return -1; return a + b; }
static int32_t mx_or(int32_t a, int32_t b){ if (a < 0) return b; if (b < 0) return a; return a > b ? a : b; }
/* SatInfo */
typedef struct { int valid; int32_t net, exec; } sat_t;
static sat_t si(int32_t net, int32_t exec){ sat_t s = { 1, net, exec }; return s; }
static sat_t si_none(void){ sat_t s = { 0, 0, 0 }; return s; }
static sat_t si_or(sat_t a, sat_t b){ if (!a.valid) return b; if (!b.valid) return a; return si(a.net > b.net ? a.net : b.net, a.exec > b.exec ? a.exec : b.exec); }
static sat_t si_cat(sat_t a, sat_t b){ if (!a.valid || !b.valid) return si_none(); int32_t e2 = b.net + a.exec; return si(a.net + b.net, b.exec > e2 ? b.exec : e2); }
#define SI_EMPTY si(0, 0)
#define SI_PUSH  si(-1, 0)
#define SI_HASH  si(0, 0)
#define SI_NOP   si(0, 0)
#define SI_IF    si(1, 1)
#define SI_BINOP si(1, 1)
#define SI_DUP   si(-1, 0)
#define SI_IFDUP(nz) si((nz) ? -1 : 0, 0)
#define SI_EQUALVERIFY si(2, 2)
#define SI_EQUAL si(1, 1)
#define SI_SIZE  si(-1, 0)
#define SI_CHECKSIG si(1, 1)
#define SI_0NOTEQUAL si(0, 0)
#define SI_VERIFY si(1, 1)
static sat_t nsat(const ms_node_t* n){ sat_t s = { n->ss_sat_valid, n->ss_sat_net, n->ss_sat_exec }; return s; }
static sat_t ndsat(const ms_node_t* n){ sat_t s = { n->ss_dsat_valid, n->ss_dsat_net, n->ss_dsat_exec }; return s; }

/* build a node whose children (in t->subs) and keys (in t->keys) are already placed */
static int32_t mk_node(ms_tree_t* t, int frag, uint32_t k, const int32_t* subs, int nsubs, const int32_t* keys, int nkeys, const u8* data, int datalen){
    if (!grow((void**)&t->nodes, &t->ncap, t->nn + 1, sizeof(ms_node_t), t->growable)) return -1;
    int32_t soff = 0, koff = 0;
    if (nsubs){ soff = subs_push(t, subs, nsubs); if (soff < 0) return -1; }
    if (nkeys){ koff = keys_push(t, keys, nkeys); if (koff < 0) return -1; }
    ms_node_t* n = &t->nodes[t->nn]; memset(n, 0, sizeof *n);
    n->frag = (u8)frag; n->nsubs = (u8)nsubs; n->subs_off = soff; n->nkeys = nkeys; n->keys_off = koff; n->k = k;
    if (data && datalen){ memcpy(n->data, data, (size_t)datalen); n->datalen = (u8)datalen; }
    int tap = t->tapscript;
    const ms_node_t* s0 = nsubs > 0 ? NODE(t, subs[0]) : NULL;
    const ms_node_t* s1 = nsubs > 1 ? NODE(t, subs[1]) : NULL;
    const ms_node_t* s2 = nsubs > 2 ? NODE(t, subs[2]) : NULL;
    uint32_t x = s0 ? s0->typ : 0, y = s1 ? s1->typ : 0, z = s2 ? s2->typ : 0;

    /* ---- type ---- */
    if (frag == MS_THRESH){
        uint32_t* st = malloc((size_t)(nsubs ? nsubs : 1) * sizeof(uint32_t)); if (!st) return -1;
        for (int i = 0; i < nsubs; i++) st[i] = NODE(t, subs[i])->typ;
        n->typ = compute_type(frag, x, y, z, st, k, nsubs, tap); free(st);
    } else n->typ = compute_type(frag, x, y, z, NULL, k, nsubs, tap);
    /* SanitizeType: no base type means no type at all */
    if (!(n->typ & (MST_B | MST_V | MST_K | MST_W))) n->typ = 0;

    /* ---- script length ---- */
    size_t subsize = 0; for (int i = 0; i < nsubs; i++) subsize += NODE(t, subs[i])->scriptlen;
    switch (frag){
    case MS_JUST_1: case MS_JUST_0: n->scriptlen = 1; break;
    case MS_PK_K: n->scriptlen = tap ? 33 : 34; break;
    case MS_PK_H: n->scriptlen = 3 + 21; break;
    case MS_OLDER: case MS_AFTER: n->scriptlen = 1 + (uint32_t)push_num_size(k); break;
    case MS_HASH256: case MS_SHA256: n->scriptlen = 4 + 2 + 33; break;
    case MS_HASH160: case MS_RIPEMD160: n->scriptlen = 4 + 2 + 21; break;
    case MS_MULTI: n->scriptlen = 1 + (uint32_t)push_num_size(nkeys) + (uint32_t)push_num_size(k) + 34 * (uint32_t)nkeys; break;
    case MS_MULTI_A: n->scriptlen = (1 + 32 + 1) * (uint32_t)nkeys + (uint32_t)push_num_size(k) + 1; break;
    case MS_AND_V: n->scriptlen = (uint32_t)subsize; break;
    case MS_WRAP_V: n->scriptlen = (uint32_t)subsize + (HAS(x, "x") ? 1 : 0); break;
    case MS_WRAP_S: case MS_WRAP_C: case MS_WRAP_N: case MS_AND_B: case MS_OR_B: n->scriptlen = (uint32_t)subsize + 1; break;
    case MS_WRAP_A: case MS_OR_C: n->scriptlen = (uint32_t)subsize + 2; break;
    case MS_WRAP_D: case MS_OR_D: case MS_OR_I: case MS_ANDOR: n->scriptlen = (uint32_t)subsize + 3; break;
    case MS_WRAP_J: n->scriptlen = (uint32_t)subsize + 4; break;
    case MS_THRESH: n->scriptlen = (uint32_t)subsize + (uint32_t)nsubs + (uint32_t)push_num_size(k); break;
    }

    /* ---- ops ---- */
    {
        uint32_t c = 0; int32_t sat = -1, dsat = -1;
        switch (frag){
        case MS_JUST_1: c = 0; sat = 0; dsat = -1; break;
        case MS_JUST_0: c = 0; sat = -1; dsat = 0; break;
        case MS_PK_K: c = 0; sat = 0; dsat = 0; break;
        case MS_PK_H: c = 3; sat = 0; dsat = 0; break;
        case MS_OLDER: case MS_AFTER: c = 1; sat = 0; dsat = -1; break;
        case MS_SHA256: case MS_RIPEMD160: case MS_HASH256: case MS_HASH160: c = 4; sat = 0; dsat = -1; break;
        case MS_AND_V: c = s0->ops_count + s1->ops_count; sat = mx_add(s0->ops_sat, s1->ops_sat); dsat = -1; break;
        case MS_AND_B: c = 1 + s0->ops_count + s1->ops_count; sat = mx_add(s0->ops_sat, s1->ops_sat); dsat = mx_add(s0->ops_dsat, s1->ops_dsat); break;
        case MS_OR_B: c = 1 + s0->ops_count + s1->ops_count; sat = mx_or(mx_add(s0->ops_sat, s1->ops_dsat), mx_add(s1->ops_sat, s0->ops_dsat)); dsat = mx_add(s0->ops_dsat, s1->ops_dsat); break;
        case MS_OR_D: c = 3 + s0->ops_count + s1->ops_count; sat = mx_or(s0->ops_sat, mx_add(s1->ops_sat, s0->ops_dsat)); dsat = mx_add(s0->ops_dsat, s1->ops_dsat); break;
        case MS_OR_C: c = 2 + s0->ops_count + s1->ops_count; sat = mx_or(s0->ops_sat, mx_add(s1->ops_sat, s0->ops_dsat)); dsat = -1; break;
        case MS_OR_I: c = 3 + s0->ops_count + s1->ops_count; sat = mx_or(s0->ops_sat, s1->ops_sat); dsat = mx_or(s0->ops_dsat, s1->ops_dsat); break;
        case MS_ANDOR: c = 3 + s0->ops_count + s1->ops_count + s2->ops_count; sat = mx_or(mx_add(s1->ops_sat, s0->ops_sat), mx_add(s0->ops_dsat, s2->ops_sat)); dsat = mx_add(s0->ops_dsat, s2->ops_dsat); break;
        case MS_MULTI: c = 1; sat = nkeys; dsat = nkeys; break;
        case MS_MULTI_A: c = (uint32_t)nkeys + 1; sat = 0; dsat = 0; break;
        case MS_WRAP_S: case MS_WRAP_C: case MS_WRAP_N: c = 1 + s0->ops_count; sat = s0->ops_sat; dsat = s0->ops_dsat; break;
        case MS_WRAP_A: c = 2 + s0->ops_count; sat = s0->ops_sat; dsat = s0->ops_dsat; break;
        case MS_WRAP_D: c = 3 + s0->ops_count; sat = s0->ops_sat; dsat = 0; break;
        case MS_WRAP_J: c = 4 + s0->ops_count; sat = s0->ops_sat; dsat = 0; break;
        case MS_WRAP_V: c = s0->ops_count + (HAS(x, "x") ? 1 : 0); sat = s0->ops_sat; dsat = -1; break;
        case MS_THRESH: {
            int32_t* sats = malloc((size_t)(nsubs + 1) * sizeof(int32_t)); int32_t* nx = malloc((size_t)(nsubs + 2) * sizeof(int32_t));
            if (!sats || !nx){ free(sats); free(nx); return -1; }
            int ns = 1; sats[0] = 0; c = 0;
            for (int i = 0; i < nsubs; i++){
                const ms_node_t* s = NODE(t, subs[i]); c += s->ops_count + 1;
                nx[0] = mx_add(sats[0], s->ops_dsat);
                for (int j = 1; j < ns; j++) nx[j] = mx_or(mx_add(sats[j], s->ops_dsat), mx_add(sats[j - 1], s->ops_sat));
                nx[ns] = mx_add(sats[ns - 1], s->ops_sat);
                ns++; memcpy(sats, nx, (size_t)ns * sizeof(int32_t));
            }
            sat = (int)k < ns ? sats[k] : -1; dsat = sats[0];
            free(sats); free(nx); break; }
        }
        n->ops_count = c; n->ops_sat = sat; n->ops_dsat = dsat;
    }

    /* ---- stack size ---- */
    {
        sat_t S = si_none(), D = si_none();
        switch (frag){
        case MS_JUST_0: S = si_none(); D = SI_PUSH; break;
        case MS_JUST_1: S = SI_PUSH; D = si_none(); break;
        case MS_OLDER: case MS_AFTER: S = si_cat(SI_PUSH, SI_NOP); D = si_none(); break;
        case MS_PK_K: S = D = SI_PUSH; break;
        case MS_PK_H: S = D = si_cat(si_cat(si_cat(SI_DUP, SI_HASH), SI_PUSH), SI_EQUALVERIFY); break;
        case MS_SHA256: case MS_RIPEMD160: case MS_HASH256: case MS_HASH160:
            S = si_cat(si_cat(si_cat(si_cat(si_cat(SI_SIZE, SI_PUSH), SI_EQUALVERIFY), SI_HASH), SI_PUSH), SI_EQUAL); D = si_none(); break;
        case MS_ANDOR:
            S = si_or(si_cat(si_cat(nsat(s0), SI_IF), nsat(s1)), si_cat(si_cat(ndsat(s0), SI_IF), nsat(s2)));
            D = si_cat(si_cat(ndsat(s0), SI_IF), ndsat(s2)); break;
        case MS_AND_V: S = si_cat(nsat(s0), nsat(s1)); D = si_none(); break;
        case MS_AND_B: S = si_cat(si_cat(nsat(s0), nsat(s1)), SI_BINOP); D = si_cat(si_cat(ndsat(s0), ndsat(s1)), SI_BINOP); break;
        case MS_OR_B: S = si_cat(si_or(si_cat(nsat(s0), ndsat(s1)), si_cat(ndsat(s0), nsat(s1))), SI_BINOP); D = si_cat(si_cat(ndsat(s0), ndsat(s1)), SI_BINOP); break;
        case MS_OR_C: S = si_or(si_cat(nsat(s0), SI_IF), si_cat(si_cat(ndsat(s0), SI_IF), nsat(s1))); D = si_none(); break;
        case MS_OR_D:
            S = si_or(si_cat(si_cat(nsat(s0), SI_IFDUP(1)), SI_IF), si_cat(si_cat(si_cat(ndsat(s0), SI_IFDUP(0)), SI_IF), nsat(s1)));
            D = si_cat(si_cat(si_cat(ndsat(s0), SI_IFDUP(0)), SI_IF), ndsat(s1)); break;
        case MS_OR_I: S = si_cat(SI_IF, si_or(nsat(s0), nsat(s1))); D = si_cat(SI_IF, si_or(ndsat(s0), ndsat(s1))); break;
        case MS_MULTI: S = D = si((int32_t)k, (int32_t)k + nkeys + 2); break;
        case MS_MULTI_A: S = D = si(nkeys - 1, nkeys); break;
        case MS_WRAP_A: case MS_WRAP_N: case MS_WRAP_S: S = nsat(s0); D = ndsat(s0); break;
        case MS_WRAP_C: S = si_cat(nsat(s0), SI_CHECKSIG); D = si_cat(ndsat(s0), SI_CHECKSIG); break;
        case MS_WRAP_D: S = si_cat(si_cat(SI_DUP, SI_IF), nsat(s0)); D = si_cat(SI_DUP, SI_IF); break;
        case MS_WRAP_V: S = si_cat(nsat(s0), SI_VERIFY); D = si_none(); break;
        case MS_WRAP_J: S = si_cat(si_cat(si_cat(SI_SIZE, SI_0NOTEQUAL), SI_IF), nsat(s0)); D = si_cat(si_cat(SI_SIZE, SI_0NOTEQUAL), SI_IF); break;
        case MS_THRESH: {
            sat_t* sats = malloc((size_t)(nsubs + 1) * sizeof(sat_t)); sat_t* nx = malloc((size_t)(nsubs + 2) * sizeof(sat_t));
            if (!sats || !nx){ free(sats); free(nx); return -1; }
            int ns = 1; sats[0] = SI_EMPTY;
            for (int i = 0; i < nsubs; i++){
                const ms_node_t* s = NODE(t, subs[i]); sat_t add = i ? SI_BINOP : SI_EMPTY;
                nx[0] = si_cat(si_cat(sats[0], ndsat(s)), add);
                for (int j = 1; j < ns; j++) nx[j] = si_cat(si_or(si_cat(sats[j], ndsat(s)), si_cat(sats[j - 1], nsat(s))), add);
                nx[ns] = si_cat(si_cat(sats[ns - 1], nsat(s)), add);
                ns++; memcpy(sats, nx, (size_t)ns * sizeof(sat_t));
            }
            S = (int)k < ns ? si_cat(si_cat(sats[k], SI_PUSH), SI_EQUAL) : si_none();
            D = si_cat(si_cat(sats[0], SI_PUSH), SI_EQUAL);
            free(sats); free(nx); break; }
        }
        n->ss_sat_valid = S.valid; n->ss_sat_net = S.net; n->ss_sat_exec = S.exec;
        n->ss_dsat_valid = D.valid; n->ss_dsat_net = D.net; n->ss_dsat_exec = D.exec;
    }

    /* ---- witness size ---- */
    {
        int32_t sig = tap ? 1 + 65 : 1 + 72, pub = tap ? 1 + 32 : 1 + 33;
        int32_t S = -1, D = -1;
        switch (frag){
        case MS_JUST_0: S = -1; D = 0; break;
        case MS_JUST_1: case MS_OLDER: case MS_AFTER: S = 0; D = -1; break;
        case MS_PK_K: S = sig; D = 1; break;
        case MS_PK_H: S = sig + pub; D = 1 + pub; break;
        case MS_SHA256: case MS_RIPEMD160: case MS_HASH256: case MS_HASH160: S = 1 + 32; D = -1; break;
        case MS_ANDOR: S = mx_or(mx_add(s0->ws_sat, s1->ws_sat), mx_add(s0->ws_dsat, s2->ws_sat)); D = mx_add(s0->ws_dsat, s2->ws_dsat); break;
        case MS_AND_V: S = mx_add(s0->ws_sat, s1->ws_sat); D = -1; break;
        case MS_AND_B: S = mx_add(s0->ws_sat, s1->ws_sat); D = mx_add(s0->ws_dsat, s1->ws_dsat); break;
        case MS_OR_B: S = mx_or(mx_add(s0->ws_dsat, s1->ws_sat), mx_add(s0->ws_sat, s1->ws_dsat)); D = mx_add(s0->ws_dsat, s1->ws_dsat); break;
        case MS_OR_C: S = mx_or(s0->ws_sat, mx_add(s0->ws_dsat, s1->ws_sat)); D = -1; break;
        case MS_OR_D: S = mx_or(s0->ws_sat, mx_add(s0->ws_dsat, s1->ws_sat)); D = mx_add(s0->ws_dsat, s1->ws_dsat); break;
        case MS_OR_I: S = mx_or(mx_add(s0->ws_sat, 2), mx_add(s1->ws_sat, 1)); D = mx_or(mx_add(s0->ws_dsat, 2), mx_add(s1->ws_dsat, 1)); break;
        case MS_MULTI: S = (int32_t)k * sig + 1; D = (int32_t)k + 1; break;
        case MS_MULTI_A: S = (int32_t)k * sig + nkeys - (int32_t)k; D = nkeys; break;
        case MS_WRAP_A: case MS_WRAP_N: case MS_WRAP_S: case MS_WRAP_C: S = s0->ws_sat; D = s0->ws_dsat; break;
        case MS_WRAP_D: S = mx_add(2, s0->ws_sat); D = 1; break;
        case MS_WRAP_V: S = s0->ws_sat; D = -1; break;
        case MS_WRAP_J: S = s0->ws_sat; D = 1; break;
        case MS_THRESH: {
            int32_t* sats = malloc((size_t)(nsubs + 1) * sizeof(int32_t)); int32_t* nx = malloc((size_t)(nsubs + 2) * sizeof(int32_t));
            if (!sats || !nx){ free(sats); free(nx); return -1; }
            int ns = 1; sats[0] = 0;
            for (int i = 0; i < nsubs; i++){
                const ms_node_t* s = NODE(t, subs[i]);
                nx[0] = mx_add(sats[0], s->ws_dsat);
                for (int j = 1; j < ns; j++) nx[j] = mx_or(mx_add(sats[j], s->ws_dsat), mx_add(sats[j - 1], s->ws_sat));
                nx[ns] = mx_add(sats[ns - 1], s->ws_sat);
                ns++; memcpy(sats, nx, (size_t)ns * sizeof(int32_t));
            }
            S = (int)k < ns ? sats[k] : -1; D = sats[0];
            free(sats); free(nx); break; }
        }
        n->ws_sat = S; n->ws_dsat = D;
    }
    return t->nn++;
}
static int32_t mk1(ms_tree_t* t, int frag, int32_t sub){ return mk_node(t, frag, 0, &sub, 1, NULL, 0, NULL, 0); }
static int32_t mk2(ms_tree_t* t, int frag, int32_t a, int32_t b){ int32_t s[2] = { a, b }; return mk_node(t, frag, 0, s, 2, NULL, 0, NULL, 0); }
static int32_t mk3(ms_tree_t* t, int frag, int32_t a, int32_t b, int32_t c){ int32_t s[3] = { a, b, c }; return mk_node(t, frag, 0, s, 3, NULL, 0, NULL, 0); }
static int32_t mk0(ms_tree_t* t, int frag, uint32_t k){ return mk_node(t, frag, k, NULL, 0, NULL, 0, NULL, 0); }

/* ---- generic growable int stack --------------------------------------------- */
typedef struct { int32_t* v; int n, cap; } ivec_t;
static int iv_push(ivec_t* s, int32_t x){ if (s->n == s->cap){ int nc = s->cap ? s->cap * 2 : 64; int32_t* q = realloc(s->v, (size_t)nc * sizeof(int32_t)); if (!q) return 0; s->v = q; s->cap = nc; } s->v[s->n++] = x; return 1; }
static void iv_free(ivec_t* s){ free(s->v); s->v = NULL; s->n = s->cap = 0; }

/* the nodes of the tree rooted at root, marked in a byte map (1 per pool index) */
static u8* subtree_mark(const ms_tree_t* t, int root){
    u8* m = calloc((size_t)t->nn + 1, 1); if (!m) return NULL;
    ivec_t st = { 0 }; if (!iv_push(&st, root)){ free(m); return NULL; }
    while (st.n){
        int32_t i = st.v[--st.n]; if (m[i]) continue; m[i] = 1;
        const ms_node_t* n = NODE(t, i);
        for (int c = 0; c < n->nsubs; c++) if (!iv_push(&st, SUB(t, n, c))){ iv_free(&st); free(m); return NULL; }
    }
    iv_free(&st); return m;
}

/* ---- parsing (Core's Parse) --------------------------------------------------- */
enum { PC_WRAPPED_EXPR, PC_EXPR, PC_SWAP, PC_ALT, PC_CHECK, PC_DUP_IF, PC_VERIFY, PC_NON_ZERO, PC_ZERO_NOTEQUAL, PC_WRAP_U, PC_WRAP_T,
       PC_AND_N, PC_AND_V, PC_AND_B, PC_ANDOR, PC_OR_B, PC_OR_C, PC_OR_D, PC_OR_I, PC_THRESH, PC_COMMA, PC_CLOSE_BRACKET };
typedef struct { int ctx; int64_t n, k; } pframe_t;
typedef struct { pframe_t* v; int n, cap; } pvec_t;
static int pv_push(pvec_t* s, int ctx, int64_t n, int64_t k){ if (s->n == s->cap){ int nc = s->cap ? s->cap * 2 : 64; pframe_t* q = realloc(s->v, (size_t)nc * sizeof(pframe_t)); if (!q) return 0; s->v = q; s->cap = nc; } s->v[s->n].ctx = ctx; s->v[s->n].n = n; s->v[s->n].k = k; s->n++; return 1; }

typedef struct { const char* p; size_t n; } span_t;
static int find_next_char(span_t sp, char m){ for (size_t i = 0; i < sp.n; i++){ if (sp.p[i] == m) return (int)i; if (sp.p[i] == ')') break; } return -1; }
/* script::Expr: the expression up to a level-0 ',' ')' or '}' */
static span_t expr_of(span_t* sp){
    int level = 0; size_t i = 0;
    while (i < sp->n){
        char c = sp->p[i];
        if (c == '(' || c == '{') level++;
        else if (level && (c == ')' || c == '}')) level--;
        else if (level == 0 && (c == ')' || c == '}' || c == ',')) break;
        i++;
    }
    span_t r = { sp->p, i }; sp->p += i; sp->n -= i; return r;
}
/* script::Func: "name(" ... ")" -> the inside */
static int func_of(const char* name, span_t* sp){
    size_t l = strlen(name);
    if (sp->n >= l + 2 && sp->p[l] == '(' && sp->p[sp->n - 1] == ')' && !memcmp(sp->p, name, l)){ sp->p += l + 1; sp->n -= l + 2; return 1; }
    return 0;
}
static int starts(span_t sp, const char* s){ size_t l = strlen(s); return sp.n >= l && !memcmp(sp.p, s, l); }
static int const_skip(span_t* sp, const char* s){ if (!starts(*sp, s)){ return 0; } size_t l = strlen(s); sp->p += l; sp->n -= l; return 1; }
/* ToIntegral<int64_t>: decimal digits only, no sign, no overflow */
static int to_int(const char* p, size_t n, int64_t* out){
    if (n == 0) return 0;
    int64_t v = 0;
    for (size_t i = 0; i < n; i++){ if (p[i] < '0' || p[i] > '9') return 0; if (v > (INT64_MAX - (p[i] - '0')) / 10) return 0; v = v * 10 + (p[i] - '0'); }
    *out = v; return 1;
}
static int hexval(int c){ if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }

static int parse_key_expr(const ms_ctx_t* ctx, const char* func, span_t* in, int32_t* key, char* err, size_t errcap){
    span_t e = expr_of(in);
    if (!func_of(func, &e)) return 0;
    int k = 0; if (!ctx->key_from_str(ctx->user, e.p, e.n, &k, err, errcap)) return 0;
    *key = k; return 1;
}
static int parse_hex_expr(const char* func, span_t* in, size_t want, u8* out){
    span_t e = expr_of(in);
    if (!func_of(func, &e)) return 0;
    if (e.n != want * 2) return 0;
    for (size_t i = 0; i < want; i++){ int h = hexval(e.p[2 * i]), l = hexval(e.p[2 * i + 1]); if (h < 0 || l < 0) return 0; out[i] = (u8)((h << 4) | l); }
    return 1;
}

int ms_parse(ms_tree_t* t, const ms_ctx_t* ctx, const char* s, size_t n, char* err, size_t errcap){
    if (errcap) err[0] = 0;
    int32_t nn0 = t->nn, ns0 = t->ns, nk0 = t->nk;
    size_t max_size = ms_max_script_size(t->tapscript);
    pvec_t tp = { 0 }; ivec_t con = { 0 };
    span_t in = { s, n };
    int ok = 0;
    int32_t keybuf_cap = 0; int32_t* keybuf = NULL;
    if (!pv_push(&tp, PC_WRAPPED_EXPR, -1, -1)) goto done;
#define FAIL goto done
#define PUSHC(x) do{ if (!iv_push(&con, (x))) FAIL; }while(0)
#define MK_OR_FAIL(v, expr) do{ (v) = (expr); if ((v) < 0) FAIL; if (NODE(t, (v))->scriptlen > max_size) FAIL; }while(0)
    while (tp.n){
        pframe_t f = tp.v[--tp.n];
        switch (f.ctx){
        case PC_WRAPPED_EXPR: {
            size_t colon = 0; int has_colon = 0;
            for (size_t i = 1; i < in.n; i++){ if (in.p[i] == ':'){ colon = i; has_colon = 1; break; } if (in.p[i] < 'a' || in.p[i] > 'z') break; }
            int last_was_v = 0;
            for (size_t j = 0; has_colon && j < colon; j++){
                char c = in.p[j];
                if (c == 'a'){ if (!pv_push(&tp, PC_ALT, -1, -1)) FAIL; }
                else if (c == 's'){ if (!pv_push(&tp, PC_SWAP, -1, -1)) FAIL; }
                else if (c == 'c'){ if (!pv_push(&tp, PC_CHECK, -1, -1)) FAIL; }
                else if (c == 'd'){ if (!pv_push(&tp, PC_DUP_IF, -1, -1)) FAIL; }
                else if (c == 'j'){ if (!pv_push(&tp, PC_NON_ZERO, -1, -1)) FAIL; }
                else if (c == 'n'){ if (!pv_push(&tp, PC_ZERO_NOTEQUAL, -1, -1)) FAIL; }
                else if (c == 'v'){ if (last_was_v) FAIL; if (!pv_push(&tp, PC_VERIFY, -1, -1)) FAIL; }
                else if (c == 'u'){ if (!pv_push(&tp, PC_WRAP_U, -1, -1)) FAIL; }
                else if (c == 't'){ if (!pv_push(&tp, PC_WRAP_T, -1, -1)) FAIL; }
                else if (c == 'l'){ int32_t z; MK_OR_FAIL(z, mk0(t, MS_JUST_0, 0)); PUSHC(z); if (!pv_push(&tp, PC_OR_I, -1, -1)) FAIL; }
                else FAIL;
                last_was_v = (c == 'v');
            }
            if (!pv_push(&tp, PC_EXPR, -1, -1)) FAIL;
            if (has_colon){ in.p += colon + 1; in.n -= colon + 1; }
            break; }
        case PC_EXPR: {
            int32_t nd;
            if (const_skip(&in, "0")){ MK_OR_FAIL(nd, mk0(t, MS_JUST_0, 0)); PUSHC(nd); }
            else if (const_skip(&in, "1")){ MK_OR_FAIL(nd, mk0(t, MS_JUST_1, 0)); PUSHC(nd); }
            else if (starts(in, "pk(")){ int32_t key; if (!parse_key_expr(ctx, "pk", &in, &key, err, errcap)) FAIL;
                int32_t pk; MK_OR_FAIL(pk, mk_node(t, MS_PK_K, 0, NULL, 0, &key, 1, NULL, 0)); MK_OR_FAIL(nd, mk1(t, MS_WRAP_C, pk)); PUSHC(nd); }
            else if (starts(in, "pkh(")){ int32_t key; if (!parse_key_expr(ctx, "pkh", &in, &key, err, errcap)) FAIL;
                int32_t pk; MK_OR_FAIL(pk, mk_node(t, MS_PK_H, 0, NULL, 0, &key, 1, NULL, 0)); MK_OR_FAIL(nd, mk1(t, MS_WRAP_C, pk)); PUSHC(nd); }
            else if (starts(in, "pk_k(")){ int32_t key; if (!parse_key_expr(ctx, "pk_k", &in, &key, err, errcap)) FAIL;
                MK_OR_FAIL(nd, mk_node(t, MS_PK_K, 0, NULL, 0, &key, 1, NULL, 0)); PUSHC(nd); }
            else if (starts(in, "pk_h(")){ int32_t key; if (!parse_key_expr(ctx, "pk_h", &in, &key, err, errcap)) FAIL;
                MK_OR_FAIL(nd, mk_node(t, MS_PK_H, 0, NULL, 0, &key, 1, NULL, 0)); PUSHC(nd); }
            else if (starts(in, "sha256(")){ u8 h[32]; if (!parse_hex_expr("sha256", &in, 32, h)) FAIL; MK_OR_FAIL(nd, mk_node(t, MS_SHA256, 0, NULL, 0, NULL, 0, h, 32)); PUSHC(nd); }
            else if (starts(in, "ripemd160(")){ u8 h[20]; if (!parse_hex_expr("ripemd160", &in, 20, h)) FAIL; MK_OR_FAIL(nd, mk_node(t, MS_RIPEMD160, 0, NULL, 0, NULL, 0, h, 20)); PUSHC(nd); }
            else if (starts(in, "hash256(")){ u8 h[32]; if (!parse_hex_expr("hash256", &in, 32, h)) FAIL; MK_OR_FAIL(nd, mk_node(t, MS_HASH256, 0, NULL, 0, NULL, 0, h, 32)); PUSHC(nd); }
            else if (starts(in, "hash160(")){ u8 h[20]; if (!parse_hex_expr("hash160", &in, 20, h)) FAIL; MK_OR_FAIL(nd, mk_node(t, MS_HASH160, 0, NULL, 0, NULL, 0, h, 20)); PUSHC(nd); }
            else if (starts(in, "after(") || starts(in, "older(")){
                int older = in.p[0] == 'o';
                span_t e = expr_of(&in); if (!func_of(older ? "older" : "after", &e)) FAIL;
                int64_t num; if (!to_int(e.p, e.n, &num) || num < 1 || num >= 0x80000000L) FAIL;
                MK_OR_FAIL(nd, mk0(t, older ? MS_OLDER : MS_AFTER, (uint32_t)num)); PUSHC(nd); }
            else if (starts(in, "multi(") || starts(in, "multi_a(")){
                int is_a = in.p[5] == '_';
                const_skip(&in, is_a ? "multi_a(" : "multi(");
                if ((is_a && !t->tapscript) || (!is_a && t->tapscript)) FAIL;
                int nc = find_next_char(in, ','); if (nc < 1) FAIL;
                int64_t k; if (!to_int(in.p, (size_t)nc, &k)) FAIL;
                in.p += nc + 1; in.n -= (size_t)nc + 1;
                int nkeys = 0; int max_keys = is_a ? MAX_PUBKEYS_PER_MULTI_A : MAX_PUBKEYS_PER_MULTISIG;
                while (nc != -1){
                    nc = find_next_char(in, ',');
                    int kl = (nc == -1) ? find_next_char(in, ')') : nc;
                    if (kl < 1) FAIL;
                    if (nkeys >= keybuf_cap){ int32_t c2 = keybuf_cap ? keybuf_cap * 2 : 32; int32_t* q = realloc(keybuf, (size_t)c2 * sizeof(int32_t)); if (!q) FAIL; keybuf = q; keybuf_cap = c2; }
                    int key; if (!ctx->key_from_str(ctx->user, in.p, (size_t)kl, &key, err, errcap)) FAIL;
                    keybuf[nkeys++] = key;
                    in.p += kl + 1; in.n -= (size_t)kl + 1;
                    if (nkeys > max_keys) FAIL;
                }
                if (nkeys < 1 || nkeys > max_keys) FAIL;
                if (k < 1 || k > nkeys) FAIL;
                MK_OR_FAIL(nd, mk_node(t, is_a ? MS_MULTI_A : MS_MULTI, (uint32_t)k, NULL, 0, keybuf, nkeys, NULL, 0)); PUSHC(nd); }
            else if (const_skip(&in, "thresh(")){
                int nc = find_next_char(in, ','); if (nc < 1) FAIL;
                int64_t k; if (!to_int(in.p, (size_t)nc, &k) || k < 1) FAIL;
                in.p += nc + 1; in.n -= (size_t)nc + 1;
                if (!pv_push(&tp, PC_THRESH, 1, k)) FAIL;
                if (!pv_push(&tp, PC_WRAPPED_EXPR, -1, -1)) FAIL; }
            else if (const_skip(&in, "andor(")){
                if (!pv_push(&tp, PC_ANDOR, -1, -1) || !pv_push(&tp, PC_CLOSE_BRACKET, -1, -1) || !pv_push(&tp, PC_WRAPPED_EXPR, -1, -1) ||
                    !pv_push(&tp, PC_COMMA, -1, -1) || !pv_push(&tp, PC_WRAPPED_EXPR, -1, -1) || !pv_push(&tp, PC_COMMA, -1, -1) || !pv_push(&tp, PC_WRAPPED_EXPR, -1, -1)) FAIL; }
            else {
                int c;
                if (const_skip(&in, "and_n(")) c = PC_AND_N;
                else if (const_skip(&in, "and_b(")) c = PC_AND_B;
                else if (const_skip(&in, "and_v(")) c = PC_AND_V;
                else if (const_skip(&in, "or_b(")) c = PC_OR_B;
                else if (const_skip(&in, "or_c(")) c = PC_OR_C;
                else if (const_skip(&in, "or_d(")) c = PC_OR_D;
                else if (const_skip(&in, "or_i(")) c = PC_OR_I;
                else FAIL;
                if (!pv_push(&tp, c, -1, -1) || !pv_push(&tp, PC_CLOSE_BRACKET, -1, -1) || !pv_push(&tp, PC_WRAPPED_EXPR, -1, -1) ||
                    !pv_push(&tp, PC_COMMA, -1, -1) || !pv_push(&tp, PC_WRAPPED_EXPR, -1, -1)) FAIL;
            }
            break; }
        case PC_ALT: case PC_SWAP: case PC_CHECK: case PC_DUP_IF: case PC_NON_ZERO: case PC_ZERO_NOTEQUAL: case PC_VERIFY: {
            if (con.n < 1) FAIL;
            int frag = f.ctx == PC_ALT ? MS_WRAP_A : f.ctx == PC_SWAP ? MS_WRAP_S : f.ctx == PC_CHECK ? MS_WRAP_C : f.ctx == PC_DUP_IF ? MS_WRAP_D :
                       f.ctx == PC_NON_ZERO ? MS_WRAP_J : f.ctx == PC_ZERO_NOTEQUAL ? MS_WRAP_N : MS_WRAP_V;
            int32_t nd; MK_OR_FAIL(nd, mk1(t, frag, con.v[con.n - 1])); con.v[con.n - 1] = nd; break; }
        case PC_WRAP_U: { if (con.n < 1) FAIL; int32_t z; MK_OR_FAIL(z, mk0(t, MS_JUST_0, 0)); int32_t nd; MK_OR_FAIL(nd, mk2(t, MS_OR_I, con.v[con.n - 1], z)); con.v[con.n - 1] = nd; break; }
        case PC_WRAP_T: { if (con.n < 1) FAIL; int32_t o; MK_OR_FAIL(o, mk0(t, MS_JUST_1, 0)); int32_t nd; MK_OR_FAIL(nd, mk2(t, MS_AND_V, con.v[con.n - 1], o)); con.v[con.n - 1] = nd; break; }
        case PC_AND_B: case PC_AND_V: case PC_OR_B: case PC_OR_C: case PC_OR_D: case PC_OR_I: {
            if (con.n < 2) FAIL;
            int frag = f.ctx == PC_AND_B ? MS_AND_B : f.ctx == PC_AND_V ? MS_AND_V : f.ctx == PC_OR_B ? MS_OR_B : f.ctx == PC_OR_C ? MS_OR_C : f.ctx == PC_OR_D ? MS_OR_D : MS_OR_I;
            int32_t b = con.v[--con.n]; int32_t nd; MK_OR_FAIL(nd, mk2(t, frag, con.v[con.n - 1], b)); con.v[con.n - 1] = nd; break; }
        case PC_AND_N: { if (con.n < 2) FAIL; int32_t mid = con.v[--con.n]; int32_t z; MK_OR_FAIL(z, mk0(t, MS_JUST_0, 0));
            int32_t nd; MK_OR_FAIL(nd, mk3(t, MS_ANDOR, con.v[con.n - 1], mid, z)); con.v[con.n - 1] = nd; break; }
        case PC_ANDOR: { if (con.n < 3) FAIL; int32_t r = con.v[--con.n]; int32_t mid = con.v[--con.n];
            int32_t nd; MK_OR_FAIL(nd, mk3(t, MS_ANDOR, con.v[con.n - 1], mid, r)); con.v[con.n - 1] = nd; break; }
        case PC_THRESH: {
            if (in.n < 1) FAIL;
            if (in.p[0] == ','){ in.p++; in.n--; if (!pv_push(&tp, PC_THRESH, f.n + 1, f.k) || !pv_push(&tp, PC_WRAPPED_EXPR, -1, -1)) FAIL; }
            else if (in.p[0] == ')'){
                if (f.k > f.n) FAIL;
                in.p++; in.n--;
                if (con.n < f.n) FAIL;
                int32_t nd; MK_OR_FAIL(nd, mk_node(t, MS_THRESH, (uint32_t)f.k, con.v + con.n - f.n, (int)f.n, NULL, 0, NULL, 0));
                con.n -= (int)f.n; PUSHC(nd);
            } else FAIL;
            break; }
        case PC_COMMA: if (in.n < 1 || in.p[0] != ',') FAIL; in.p++; in.n--; break;
        case PC_CLOSE_BRACKET: if (in.n < 1 || in.p[0] != ')') FAIL; in.p++; in.n--; break;
        }
    }
    if (con.n != 1) FAIL;
    if (in.n > 0) FAIL;
    ok = 1;
#undef FAIL
#undef PUSHC
#undef MK_OR_FAIL
done:
    free(tp.v); free(keybuf);
    if (!ok){ iv_free(&con); t->nn = nn0; t->ns = ns0; t->nk = nk0; return -1; }
    int32_t root = con.v[0]; iv_free(&con);
    ms_duplicate_key_check(t, ctx, root);
    return root;
}

/* ---- duplicate keys ------------------------------------------------------------ */
typedef struct { int32_t* v; int n; int dup; } kset_t;
void ms_duplicate_key_check(ms_tree_t* t, const ms_ctx_t* ctx, int root){
    u8* mark = subtree_mark(t, root); if (!mark) return;
    kset_t* sets = calloc((size_t)root + 1, sizeof(kset_t)); if (!sets){ free(mark); return; }
    for (int32_t i = 0; i <= root; i++){
        if (!mark[i]) continue;
        ms_node_t* n = NODE(t, i);
        kset_t r = { NULL, 0, 0 };
        /* children known to have duplicates */
        for (int c = 0; c < n->nsubs && !r.dup; c++) if (sets[SUB(t, n, c)].dup) r.dup = 1;
        if (!r.dup){
            int total = n->nkeys; for (int c = 0; c < n->nsubs; c++) total += sets[SUB(t, n, c)].n;
            r.v = malloc((size_t)(total ? total : 1) * sizeof(int32_t));
            if (!r.v){ r.dup = 1; }
            else {
                /* insertion-merge: every element is compared against the set (sets are small: the keys of one script) */
                for (int q = 0; q < n->nkeys && !r.dup; q++){
                    int32_t key = t->keys[n->keys_off + q];
                    for (int w = 0; w < r.n; w++) if (ctx->key_cmp(ctx->user, r.v[w], key) == 0){ r.dup = 1; break; }
                    if (!r.dup) r.v[r.n++] = key;
                }
                for (int c = 0; c < n->nsubs && !r.dup; c++){
                    kset_t* s = &sets[SUB(t, n, c)];
                    for (int q = 0; q < s->n && !r.dup; q++){
                        for (int w = 0; w < r.n; w++) if (ctx->key_cmp(ctx->user, r.v[w], s->v[q]) == 0){ r.dup = 1; break; }
                        if (!r.dup) r.v[r.n++] = s->v[q];
                    }
                }
            }
        }
        for (int c = 0; c < n->nsubs; c++){ kset_t* s = &sets[SUB(t, n, c)]; free(s->v); s->v = NULL; s->n = 0; }
        if (r.dup){ free(r.v); r.v = NULL; r.n = 0; }
        n->dup = r.dup ? 2 : 1;
        sets[i] = r;
    }
    for (int32_t i = 0; i <= root; i++) free(sets[i].v);
    free(sets); free(mark);
}

/* ---- script decoding (Core's DecomposeScript + DecodeScript) --------------------- */
typedef struct { u8 op; uint32_t off, len; u8 opn; } opc_t;   /* opn: data byte for OP_n pushes */
static int minimal_push(const u8* d, uint32_t n, int op){
    if (n == 0) return op == OP_0;
    if (n == 1 && d[0] >= 1 && d[0] <= 16) return op == OP_1 + (d[0] - 1);
    if (n == 1 && d[0] == 0x81) return op == OP_1NEGATE;
    if (n <= 75) return op == (int)n;
    if (n <= 255) return op == OP_PUSHDATA1;
    if (n <= 65535) return op == OP_PUSHDATA2;
    return 1;
}
/* opcodes in REVERSE order; -1 on malformed / non-minimal */
static int decompose(const u8* s, size_t n, opc_t** out, int* count){
    opc_t* v = NULL; int nv = 0, cap = 0;
    size_t i = 0;
    while (i < n){
        u8 op = s[i++]; uint32_t off = 0, len = 0; u8 opn = 0;
        if (op <= OP_PUSHDATA4){
            uint32_t l = 0;
            if (op < OP_PUSHDATA1) l = op;
            else if (op == OP_PUSHDATA1){ if (i + 1 > n) goto bad; l = s[i]; i += 1; }
            else if (op == OP_PUSHDATA2){ if (i + 2 > n) goto bad; l = (uint32_t)s[i] | ((uint32_t)s[i + 1] << 8); i += 2; }
            else { if (i + 4 > n) goto bad; l = (uint32_t)s[i] | ((uint32_t)s[i + 1] << 8) | ((uint32_t)s[i + 2] << 16) | ((uint32_t)s[i + 3] << 24); i += 4; }
            if (i + l > n) goto bad;
            off = (uint32_t)i; len = l; i += l;
            if (op > OP_0 && !minimal_push(s + off, len, op)) goto bad;
        }
        int add_verify = 0;
        if (op >= OP_1 && op <= OP_16){ opn = (u8)(op - OP_1 + 1); len = 1; }
        else if (op == OP_CHECKSIGVERIFY){ op = OP_CHECKSIG; add_verify = 1; }
        else if (op == OP_CHECKMULTISIGVERIFY){ op = OP_CHECKMULTISIG; add_verify = 1; }
        else if (op == OP_EQUALVERIFY){ op = OP_EQUAL; add_verify = 1; }
        else if (op == OP_NUMEQUALVERIFY){ op = OP_NUMEQUAL; add_verify = 1; }
        else if (i < n && (op == OP_CHECKSIG || op == OP_CHECKMULTISIG || op == OP_EQUAL || op == OP_NUMEQUAL) && s[i] == OP_VERIFY) goto bad;
        if (nv + 2 > cap){ int nc = cap ? cap * 2 : 64; opc_t* q = realloc(v, (size_t)nc * sizeof(opc_t)); if (!q) goto bad; v = q; cap = nc; }
        v[nv].op = op; v[nv].off = off; v[nv].len = len; v[nv].opn = opn; nv++;
        if (add_verify){ v[nv].op = OP_VERIFY; v[nv].off = 0; v[nv].len = 0; v[nv].opn = 0; nv++; }
    }
    for (int a = 0, b = nv - 1; a < b; a++, b--){ opc_t tmp = v[a]; v[a] = v[b]; v[b] = tmp; }
    *out = v; *count = nv; return 1;
bad:
    free(v); return -1;
}
/* the data an opcode pushes: OP_n yields its number as one byte */
static const u8* op_data(const opc_t* o, const u8* script, u8* tmp1){ if (o->opn){ tmp1[0] = o->opn; return tmp1; } return script + o->off; }
static int is_pushdata_op(int op){ return op > OP_0 && op <= OP_PUSHDATA4; }
static int parse_script_number(const opc_t* o, const u8* script, int64_t* out){
    if (o->op == OP_0){ *out = 0; return 1; }
    if (o->len == 0) return 0;
    u8 tmp; const u8* d = op_data(o, script, &tmp); uint32_t n = o->len;
    if (is_pushdata_op(o->op) && !minimal_push(d, n, o->op)) return 0;
    if (n > 4) return 0;
    if ((d[n - 1] & 0x7f) == 0){ if (n <= 1 || (d[n - 2] & 0x80) == 0) return 0; }
    int64_t v = 0; for (uint32_t i = 0; i < n; i++) v |= (int64_t)d[i] << (8 * i);
    if (d[n - 1] & 0x80){ v &= ~((int64_t)0x80 << (8 * (n - 1))); v = -v; }
    *out = v; return 1;
}

enum { DC_SINGLE_BKV_EXPR, DC_BKV_EXPR, DC_W_EXPR, DC_SWAP, DC_ALT, DC_CHECK, DC_DUP_IF, DC_VERIFY, DC_NON_ZERO, DC_ZERO_NOTEQUAL,
       DC_MAYBE_AND_V, DC_AND_V, DC_AND_B, DC_ANDOR, DC_OR_B, DC_OR_C, DC_OR_D, DC_THRESH_W, DC_THRESH_E, DC_ENDIF, DC_ENDIF_NOTIF, DC_ENDIF_ELSE };

int ms_decode(ms_tree_t* t, const ms_ctx_t* ctx, const u8* script, size_t n){
    if (n > ms_max_script_size(t->tapscript)) return -1;
    opc_t* ops = NULL; int last = 0;
    if (decompose(script, n, &ops, &last) < 0) return -1;
    int32_t nn0 = t->nn, ns0 = t->ns, nk0 = t->nk;
    pvec_t tp = { 0 }; ivec_t con = { 0 }; int ok = 0; int in = 0;
    int32_t* keybuf = NULL; int32_t keybuf_cap = 0;
    u8 tmp1;
#define FAIL goto done
#define PUSHC(x) do{ if (!iv_push(&con, (x))) FAIL; }while(0)
#define MK_OR_FAIL(v, expr) do{ (v) = (expr); if ((v) < 0) FAIL; }while(0)
#define OPAT(i) (&ops[i])
    if (!pv_push(&tp, DC_BKV_EXPR, -1, -1)) FAIL;
    while (tp.n){
        if (con.n && !ms_is_valid(t, con.v[con.n - 1])) FAIL;
        pframe_t f = tp.v[--tp.n];
        switch (f.ctx){
        case DC_SINGLE_BKV_EXPR: {
            if (in >= last) FAIL;
            int32_t nd; int64_t num;
            if (OPAT(in)->op == OP_1 && OPAT(in)->opn == 1){ in++; MK_OR_FAIL(nd, mk0(t, MS_JUST_1, 0)); PUSHC(nd); break; }
            if (OPAT(in)->op == OP_0){ in++; MK_OR_FAIL(nd, mk0(t, MS_JUST_0, 0)); PUSHC(nd); break; }
            if (OPAT(in)->len == 33 || OPAT(in)->len == 32){
                int key; if (!ctx->key_from_bytes(ctx->user, op_data(OPAT(in), script, &tmp1), OPAT(in)->len, &key)) FAIL;
                in++; int32_t k32 = key; MK_OR_FAIL(nd, mk_node(t, MS_PK_K, 0, NULL, 0, &k32, 1, NULL, 0)); PUSHC(nd); break; }
            if (last - in >= 5 && OPAT(in)->op == OP_VERIFY && OPAT(in + 1)->op == OP_EQUAL && OPAT(in + 3)->op == OP_HASH160 && OPAT(in + 4)->op == OP_DUP && OPAT(in + 2)->len == 20){
                int key; if (!ctx->key_from_hash(ctx->user, script + OPAT(in + 2)->off, &key)) FAIL;
                in += 5; int32_t k32 = key; MK_OR_FAIL(nd, mk_node(t, MS_PK_H, 0, NULL, 0, &k32, 1, NULL, 0)); PUSHC(nd); break; }
            if (last - in >= 2 && OPAT(in)->op == OP_CHECKSEQUENCEVERIFY && parse_script_number(OPAT(in + 1), script, &num)){
                in += 2; if (num < 1 || num > 0x7FFFFFFFL) FAIL; MK_OR_FAIL(nd, mk0(t, MS_OLDER, (uint32_t)num)); PUSHC(nd); break; }
            if (last - in >= 2 && OPAT(in)->op == OP_CHECKLOCKTIMEVERIFY && parse_script_number(OPAT(in + 1), script, &num)){
                in += 2; if (num < 1 || num > 0x7FFFFFFFL) FAIL; MK_OR_FAIL(nd, mk0(t, MS_AFTER, (uint32_t)num)); PUSHC(nd); break; }
            if (last - in >= 7 && OPAT(in)->op == OP_EQUAL && OPAT(in + 3)->op == OP_VERIFY && OPAT(in + 4)->op == OP_EQUAL && parse_script_number(OPAT(in + 5), script, &num) && num == 32 && OPAT(in + 6)->op == OP_SIZE){
                int frag = -1; uint32_t dl = OPAT(in + 1)->len; u8 hop = OPAT(in + 2)->op;
                if (hop == OP_SHA256 && dl == 32) frag = MS_SHA256; else if (hop == OP_RIPEMD160 && dl == 20) frag = MS_RIPEMD160;
                else if (hop == OP_HASH256 && dl == 32) frag = MS_HASH256; else if (hop == OP_HASH160 && dl == 20) frag = MS_HASH160;
                if (frag >= 0){ MK_OR_FAIL(nd, mk_node(t, frag, 0, NULL, 0, NULL, 0, script + OPAT(in + 1)->off, (int)dl)); in += 7; PUSHC(nd); break; }
            }
            if (last - in >= 3 && OPAT(in)->op == OP_CHECKMULTISIG){
                if (t->tapscript) FAIL;
                int64_t nk; if (!parse_script_number(OPAT(in + 1), script, &nk) || last - in < 3 + nk) FAIL;
                if (nk < 1 || nk > 20) FAIL;
                int32_t keys[20];
                for (int i = 0; i < nk; i++){ if (OPAT(in + 2 + i)->len != 33) FAIL; int key; if (!ctx->key_from_bytes(ctx->user, script + OPAT(in + 2 + i)->off, 33, &key)) FAIL; keys[i] = key; }
                int64_t k; if (!parse_script_number(OPAT(in + 2 + nk), script, &k) || k < 1 || k > nk) FAIL;
                in += 3 + (int)nk;
                for (int a = 0, b = (int)nk - 1; a < b; a++, b--){ int32_t x = keys[a]; keys[a] = keys[b]; keys[b] = x; }
                MK_OR_FAIL(nd, mk_node(t, MS_MULTI, (uint32_t)k, NULL, 0, keys, (int)nk, NULL, 0)); PUSHC(nd); break; }
            if (last - in >= 4 && OPAT(in)->op == OP_NUMEQUAL){
                if (!t->tapscript) FAIL;
                int64_t k; if (!parse_script_number(OPAT(in + 1), script, &k)) FAIL;
                if (k < 1 || k > MAX_PUBKEYS_PER_MULTI_A) FAIL;
                if (last - in < 2 + k * 2) FAIL;
                int nkeys = 0;
                for (int pos = 2;; pos += 2){
                    if (last - in < pos + 2) FAIL;
                    if (OPAT(in + pos)->op != OP_CHECKSIGADD && OPAT(in + pos)->op != OP_CHECKSIG) FAIL;
                    if (OPAT(in + pos + 1)->len != 32) FAIL;
                    int key; if (!ctx->key_from_bytes(ctx->user, script + OPAT(in + pos + 1)->off, 32, &key)) FAIL;
                    if (nkeys >= keybuf_cap){ int32_t c2 = keybuf_cap ? keybuf_cap * 2 : 32; int32_t* q = realloc(keybuf, (size_t)c2 * sizeof(int32_t)); if (!q) FAIL; keybuf = q; keybuf_cap = c2; }
                    keybuf[nkeys++] = key;
                    if (nkeys > MAX_PUBKEYS_PER_MULTI_A) FAIL;
                    if (OPAT(in + pos)->op == OP_CHECKSIG) break;
                }
                if (nkeys < k) FAIL;
                in += 2 + nkeys * 2;
                for (int a = 0, b = nkeys - 1; a < b; a++, b--){ int32_t x = keybuf[a]; keybuf[a] = keybuf[b]; keybuf[b] = x; }
                MK_OR_FAIL(nd, mk_node(t, MS_MULTI_A, (uint32_t)k, NULL, 0, keybuf, nkeys, NULL, 0)); PUSHC(nd); break; }
            if (OPAT(in)->op == OP_CHECKSIG){ in++; if (!pv_push(&tp, DC_CHECK, -1, -1) || !pv_push(&tp, DC_SINGLE_BKV_EXPR, -1, -1)) FAIL; break; }
            if (OPAT(in)->op == OP_VERIFY){ in++; if (!pv_push(&tp, DC_VERIFY, -1, -1) || !pv_push(&tp, DC_SINGLE_BKV_EXPR, -1, -1)) FAIL; break; }
            if (OPAT(in)->op == OP_0NOTEQUAL){ in++; if (!pv_push(&tp, DC_ZERO_NOTEQUAL, -1, -1) || !pv_push(&tp, DC_SINGLE_BKV_EXPR, -1, -1)) FAIL; break; }
            if (last - in >= 3 && OPAT(in)->op == OP_EQUAL && parse_script_number(OPAT(in + 1), script, &num)){
                if (num < 1) FAIL;
                in += 2; if (!pv_push(&tp, DC_THRESH_W, 0, num)) FAIL;
                break; }
            if (OPAT(in)->op == OP_ENDIF){ in++; if (!pv_push(&tp, DC_ENDIF, -1, -1) || !pv_push(&tp, DC_BKV_EXPR, -1, -1)) FAIL; break; }
            if (OPAT(in)->op == OP_BOOLAND){ in++; if (!pv_push(&tp, DC_AND_B, -1, -1) || !pv_push(&tp, DC_SINGLE_BKV_EXPR, -1, -1) || !pv_push(&tp, DC_W_EXPR, -1, -1)) FAIL; break; }
            if (OPAT(in)->op == OP_BOOLOR){ in++; if (!pv_push(&tp, DC_OR_B, -1, -1) || !pv_push(&tp, DC_SINGLE_BKV_EXPR, -1, -1) || !pv_push(&tp, DC_W_EXPR, -1, -1)) FAIL; break; }
            FAIL; }
        case DC_BKV_EXPR: if (!pv_push(&tp, DC_MAYBE_AND_V, -1, -1) || !pv_push(&tp, DC_SINGLE_BKV_EXPR, -1, -1)) FAIL; break;
        case DC_W_EXPR: {
            if (in >= last) FAIL;
            if (OPAT(in)->op == OP_FROMALTSTACK){ in++; if (!pv_push(&tp, DC_ALT, -1, -1)) FAIL; }
            else { if (!pv_push(&tp, DC_SWAP, -1, -1)) FAIL; }
            if (!pv_push(&tp, DC_BKV_EXPR, -1, -1)) FAIL;
            break; }
        case DC_MAYBE_AND_V: {
            if (in < last && OPAT(in)->op != OP_IF && OPAT(in)->op != OP_ELSE && OPAT(in)->op != OP_NOTIF && OPAT(in)->op != OP_TOALTSTACK && OPAT(in)->op != OP_SWAP){
                if (!pv_push(&tp, DC_AND_V, -1, -1) || !pv_push(&tp, DC_BKV_EXPR, -1, -1)) FAIL; }
            break; }
        case DC_SWAP: { if (in >= last || OPAT(in)->op != OP_SWAP || con.n < 1) FAIL; in++; int32_t nd; MK_OR_FAIL(nd, mk1(t, MS_WRAP_S, con.v[con.n - 1])); con.v[con.n - 1] = nd; break; }
        case DC_ALT: { if (in >= last || OPAT(in)->op != OP_TOALTSTACK || con.n < 1) FAIL; in++; int32_t nd; MK_OR_FAIL(nd, mk1(t, MS_WRAP_A, con.v[con.n - 1])); con.v[con.n - 1] = nd; break; }
        case DC_CHECK: case DC_DUP_IF: case DC_VERIFY: case DC_NON_ZERO: case DC_ZERO_NOTEQUAL: {
            if (con.n < 1) FAIL;
            int frag = f.ctx == DC_CHECK ? MS_WRAP_C : f.ctx == DC_DUP_IF ? MS_WRAP_D : f.ctx == DC_VERIFY ? MS_WRAP_V : f.ctx == DC_NON_ZERO ? MS_WRAP_J : MS_WRAP_N;
            int32_t nd; MK_OR_FAIL(nd, mk1(t, frag, con.v[con.n - 1])); con.v[con.n - 1] = nd; break; }
        case DC_AND_V: case DC_AND_B: case DC_OR_B: case DC_OR_C: case DC_OR_D: {
            if (con.n < 2) FAIL;
            int frag = f.ctx == DC_AND_V ? MS_AND_V : f.ctx == DC_AND_B ? MS_AND_B : f.ctx == DC_OR_B ? MS_OR_B : f.ctx == DC_OR_C ? MS_OR_C : MS_OR_D;
            int32_t child = con.v[--con.n]; int32_t nd; MK_OR_FAIL(nd, mk2(t, frag, child, con.v[con.n - 1])); con.v[con.n - 1] = nd; break; }
        case DC_ANDOR: {
            if (con.n < 3) FAIL;
            int32_t left = con.v[--con.n]; int32_t right = con.v[--con.n]; int32_t mid = con.v[con.n - 1];
            int32_t nd; MK_OR_FAIL(nd, mk3(t, MS_ANDOR, left, mid, right)); con.v[con.n - 1] = nd; break; }
        case DC_THRESH_W: {
            if (in >= last) FAIL;
            if (OPAT(in)->op == OP_ADD){ in++; if (!pv_push(&tp, DC_THRESH_W, f.n + 1, f.k) || !pv_push(&tp, DC_W_EXPR, -1, -1)) FAIL; }
            else { if (!pv_push(&tp, DC_THRESH_E, f.n + 1, f.k) || !pv_push(&tp, DC_SINGLE_BKV_EXPR, -1, -1)) FAIL; }
            break; }
        case DC_THRESH_E: {
            if (f.k < 1 || f.k > f.n || con.n < f.n) FAIL;
            /* the children were constructed last-first: reverse them into script order */
            int32_t* subs = malloc((size_t)f.n * sizeof(int32_t)); if (!subs) FAIL;
            for (int i = 0; i < f.n; i++) subs[i] = con.v[con.n - 1 - i];
            con.n -= (int)f.n;
            int32_t nd = mk_node(t, MS_THRESH, (uint32_t)f.k, subs, (int)f.n, NULL, 0, NULL, 0); free(subs);
            if (nd < 0) FAIL;
            PUSHC(nd); break; }
        case DC_ENDIF: {
            if (in >= last) FAIL;
            if (OPAT(in)->op == OP_ELSE){ in++; if (!pv_push(&tp, DC_ENDIF_ELSE, -1, -1) || !pv_push(&tp, DC_BKV_EXPR, -1, -1)) FAIL; }
            else if (OPAT(in)->op == OP_IF){
                if (last - in >= 2 && OPAT(in + 1)->op == OP_DUP){ in += 2; if (!pv_push(&tp, DC_DUP_IF, -1, -1)) FAIL; }
                else if (last - in >= 3 && OPAT(in + 1)->op == OP_0NOTEQUAL && OPAT(in + 2)->op == OP_SIZE){ in += 3; if (!pv_push(&tp, DC_NON_ZERO, -1, -1)) FAIL; }
                else FAIL;
            } else if (OPAT(in)->op == OP_NOTIF){ in++; if (!pv_push(&tp, DC_ENDIF_NOTIF, -1, -1)) FAIL; }
            else FAIL;
            break; }
        case DC_ENDIF_NOTIF: {
            if (in >= last) FAIL;
            if (OPAT(in)->op == OP_IFDUP){ in++; if (!pv_push(&tp, DC_OR_D, -1, -1)) FAIL; }
            else { if (!pv_push(&tp, DC_OR_C, -1, -1)) FAIL; }
            if (!pv_push(&tp, DC_SINGLE_BKV_EXPR, -1, -1)) FAIL;
            break; }
        case DC_ENDIF_ELSE: {
            if (in >= last) FAIL;
            if (OPAT(in)->op == OP_IF){ in++; if (con.n < 2) FAIL; int32_t child = con.v[--con.n]; int32_t nd; MK_OR_FAIL(nd, mk2(t, MS_OR_I, child, con.v[con.n - 1])); con.v[con.n - 1] = nd; }
            else if (OPAT(in)->op == OP_NOTIF){ in++; if (!pv_push(&tp, DC_ANDOR, -1, -1) || !pv_push(&tp, DC_SINGLE_BKV_EXPR, -1, -1)) FAIL; }
            else FAIL;
            break; }
        }
    }
    if (con.n != 1) FAIL;
    if (in != last) FAIL;
    if (!ms_is_valid_top(t, con.v[0])) FAIL;
    ok = 1;
#undef FAIL
#undef PUSHC
#undef MK_OR_FAIL
#undef OPAT
done:
    free(ops); free(tp.v); free(keybuf);
    if (!ok){ iv_free(&con); t->nn = nn0; t->ns = ns0; t->nk = nk0; return -1; }
    int32_t root = con.v[0]; iv_free(&con);
    ms_duplicate_key_check(t, ctx, root);
    return root;
}

/* ---- script emission ----------------------------------------------------------- */
typedef struct { int32_t node; int pos; int verify; } eframe_t;
/* the child at emission position pos (andor emits X, Z, Y) */
static int32_t emit_child(const ms_tree_t* t, const ms_node_t* n, int pos){
    if (n->frag == MS_ANDOR) return SUB(t, n, pos == 0 ? 0 : pos == 1 ? 2 : 1);
    return SUB(t, n, pos);
}
#define EMIT(b) do{ if (o + 1 > cap) return -1; out[o++] = (u8)(b); }while(0)
/* the bytes of node n at emission position pos (before child pos; pos == nchildren is the suffix) */
static long emit_piece(const ms_tree_t* t, const ms_ctx_t* ctx, const ms_node_t* n, int pos, int verify, u8* out, size_t cap, size_t o){
    int r;
    switch (n->frag){
    case MS_PK_K: { u8 kb[33]; int kl; if (!ctx->key_bytes(ctx->user, t->keys[n->keys_off], kb, &kl)) return -1; r = push_data(out, cap, o, kb, (size_t)kl); return r; }
    case MS_PK_H: { u8 h[20]; if (!ctx->key_hash(ctx->user, t->keys[n->keys_off], h)) return -1; EMIT(OP_DUP); EMIT(OP_HASH160); r = push_data(out, cap, o, h, 20); if (r < 0) return -1; o = (size_t)r; EMIT(OP_EQUALVERIFY); return (long)o; }
    case MS_OLDER: case MS_AFTER: r = push_num(out, cap, o, n->k); if (r < 0) return -1; o = (size_t)r; EMIT(n->frag == MS_OLDER ? OP_CHECKSEQUENCEVERIFY : OP_CHECKLOCKTIMEVERIFY); return (long)o;
    case MS_SHA256: case MS_RIPEMD160: case MS_HASH256: case MS_HASH160:
        EMIT(OP_SIZE); r = push_num(out, cap, o, 32); if (r < 0) return -1; o = (size_t)r; EMIT(OP_EQUALVERIFY);
        EMIT(n->frag == MS_SHA256 ? OP_SHA256 : n->frag == MS_RIPEMD160 ? OP_RIPEMD160 : n->frag == MS_HASH256 ? OP_HASH256 : OP_HASH160);
        r = push_data(out, cap, o, n->data, n->datalen); if (r < 0) return -1; o = (size_t)r; EMIT(verify ? OP_EQUALVERIFY : OP_EQUAL); return (long)o;
    case MS_JUST_1: EMIT(OP_1); return (long)o;
    case MS_JUST_0: EMIT(OP_0); return (long)o;
    case MS_WRAP_A: if (pos == 0) EMIT(OP_TOALTSTACK); else EMIT(OP_FROMALTSTACK); return (long)o;
    case MS_WRAP_S: if (pos == 0) EMIT(OP_SWAP); return (long)o;
    case MS_WRAP_C: if (pos == 1) EMIT(verify ? OP_CHECKSIGVERIFY : OP_CHECKSIG); return (long)o;
    case MS_WRAP_D: if (pos == 0){ EMIT(OP_DUP); EMIT(OP_IF); } else EMIT(OP_ENDIF); return (long)o;
    case MS_WRAP_V: if (pos == 1 && HAS(NODE(t, SUB(t, n, 0))->typ, "x")) EMIT(OP_VERIFY); return (long)o;
    case MS_WRAP_J: if (pos == 0){ EMIT(OP_SIZE); EMIT(OP_0NOTEQUAL); EMIT(OP_IF); } else EMIT(OP_ENDIF); return (long)o;
    case MS_WRAP_N: if (pos == 1) EMIT(OP_0NOTEQUAL); return (long)o;
    case MS_AND_V: return (long)o;
    case MS_AND_B: if (pos == 2) EMIT(OP_BOOLAND); return (long)o;
    case MS_OR_B: if (pos == 2) EMIT(OP_BOOLOR); return (long)o;
    case MS_OR_D: if (pos == 1){ EMIT(OP_IFDUP); EMIT(OP_NOTIF); } else if (pos == 2) EMIT(OP_ENDIF); return (long)o;
    case MS_OR_C: if (pos == 1) EMIT(OP_NOTIF); else if (pos == 2) EMIT(OP_ENDIF); return (long)o;
    case MS_OR_I: if (pos == 0) EMIT(OP_IF); else if (pos == 1) EMIT(OP_ELSE); else EMIT(OP_ENDIF); return (long)o;
    case MS_ANDOR: if (pos == 1) EMIT(OP_NOTIF); else if (pos == 2) EMIT(OP_ELSE); else if (pos == 3) EMIT(OP_ENDIF); return (long)o;
    case MS_MULTI: {
        r = push_num(out, cap, o, n->k); if (r < 0) return -1; o = (size_t)r;
        for (int i = 0; i < n->nkeys; i++){ u8 kb[33]; int kl; if (!ctx->key_bytes(ctx->user, t->keys[n->keys_off + i], kb, &kl)) return -1; r = push_data(out, cap, o, kb, (size_t)kl); if (r < 0) return -1; o = (size_t)r; }
        r = push_num(out, cap, o, n->nkeys); if (r < 0) return -1; o = (size_t)r; EMIT(verify ? OP_CHECKMULTISIGVERIFY : OP_CHECKMULTISIG); return (long)o; }
    case MS_MULTI_A: {
        for (int i = 0; i < n->nkeys; i++){ u8 kb[33]; int kl; if (!ctx->key_bytes(ctx->user, t->keys[n->keys_off + i], kb, &kl)) return -1; r = push_data(out, cap, o, kb, (size_t)kl); if (r < 0) return -1; o = (size_t)r; EMIT(i == 0 ? OP_CHECKSIG : OP_CHECKSIGADD); }
        r = push_num(out, cap, o, n->k); if (r < 0) return -1; o = (size_t)r; EMIT(verify ? OP_NUMEQUALVERIFY : OP_NUMEQUAL); return (long)o; }
    case MS_THRESH: {
        if (pos >= 2 && pos < n->nsubs) EMIT(OP_ADD);
        if (pos == n->nsubs){ if (n->nsubs >= 2) EMIT(OP_ADD); r = push_num(out, cap, o, n->k); if (r < 0) return -1; o = (size_t)r; EMIT(verify ? OP_EQUALVERIFY : OP_EQUAL); }
        return (long)o; }
    }
    return -1;
}
#undef EMIT
int ms_to_script(const ms_tree_t* t, const ms_ctx_t* ctx, int root, u8* out, size_t cap){
    eframe_t* st = NULL; int sn = 0, scap = 0; size_t o = 0;
    #define SPUSH(nd, vf) do{ if (sn == scap){ int nc = scap ? scap * 2 : 64; eframe_t* q = realloc(st, (size_t)nc * sizeof(eframe_t)); if (!q){ free(st); return -1; } st = q; scap = nc; } st[sn].node = (nd); st[sn].pos = 0; st[sn].verify = (vf); sn++; }while(0)
    SPUSH(root, 0);
    while (sn){
        eframe_t* f = &st[sn - 1]; const ms_node_t* n = NODE(t, f->node);
        long r = emit_piece(t, ctx, n, f->pos, f->verify, out, cap, o);
        if (r < 0){ free(st); return -1; }
        o = (size_t)r;
        if (f->pos >= n->nsubs){ sn--; continue; }
        int pos = f->pos++;
        int cv = n->frag == MS_WRAP_V ? 1 : (n->frag == MS_WRAP_S || (n->frag == MS_AND_V && pos == 1)) ? f->verify : 0;
        int32_t c = emit_child(t, n, pos);
        SPUSH(c, cv);
    }
    #undef SPUSH
    free(st);
    return (int)o;
}

/* ---- textual form ----------------------------------------------------------------- */
typedef struct { char* p; size_t cap, n; int ovf; } sbuf_t;
static void sb_puts(sbuf_t* b, const char* s){ size_t l = strlen(s); if (b->n + l + 1 > b->cap){ b->ovf = 1; return; } memcpy(b->p + b->n, s, l + 1); b->n += l; }
static void sb_putc(sbuf_t* b, char c){ if (b->n + 2 > b->cap){ b->ovf = 1; return; } b->p[b->n++] = c; b->p[b->n] = 0; }
static void sb_hex(sbuf_t* b, const u8* d, int n){ static const char* H = "0123456789abcdef"; for (int i = 0; i < n; i++){ sb_putc(b, H[d[i] >> 4]); sb_putc(b, H[d[i] & 15]); } }
static void sb_u32(sbuf_t* b, uint32_t v){ char t[16]; snprintf(t, sizeof t, "%u", v); sb_puts(b, t); }
static int sb_key(sbuf_t* b, const ms_ctx_t* ctx, int key){
    char tmp[1400]; if (!ctx->key_to_str(ctx->user, key, tmp, sizeof tmp)) return 0; sb_puts(b, tmp); return 1;
}
typedef struct { int32_t node; int pos; int wrapped; int mode; } sframe_t;
/* mode: 0 plain, 1 pk sugar, 2 pkh sugar, 3 t:, 4 l:, 5 u:, 6 and_n */
static int str_mode(const ms_tree_t* t, const ms_node_t* n){
    if (n->frag == MS_WRAP_C){ int cf = NODE(t, SUB(t, n, 0))->frag; if (cf == MS_PK_K) return 1; if (cf == MS_PK_H) return 2; }
    if (n->frag == MS_AND_V && NODE(t, SUB(t, n, 1))->frag == MS_JUST_1) return 3;
    if (n->frag == MS_OR_I && NODE(t, SUB(t, n, 0))->frag == MS_JUST_0) return 4;
    if (n->frag == MS_OR_I && NODE(t, SUB(t, n, 1))->frag == MS_JUST_0) return 5;
    if (n->frag == MS_ANDOR && NODE(t, SUB(t, n, 2))->frag == MS_JUST_0) return 6;
    return 0;
}
static int is_wrapper(int frag){ return frag == MS_WRAP_A || frag == MS_WRAP_S || frag == MS_WRAP_D || frag == MS_WRAP_V || frag == MS_WRAP_J || frag == MS_WRAP_N || frag == MS_WRAP_C; }
static const char* FRAG_NAME[] = { "0", "1", "pk_k", "pk_h", "older", "after", "sha256", "hash256", "ripemd160", "hash160",
    "a", "s", "c", "d", "v", "j", "n", "and_v", "and_b", "or_b", "or_c", "or_d", "or_i", "andor", "thresh", "multi", "multi_a" };
int ms_to_string(const ms_tree_t* t, const ms_ctx_t* ctx, int root, char* out, size_t cap){
    if (!cap) return 0;
    sbuf_t b = { out, cap, 0, 0 }; out[0] = 0;
    sframe_t* st = NULL; int sn = 0, scap = 0;
    #define SPUSH(nd, wr) do{ if (sn == scap){ int nc = scap ? scap * 2 : 64; sframe_t* q = realloc(st, (size_t)nc * sizeof(sframe_t)); if (!q){ free(st); return 0; } st = q; scap = nc; } st[sn].node = (nd); st[sn].pos = 0; st[sn].wrapped = (wr); st[sn].mode = -1; sn++; }while(0)
    SPUSH(root, 0);
    while (sn && !b.ovf){
        sframe_t* f = &st[sn - 1]; const ms_node_t* n = NODE(t, f->node);
        if (f->mode < 0) f->mode = str_mode(t, n);
        int mode = f->mode;
        /* the number of children printed and the child for a position */
        int nch = mode == 1 || mode == 2 ? 0 : mode == 3 || mode == 4 || mode == 5 ? 1 : mode == 6 ? 2 : n->nsubs;
        if (f->pos == 0){
            /* prefix */
            if (is_wrapper(n->frag) && mode == 0){ sb_puts(&b, FRAG_NAME[n->frag]); }
            else if (mode == 3) sb_puts(&b, "t");
            else if (mode == 4) sb_puts(&b, "l");
            else if (mode == 5) sb_puts(&b, "u");
            else {
                if (f->wrapped) sb_putc(&b, ':');
                switch (n->frag){
                case MS_WRAP_C: sb_puts(&b, mode == 1 ? "pk(" : "pkh("); if (!sb_key(&b, ctx, t->keys[NODE(t, SUB(t, n, 0))->keys_off])){ free(st); return 0; } sb_puts(&b, ")"); break;
                case MS_PK_K: case MS_PK_H: sb_puts(&b, FRAG_NAME[n->frag]); sb_puts(&b, "("); if (!sb_key(&b, ctx, t->keys[n->keys_off])){ free(st); return 0; } sb_puts(&b, ")"); break;
                case MS_AFTER: case MS_OLDER: sb_puts(&b, FRAG_NAME[n->frag]); sb_puts(&b, "("); sb_u32(&b, n->k); sb_puts(&b, ")"); break;
                case MS_SHA256: case MS_HASH256: case MS_RIPEMD160: case MS_HASH160: sb_puts(&b, FRAG_NAME[n->frag]); sb_puts(&b, "("); sb_hex(&b, n->data, n->datalen); sb_puts(&b, ")"); break;
                case MS_JUST_0: sb_puts(&b, "0"); break;
                case MS_JUST_1: sb_puts(&b, "1"); break;
                case MS_MULTI: case MS_MULTI_A: sb_puts(&b, FRAG_NAME[n->frag]); sb_puts(&b, "("); sb_u32(&b, n->k);
                    for (int i = 0; i < n->nkeys; i++){ sb_putc(&b, ','); if (!sb_key(&b, ctx, t->keys[n->keys_off + i])){ free(st); return 0; } }
                    sb_puts(&b, ")"); break;
                case MS_THRESH: sb_puts(&b, "thresh("); sb_u32(&b, n->k); sb_putc(&b, ','); break;
                case MS_ANDOR: sb_puts(&b, mode == 6 ? "and_n(" : "andor("); break;
                default: sb_puts(&b, FRAG_NAME[n->frag]); sb_puts(&b, "("); break;
                }
            }
        } else if (f->pos < nch){
            sb_putc(&b, ',');
        }
        if (f->pos >= nch){
            /* "name(" ... ")" forms close here; leaves, wrappers and the t/l/u/pk/pkh sugar printed everything already */
            if ((mode == 0 && !is_wrapper(n->frag) && n->nsubs > 0) || mode == 6) sb_putc(&b, ')');
            sn--; continue;
        }
        int pos = f->pos++;
        int32_t child = mode == 4 ? SUB(t, n, 1) : SUB(t, n, pos);
        int cw = is_wrapper(n->frag) || mode == 3 || mode == 4 || mode == 5;
        SPUSH(child, cw);
    }
    #undef SPUSH
    free(st);
    return !b.ovf;
}

/* ---- the satisfier (Core's ProduceInput) --------------------------------------------- */
typedef struct { u8* b; size_t n, cap; } arena_t;
static int arena_put(arena_t* a, const u8* d, size_t n, uint32_t* off){
    if (a->n + n > a->cap){ size_t nc = a->cap ? a->cap * 2 : 4096; while (nc < a->n + n) nc *= 2; u8* q = realloc(a->b, nc); if (!q) return 0; a->b = q; a->cap = nc; }
    *off = (uint32_t)a->n; if (n) memcpy(a->b + a->n, d, n); a->n += n; return 1;
}
typedef struct { uint32_t off, len; } elref_t;
typedef struct { u8 avail, has_sig, malleable, non_canon; uint64_t size; elref_t* el; int n; } instk_t;
static instk_t stk_empty(void){ instk_t s; memset(&s, 0, sizeof s); s.avail = MS_AVAIL_YES; return s; }
static instk_t stk_invalid(void){ instk_t s; memset(&s, 0, sizeof s); s.avail = MS_AVAIL_NO; s.size = UINT64_MAX; return s; }
static void stk_free(instk_t* s){ free(s->el); s->el = NULL; s->n = 0; }
static int stk_set_avail(instk_t* s, int avail){
    s->avail = (u8)avail;
    if (avail == MS_AVAIL_NO){ stk_free(s); s->size = UINT64_MAX; s->has_sig = s->malleable = s->non_canon = 0; }
    return 1;
}
static instk_t stk_elem(arena_t* a, const u8* d, size_t n, int* oom){
    instk_t s = stk_empty(); uint32_t off;
    if (!arena_put(a, d, n, &off)){ *oom = 1; return stk_invalid(); }
    s.el = malloc(sizeof(elref_t)); if (!s.el){ *oom = 1; return stk_invalid(); }
    s.el[0].off = off; s.el[0].len = (uint32_t)n; s.n = 1; s.size = n + 1; return s;
}
static instk_t stk_copy(const instk_t* s, int* oom){
    instk_t r = *s; r.el = NULL;
    if (s->n){ r.el = malloc((size_t)s->n * sizeof(elref_t)); if (!r.el){ *oom = 1; return stk_invalid(); } memcpy(r.el, s->el, (size_t)s->n * sizeof(elref_t)); }
    return r;
}
/* a + b (consumes both) */
static instk_t stk_cat(instk_t a, instk_t b, int* oom){
    instk_t r; memset(&r, 0, sizeof r);
    int n = a.n + b.n;
    if (n){ r.el = malloc((size_t)n * sizeof(elref_t)); if (!r.el){ *oom = 1; stk_free(&a); stk_free(&b); return stk_invalid(); }
            if (a.n) memcpy(r.el, a.el, (size_t)a.n * sizeof(elref_t));
            if (b.n) memcpy(r.el + a.n, b.el, (size_t)b.n * sizeof(elref_t)); }
    r.n = n; r.size = a.size;
    if (a.avail != MS_AVAIL_NO && b.avail != MS_AVAIL_NO) r.size = a.size + b.size;
    r.has_sig = a.has_sig | b.has_sig; r.malleable = a.malleable | b.malleable; r.non_canon = a.non_canon | b.non_canon;
    r.avail = a.avail;
    if (a.avail == MS_AVAIL_NO || b.avail == MS_AVAIL_NO) stk_set_avail(&r, MS_AVAIL_NO);
    else if (a.avail == MS_AVAIL_MAYBE || b.avail == MS_AVAIL_MAYBE) stk_set_avail(&r, MS_AVAIL_MAYBE);
    stk_free(&a); stk_free(&b);
    return r;
}
/* a | b (consumes both) */
static instk_t stk_or(instk_t a, instk_t b){
    if (a.avail == MS_AVAIL_NO){ stk_free(&a); return b; }
    if (b.avail == MS_AVAIL_NO){ stk_free(&b); return a; }
    if (!a.has_sig && b.has_sig){ stk_free(&b); return a; }
    if (!b.has_sig && a.has_sig){ stk_free(&a); return b; }
    if (!a.has_sig && !b.has_sig){ a.malleable = 1; b.malleable = 1; }
    else {
        if (b.malleable && !a.malleable){ stk_free(&b); return a; }
        if (a.malleable && !b.malleable){ stk_free(&a); return b; }
    }
    if (a.avail == MS_AVAIL_YES && b.avail == MS_AVAIL_YES){ if (a.size <= b.size){ stk_free(&b); return a; } stk_free(&a); return b; }
    if (a.avail == MS_AVAIL_MAYBE && b.avail == MS_AVAIL_MAYBE){ if (a.size >= b.size){ stk_free(&b); return a; } stk_free(&a); return b; }
    if (a.avail == MS_AVAIL_YES){ stk_free(&b); return a; }
    stk_free(&a); return b;
}
typedef struct { instk_t nsat, sat; } inres_t;
static instk_t stk_zero32(arena_t* a, const u8* z32, int* oom){ instk_t s = stk_elem(a, z32, 32, oom); s.malleable = 1; return s; }

int ms_satisfy(const ms_tree_t* t, const ms_ctx_t* ctx, const ms_sat_ctx_t* sc, int root, int nonmalleable, ms_witness_t* w){
    u8* mark = subtree_mark(t, root); if (!mark) return MS_AVAIL_NO;
    inres_t* res = calloc((size_t)root + 1, sizeof(inres_t)); if (!res){ free(mark); return MS_AVAIL_NO; }
    arena_t ar = { 0 }; int oom = 0;
    static const u8 ONEB[1] = { 1 }; static const u8 Z32[32] = { 0 };
    #define ZERO() stk_elem(&ar, NULL, 0, &oom)
    #define ONE() stk_elem(&ar, ONEB, 1, &oom)
    #define ZERO32() stk_zero32(&ar, Z32, &oom)
    #define EMPTY() stk_empty()
    #define INVALID() stk_invalid()
    #define CP(s) stk_copy(&(s), &oom)
    #define CAT(a, b) stk_cat((a), (b), &oom)
    for (int32_t i = 0; i <= root && !oom; i++){
        if (!mark[i]) continue;
        const ms_node_t* n = NODE(t, i);
        inres_t* x = n->nsubs > 0 ? &res[SUB(t, n, 0)] : NULL;
        inres_t* y = n->nsubs > 1 ? &res[SUB(t, n, 1)] : NULL;
        inres_t* z = n->nsubs > 2 ? &res[SUB(t, n, 2)] : NULL;
        inres_t r; r.nsat = INVALID(); r.sat = INVALID();
        switch (n->frag){
        case MS_PK_K: {
            u8 sig[80]; size_t sl = 0; int av = sc->sign(sc->user, t->keys[n->keys_off], sig, &sl, sizeof sig);
            instk_t s = stk_elem(&ar, sig, av == MS_AVAIL_NO ? 0 : sl, &oom); s.has_sig = 1; stk_set_avail(&s, av);
            r.nsat = ZERO(); r.sat = s; break; }
        case MS_PK_H: {
            u8 kb[33]; int kl = 0; if (!ctx->key_bytes(ctx->user, t->keys[n->keys_off], kb, &kl)){ kl = 0; }
            u8 sig[80]; size_t sl = 0; int av = sc->sign(sc->user, t->keys[n->keys_off], sig, &sl, sizeof sig);
            instk_t s = stk_elem(&ar, sig, av == MS_AVAIL_NO ? 0 : sl, &oom); s.has_sig = 1;
            r.nsat = CAT(ZERO(), stk_elem(&ar, kb, (size_t)kl, &oom));
            instk_t sat = CAT(s, stk_elem(&ar, kb, (size_t)kl, &oom)); stk_set_avail(&sat, av); r.sat = sat; break; }
        case MS_MULTI_A: {
            int nk = n->nkeys; instk_t* sats = malloc((size_t)(nk + 1) * sizeof(instk_t)); instk_t* nx = malloc((size_t)(nk + 2) * sizeof(instk_t));
            if (!sats || !nx){ free(sats); free(nx); oom = 1; break; }
            int ns = 1; sats[0] = EMPTY();
            for (int q = 0; q < nk && !oom; q++){
                u8 sig[80]; size_t sl = 0; int av = sc->sign(sc->user, t->keys[n->keys_off + nk - 1 - q], sig, &sl, sizeof sig);
                instk_t sat = stk_elem(&ar, sig, av == MS_AVAIL_NO ? 0 : sl, &oom); sat.has_sig = 1; stk_set_avail(&sat, av);
                nx[0] = CAT(CP(sats[0]), ZERO());
                for (int j = 1; j < ns; j++) nx[j] = stk_or(CAT(CP(sats[j]), ZERO()), CAT(CP(sats[j - 1]), CP(sat)));
                nx[ns] = CAT(CP(sats[ns - 1]), sat);
                for (int j = 0; j < ns; j++) stk_free(&sats[j]);
                ns++; memcpy(sats, nx, (size_t)ns * sizeof(instk_t));
            }
            if (!oom && (int)n->k < ns){ r.nsat = sats[0]; r.sat = sats[n->k]; for (int j = 1; j < ns; j++) if (j != (int)n->k) stk_free(&sats[j]); }
            else for (int j = 0; j < ns; j++) stk_free(&sats[j]);
            free(sats); free(nx); break; }
        case MS_MULTI: {
            int nk = n->nkeys; instk_t* sats = malloc((size_t)(nk + 1) * sizeof(instk_t)); instk_t* nx = malloc((size_t)(nk + 2) * sizeof(instk_t));
            if (!sats || !nx){ free(sats); free(nx); oom = 1; break; }
            int ns = 1; sats[0] = ZERO();
            for (int q = 0; q < nk && !oom; q++){
                u8 sig[80]; size_t sl = 0; int av = sc->sign(sc->user, t->keys[n->keys_off + q], sig, &sl, sizeof sig);
                instk_t sat = stk_elem(&ar, sig, av == MS_AVAIL_NO ? 0 : sl, &oom); sat.has_sig = 1; stk_set_avail(&sat, av);
                nx[0] = CP(sats[0]);
                for (int j = 1; j < ns; j++) nx[j] = stk_or(CP(sats[j]), CAT(CP(sats[j - 1]), CP(sat)));
                nx[ns] = CAT(CP(sats[ns - 1]), sat);
                for (int j = 0; j < ns; j++) stk_free(&sats[j]);
                ns++; memcpy(sats, nx, (size_t)ns * sizeof(instk_t));
            }
            instk_t ns_ = ZERO(); for (uint32_t q = 0; q < n->k && !oom; q++) ns_ = CAT(ns_, ZERO());
            if (!oom && (int)n->k < ns){ r.nsat = ns_; r.sat = sats[n->k]; for (int j = 0; j < ns; j++) if (j != (int)n->k) stk_free(&sats[j]); }
            else { stk_free(&ns_); for (int j = 0; j < ns; j++) stk_free(&sats[j]); }
            free(sats); free(nx); break; }
        case MS_THRESH: {
            int nsb = n->nsubs; instk_t* sats = malloc((size_t)(nsb + 1) * sizeof(instk_t)); instk_t* nx = malloc((size_t)(nsb + 2) * sizeof(instk_t));
            if (!sats || !nx){ free(sats); free(nx); oom = 1; break; }
            int ns = 1; sats[0] = EMPTY();
            for (int q = 0; q < nsb && !oom; q++){
                inres_t* sr = &res[SUB(t, n, nsb - 1 - q)];
                nx[0] = CAT(CP(sats[0]), CP(sr->nsat));
                for (int j = 1; j < ns; j++) nx[j] = stk_or(CAT(CP(sats[j]), CP(sr->nsat)), CAT(CP(sats[j - 1]), CP(sr->sat)));
                nx[ns] = CAT(CP(sats[ns - 1]), CP(sr->sat));
                for (int j = 0; j < ns; j++) stk_free(&sats[j]);
                ns++; memcpy(sats, nx, (size_t)ns * sizeof(instk_t));
            }
            if (!oom && (int)n->k < ns){
                instk_t nsat_ = INVALID();
                for (int q = 0; q < ns; q++){
                    if (q != 0 && q != (int)n->k){ sats[q].malleable = 1; sats[q].non_canon = 1; }
                    if (q != (int)n->k) nsat_ = stk_or(nsat_, sats[q]);
                }
                r.nsat = nsat_; r.sat = sats[n->k];
            } else for (int j = 0; j < ns; j++) stk_free(&sats[j]);
            free(sats); free(nx); break; }
        case MS_OLDER: r.nsat = INVALID(); r.sat = sc->check_older(sc->user, n->k) ? EMPTY() : INVALID(); break;
        case MS_AFTER: r.nsat = INVALID(); r.sat = sc->check_after(sc->user, n->k) ? EMPTY() : INVALID(); break;
        case MS_SHA256: case MS_RIPEMD160: case MS_HASH256: case MS_HASH160: {
            u8 pre[32]; int av = sc->preimage(sc->user, n->frag, n->data, pre);
            instk_t s = stk_elem(&ar, pre, av == MS_AVAIL_NO ? 0 : 32, &oom); stk_set_avail(&s, av);
            r.nsat = ZERO32(); r.sat = s; break; }
        case MS_AND_V: { instk_t a = CAT(CP(y->nsat), CP(x->sat)); a.non_canon = 1; r.nsat = a; r.sat = CAT(CP(y->sat), CP(x->sat)); break; }
        case MS_AND_B: {
            instk_t a = CAT(CP(y->nsat), CP(x->nsat));
            instk_t b = CAT(CP(y->sat), CP(x->nsat)); b.malleable = 1; b.non_canon = 1;
            instk_t c = CAT(CP(y->nsat), CP(x->sat)); c.malleable = 1; c.non_canon = 1;
            r.nsat = stk_or(stk_or(a, b), c); r.sat = CAT(CP(y->sat), CP(x->sat)); break; }
        case MS_OR_B: {
            r.nsat = CAT(CP(y->nsat), CP(x->nsat));
            instk_t a = CAT(CP(y->nsat), CP(x->sat)), b = CAT(CP(y->sat), CP(x->nsat)), c = CAT(CP(y->sat), CP(x->sat)); c.malleable = 1; c.non_canon = 1;
            r.sat = stk_or(stk_or(a, b), c); break; }
        case MS_OR_C: r.nsat = INVALID(); r.sat = stk_or(CP(x->sat), CAT(CP(y->sat), CP(x->nsat))); break;
        case MS_OR_D: r.nsat = CAT(CP(y->nsat), CP(x->nsat)); r.sat = stk_or(CP(x->sat), CAT(CP(y->sat), CP(x->nsat))); break;
        case MS_OR_I: r.nsat = stk_or(CAT(CP(x->nsat), ONE()), CAT(CP(y->nsat), ZERO())); r.sat = stk_or(CAT(CP(x->sat), ONE()), CAT(CP(y->sat), ZERO())); break;
        case MS_ANDOR: {
            instk_t a = CAT(CP(y->nsat), CP(x->sat)); a.non_canon = 1;
            r.nsat = stk_or(a, CAT(CP(z->nsat), CP(x->nsat)));
            r.sat = stk_or(CAT(CP(y->sat), CP(x->sat)), CAT(CP(z->sat), CP(x->nsat))); break; }
        case MS_WRAP_A: case MS_WRAP_S: case MS_WRAP_C: case MS_WRAP_N: r.nsat = CP(x->nsat); r.sat = CP(x->sat); break;
        case MS_WRAP_D: r.nsat = ZERO(); r.sat = CAT(CP(x->sat), ONE()); break;
        case MS_WRAP_J: { instk_t a = ZERO(); a.malleable = (x->nsat.avail != MS_AVAIL_NO && !x->nsat.has_sig); r.nsat = a; r.sat = CP(x->sat); break; }
        case MS_WRAP_V: r.nsat = INVALID(); r.sat = CP(x->sat); break;
        case MS_JUST_0: r.nsat = EMPTY(); r.sat = INVALID(); break;
        case MS_JUST_1: r.nsat = INVALID(); r.sat = EMPTY(); break;
        }
        for (int c = 0; c < n->nsubs; c++){ inres_t* cr = &res[SUB(t, n, c)]; stk_free(&cr->nsat); stk_free(&cr->sat); }
        res[i] = r;
    }
    int ret = MS_AVAIL_NO;
    if (!oom){
        instk_t* s = &res[root].sat;
        if (!(nonmalleable && (s->malleable || !s->has_sig)) && s->avail != MS_AVAIL_NO){
            /* serialize: varint length + bytes per element, bottom first */
            size_t need = 0; for (int q = 0; q < s->n; q++) need += (s->el[q].len < 253 ? 1 : 3) + s->el[q].len;
            if (need > w->cap){ u8* q = realloc(w->buf, need ? need : 1); if (q){ w->buf = q; w->cap = need; } else oom = 1; }
            if (!oom){
                size_t o = 0;
                for (int q = 0; q < s->n; q++){
                    uint32_t l = s->el[q].len;
                    if (l < 253) w->buf[o++] = (u8)l; else { w->buf[o++] = 0xfd; w->buf[o++] = (u8)l; w->buf[o++] = (u8)(l >> 8); }
                    if (l) memcpy(w->buf + o, ar.b + s->el[q].off, l);
                    o += l;
                }
                w->len = o; w->nelems = s->n; ret = s->avail;
            }
        } else if (s->avail != MS_AVAIL_NO) ret = MS_AVAIL_NO;
    }
    stk_free(&res[root].nsat); stk_free(&res[root].sat);
    free(res); free(mark); free(ar.b);
    #undef ZERO
    #undef ONE
    #undef ZERO32
    #undef EMPTY
    #undef INVALID
    #undef CP
    #undef CAT
    return ret;
}
void ms_witness_free(ms_witness_t* w){ free(w->buf); w->buf = NULL; w->cap = w->len = 0; w->nelems = 0; }

/* ---- properties ---------------------------------------------------------------------- */
uint32_t ms_type(const ms_tree_t* t, int root){ return NODE(t, root)->typ; }
size_t ms_script_size(const ms_tree_t* t, int root){ return NODE(t, root)->scriptlen; }
int ms_is_valid(const ms_tree_t* t, int root){ const ms_node_t* n = NODE(t, root); return n->typ != 0 && n->scriptlen <= ms_max_script_size(t->tapscript); }
int ms_is_valid_top(const ms_tree_t* t, int root){ return ms_is_valid(t, root) && HAS(NODE(t, root)->typ, "B"); }
int ms_is_nonmalleable(const ms_tree_t* t, int root){ return HAS(NODE(t, root)->typ, "m"); }
int ms_needs_signature(const ms_tree_t* t, int root){ return HAS(NODE(t, root)->typ, "s"); }
int ms_check_timelocks_mix(const ms_tree_t* t, int root){ return HAS(NODE(t, root)->typ, "k"); }
int ms_check_duplicate_key(const ms_tree_t* t, int root){ return NODE(t, root)->dup == 1; }
int ms_get_ops(const ms_tree_t* t, int root, uint32_t* out){ const ms_node_t* n = NODE(t, root); if (n->ops_sat < 0) return 0; *out = n->ops_count + (uint32_t)n->ops_sat; return 1; }
static int is_bkw(const ms_node_t* n){ return (n->typ & (MST_B | MST_K | MST_W)) != 0; }
int ms_get_stack_size(const ms_tree_t* t, int root, uint32_t* out){ const ms_node_t* n = NODE(t, root); if (!n->ss_sat_valid) return 0; *out = (uint32_t)(n->ss_sat_net + is_bkw(n)); return 1; }
int ms_get_exec_stack_size(const ms_tree_t* t, int root, uint32_t* out){ const ms_node_t* n = NODE(t, root); if (!n->ss_sat_valid) return 0; *out = (uint32_t)(n->ss_sat_exec + is_bkw(n)); return 1; }
int ms_get_witness_size(const ms_tree_t* t, int root, uint32_t* out){ const ms_node_t* n = NODE(t, root); if (n->ws_sat < 0) return 0; *out = (uint32_t)n->ws_sat; return 1; }
int ms_check_ops_limit(const ms_tree_t* t, int root){ if (t->tapscript) return 1; uint32_t o; if (ms_get_ops(t, root, &o)) return o <= MAX_OPS_PER_SCRIPT; return 1; }
int ms_check_stack_size(const ms_tree_t* t, int root){
    uint32_t s;
    if (t->tapscript){ if (ms_get_exec_stack_size(t, root, &s)) return s <= MAX_STACK_SIZE; return 1; }
    if (ms_get_stack_size(t, root, &s)) return s <= MAX_STANDARD_P2WSH_STACK_ITEMS;
    return 1;
}
int ms_is_not_satisfiable(const ms_tree_t* t, int root){ uint32_t s; return !ms_get_stack_size(t, root, &s); }
int ms_valid_satisfactions(const ms_tree_t* t, int root){ return ms_is_valid(t, root) && ms_check_ops_limit(t, root) && ms_check_stack_size(t, root); }
int ms_is_sane_subexpression(const ms_tree_t* t, int root){ return ms_valid_satisfactions(t, root) && ms_is_nonmalleable(t, root) && ms_check_timelocks_mix(t, root) && ms_check_duplicate_key(t, root); }
int ms_is_sane(const ms_tree_t* t, int root){ return ms_is_valid_top(t, root) && ms_is_sane_subexpression(t, root) && ms_needs_signature(t, root); }
int ms_find_insane_sub(const ms_tree_t* t, int root){
    u8* mark = subtree_mark(t, root); if (!mark) return -1;
    int32_t* r = malloc((size_t)(root + 1) * sizeof(int32_t)); if (!r){ free(mark); return -1; }
    for (int32_t i = 0; i <= root; i++){
        if (!mark[i]) continue;
        const ms_node_t* n = NODE(t, i); int32_t found = -1;
        for (int c = 0; c < n->nsubs && found < 0; c++) found = r[SUB(t, n, c)];
        if (found < 0 && !ms_is_sane_subexpression(t, i)) found = i;
        r[i] = found;
    }
    int32_t out = r[root]; free(r); free(mark); return out;
}
int ms_unsafe_older(const ms_tree_t* t, int root, uint32_t* raw_out, int* time_based){
    u8* mark = subtree_mark(t, root); if (!mark) return 0;
    int found = 0;
    for (int32_t i = 0; i <= root && !found; i++){
        if (!mark[i]) continue;
        const ms_node_t* n = NODE(t, i);
        if (n->frag == MS_OLDER){
            uint32_t raw = n->k, value = raw & ~SEQUENCE_LOCKTIME_TYPE_FLAG;
            if (value > SEQUENCE_LOCKTIME_MASK){ *raw_out = raw; *time_based = (raw & SEQUENCE_LOCKTIME_TYPE_FLAG) != 0; found = 1; }
        }
    }
    free(mark); return found;
}

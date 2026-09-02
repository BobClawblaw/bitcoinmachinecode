/* tests/fuzz_verify_diff.c -- randomized differential of this node's WHOLE
 * input verification (sv_verify_script / sv_verify_witness_v0 /
 * taproot_verify_input: the functions daemon/tx_verify.c runs on every
 * input) against Bitcoin Core's VerifyScript, with REAL transactions and
 * REAL signatures produced by Core itself (validation/core_verify_oracle:
 * Core is both the reference and the signer, so a valid signature is valid
 * by definition and any rejection on our side is our bug; any acceptance of
 * a mutated one is worse).
 *
 *   fuzz_verify_diff [count] [seed] [oracle] [shown]
 *
 * Every case: a random tx (1-3 inputs, 1-3 outputs, random version /
 * locktime / sequences / amounts), one input built from a template -- P2PK,
 * P2PKH, bare multisig, P2SH of those, P2WPKH, P2WSH, P2SH-wrapped witness,
 * P2TR key path (with/without annex, with/without a script tree), P2TR script
 * path (CHECKSIG, CHECKSIGVERIFY chains, CHECKSIGADD k-of-n, OP_SUCCESS,
 * CODESEPARATOR, CLTV/CSV, 1- and 2-leaf trees) -- random hashtypes, and a
 * mutation about a third of the time (flipped signature byte, wrong key,
 * wrong hashtype byte, wrong amount signed, dropped/extra witness item, bad
 * control-block parity, uncommitted annex, non-DER sig, empty sig).
 * Compared: the verdict always; Core's error code where our side reports
 * one (legacy and witness v0). Taproot on our side reports a reason string,
 * so it is verdict-only. MANUAL: needs the scratch Core build. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
/* ---- our verifiers (daemon/tx_verify.c's exact call surface) ---- */
extern int sv_verify_script(const unsigned char* scriptSig, unsigned long ssl, const unsigned char* spk, unsigned long spl, u64 flags, unsigned long nIn, const unsigned char* tx, unsigned long txlen, unsigned char* work, unsigned long workcap);
extern int sv_classify_segwit(const u8* spk, u32 spl, const u8* ss, u32 ssl, u32* version, const u8** prog, u32* proglen, int* wrapped);
extern int sv_verify_witness_v0(const u8* prog, u32 proglen, const u8* const* wit, const u32* witlen, u32 nwit, u64 amount, u64 flags, unsigned long nIn, const u8* tx, unsigned long txlen, unsigned char* work, unsigned long workcap);
extern int taproot_verify_input(const u8* spk, const u8* const* wit, const u32* witlen, u32 nwit, const u8* tx, int64_t txlen, int64_t n_in, const u8* prevouts, const u8* amounts, const u8* spks, int64_t num_inputs, const char** reason);
extern void sha256_full(u8* out, const void* msg, int64_t len);
extern void hash160(u8 o[20], const void* in, long long len);
/* bitcoin_txval_modern.c reaches for the daemon's mempool on one path this driver never takes */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index, unsigned long long* value, const unsigned char** script, unsigned long* slen){ (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen; return 0; }
/* ---- flags (Core bit numbers) ---- */
#define F_P2SH (1ull<<0)
#define F_STRICTENC (1ull<<1)
#define F_DERSIG (1ull<<2)
#define F_LOW_S (1ull<<3)
#define F_NULLDUMMY (1ull<<4)
#define F_SIGPUSHONLY (1ull<<5)
#define F_MINIMALDATA (1ull<<6)
#define F_DISC_NOPS (1ull<<7)
#define F_CLEANSTACK (1ull<<8)
#define F_CLTV (1ull<<9)
#define F_CSV (1ull<<10)
#define F_WITNESS (1ull<<11)
#define F_DISC_WPROG (1ull<<12)
#define F_MINIMALIF (1ull<<13)
#define F_NULLFAIL (1ull<<14)
#define F_WITNESS_PUBKEYTYPE (1ull<<15)
#define F_CONST_SCRIPTCODE (1ull<<16)
#define F_TAPROOT (1ull<<17)
#define F_DISC_TAPVER (1ull<<18)
#define F_DISC_OPSUCCESS (1ull<<19)
#define F_DISC_PUBKEYTYPE (1ull<<20)
#define CONSENSUS (F_P2SH|F_DERSIG|F_CLTV|F_CSV|F_WITNESS|F_NULLDUMMY|F_TAPROOT)
#define STANDARD (CONSENSUS|F_STRICTENC|F_LOW_S|F_SIGPUSHONLY|F_MINIMALDATA|F_DISC_NOPS|F_CLEANSTACK|F_MINIMALIF|F_NULLFAIL|F_WITNESS_PUBKEYTYPE|F_CONST_SCRIPTCODE|F_DISC_WPROG|F_DISC_TAPVER|F_DISC_OPSUCCESS|F_DISC_PUBKEYTYPE)
/* ---- rng ---- */
static u64 rs; static u64 rnd(void){ rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27; return rs * 2685821657736338717ULL; }
static unsigned r(unsigned n){ return (unsigned)(rnd() % n); }
/* ---- hex ---- */
static void hexstr(char* o, const u8* p, size_t n){ static const char* H = "0123456789abcdef"; for (size_t i = 0; i < n; i++){ o[2*i] = H[p[i] >> 4]; o[2*i+1] = H[p[i] & 15]; } o[2*n] = 0; }
static int unhex(const char* h, u8* out, int cap){ int n = 0; if (!strcmp(h, "-")) return 0; for (const char* p = h; p[0] && p[1] && n < cap; p += 2){ unsigned v; sscanf(p, "%2x", &v); out[n++] = (u8)v; } return n; }
/* ---- oracle ---- */
static FILE *oin, *oout; static char obuf[1 << 16];
static void spawn_oracle(const char* path){ int a[2], b[2]; if (pipe(a) || pipe(b)){ perror("pipe"); exit(2); } pid_t pid = fork(); if (pid == 0){ dup2(a[0], 0); dup2(b[1], 1); close(a[1]); close(b[0]); execl(path, path, (char*)0); perror(path); _exit(3); } close(a[0]); close(b[1]); oin = fdopen(a[1], "w"); oout = fdopen(b[0], "r"); }
static int g_soft; static const char* ask(const char* line){ fputs(line, oin); fputc('\n', oin); fflush(oin); if (!fgets(obuf, sizeof obuf, oout)){ fprintf(stderr, "oracle died on: %.200s\n", line); exit(2); } size_t l = strlen(obuf); while (l && (obuf[l-1] == '\n' || obuf[l-1] == '\r')) obuf[--l] = 0; if (obuf[0] == 'E'){ if (g_soft) return NULL; fprintf(stderr, "oracle error '%s' on: %.200s\n", obuf, line); exit(2); } return obuf; }
/* ---- keys ---- */
#define NKEYS 4
static u8 PUB[NKEYS][33], XONLY[NKEYS][32];
/* ---- byte buffers ---- */
typedef struct { u8 b[70000]; int n; } buf;
static void put(buf* o, const void* p, int n){ memcpy(o->b + o->n, p, n); o->n += n; }
static void put1(buf* o, int v){ o->b[o->n++] = (u8)v; }
static void put4(buf* o, u32 v){ for (int i = 0; i < 4; i++) put1(o, (v >> (8*i)) & 255); }
static void put8(buf* o, u64 v){ for (int i = 0; i < 8; i++) put1(o, (v >> (8*i)) & 255); }
static void putcs(buf* o, u64 n){ if (n < 0xfd) put1(o, (int)n); else if (n <= 0xffff){ put1(o, 0xfd); put1(o, n & 255); put1(o, (n >> 8) & 255); } else { put1(o, 0xfe); put4(o, (u32)n); } }
static void putpush(buf* o, const u8* d, int n){ if (n == 0) put1(o, 0x00); else if (n == 1 && d[0] >= 1 && d[0] <= 16) put1(o, 0x50 + d[0]); else if (n == 1 && d[0] == 0x81) put1(o, 0x4f); else if (n <= 75){ put1(o, n); put(o, d, n); } else if (n <= 255){ put1(o, 0x4c); put1(o, n); put(o, d, n); } else { put1(o, 0x4d); put1(o, n & 255); put1(o, n >> 8); put(o, d, n); } }
static void putnum(buf* o, int64_t v){ if (v == 0){ put1(o, 0); return; } if (v >= 1 && v <= 16){ put1(o, 0x50 + (int)v); return; } if (v == -1){ put1(o, 0x4f); return; } u8 b[9]; int n = 0; int neg = v < 0; u64 a = (u64)(neg ? -v : v); while (a){ b[n++] = a & 255; a >>= 8; } if (b[n-1] & 0x80) b[n++] = neg ? 0x80 : 0; else if (neg) b[n-1] |= 0x80; putpush(o, b, n); }
/* ---- transaction ---- */
#define MAXIN 3
#define MAXOUT 3
#define MAXWIT 8
typedef struct { u8 txid[32]; u32 vout; buf ss; u32 seq; int nwit; u8 wit[MAXWIT][600]; u32 witlen[MAXWIT]; u64 amount; buf spk; } txin;
typedef struct { u64 value; buf spk; } txout;
typedef struct { u32 version; u32 locktime; int nin, nout; txin in[MAXIN]; txout out[MAXOUT]; } tx_t;
static tx_t T;
static void ser_tx(buf* o, int with_wit){
    int anyw = 0; for (int i = 0; i < T.nin; i++) if (T.in[i].nwit) anyw = 1;
    with_wit = with_wit && anyw;
    put4(o, T.version); if (with_wit){ put1(o, 0); put1(o, 1); }
    putcs(o, (u64)T.nin);
    for (int i = 0; i < T.nin; i++){ put(o, T.in[i].txid, 32); put4(o, T.in[i].vout); putcs(o, (u64)T.in[i].ss.n); put(o, T.in[i].ss.b, T.in[i].ss.n); put4(o, T.in[i].seq); }
    putcs(o, (u64)T.nout);
    for (int i = 0; i < T.nout; i++){ put8(o, T.out[i].value); putcs(o, (u64)T.out[i].spk.n); put(o, T.out[i].spk.b, T.out[i].spk.n); }
    if (with_wit) for (int i = 0; i < T.nin; i++){ putcs(o, (u64)T.in[i].nwit); for (int k = 0; k < T.in[i].nwit; k++){ putcs(o, T.in[i].witlen[k]); put(o, T.in[i].wit[k], (int)T.in[i].witlen[k]); } }
    put4(o, T.locktime);
}
static void ser_spent(buf* o){ for (int i = 0; i < T.nin; i++){ put8(o, T.in[i].amount); putcs(o, (u64)T.in[i].spk.n); put(o, T.in[i].spk.b, T.in[i].spk.n); } }
static char HEXTX[140000], HEXSP[8000], LINE[160000];
static void render(void){ static buf t, s; t.n = 0; s.n = 0; ser_tx(&t, 1); ser_spent(&s); hexstr(HEXTX, t.b, (size_t)t.n); hexstr(HEXSP, s.b, (size_t)s.n); }
/* ---- signing through the oracle ---- */
static int sign_ecdsa(u8* out, int key, int sigv, int hashtype, u64 amount, int nIn, const u8* scode, int sclen){
    static char sc[4000]; hexstr(sc, scode, (size_t)sclen); render();
    snprintf(LINE, sizeof LINE, "signecdsa %d %d %d %llu %s %d %s", key, sigv, hashtype, (unsigned long long)amount, HEXTX, nIn, sc);
    return unhex(ask(LINE), out, 80);
}
static int sign_schnorr(u8* out, int key, int sigv, int hashtype, int nIn, const char* root, const char* leaf, u32 codesep, const u8* annex, int annexlen){
    static char ax[1300]; if (annexlen) hexstr(ax, annex, (size_t)annexlen); else strcpy(ax, "-"); render();
    snprintf(LINE, sizeof LINE, "signschnorr %d %d %d %s %d %s %s %s %u %s", key, sigv, hashtype, HEXTX, nIn, HEXSP, root, leaf, codesep, ax);
    g_soft = 1; const char* rsp = ask(LINE); g_soft = 0;
    if (!rsp){ for (int i = 0; i < 64; i++) out[i] = (u8)rnd(); if (hashtype){ out[64] = (u8)hashtype; return 65; } return 64; }   /* Core refuses this sighash (SINGLE without a matching output): junk sig, both sides must reject */
    return unhex(rsp, out, 80);
}
static void leafhash(char* out65, const u8* script, int n){ static char sc[4000]; hexstr(sc, script, (size_t)n); snprintf(LINE, sizeof LINE, "leafhash %s", sc); strcpy(out65, ask(LINE)); }
static void branch(char* out65, const char* a, const char* b){ snprintf(LINE, sizeof LINE, "branch %s %s", a, b); strcpy(out65, ask(LINE)); }
static int tweak(u8 out32[32], int key, const char* root){ snprintf(LINE, sizeof LINE, "tweak %d %s", key, root); const char* rsp = ask(LINE); char xh[80]; int par; sscanf(rsp, "%64s %d", xh, &par); unhex(xh, out32, 32); return par; }
/* ---- scripts ---- */
static void spk_p2pkh(buf* o, int k){ u8 h[20]; hash160(h, PUB[k], 33); put1(o, 0x76); put1(o, 0xa9); putpush(o, h, 20); put1(o, 0x88); put1(o, 0xac); }
static void spk_p2pk(buf* o, int k){ putpush(o, PUB[k], 33); put1(o, 0xac); }
static void spk_multisig(buf* o, int m, int n, const int* keys){ putnum(o, m); for (int i = 0; i < n; i++) putpush(o, PUB[keys[i]], 33); putnum(o, n); put1(o, 0xae); }
static void spk_p2sh(buf* o, const buf* redeem){ u8 h[20]; hash160(h, redeem->b, redeem->n); put1(o, 0xa9); putpush(o, h, 20); put1(o, 0x87); }
static void spk_p2wpkh(buf* o, int k){ u8 h[20]; hash160(h, PUB[k], 33); put1(o, 0x00); putpush(o, h, 20); }
static void spk_p2wsh(buf* o, const buf* ws){ u8 h[32]; sha256_full(h, ws->b, ws->n); put1(o, 0x00); putpush(o, h, 32); }
static void spk_p2tr(buf* o, const u8 x[32]){ put1(o, 0x51); putpush(o, x, 32); }
/* ---- case state ---- */
static int g_nIn, g_mut; static const char* g_tmpl; static const char* g_mutname;
static int F_TMPL = -1, F_MAXIN = 0, F_HT = -1, F_MUT = -1, F_ANNEX = -1;   /* debug forcing knobs (env) */
static void setwit(txin* in, int idx, const u8* d, int n){ memcpy(in->wit[idx], d, (size_t)n); in->witlen[idx] = (u32)n; }
static const char* MUTS[] = { "none", "flip-sig-byte", "wrong-key", "wrong-hashtype-byte", "wrong-amount-signed", "drop-witness-item", "extra-witness-item", "bad-cb-parity", "uncommitted-annex", "non-DER-sig", "empty-sig", "flip-script-byte" };
static int choose_mut(void){ if (F_MUT >= 0) return F_MUT; if (r(3)) return 0; return 1 + (int)r(11); }
static int sig_mut_key(int k){ return g_mut == 2 ? (k + 1) % NKEYS : k; }
static u64 sig_mut_amount(u64 a){ return g_mut == 4 ? a + 1 : a; }
static void mutate_sig(u8* sig, int* n){
    if (*n == 0) return;
    switch (g_mut){
    case 1: sig[(int)r((unsigned)*n)] ^= 1 << r(8); break;
    case 3: sig[*n - 1] ^= 0x02; break;
    case 9: if (sig[0] == 0x30) sig[0] = 0x31; else sig[0] ^= 0x80; break;
    case 10: *n = 0; break;
    default: break;
    }
}
static int random_hashtype_legacy(void){ static const int H[] = {1,1,1,2,3,0x81,0x82,0x83}; return F_HT >= 0 ? F_HT : H[r(8)]; }
static int random_hashtype_tap(void){ static const int H[] = {0,0,1,2,3,0x81,0x82,0x83}; return F_HT >= 0 ? F_HT : H[r(8)]; }
/* build the transaction skeleton; input g_nIn gets the template afterwards */
static void build_skeleton(void){
    memset(&T, 0, sizeof T);
    T.version = r(4) == 0 ? 1 : 2; T.locktime = r(3) == 0 ? 0 : (r(2) ? r(500000000) : 500000000u + r(100000000)); T.nin = F_MAXIN ? F_MAXIN : 1 + (int)r(MAXIN); T.nout = 1 + (int)r(MAXOUT);
    for (int i = 0; i < T.nin; i++){ for (int k = 0; k < 32; k++) T.in[i].txid[k] = (u8)rnd(); T.in[i].vout = r(5); T.in[i].seq = r(3) == 0 ? 0xffffffff : (r(2) ? 0xfffffffe : r(0x0040ffff)); T.in[i].amount = 1000 + r(100000000); T.in[i].spk.n = 0; spk_p2pkh(&T.in[i].spk, (int)r(NKEYS)); }
    for (int i = 0; i < T.nout; i++){ T.out[i].value = r(50000000); T.out[i].spk.n = 0; if (r(2)) spk_p2wpkh(&T.out[i].spk, (int)r(NKEYS)); else spk_p2pkh(&T.out[i].spk, (int)r(NKEYS)); }
    g_nIn = (int)r((unsigned)T.nin);
}
/* legacy-style script + its satisfying pushes (for bare, P2SH redeem, P2WSH witness) */
static int g_keys[3], g_m, g_n, g_kind;   /* kind 0 p2pk, 1 p2pkh, 2 multisig, 3 cltv+p2pk, 4 csv+p2pk */
static void gen_inner_script(buf* o){
    g_kind = (int)r(5); g_n = 1 + (int)r(3); g_m = 1 + (int)r((unsigned)g_n); for (int i = 0; i < 3; i++) g_keys[i] = (int)r(NKEYS);
    o->n = 0;
    if (g_kind == 0) spk_p2pk(o, g_keys[0]);
    else if (g_kind == 1) spk_p2pkh(o, g_keys[0]);
    else if (g_kind == 2) spk_multisig(o, g_m, g_n, g_keys);
    else if (g_kind == 3){ int64_t lt = r(2) ? (int64_t)T.locktime - (int64_t)r(1000) : (int64_t)T.locktime + 1; if (lt < 0) lt = 0; putnum(o, lt); put1(o, 0xb1); put1(o, 0x75); spk_p2pk(o, g_keys[0]); }
    else { int64_t s = r(2) ? (int64_t)(T.in[g_nIn].seq & 0x0040ffff) : (int64_t)(T.in[g_nIn].seq & 0x0040ffff) + 1; putnum(o, s & 0x0040ffff); put1(o, 0xb2); put1(o, 0x75); spk_p2pk(o, g_keys[0]); }
}
/* the satisfying data for gen_inner_script: as scriptSig pushes (legacy) or witness items (v0) */
static void gen_inner_sat(int sigv, const buf* scode, int nIn, buf* ss, txin* in, int* nw){
    int ht = random_hashtype_legacy(); u8 sig[80]; int sl;
    u64 amt = sig_mut_amount(T.in[nIn].amount);
    if (g_kind == 2){
        if (sigv == 0) put1(ss, 0x00); else { setwit(in, (*nw)++, (const u8*)"", 0); }
        int ki = 0; for (int i = 0; i < g_n && ki < g_m; i++){ /* sign with the first m keys in key order (Core requires that order) */
            sl = sign_ecdsa(sig, sig_mut_key(g_keys[i]), sigv, ht, amt, nIn, scode->b, scode->n); if (ki == 0) mutate_sig(sig, &sl); ki++;
            if (sigv == 0) putpush(ss, sig, sl); else setwit(in, (*nw)++, sig, sl); }
    } else {
        sl = sign_ecdsa(sig, sig_mut_key(g_keys[0]), sigv, ht, amt, nIn, scode->b, scode->n); mutate_sig(sig, &sl);
        if (sigv == 0) putpush(ss, sig, sl); else setwit(in, (*nw)++, sig, sl);
        if (g_kind == 1){ if (sigv == 0) putpush(ss, PUB[g_keys[0]], 33); else setwit(in, (*nw)++, PUB[g_keys[0]], 33); }
    }
}
static void build_case(void){
    build_skeleton(); g_mut = choose_mut(); g_mutname = MUTS[g_mut];
    txin* in = &T.in[g_nIn]; int nIn = g_nIn; static buf inner, redeem; inner.n = 0; redeem.n = 0;
    int tm = F_TMPL >= 0 ? F_TMPL : (int)r(9);
    if (tm == 0){ g_tmpl = "bare"; gen_inner_script(&inner); in->spk = inner; if (g_mut == 11) in->spk.b[r((unsigned)in->spk.n)] ^= 1; in->ss.n = 0; gen_inner_sat(0, &in->spk, nIn, &in->ss, in, &in->nwit); }
    else if (tm == 1){ g_tmpl = "p2sh"; gen_inner_script(&inner); in->spk.n = 0; spk_p2sh(&in->spk, &inner); in->ss.n = 0; gen_inner_sat(0, &inner, nIn, &in->ss, in, &in->nwit); if (g_mut == 11) inner.b[r((unsigned)inner.n)] ^= 1; putpush(&in->ss, inner.b, inner.n); }
    else if (tm == 2){ g_tmpl = "p2wpkh"; int k = (int)r(NKEYS); in->spk.n = 0; spk_p2wpkh(&in->spk, k); static buf sc; sc.n = 0; spk_p2pkh(&sc, k); in->ss.n = 0; in->nwit = 0; g_kind = 1; g_keys[0] = k; gen_inner_sat(1, &sc, nIn, &in->ss, in, &in->nwit); }
    else if (tm == 3){ g_tmpl = "p2wsh"; gen_inner_script(&inner); in->spk.n = 0; spk_p2wsh(&in->spk, &inner); in->ss.n = 0; in->nwit = 0; gen_inner_sat(1, &inner, nIn, &in->ss, in, &in->nwit); if (g_mut == 11) inner.b[r((unsigned)inner.n)] ^= 1; setwit(in, in->nwit++, inner.b, inner.n); }
    else if (tm == 4){ g_tmpl = "p2sh-p2wpkh"; int k = (int)r(NKEYS); redeem.n = 0; spk_p2wpkh(&redeem, k); in->spk.n = 0; spk_p2sh(&in->spk, &redeem); in->ss.n = 0; putpush(&in->ss, redeem.b, redeem.n); static buf sc; sc.n = 0; spk_p2pkh(&sc, k); in->nwit = 0; g_kind = 1; g_keys[0] = k; { buf dummy; dummy.n = 0; gen_inner_sat(1, &sc, nIn, &dummy, in, &in->nwit); } }
    else if (tm == 5){ g_tmpl = "p2sh-p2wsh"; gen_inner_script(&inner); redeem.n = 0; spk_p2wsh(&redeem, &inner); in->spk.n = 0; spk_p2sh(&in->spk, &redeem); in->ss.n = 0; putpush(&in->ss, redeem.b, redeem.n); in->nwit = 0; { buf dummy; dummy.n = 0; gen_inner_sat(1, &inner, nIn, &dummy, in, &in->nwit); } setwit(in, in->nwit++, inner.b, inner.n); }
    else if (tm == 6){ /* taproot key path */
        g_tmpl = "p2tr-keypath"; int k = (int)r(NKEYS); char root[80] = "-"; static buf leaf; leaf.n = 0;
        if (r(2)){ putpush(&leaf, XONLY[(int)r(NKEYS)], 32); put1(&leaf, 0xac); leafhash(root, leaf.b, leaf.n); }
        u8 outk[32]; tweak(outk, k, root); in->spk.n = 0; spk_p2tr(&in->spk, outk); in->ss.n = 0; in->nwit = 0;
        int ht = random_hashtype_tap(); u8 annex[40]; int al = 0; if (F_ANNEX == 0 ? 0 : (F_ANNEX == 1 || r(3) == 0)){ al = 1 + (int)r(30); annex[0] = 0x50; for (int i = 1; i < al; i++) annex[i] = (u8)rnd(); }
        u8 sig[80]; int sl = sign_schnorr(sig, sig_mut_key(k), 2, ht, nIn, root, "-", 0xffffffff, (g_mut == 8) ? NULL : annex, (g_mut == 8) ? 0 : al);
        if (g_mut == 1 || g_mut == 3 || g_mut == 10) mutate_sig(sig, &sl);
        setwit(in, in->nwit++, sig, sl); if (al) setwit(in, in->nwit++, annex, al);
    } else if (tm == 7 || tm == 8){ /* taproot script path */
        g_tmpl = tm == 7 ? "p2tr-script" : "p2tr-script-2leaf"; int ik = (int)r(NKEYS); static buf leaf; leaf.n = 0; int kind = (int)r(8); int k1 = (int)r(NKEYS), k2 = (int)r(NKEYS); u32 codesep = 0xffffffff; int nsigs = 1; int succ = 0;
        if (kind == 0){ putpush(&leaf, XONLY[k1], 32); put1(&leaf, 0xac); }
        else if (kind == 1){ putpush(&leaf, XONLY[k1], 32); put1(&leaf, 0xad); putpush(&leaf, XONLY[k2], 32); put1(&leaf, 0xac); nsigs = 2; }
        else if (kind == 2){ putpush(&leaf, XONLY[k1], 32); put1(&leaf, 0xac); putpush(&leaf, XONLY[k2], 32); put1(&leaf, 0xba); put1(&leaf, 0x52); put1(&leaf, 0x9c); nsigs = 2; }
        else if (kind == 3){ put1(&leaf, 0xab); codesep = 0; putpush(&leaf, XONLY[k1], 32); put1(&leaf, 0xac); }
        else if (kind == 4){ static const u8 S[] = {0x50,0x62,0x7e,0x7f,0x80,0x81,0x83,0x84,0x85,0x86,0x89,0x8a,0x8d,0x8e,0x95,0x96,0x97,0x98,0x99,0xbb,0xc0,0xfe}; put1(&leaf, S[r(sizeof S)]); for (int i = 0; i < (int)r(6); i++) put1(&leaf, (int)rnd()); succ = 1; nsigs = 0; }
        else if (kind == 5){ int64_t lt = r(2) ? (int64_t)T.locktime - (int64_t)r(1000) : (int64_t)T.locktime + 1; if (lt < 0) lt = 0; putnum(&leaf, lt); put1(&leaf, 0xb1); put1(&leaf, 0x75); putpush(&leaf, XONLY[k1], 32); put1(&leaf, 0xac); }
        else if (kind == 6){ putpush(&leaf, XONLY[k1], 32); put1(&leaf, 0xac); put1(&leaf, 0xb0); }
        else { putpush(&leaf, XONLY[k1], 32); put1(&leaf, 0xac); put1(&leaf, 0x69); put1(&leaf, 0x51); }   /* CHECKSIG VERIFY 1 */
        if (g_mut == 11) leaf.b[r((unsigned)leaf.n)] ^= 1;
        char lh[80], root[80]; leafhash(lh, leaf.b, leaf.n); u8 sib[32]; int two = tm == 8; if (two){ for (int i = 0; i < 32; i++) sib[i] = (u8)rnd(); char sh[80]; hexstr(sh, sib, 32); branch(root, lh, sh); } else strcpy(root, lh);
        u8 outk[32]; int par = tweak(outk, ik, root); in->spk.n = 0; spk_p2tr(&in->spk, outk); in->ss.n = 0; in->nwit = 0;
        int ht = random_hashtype_tap(); u8 annex[40]; int al = 0; if (F_ANNEX == 0 ? 0 : (F_ANNEX == 1 || r(4) == 0)){ al = 1 + (int)r(30); annex[0] = 0x50; for (int i = 1; i < al; i++) annex[i] = (u8)rnd(); }
        /* witness: [sigs in reverse consumption order...] script control [annex] */
        if (nsigs >= 1){ int keys[2] = {k1, k2}; for (int s = nsigs - 1; s >= 0; s--){ u8 sig[80]; int sl = sign_schnorr(sig, sig_mut_key(keys[s]), 3, ht, nIn, "-", lh, codesep, (g_mut == 8) ? NULL : annex, (g_mut == 8) ? 0 : al); if (s == 0 && (g_mut == 1 || g_mut == 3 || g_mut == 10)) mutate_sig(sig, &sl); setwit(in, in->nwit++, sig, sl); } }
        else if (!succ) setwit(in, in->nwit++, (const u8*)"", 0);
        setwit(in, in->nwit++, leaf.b, leaf.n);
        u8 cb[65]; cb[0] = (u8)(0xc0 | (par ^ (g_mut == 7 ? 1 : 0))); memcpy(cb + 1, XONLY[ik], 32); int cbl = 33; if (two){ memcpy(cb + 33, sib, 32); cbl = 65; }
        setwit(in, in->nwit++, cb, cbl); if (al) setwit(in, in->nwit++, annex, al);
    }
    if (g_mut == 5 && in->nwit > 0) in->nwit--;
    if (g_mut == 6 && in->nwit < MAXWIT){ u8 x[3] = {1,2,3}; if (in->nwit && in->wit[in->nwit-1][0] == 0x50 && in->witlen[in->nwit-1] >= 1){ setwit(in, in->nwit, in->wit[in->nwit-1], (int)in->witlen[in->nwit-1]); setwit(in, in->nwit-1, x, 3); in->nwit++; } else setwit(in, in->nwit++, x, 3); }
}
/* ---- our side, exactly as daemon/tx_verify.c dispatches ---- */
static u8 work[1 << 16];
static int ours_verify(u64 flags, int* err, const char** reason){
    txin* in = &T.in[g_nIn]; static buf t; t.n = 0; ser_tx(&t, 1); *err = 0; *reason = "";
    const u8* wp[MAXWIT]; u32 wl[MAXWIT]; for (int k = 0; k < in->nwit; k++){ wp[k] = in->wit[k]; wl[k] = in->witlen[k]; }
    if (in->spk.n == 34 && in->spk.b[0] == 0x51 && in->spk.b[1] == 0x20 && (flags & F_TAPROOT)){
        if (in->ss.n != 0){ *reason = "p2tr scriptSig must be empty"; *err = -1; return 0; }
        if (in->nwit == 0){ *reason = "p2tr empty witness"; *err = -1; return 0; }
        static u8 prevouts[36 * MAXIN], amounts[8 * MAXIN], spks[2000]; int sp = 0;
        for (int i = 0; i < T.nin; i++){ memcpy(prevouts + 36*i, T.in[i].txid, 32); for (int k = 0; k < 4; k++) prevouts[36*i+32+k] = (T.in[i].vout >> (8*k)) & 255; for (int k = 0; k < 8; k++) amounts[8*i+k] = (T.in[i].amount >> (8*k)) & 255; spks[sp++] = (u8)T.in[i].spk.n; memcpy(spks + sp, T.in[i].spk.b, (size_t)T.in[i].spk.n); sp += T.in[i].spk.n; }
        static buf ns; ns.n = 0; ser_tx(&ns, 0);   /* daemon/tx_verify.c hands the taproot verifier the witness-STRIPPED tx (tapagg_build: strip_witness) */
        *err = -1; return taproot_verify_input(in->spk.b, wp, wl, (u32)in->nwit, ns.b, ns.n, g_nIn, prevouts, amounts, spks, T.nin, reason);
    }
    if (flags & F_WITNESS){
        u32 wver = 0, wplen = 0; const u8* wprog = 0; int wrapped = 0;
        int cls = sv_classify_segwit(in->spk.b, (u32)in->spk.n, in->ss.b, (u32)in->ss.n, &wver, &wprog, &wplen, &wrapped);
        if (cls < 0){ *err = 42; return 0; }                                   /* WITNESS_MALLEATED_P2SH */
        if (cls > 0){
            if (!wrapped && in->ss.n != 0){ *err = 41; return 0; }             /* WITNESS_MALLEATED */
            if (wver == 0){
                if (wplen == 20 && in->nwit != 2){ *err = 40; return 0; }       /* WITNESS_PROGRAM_MISMATCH */
                if (wplen == 32 && in->nwit < 1){ *err = 39; return 0; }        /* WITNESS_PROGRAM_WITNESS_EMPTY */
                *err = sv_verify_witness_v0(wprog, wplen, wp, wl, (u32)in->nwit, in->amount, flags, (unsigned long)g_nIn, t.b, (unsigned long)t.n, work, sizeof work);
                return *err == 0;
            }
            if (flags & F_DISC_WPROG){ *err = 34; return 0; }                 /* DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM */
            return 1;
        }
    }
    if (in->nwit && !(flags & F_WITNESS)){ /* Core: witness present but not consumed -> WITNESS_UNEXPECTED only when WITNESS flag set; without it, ignored */ }
    static buf lt; lt.n = 0; ser_tx(&lt, 0);   /* daemon/tx_verify.c: legacy inputs see legacy_tx_view(), the witness-stripped serialization */
    *err = sv_verify_script(in->ss.b, (unsigned long)in->ss.n, in->spk.b, (unsigned long)in->spk.n, flags, (unsigned long)g_nIn, lt.b, (unsigned long)lt.n, work, sizeof work);
    if (*err == 0 && in->nwit && (flags & F_WITNESS)){ *err = 43; return 0; }  /* WITNESS_UNEXPECTED: Core raises it AFTER the scripts ran */
    return *err == 0;
}
int main(int argc, char** argv){
    long count = argc > 1 ? atol(argv[1]) : 2000; rs = argc > 2 ? strtoull(argv[2], 0, 0) : 0x1234567; if (!rs) rs = 1;
    const char* oracle = argc > 3 ? argv[3] : "../validation/core_verify_oracle"; int shown_max = argc > 4 ? atoi(argv[4]) : 20;
    if (getenv("FZ_TMPL")) F_TMPL = atoi(getenv("FZ_TMPL"));
    if (getenv("FZ_MAXIN")) F_MAXIN = atoi(getenv("FZ_MAXIN"));
    if (getenv("FZ_HT")) F_HT = atoi(getenv("FZ_HT"));
    if (getenv("FZ_MUT")) F_MUT = atoi(getenv("FZ_MUT"));
    if (getenv("FZ_ANNEX")) F_ANNEX = atoi(getenv("FZ_ANNEX"));
    spawn_oracle(oracle);
    for (int i = 0; i < NKEYS; i++){ snprintf(LINE, sizeof LINE, "key %d", i); const char* rsp = ask(LINE); char a[80], b[80]; sscanf(rsp, "%66s %64s", a, b); unhex(a, PUB[i], 33); unhex(b, XONLY[i], 32); }
    long verdict_mm = 0, code_mm = 0, both_ok = 0, both_fail = 0, shown = 0; static long tmpl_ok[16], tmpl_n[16];
    for (long c = 0; c < count; c++){
        build_case(); render();
        int mode = r(2); u64 flags = mode ? STANDARD : CONSENSUS;
        int is_tap = T.in[g_nIn].spk.n == 34 && T.in[g_nIn].spk.b[0] == 0x51;
        if (is_tap) flags = CONSENSUS | (mode ? (F_STRICTENC|F_LOW_S|F_MINIMALDATA|F_CLEANSTACK|F_NULLFAIL|F_MINIMALIF) : 0);   /* our taproot path has no policy knobs */
        snprintf(LINE, sizeof LINE, "verify %llx %s %d %s", (unsigned long long)flags, HEXTX, g_nIn, HEXSP);
        const char* rsp = ask(LINE); int cok = 0, cerr = 0; sscanf(rsp, "%d %d", &cok, &cerr);
        int oerr = 0; const char* reason = ""; int ook = ours_verify(flags, &oerr, &reason);
        if (getenv("FZ_ONLY") && atol(getenv("FZ_ONLY")) == c){ char h1[4000], h2[4000]; hexstr(h1, T.in[g_nIn].ss.b, (size_t)T.in[g_nIn].ss.n); hexstr(h2, T.in[g_nIn].spk.b, (size_t)T.in[g_nIn].spk.n);
            printf("ONLY case %ld tmpl=%s mut=%s kind=%d m=%d n=%d keys=%d,%d,%d nwit=%d\n  scriptSig=%s\n  spk=%s\n  ours=%d err=%d core=%d err=%d\n", c, g_tmpl, g_mutname, g_kind, g_m, g_n, g_keys[0], g_keys[1], g_keys[2], T.in[g_nIn].nwit, h1, h2, ook, oerr, cok, cerr); }
        if (getenv("FZ_DUMP")) printf("VEC %s %s %d %d %llx %s %d %s\n", g_tmpl, g_mutname, cok, cerr, (unsigned long long)flags, HEXTX, g_nIn, HEXSP);
        int ti = (int)(g_tmpl[0] == 'b' ? 0 : g_tmpl[0] == 'p' && g_tmpl[1] == '2' && g_tmpl[2] == 's' ? 1 : g_tmpl[3] == 'p' ? 2 : g_tmpl[3] == 's' ? 3 : 4); tmpl_n[ti]++; if (ook && cok) tmpl_ok[ti]++;
        int same = (ook == cok); int code_same = same && (ook || oerr < 0 || oerr == cerr);
        if (same){ if (ook) both_ok++; else both_fail++; }
        if (!same) verdict_mm++; else if (!code_same) code_mm++;
        if ((!same || !code_same) && shown < shown_max){ shown++;
            printf("%s #%ld case %ld  tmpl=%s mut=%s nIn=%d/%d flags=%llx\n  ours: %d err=%d %s\n  core: %d err=%d\n  verify %llx %s %d %s\n", same ? "CODE-MISMATCH" : "VERDICT-MISMATCH", same ? code_mm : verdict_mm, c, g_tmpl, g_mutname, g_nIn, T.nin, (unsigned long long)flags, ook, oerr, reason, cok, cerr, (unsigned long long)flags, HEXTX, g_nIn, HEXSP); }
    }
    printf("cases=%ld  both-ok=%ld  both-fail=%ld  VERDICT-MISMATCHES=%ld  code-only-mismatches=%ld\n", count, both_ok, both_fail, verdict_mm, code_mm);
    printf("accepted-by-both per template: bare %ld/%ld  p2sh %ld/%ld  p2wpkh %ld/%ld  p2wsh %ld/%ld  taproot %ld/%ld\n", tmpl_ok[0], tmpl_n[0], tmpl_ok[1], tmpl_n[1], tmpl_ok[2], tmpl_n[2], tmpl_ok[3], tmpl_n[3], tmpl_ok[4], tmpl_n[4]);
    return verdict_mm ? 1 : 0;
}

/* tests/test_ir10_p2pkh_bounds.c -- IR-10 (INTERP_REVIEW_2026-09-05):
 * verify_p2pkh walked the raw tx with no bound against the tx end or the
 * scriptSig end, assumed direct single-byte pushes, and its private
 * parse_varint clobbered cl while the input walk counted in rcx.
 *
 *   1. guard page: a tx whose target input has an EMPTY scriptSig, placed so
 *      the byte after it is PROT_NONE. Pre-fix: sequence[0]=0xff is read as
 *      the sig length and the walk runs ~250 bytes past the buffer -> SIGSEGV
 *      in the forked child. Fixed: returns 0 cleanly.
 *   2. counter clobber: a signed 3-input tx whose input 0 carries a 253-byte
 *      scriptSig (varint 0xfd, two length bytes). parse_varint left cl = 8,
 *      so the walk counter jumped past the target and .found landed on
 *      input 1 instead of input 2. Legacy SIGHASH_ALL blanks the OTHER
 *      inputs' scriptSigs, so input 0's junk cannot disturb input 2's
 *      signature: the walk either reaches input 2 (verifies, 1) or it does
 *      not. Watched to FAIL against the unfixed object.
 *   3. controls: a normal signed 1-input spend verifies; a corrupted
 *      signature does not; an OP_PUSHDATA1-encoded sig is refused, not
 *      misparsed. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
typedef unsigned char u8;

extern int  verify_p2pkh(const u8* tx, unsigned long txlen, unsigned long idx,
                         const u8* pv, unsigned long pvlen, u8* work, unsigned long cap);
extern void scalar_to_pubkey(u8 pub[33], const u8 k[32]);
extern void hash160(u8 out[20], const void* in, long long len);
extern int  sighash_all(u8 out[32], const u8* tx, unsigned long txlen, unsigned long input_index,
                        const u8* script, unsigned long script_len, u8* preimg, unsigned long cap);
extern int  wallet_ecdsa_sign(uint64_t out_r[4], uint64_t out_s[4], const u8 z_be[32], const u8 priv_be[32]);

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }
static u8 work[1<<16];

static void limb_to_be(u8 out[33], const uint64_t v[4], int* olen){
    u8 tmp[32];
    for (int i = 0; i < 32; i++) tmp[31-i] = (u8)(v[i/8] >> ((i%8)*8));
    int s = 0; while (s < 31 && tmp[s] == 0) s++;
    if (tmp[s] & 0x80){ out[0] = 0; memcpy(out+1, tmp+s, 32-s); *olen = 33-s; }
    else { memcpy(out, tmp+s, 32-s); *olen = 32-s; }
}
/* DER(r, low-S(s)) || 0x01 */
static int der_enc(u8* out, const uint64_t r[4], const uint64_t s[4]){
    uint64_t n[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
    uint64_t half[4]={0xDFE92F46681B20A0ULL,0x5D576E7357A4501DULL,0xFFFFFFFFFFFFFFFEULL,0x7FFFFFFFFFFFFFFFULL};
    uint64_t sn[4]; int borrow = 0;
    for (int i = 0; i < 4; i++){ unsigned __int128 u = (unsigned __int128)n[i]-s[i]-borrow; sn[i] = (uint64_t)u; borrow = (u>>64)&1; }
    int gt = 0; for (int i = 3; i >= 0; i--){ if (s[i] > half[i]){ gt = 1; break; } if (s[i] < half[i]) break; }
    const uint64_t* su = gt ? sn : s;
    u8 rb[33], sb[33]; int rl, sl; limb_to_be(rb, r, &rl); limb_to_be(sb, su, &sl);
    size_t k = 0; out[k++] = 0x30; size_t lp = k++; out[k++] = 0x02; out[k++] = (u8)rl; memcpy(out+k, rb, rl); k += rl;
    out[k++] = 0x02; out[k++] = (u8)sl; memcpy(out+k, sb, sl); k += sl; out[lp] = (u8)(k-2); out[k++] = 0x01;
    return (int)k;
}

/* legacy tx with `nin` inputs; input i gets scriptSig ss[i]/ssl[i]; one OP_1 output */
static unsigned long build_tx(u8* o, int nin, const u8* const* ss, const unsigned long* ssl){
    u8* p = o; *p++=1; *p++=0; *p++=0; *p++=0; *p++=(u8)nin;
    for (int i = 0; i < nin; i++){
        memset(p, 0x30+i, 32); p += 32; *p++=(u8)i; *p++=0; *p++=0; *p++=0;
        unsigned long L = ssl[i];
        if (L < 0xfd) *p++ = (u8)L; else { *p++ = 0xfd; *p++ = (u8)L; *p++ = (u8)(L>>8); }
        memcpy(p, ss[i], L); p += L;
        *p++=0xff; *p++=0xff; *p++=0xff; *p++=0xff;
    }
    *p++=1; uint64_t v = 50000; memcpy(p, &v, 8); p += 8; *p++=1; *p++=0x51; *p++=0; *p++=0; *p++=0; *p++=0;
    return (unsigned long)(p - o);
}

/* sign input `idx` of the tx that build_tx(nin, ss, ssl) produces, filling ss[idx] */
static unsigned long sign_input(u8* sigscript, int nin, const u8** ss, unsigned long* ssl, int idx,
                                const u8* spk, const u8* priv, const u8* pub33){
    static u8 tx[2048]; static u8 pre[8192]; u8 z[32]; uint64_t r[4], s[4]; u8 der[80];
    unsigned long tl = build_tx(tx, nin, ss, ssl);              /* ss[idx] empty here; sighash replaces it */
    sighash_all(z, tx, tl, (unsigned long)idx, spk, 25, pre, sizeof pre);
    wallet_ecdsa_sign(r, s, z, priv);
    int dl = der_enc(der, r, s);
    u8* q = sigscript; *q++ = (u8)dl; memcpy(q, der, dl); q += dl; *q++ = 33; memcpy(q, pub33, 33); q += 33;
    (void)pub33;
    return (unsigned long)(q - sigscript);
}

/* run verify_p2pkh in a child; returns the child's result, or -1 if it died */
static int run_child(const u8* tx, unsigned long tl, unsigned long idx, const u8* spk){
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0){ alarm(20); int r = verify_p2pkh(tx, tl, idx, spk, 25, work, sizeof work); _exit(r == 1 ? 1 : (r == 0 ? 0 : 2)); }
    int st = 0; waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)){ printf("      (child killed by signal %d)\n", WTERMSIG(st)); return -1; }
    return WEXITSTATUS(st);
}

int main(void){
    static u8 priv[32]; for (int i = 0; i < 32; i++) priv[i] = (u8)(i+3);
    static u8 pub33[33]; scalar_to_pubkey(pub33, priv);
    u8 h[20]; hash160(h, pub33, 33);
    static u8 spk[25]; spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, h, 20); spk[23]=0x88; spk[24]=0xac;

    /* ---- 1. guard page: empty scriptSig on the target input ---- */
    {
        const u8* ss[1] = { (const u8*)"" }; unsigned long ssl[1] = { 0 };
        static u8 tx[256]; unsigned long tl = build_tx(tx, 1, ss, ssl);
        long ps = sysconf(_SC_PAGESIZE);
        u8* base = mmap(NULL, (size_t)ps*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED || mprotect(base+ps, (size_t)ps, PROT_NONE) != 0){ printf("FAIL: mmap\n"); return 1; }
        u8* g = base + ps - tl; memcpy(g, tx, tl);
        int r = run_child(g, tl, 0, spk);
        ck("IR-10 empty scriptSig flush against PROT_NONE: returns 0, no fault", r == 0);
        munmap(base, (size_t)ps*2);
    }
    /* ---- 2. counter clobber: 253-byte scriptSig on input 0, target input 2 ---- */
    {
        static u8 junk253[253]; memset(junk253, 0x00, sizeof junk253);   /* 253 x OP_0: push-only, harmless */
        static u8 junk1[1] = { 0x00 };
        static u8 sig2[128];
        const u8* ss[3] = { junk253, junk1, (const u8*)"" }; unsigned long ssl[3] = { 253, 1, 0 };
        ssl[2] = sign_input(sig2, 3, ss, ssl, 2, spk, priv, pub33); ss[2] = sig2;
        static u8 tx[2048]; unsigned long tl = build_tx(tx, 3, ss, ssl);
        int r = run_child(tx, tl, 2, spk);
        ck("IR-10 signed input 2 behind a 253-byte scriptSig on input 0 VERIFIES (walk reaches it)", r == 1);
    }
    /* ---- 3. controls ---- */
    {
        static u8 sig[128];
        const u8* ss[1] = { (const u8*)"" }; unsigned long ssl[1] = { 0 };
        ssl[0] = sign_input(sig, 1, ss, ssl, 0, spk, priv, pub33); ss[0] = sig;
        static u8 tx[512]; unsigned long tl = build_tx(tx, 1, ss, ssl);
        ck("control: signed 1-input spend verifies", run_child(tx, tl, 0, spk) == 1);
        static u8 bad[128]; memcpy(bad, sig, ssl[0]); bad[12] ^= 0x40;
        const u8* ssb[1] = { bad }; unsigned long sslb[1] = { ssl[0] };
        tl = build_tx(tx, 1, ssb, sslb);
        ck("control: corrupted signature does not verify", run_child(tx, tl, 0, spk) == 0);
        /* OP_PUSHDATA1-encoded sig: <0x4c><len><sig> -- refused, not misparsed */
        static u8 pd[128]; pd[0] = 0x4c; memcpy(pd+1, sig, ssl[0]);
        const u8* ssp[1] = { pd }; unsigned long sslp[1] = { ssl[0] + 1 };
        tl = build_tx(tx, 1, ssp, sslp);
        ck("control: OP_PUSHDATA1-encoded scriptSig is refused (0), no fault", run_child(tx, tl, 0, spk) == 0);
    }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}

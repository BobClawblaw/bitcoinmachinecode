/* test_interp_legacy_spend.c -- real ECDSA OP_CHECKSIG / OP_CHECKMULTISIG
 * spends driven through the ASM script interpreter (bitcoin_interp.asm) with a
 * GENUINE legacy (ECDSA) checksig_fn wired in.
 *
 * WHY (FINDING-1-adjacent, closes the last interpreter gap): the taproot test
 * (test_taproot_sighash.c) already drives real SCHNORR CHECKSIG/CHECKSIGADD
 * through the interpreter, and test_interp.c only wires a FAKE "return 1"
 * callback. So legacy ECDSA OP_CHECKSIG&CHECKMULTISIG as executed by
 * bitcoin_interp.asm had NO real-signature coverage. This test proves the
 * legacy OP_CHECKSIG / OP_CHECKMULTISIG path through the interpreter accepts a
 * genuine P2PKH and a 2-of-3 P2SH spend and rejects corrupt signatures -- the
 * same accept/reject behavior Core enforces for these scripts.
 *
 * The checksig_fn body reuses the EXACT audited legacy primitives already used
 * by bitcoin_verify.c (sighash_all + der_parse_sig + pubkey_parse +
 * ecdsa_verify) and by wallet_core.c for signing (wallet_ecdsa_sign), so this
 * is not a new crypto implementation -- it is the existing proven logic wired
 * through the interpreter's OP_CHECKSIG dispatch.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

typedef unsigned long long u64;

#define ELEM_SIZE 528
#define ELEM_DATA_OFF 4
#define MAX_STACK 1000

/* same struct layout as interp_shim.c / test_taproot_sighash.c */
struct script_state {
    uint8_t* main_elems; size_t main_sp;
    uint8_t* alt_elems;  size_t alt_sp;
    uint8_t* script;     size_t script_len;
    int      sigversion; uint64_t flags;
    uint8_t* work;       size_t work_cap;
    uint64_t* error_out;
    void*    checksig_ctx;
    uint64_t (*checksig_fn)(void*,const uint8_t*,size_t,const uint8_t*,size_t,const void*);
};
extern int script_eval(struct script_state* st);

/* audited crypto primitives (asm) */
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char k[32]);
extern void hash160(unsigned char out[20], const void* in, long long len);
extern int  sighash_all(unsigned char out[32], const unsigned char* tx, unsigned long txlen,
                        unsigned long input_index, const unsigned char* script,
                        unsigned long script_len, unsigned char* preimg, unsigned long cap);
extern int  wallet_ecdsa_sign(uint64_t out_r[4], uint64_t out_s[4],
                              const unsigned char z_be[32], const unsigned char priv_be[32]);
extern int  der_parse_sig(const unsigned char* sig, unsigned long slen,
                          uint64_t r[4], uint64_t s[4], uint32_t* hashtype);
extern int  pubkey_parse(const unsigned char* pub, unsigned long publen,
                         uint64_t qx[4], uint64_t qy[4]);
extern int  ecdsa_verify(const uint64_t z[4], const uint64_t r[4], const uint64_t s[4],
                         const uint64_t Qx[4], const uint64_t Qy[4]);

static int fails = 0, checks = 0;
static unsigned long cb_calls = 0;   /* count how many times checksig_fn is run */
static void ck(const char* name, int ok){
    checks++;
    if(ok) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails++; }
}

/* minimal DER encode of (r,s) limb arrays + SIGHASH_ALL (0x01) trailer.
 * Mirrors wallet_core.c der_signature (canonical, minimal BE). */
static void limb_to_be(uint8_t out[33], const uint64_t v[4], int* olen){
    uint8_t tmp[32];
    for(int i=0;i<4;i++) for(int b=0;b<8;b++) tmp[i*8+b]=(uint8_t)(v[i]>>(8*b));
    int s=0; while(s<31 && tmp[s]==0) s++;
    if(tmp[s]&0x80){ out[0]=0; memcpy(out+1,tmp+s,32-s); *olen=33-s; }
    else { memcpy(out,tmp+s,32-s); *olen=32-s; }
    if(*olen>33) *olen=33;
}
static int der_enc(unsigned char* out, const uint64_t r[4], const uint64_t s[4]){
    uint8_t rb[33], sb[33]; int rl, sl;
    limb_to_be(rb, r, &rl); limb_to_be(sb, s, &sl);
    if(rl<1||sl<1) return -1;
    size_t n=0;
    out[n++]=0x30; int lenpos=n-1; out[n]=0; n++; /* len patched below */
    out[n++]=0x02; out[n++]=(uint8_t)rl; memcpy(out+n,rb,rl); n+=rl;
    out[n++]=0x02; out[n++]=(uint8_t)sl; memcpy(out+n,sb,sl); n+=sl;
    int body=(int)(n-2); out[lenpos]=(uint8_t)body;
    out[n++]=0x01; /* SIGHASH_ALL */
    return (int)n;
}

/* --- legacy ECDSA checksig_fn per interpreter ABI ----------------------- */
struct leg_ctx { const uint8_t* tx; unsigned long txlen; unsigned long n_in; };
static uint64_t legacy_checksig_fn(void* cptr, const uint8_t* sig, size_t siglen,
                                   const uint8_t* pub, size_t publen, const void* slice){
    cb_calls++;
    struct leg_ctx* c = (struct leg_ctx*)cptr;
    const struct { const uint8_t* p; size_t n; }* sc = (const void*)slice;
    if(!siglen) return 0;
    /* last byte = hashtype; must be SIGHASH_ALL */
    uint8_t ht = sig[siglen-1];
    if((ht & 0x1f)!=1) return 0;
    uint64_t r[4], s[4]; uint32_t dht;
    if(!der_parse_sig(sig, siglen, r, s, &dht)) return 0;
    uint8_t z[32];
    /* sighash over the scriptCode slice (sc->p, sc->n) */
    unsigned char preimg[4096];
    if(!sighash_all(z, c->tx, c->txlen, c->n_in, sc->p, sc->n, preimg, sizeof preimg)) return 0;
    uint64_t zl[4];
    for(int i=0;i<4;i++){ u64 v=0; for(int b=0;b<8;b++) v|=((u64)z[i*8+b])<<(8*b); zl[i]=v; }
    uint64_t qx[4], qy[4];
    if(!pubkey_parse(pub, publen, qx, qy)) return 0;
    return (uint64_t)ecdsa_verify(zl, r, s, qx, qy);
}

/* --- helper: run a script through the interpreter with legacy checksig ---- */
static int run_script(const uint8_t* script, size_t slen,
                      const uint8_t* const init[], const size_t ilen[], size_t ninit,
                      struct leg_ctx* ctx){
    static uint8_t main_elems[MAX_STACK*ELEM_SIZE];
    static uint8_t alt_elems[MAX_STACK*ELEM_SIZE];
    static uint8_t scr[20000]; static uint64_t gerr;
    memset(main_elems,0,sizeof main_elems); memset(alt_elems,0,sizeof alt_elems);
    memcpy(scr, script, slen);
    for(size_t i=0;i<ninit;i++){
        uint8_t* rec = main_elems + i*ELEM_SIZE;
        ((uint32_t*)rec)[0]=(uint32_t)ilen[i];
        memcpy(rec+ELEM_DATA_OFF, init[i], ilen[i]);
    }
    struct script_state st;
    memset(&st,0,sizeof st);
    st.main_elems=main_elems; st.main_sp=ninit;
    st.alt_elems=alt_elems; st.alt_sp=0;
    st.script=scr; st.script_len=slen;
    st.sigversion=0; st.flags=0;
    st.error_out=&gerr; gerr=0;
    st.checksig_ctx=ctx; st.checksig_fn=(void*)(size_t)legacy_checksig_fn;
    return script_eval(&st);
}

/* --- build a minimal SINGLE-INPUT legacy tx (just for sighash) ---------- */
static size_t build_tx(uint8_t* tx){
    /* version 2 ; 1 input (prevout txid 32 x 0x11, idx 0, scriptSig empty, seq ffffffff)
     * ; 1 output (value 50_0000_0000 = 0x12A05F200, script empty) ; locktime 0 */
    size_t n=0;
    tx[n++]=0x02;tx[n++]=0x00;tx[n++]=0x00;tx[n++]=0x00;      /* version */
    tx[n++]=0x01;                                             /* 1 input */
    for(int i=0;i<32;i++) tx[n++]=0x11;                       /* prevout txid */
    tx[n++]=0x00;tx[n++]=0x00;tx[n++]=0x00;tx[n++]=0x00;      /* prevout idx 0 */
    tx[n++]=0x00;                                             /* scriptSig len 0 */
    tx[n++]=0xff;tx[n++]=0xff;tx[n++]=0xff;tx[n++]=0xff;       /* sequence */
    tx[n++]=0x01;                                             /* 1 output */
    tx[n++]=0x00;tx[n++]=0xF2;tx[n++]=0x05;tx[n++]=0x2A;tx[n++]=0x01;tx[n++]=0x00;tx[n++]=0x00;tx[n++]=0x00; /* value */
    tx[n++]=0x00;                                             /* out script len 0 */
    tx[n++]=0x00;tx[n++]=0x00;tx[n++]=0x00;tx[n++]=0x00;      /* locktime */
    return n;
}

static void sign_p2pkh(uint8_t sig[80], size_t* siglen, const uint8_t* tx, size_t txlen,
                       const uint8_t* script, size_t slen, const uint8_t priv[32]){
    uint8_t z[32]; unsigned char preimg[4096];
    sighash_all(z, tx, txlen, 0, script, slen, preimg, sizeof preimg);
    uint64_t r[4], s[4];
    wallet_ecdsa_sign(r, s, z, priv);
    *siglen = (size_t)der_enc(sig, r, s);
}

int main(void){
    /* three fixed private keys + their compressed pubkeys */
    uint8_t k1[32]={1,0}, k2[32]={2,0}, k3[32]={3,0};
    k1[0]=0xb7; k2[0]=0x5a; k3[0]=0xEA; /* vary high bytes so not trivially small */
    uint8_t p1[33], p2[33], p3[33];
    scalar_to_pubkey(p1, k1); scalar_to_pubkey(p2, k2); scalar_to_pubkey(p3, k3);

    uint8_t tx[128]; size_t txlen = build_tx(tx);
    struct leg_ctx ctx = { tx, txlen, 0 };

    /* ---------------- 1. genuine P2PKH OP_CHECKSIG spend ----------------
     * script: OP_DUP OP_HASH160 <20=h(p1)> OP_EQUALVERIFY OP_CHECKSIG
     * init stack: [sig] [p1] (scriptSig pushes sig then pubkey)                 */
    uint8_t h1[20]; hash160(h1, p1, 33);
    uint8_t sc1[26]; int sc1n=0;
    sc1[sc1n++]=0x76; sc1[sc1n++]=0xa9; sc1[sc1n++]=0x14;           /* DUP HASH160 PUSH20 */
    memcpy(sc1+sc1n,h1,20); sc1n+=20;
    sc1[sc1n++]=0x88; sc1[sc1n++]=0xac;                              /* EQUALVERIFY CHECKSIG */

    /* scriptSig is part of the spending context; create a realistic scriptCode =
     * the P2PKH output script itself (the standard). Here we use sc1 as the
     * signature-checking script (scriptCode), which is what OP_CHECKSIG signs. */
    uint8_t sig1[80]; size_t sig1len;
    sign_p2pkh(sig1, &sig1len, tx, txlen, sc1, sc1n, k1);

    printf("== legacy P2PKH OP_CHECKSIG through the ASM interpreter ==\n");
    {
        const uint8_t* init[2] = { sig1, p1 };
        size_t il[2] = { sig1len, 33 };
        int r = run_script(sc1, sc1n, init, il, 2, &ctx);
        ck("P2PKH: genuine sig+pub, OP_CHECKSIG ACCEPT", r==1);
    }
    {
        /* corrupted signature: sign a DIFFERENT message (flipped tx byte) so
         * the sig is genuinely invalid for this script/tx, independent of DER
         * padding positions. */
        uint8_t tx2[128]; memcpy(tx2, tx, txlen); tx2[4] ^= 0x80; /* not same tx */
        uint8_t z2[32]; unsigned char preimg2[4096];
        sighash_all(z2, tx2, txlen, 0, sc1, sc1n, preimg2, sizeof preimg2);
        uint64_t r2[4], s2[4];
        wallet_ecdsa_sign(r2, s2, z2, k1);
        uint8_t badsig[80]; size_t badsiglen = (size_t)der_enc(badsig, r2, s2);
        const uint8_t* init[2] = { badsig, p1 };
        size_t il[2] = { badsiglen, 33 };
        int r = run_script(sc1, sc1n, init, il, 2, &ctx);
        ck("P2PKH: corrupted (wrong-message) sig REJECT", r==0);
    }
    {
        /* wrong pubkey (p2 instead of p1) must reject */
        const uint8_t* init[2] = { sig1, p2 };
        size_t il[2] = { sig1len, 33 };
        int r = run_script(sc1, sc1n, init, il, 2, &ctx);
        ck("P2PKH: wrong pubkey REJECT", r==0);
    }

    /* ---------------- 2. genuine 2-of-3 OP_CHECKMULTISIG P2SH redeem -----
     * script (redeem): OP_2 <p1> <p2> <p3> OP_3 OP_CHECKMULTISIG
     * init stack (scriptSig pushes): [OP_0 (dummy)] [sig3? pair order] ... */
    uint8_t sc2[80]; int sc2n=0;
    sc2[sc2n++]=0x52;                                            /* OP_2 */
    sc2[sc2n++]=0x21; memcpy(sc2+sc2n,p1,33); sc2n+=33;          /* PUSH33 p1 */
    sc2[sc2n++]=0x21; memcpy(sc2+sc2n,p2,33); sc2n+=33;          /* PUSH33 p2 */
    sc2[sc2n++]=0x21; memcpy(sc2+sc2n,p3,33); sc2n+=33;          /* PUSH33 p3 */
    sc2[sc2n++]=0x53;                                            /* OP_3 */
    sc2[sc2n++]=0xae;                                            /* OP_CHECKMULTISIG */

    uint8_t sig2[80], sig3[80]; size_t sig2len, sig3len;
    sign_p2pkh(sig2,&sig2len,tx,txlen,sc2,sc2n,k2);  /* sig for p2 */
    sign_p2pkh(sig3,&sig3len,tx,txlen,sc2,sc2n,k3);  /* sig for p3 */

    printf("\n== legacy 2-of-3 OP_CHECKMULTISIG P2SH redeem via interpreter ==\n");
    {
        /* TWO valid sigs (p2,p3) + dummy OP_0 at bottom -> accept.
         * scriptSig init stack bottom->top: [OP_0, sig(p3), sig(p2)] */
        uint8_t zero=0x00; /* OP_0 dummy */
        const uint8_t* init[3] = { &zero, sig3, sig2 };
        size_t il[3] = { 1, sig3len, sig2len };
        int r = run_script(sc2, sc2n, init, il, 3, &ctx);
        ck("2-of-3: two valid sigs ACCEPT", r==1);
    }
    {
        /* only ONE valid sig -> needs 2 -> reject */
        uint8_t zero=0x00;
        const uint8_t* init[2] = { &zero, sig3 };
        size_t il[2] = { 1, sig3len };
        int r = run_script(sc2, sc2n, init, il, 2, &ctx);
        ck("2-of-3: one valid sig REJECT (needs 2)", r==0);
    }
    {
        /* two sigs but one signer used a DIFFERENT message -> genuinely invalid */
        uint8_t tx3[128]; memcpy(tx3, tx, txlen); tx3[4] ^= 0x40;
        uint8_t z3[32]; unsigned char preimg3[4096];
        sighash_all(z3, tx3, txlen, 0, sc2, sc2n, preimg3, sizeof preimg3);
        uint64_t r3[4], s3[4];
        wallet_ecdsa_sign(r3, s3, z3, k2);               /* wrong-message sig for p2 */
        uint8_t bad2[80]; size_t bad2len = (size_t)der_enc(bad2, r3, s3);
        uint8_t zero=0x00;
        const uint8_t* init[3] = { &zero, sig3, bad2 };
        size_t il[3] = { 1, sig3len, bad2len };
        int r = run_script(sc2, sc2n, init, il, 3, &ctx);
        ck("2-of-3: one wrong-message sig REJECT", r==0);
    }

    printf("\n%s (%d checks, %d failures) [checksig_fn invoked %lu times]\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails, cb_calls);
    return fails?1:0;
}

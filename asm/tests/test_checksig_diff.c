/* test_checksig_diff.c -- bitcoin_checksig.asm vs the C checksig hooks.
 *
 * Phase 2 slice 11. Both hooks have the sv_checksig_fn pointer type, so the
 * strongest available differential drives the REAL interpreter twice over
 * identical inputs -- once with the C hook, once with the asm hook -- via
 * sv_run_v, and compares the verdict and error code. That exercises the
 * hooks exactly as consensus does: FindAndDelete on the BASE path, BIP143
 * over the post-CODESEPARATOR slice on the WITNESS_V0 path, the raw
 * last-byte hashtype rule, and every early-return (empty sig, bad DER,
 * unparseable pubkey).
 *
 * Real signatures come from the wallet's own signer, so accepts are real
 * accepts (not just matching rejections): a P2PKH spend and a P2WPKH spend
 * are signed here and verified through both hooks.
 *
 * Usage: ./test_checksig_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;
typedef struct { u8* e; size_t sp; } sv_stack;
struct sv_ctx {
    const u8* tx; unsigned long txlen; unsigned long nIn;
    u8* work; unsigned long workcap;
    u32 tx_locktime; u32 in_sequence; u32 tx_version;
    u64 amount;
};
typedef u64 (*cs_fn)(void*, const u8*, size_t, const u8*, size_t, const void*);

extern int  sv_run_v(const u8* script, size_t slen, sv_stack* st, u64 flags,
                     struct sv_ctx* ctx, int* err, int sigversion, cs_fn cs);
extern int  sv_get_locktime_context(const u8* tx, unsigned long txlen, unsigned long nIn,
                                    u32* ver, u32* lt, u32* seq);
extern u64  sv_checksig_export(void*, const u8*, size_t, const u8*, size_t, const void*);
extern u64  sv_checksig_witness_v0_export(void*, const u8*, size_t, const u8*, size_t, const void*);
extern u64  sv_checksig_asm(void*, const u8*, size_t, const u8*, size_t, const void*);
extern u64  sv_checksig_witness_v0_asm(void*, const u8*, size_t, const u8*, size_t, const void*);
extern int  wallet_ecdsa_sign(u64 r[4], u64 s[4], const u8 z[32], const u8 priv[32]);
extern int  der_signature_export(u8* out, const u64 r[4], const u64 s[4]);
#define der_signature der_signature_export
extern void scalar_to_pubkey(u8 out33[33], const u8 priv[32]);
extern int  legacy_sighash(u8 out32[32], const u8* tx, unsigned long txlen,
                           unsigned long nIn, const u8* sc, unsigned long scl,
                           int32_t ht, u8* pre, unsigned long cap);
extern long segwit_v0_sighash(u8 out32[32], const u8* tx, int64_t txlen, int64_t n_in,
                              u32 ht, u64 amount, const u8* sc, u64 scl, u8* pre, long cap);
extern void hash160(u8 o[20], const void* in, long long len);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen; abort();
}

static long fails = 0, compared = 0;
#define ELEM_SIZE 528
#define MAX_STACK 1000
static u8 *ec, *ea, workc[1<<20], worka[1<<20], pre[1<<16];

/* run `script` through sv_run_v with each hook; compare ok + err + final sp */
static void diff_run(const char* nm, const u8* script, size_t slen,
                     const u8* const* init, const u32* initlen, u32 ninit,
                     const u8* tx, u64 txlen, u64 amount, int sigversion){
    memset(ec, 0, MAX_STACK*ELEM_SIZE); memset(ea, 0, MAX_STACK*ELEM_SIZE);
    sv_stack sc = { ec, 0 }, sa = { ea, 0 };
    for (u32 i = 0; i < ninit; i++){
        u8* rc = ec + i*ELEM_SIZE; *(u32*)rc = initlen[i]; memcpy(rc+4, init[i], initlen[i]);
        u8* ra = ea + i*ELEM_SIZE; *(u32*)ra = initlen[i]; memcpy(ra+4, init[i], initlen[i]);
        sc.sp++; sa.sp++;
    }
    struct sv_ctx cc = { tx, txlen, 0, workc, sizeof workc, 0,0,0, amount };
    struct sv_ctx ca = { tx, txlen, 0, worka, sizeof worka, 0,0,0, amount };
    sv_get_locktime_context(tx, txlen, 0, &cc.tx_version, &cc.tx_locktime, &cc.in_sequence);
    sv_get_locktime_context(tx, txlen, 0, &ca.tx_version, &ca.tx_locktime, &ca.in_sequence);
    int errc = 0, erra = 0;
    int okc = sv_run_v(script, slen, &sc, (1ULL<<11)|(1ULL<<0), &cc, &errc, sigversion,
                       sigversion ? sv_checksig_witness_v0_export : sv_checksig_export);
    int oka = sv_run_v(script, slen, &sa, (1ULL<<11)|(1ULL<<0), &ca, &erra, sigversion,
                       sigversion ? sv_checksig_witness_v0_asm : sv_checksig_asm);
    compared++;
    if (okc != oka || errc != erra || sc.sp != sa.sp){
        if (fails < 30) printf("FAIL %s: ok %d/%d err %d/%d sp %zu/%zu\n",
                               nm, okc, oka, errc, erra, sc.sp, sa.sp);
        fails++;
    } else if (okc && sc.sp && memcmp(ec, ea, sc.sp*ELEM_SIZE)){
        if (fails < 30){
            size_t off = 0, lim = sc.sp*ELEM_SIZE;
            while (off < lim && ec[off] == ea[off]) off++;
            printf("FAIL %s: stacks differ at +%zu (rec %zu, field-off %zu): C=%02x asm=%02x; len C=%u asm=%u\n",
                   nm, off, off/ELEM_SIZE, off%ELEM_SIZE, ec[off], ea[off],
                   *(u32*)ec, *(u32*)ea);
        }
        fails++;
    }
}

static u64 mk_tx(u8* o){
    u64 n = 0;
    o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0;
    o[n++]=1; for (int k=0;k<36;k++) o[n++]=(u8)(k+3);
    o[n++]=0; o[n++]=0xfe;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    o[n++]=1; for (int k=0;k<8;k++) o[n++]=0; o[n++]=1; o[n++]=0x51;
    o[n++]=0x11;o[n++]=0;o[n++]=0;o[n++]=0;
    return n;
}

int main(void){
    ec = malloc(MAX_STACK*ELEM_SIZE); ea = malloc(MAX_STACK*ELEM_SIZE);
    static u8 tx[128]; u64 txlen = mk_tx(tx);
    static u8 priv[32]; for (int i=0;i<32;i++) priv[i] = (u8)(i+1);
    static u8 pub[33]; scalar_to_pubkey(pub, priv);
    u8 h160[20]; hash160(h160, pub, 33);

    /* ---- BASE: a real P2PKH-style CHECKSIG that must ACCEPT ---- */
    static u8 spk[25];
    spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, h160, 20);
    spk[23]=0x88; spk[24]=0xac;
    u8 z[32];
    if (!legacy_sighash(z, tx, txlen, 0, spk, 25, 1, pre, sizeof pre)){
        printf("FAIL: could not build legacy sighash\n"); return 1;
    }
    u64 r[4], s[4]; wallet_ecdsa_sign(r, s, z, priv);
    static u8 der[80]; int dl = der_signature(der, r, s);
    static u8 sigall[96]; memcpy(sigall, der, dl); sigall[dl] = 0x01;
    u32 sigall_len = (u32)dl + 1;
    { const u8* init[2] = { sigall, pub }; u32 il[2] = { sigall_len, 33 };
      diff_run("BASE p2pkh accept", spk, 25, init, il, 2, tx, txlen, 0, 0); }
    { /* corrupted signature -> both reject identically */
      static u8 bad[96]; memcpy(bad, sigall, sigall_len); bad[10] ^= 0x40;
      const u8* init[2] = { bad, pub }; u32 il[2] = { sigall_len, 33 };
      diff_run("BASE corrupted sig", spk, 25, init, il, 2, tx, txlen, 0, 0); }
    { /* empty signature (the hook's first early return) */
      const u8* init[2] = { sigall, pub }; u32 il[2] = { 0, 33 };
      diff_run("BASE empty sig", spk, 25, init, il, 2, tx, txlen, 0, 0); }
    { /* garbage (non-DER) signature */
      static u8 junk[10]; memset(junk, 0xab, sizeof junk);
      const u8* init[2] = { junk, pub }; u32 il[2] = { 10, 33 };
      diff_run("BASE non-DER sig", spk, 25, init, il, 2, tx, txlen, 0, 0); }
    { /* bad pubkey encoding */
      static u8 badpub[33]; memset(badpub, 0x07, 33);
      const u8* init[2] = { sigall, badpub }; u32 il[2] = { sigall_len, 33 };
      diff_run("BASE bad pubkey", spk, 25, init, il, 2, tx, txlen, 0, 0); }
    { /* FindAndDelete path: the scriptCode itself embeds the signature push */
      static u8 sc2[160]; int m = 0;
      sc2[m++] = (u8)sigall_len; memcpy(sc2+m, sigall, sigall_len); m += sigall_len;
      memcpy(sc2+m, spk, 25); m += 25;
      const u8* init[2] = { sigall, pub }; u32 il[2] = { sigall_len, 33 };
      diff_run("BASE find-and-delete", sc2, (size_t)m, init, il, 2, tx, txlen, 0, 0); }
    { /* alternate hashtypes exercised through the raw-last-byte rule */
      u8 hts[] = { 0x00, 0x02, 0x03, 0x81, 0x83 };
      for (unsigned i = 0; i < sizeof hts/sizeof hts[0]; i++){
          u8 zz[32];
          if (!legacy_sighash(zz, tx, txlen, 0, spk, 25, hts[i], pre, sizeof pre)) continue;
          u64 rr[4], ss[4]; wallet_ecdsa_sign(rr, ss, zz, priv);
          static u8 d2[80]; int l2 = der_signature(d2, rr, ss);
          static u8 sg[96]; memcpy(sg, d2, l2); sg[l2] = hts[i];
          const u8* init[2] = { sg, pub }; u32 il[2] = { (u32)l2+1, 33 };
          diff_run("BASE alt hashtype", spk, 25, init, il, 2, tx, txlen, 0, 0);
      } }

    /* ---- WITNESS_V0: real BIP143 accept + rejects ---- */
    {
        static u8 wsc[25];
        wsc[0]=0x76; wsc[1]=0xa9; wsc[2]=0x14; memcpy(wsc+3, h160, 20);
        wsc[23]=0x88; wsc[24]=0xac;
        u8 wz[32];
        if (segwit_v0_sighash(wz, tx, (int64_t)txlen, 0, 1, 99000, wsc, 25, pre, sizeof pre) > 0){
            u64 wr[4], ws[4]; wallet_ecdsa_sign(wr, ws, wz, priv);
            static u8 wd[80]; int wl = der_signature(wd, wr, ws);
            static u8 wsig[96]; memcpy(wsig, wd, wl); wsig[wl] = 0x01;
            const u8* init[2] = { wsig, pub }; u32 il[2] = { (u32)wl+1, 33 };
            diff_run("WV0 p2wpkh accept", wsc, 25, init, il, 2, tx, txlen, 99000, 1);
            /* wrong amount -> different sighash -> reject, both sides */
            diff_run("WV0 wrong amount", wsc, 25, init, il, 2, tx, txlen, 99001, 1);
            static u8 wbad[96]; memcpy(wbad, wsig, wl+1); wbad[7] ^= 0x20;
            const u8* ib[2] = { wbad, pub }; u32 ilb[2] = { (u32)wl+1, 33 };
            diff_run("WV0 corrupted sig", wsc, 25, ib, ilb, 2, tx, txlen, 99000, 1);
            u32 ile[2] = { 0, 33 };
            diff_run("WV0 empty sig", wsc, 25, init, ile, 2, tx, txlen, 99000, 1);
        } else { printf("FAIL: could not build BIP143 sighash\n"); fails++; }
    }


    /* ---- IR-2 (INTERP_REVIEW_2026-09-05): der_parse_sig bounded the S
     * INTEGER against the full push length, and every consensus caller passed
     * siglen INCLUDING the trailing hashtype byte. Core pops the hashtype
     * BEFORE ecdsa_signature_parse_der_lax, so its bound is one byte tighter.
     *
     * Vector: a VALID 70-byte DER signature (30 44 02 20 R[32] 02 20 S[32])
     * whose S happens to end in 0x01, pushed with NO separate hashtype byte.
     *   Core : pops 0x01 as the hashtype, lax-parses 69 bytes, S claims 32
     *          with 31 remaining -> parse fails -> CHECKSIG false.
     *   here : S ended exactly at the push end (`ja` accepted equality), the
     *          hashtype read from sig[69] was 0x01 = SIGHASH_ALL, the digest
     *          matched, verify TRUE -> consensus false accept (pre-BIP66 reach;
     *          masked above the DERSIG height by der_sig_strict).
     * Control: the same DER with an explicit 0x01 appended (71 bytes) MUST
     * verify -- proving the signature is genuine and the rejection is the
     * parse bound, not the signature. Both twins, legacy and witness v0.
     * The signer is deterministic, so the MESSAGE is ground: the tx locktime
     * (covered by both sighash algorithms) is varied until S's low byte is 0x01
     * and r,s are both exactly 32 unpadded bytes. */
    for (int wv0 = 0; wv0 <= 1; wv0++){
        static u8 txm[128]; memcpy(txm, tx, txlen);
        static u8 d70[80]; int found = 0; u32 tries;
        const u64 amt = wv0 ? 100000ULL : 0;
        for (tries = 0; tries < 300000 && !found; tries++){
            txm[txlen-4] = (u8)tries; txm[txlen-3] = (u8)(tries>>8); txm[txlen-2] = (u8)(tries>>16);
            u8 zz[32];
            if (wv0) { if (segwit_v0_sighash(zz, txm, (int64_t)txlen, 0, 1, amt, spk, 25, pre, sizeof pre) <= 0) break; }
            else     { if (!legacy_sighash(zz, txm, txlen, 0, spk, 25, 1, pre, sizeof pre)) break; }
            u64 gr[4], gs[4]; wallet_ecdsa_sign(gr, gs, zz, priv);
            int gl = der_signature(d70, gr, gs);
            if (gl == 70 && d70[1] == 0x44 && d70[69] == 0x01) found = 1;
        }
        if (!found){ printf("FAIL: IR-2 %s: no 70-byte sig ending in 0x01 after %u tries\n", wv0?"wv0":"legacy", tries); fails++; continue; }
        struct sv_ctx cc = { txm, txlen, 0, workc, sizeof workc, 0,0,0, amt };
        struct sv_ctx ca = { txm, txlen, 0, worka, sizeof worka, 0,0,0, amt };
        sv_get_locktime_context(txm, txlen, 0, &cc.tx_version, &cc.tx_locktime, &cc.in_sequence);
        sv_get_locktime_context(txm, txlen, 0, &ca.tx_version, &ca.tx_locktime, &ca.in_sequence);
        struct { const u8* p; size_t n; } slice = { spk, 25 };
        cs_fn fc = wv0 ? sv_checksig_witness_v0_export : sv_checksig_export;
        cs_fn fa = wv0 ? sv_checksig_witness_v0_asm    : sv_checksig_asm;
        static u8 d71[96]; memcpy(d71, d70, 70); d71[70] = 0x01;
        u64 c1 = fc(&cc, d71, 71, pub, 33, &slice), a1 = fa(&ca, d71, 71, pub, 33, &slice);
        u64 c0 = fc(&cc, d70, 70, pub, 33, &slice), a0 = fa(&ca, d70, 70, pub, 33, &slice);
        const char* nm = wv0 ? "witness-v0" : "legacy";
        if (c1 == 1 && a1 == 1) printf("ok: IR-2 %s control: DER+0x01 (71 B) verifies in C and asm (ground in %u tries)\n", nm, tries);
        else { printf("FAIL: IR-2 %s control: C=%llu asm=%llu (want 1/1 -- the signature itself must be valid)\n", nm, (unsigned long long)c1, (unsigned long long)a1); fails++; }
        if (c0 == 0 && a0 == 0) printf("ok: IR-2 %s: 70 B DER with S ending in 0x01 and NO hashtype byte is REJECTED (Core: lax parse fails)\n", nm);
        else { printf("FAIL: IR-2 %s: C=%llu asm=%llu (want 0/0 -- S consumed the hashtype byte; Core pops it first)\n", nm, (unsigned long long)c0, (unsigned long long)a0); fails++; }
    }
    printf("compared %ld checksig runs; %ld mismatch(es)\n", compared, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

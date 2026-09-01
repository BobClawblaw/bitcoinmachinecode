/* tests/test_bip340_sign.c -- the BIP340 signer against Core's own
 * bip340_test_vectors.csv: every vector with a secret key must produce
 * Core's exact 64-byte signature; every vector's signature must verify (or
 * not) as Core says, through the node's consensus schnorr_verify; and the
 * tweaked signing key must sign for the tweaked x-only key. */
#include <stdio.h>
#include <string.h>
#include "bip340_vectors.h"
typedef unsigned char u8;
extern int bip340_sign(u8 sig[64], const u8* msg, unsigned long msglen, const u8 priv_be[32], const u8 aux[32]);
extern int bip340_pubkey(u8 xonly[32], const u8 priv_be[32]);
extern int bip340_tweak_privkey(u8 out_priv[32], const u8 priv_be[32], const u8 tweak[32]);
extern int schnorr_verify(const u8* sig, const u8* pk, const u8* msg, int msglen);
extern int bip32_xonly_tweak_add(const u8 x[32], const u8 t[32], u8 out_x[32]);
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
static int fails = 0, checks = 0;
static void ck(const char* l, int c){ checks++; if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static int hex1(char c){ return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1; }
static int unhex(u8* out, const char* h){ int n = (int)strlen(h)/2; for (int i=0;i<n;i++) out[i]=(u8)((hex1(h[2*i])<<4)|hex1(h[2*i+1])); return n; }
static void hexs(char* o, const u8* b, int n){ for (int i=0;i<n;i++) sprintf(o+2*i,"%02x",b[i]); o[2*n]=0; }
int main(void){
    printf("== Core's BIP340 vectors ==\n");
    for (int i = 0; i < BIP340_NVECS; i++){
        const bip340_vec_t* v = &BIP340_VECS[i];
        u8 pk[32], msg[128], sig[64]; int ml = unhex(msg, v->msg); unhex(pk, v->pk); unhex(sig, v->sig);
        char label[160];
        if (v->sk[0]){
            u8 sk[32], aux[32], out[64], xo[32]; unhex(sk, v->sk); unhex(aux, v->aux);
            snprintf(label, sizeof label, "vector %d: signature equals Core's (%s)", v->idx, v->comment[0] ? v->comment : "signing");
            ck(label, bip340_sign(out, msg, (unsigned long)ml, sk, aux) && !memcmp(out, sig, 64));
            if (memcmp(out, sig, 64)){ char a[129], b[129]; hexs(a, out, 64); hexs(b, sig, 64); printf("    got  %s\n    want %s\n", a, b); }
            snprintf(label, sizeof label, "vector %d: x-only pubkey equals Core's", v->idx);
            ck(label, bip340_pubkey(xo, sk) && !memcmp(xo, pk, 32));
        }
        snprintf(label, sizeof label, "vector %d: consensus verify says %s (%s)", v->idx, v->ok ? "valid" : "invalid", v->comment);
        int r = schnorr_verify(sig, pk, msg, ml);
        ck(label, (r == 1) == (v->ok == 1));
    }
    printf("== tweaked key-path signing (BIP341) ==\n");
    { u8 sk[32]; for (int i = 0; i < 32; i++) sk[i] = (u8)(0x11 + i);
      u8 px[32]; bip340_pubkey(px, sk);
      /* tweak = TapTweak(P) with no tree: sha256(tag)||sha256(tag)||P */
      u8 th[32]; sha256_full(th, "TapTweak", 8); u8 buf[96]; memcpy(buf, th, 32); memcpy(buf+32, th, 32); memcpy(buf+64, px, 32);
      u8 t[32]; sha256_full(t, buf, 96);
      u8 q[32]; ck("output key Q = P + t*G", bip32_xonly_tweak_add(px, t, q));
      u8 dq[32]; ck("tweaked private key derives", bip340_tweak_privkey(dq, sk, t));
      u8 qq[32]; bip340_pubkey(qq, dq);
      ck("...and its x-only pubkey IS Q", !memcmp(qq, q, 32));
      u8 m[32]; memset(m, 0x42, 32); u8 aux[32]; memset(aux, 0, 32); u8 s[64];
      ck("a signature under the tweaked key verifies against Q", bip340_sign(s, m, 32, dq, aux) && schnorr_verify(s, q, m, 32) == 1);
      m[0] ^= 1;
      ck("...and not against a changed message", schnorr_verify(s, q, m, 32) != 1); }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}

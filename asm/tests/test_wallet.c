/* test_wallet.c -- end-to-end wallet CLI core test.
 *
 * Exercises asm/wallet_core.c wired to the verified asm primitives:
 *   1. address(key=1) == 1BgGZ9tc... (known vector, matches tests/test_addr.c)
 *   2. ECDSA sign -> verify roundtrip using the repo's ecdsa_verify.
 *   3. wallet_sign_tx produces a well-formed signed P2PKH tx (scriptSig is a
 *      replaced P2PKH unlock, and the embedded signature verifies against the
 *      sighash with the supplied pubkey).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* verified asm primitives */
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char k[32]);
extern int  pubkey_parse(const unsigned char* pub, unsigned long plen,
                         uint64_t qx[4], uint64_t qy[4]);
extern int  ecdsa_verify(const uint64_t z[4], const uint64_t r[4],
                         const uint64_t s[4], const uint64_t Qx[4], const uint64_t Qy[4]);

/* wallet core API */
extern void wallet_pubkey(unsigned char pub[33], const unsigned char priv_be[32]);
extern int  wallet_address(char out[64], const unsigned char priv_be[32]);
extern int  wallet_ecdsa_sign(uint64_t r[4], uint64_t s[4],
                              const unsigned char z_be[32], const unsigned char priv_be[32]);
extern long wallet_sign_tx(unsigned char* out, long cap, const unsigned char* tx,
                           unsigned long txlen, long idx, const unsigned char priv_be[32]);
extern int  wallet_sighash(unsigned char z[32], const unsigned char* tx, unsigned long txlen,
                           unsigned long idx, const unsigned char* script, unsigned long slen);

static int failures = 0;
static void ck(int cond, const char* what) {
    printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) failures++;
}
static void pr32(const char* l, const unsigned char* b) {
    printf("  %s ", l); for (int i = 0; i < 32; i++) printf("%02x", b[i]); printf("\n");
}
static unsigned char* put_varint(unsigned char* p, unsigned long n) {
    if (n < 0xfd) *p++ = (unsigned char)n;
    else if (n <= 0xffff) { *p++ = 0xfd; p[0]=n&0xff; p[1]=(n>>8)&0xff; p+=2; }
    else if (n <= 0xffffffffUL) { *p++ = 0xfe; for (int i=0;i<4;i++) p[i]=(n>>(8*i))&0xff; p+=4; }
    else { *p++ = 0xff; for (int i=0;i<8;i++) p[i]=(n>>(8*i))&0xff; p+=8; }
    return p;
}

int main(void) {
    /* ---- 1. address(key=1) == address of G ---- */
    {
        unsigned char priv[32] = {0}; priv[31] = 1;
        char addr[64];
        wallet_address(addr, priv);
        ck(strcmp(addr, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") == 0, "addr(key=1)=1BgGZ9tc...");
        if (strcmp(addr, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")) printf("  got %s\n", addr);
    }

    /* ---- 2. ECDSA sign -> verify roundtrip on a random-ish key ---- */
    {
        unsigned char priv[32];
        static const unsigned char pv[32] = {
            0x18,0xE1,0x4A,0x7B,0x6A,0x30,0x7F,0x42,0x6A,0x94,0xF8,0xE3,0x70,0xFB,0xCD,0x0D,
            0x1B,0x64,0x8D,0x09,0x08,0x77,0x2B,0x0C,0x5E,0xE3,0x00,0x71,0xDE,0xC5,0x77,0x21};
        memcpy(priv, pv, 32);
        unsigned char z[32];
        for (int i = 0; i < 32; i++) z[i] = (unsigned char)(0xA0 + i);      /* dummy z */
        uint64_t r[4], s[4];
        ck(wallet_ecdsa_sign(r, s, z, priv) == 1, "wallet_ecdsa_sign returns ok");

        unsigned char pub[33]; scalar_to_pubkey(pub, priv);
        uint64_t qx[4], qy[4];
        ck(pubkey_parse(pub, 33, qx, qy) == 1, "pubkey_parse decompresses pub");
        uint64_t zl[4];
        /* z is BE bytes; convert to limbs for ecdsa_verify */
        for (int i = 0; i < 4; i++) zl[i] = 0;
        for (int i = 0; i < 32; i++) { int lb = i/8, sh = (i%8)*8; zl[lb] |= ((uint64_t)z[31-i]) << sh; }
        int v = ecdsa_verify(zl, r, s, qx, qy);
        ck(v == 1, "ecdsa_verify accepts our signature");
        if (v != 1) { pr32("z", z); }
    }

    /* ---- 3. sign a real P2PKH tx, check structure ---- */
    {
        unsigned char priv[32] = {0}; priv[31] = 1;   /* key=1 */
        /* build a 1-in/1-out tx (unsigned: empty scriptSig) */
        unsigned char tx[512], *p = tx;
        *p++ = 2; *p++ = 0; *p++ = 0; *p++ = 0;                  /* version 2 LE */
        p = put_varint(p, 1);                                    /* 1 input */
        for (int i = 0; i < 32; i++) *p++ = 0x11;                /* prev txid */
        *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;                  /* prev vout */
        p = put_varint(p, 0);                                    /* empty scriptSig */
        *p++ = 0xfe; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff;      /* sequence */
        p = put_varint(p, 1);                                    /* 1 output */
        unsigned long long v = 50000;
        for (int i = 0; i < 8; i++) *p++ = (unsigned char)((v >> (8*i)) & 0xff);
        p = put_varint(p, 25);                                   /* script len 25 */
        *p++ = 0x76; *p++ = 0xa9; *p++ = 0x14;
        for (int i = 0; i < 20; i++) *p++ = 0x33;
        *p++ = 0x88; *p++ = 0xac;
        *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;                  /* locktime */
        unsigned long txlen = (unsigned long)(p - tx);

        unsigned char st[1024];
        long n = wallet_sign_tx(st, (long)sizeof st, tx, txlen, 0, priv);
        ck(n > (long)txlen, "signed tx is longer than unsigned (scriptSig added)");

        /* verify the embedded signature with the signing pubkey */
        if (n > 0) {
            unsigned long c;
            /* skip version(4), vin count(1), prev txid(32)+vout(4) */
            const unsigned char* s = st + 4;
            unsigned long vc = *s; (void)vc; s += 1;             /* vin count=1 */
            s += 36;                                             /* prev txid+vout */
            unsigned long siglen;
            unsigned char b0 = *s;
            if (b0 < 0xfd) { siglen = b0; c = 1; }
            else if (b0 == 0xfd) { siglen = (unsigned long)s[1] | ((unsigned long)s[2]<<8); c = 3; }
            else if (b0 == 0xfe) { siglen = 0; for (int i=0;i<4;i++) siglen |= (unsigned long)s[1+i]<<(8*i); c = 5; }
            else { siglen = (unsigned long)s[1]; c = 9; }
            s += c;
            /* scriptSig = <push l> <DER||01> <push 33> <pub>  => length l+1 + 34 */
            unsigned long l = s[0];                              /* first push length */
            ck(siglen == l + 1 + 34, "scriptSig length == pushlen+1 + 34");

            /* recompute sighash over the ORIGINAL unsigned tx */
            unsigned char pub[33]; scalar_to_pubkey(pub, priv);
            extern void hash160(unsigned char o[20], const void* in, long long len);
            unsigned char h[20]; hash160(h, pub, 33);
            unsigned char scr[25]; scr[0]=0x76; scr[1]=0xa9; scr[2]=0x14;
            memcpy(scr+3,h,20); scr[23]=0x88; scr[24]=0xac;
            unsigned char z[32];
            ck(wallet_sighash(z, tx, txlen, 0, scr, 25) == 1, "wallet_sighash ok");
            uint64_t zl[4]; for (int i=0;i<4;i++) zl[i]=0;
            for (int i=0;i<32;i++){int lb=i/8,sh=(i%8)*8; zl[lb]|=((uint64_t)z[31-i])<<sh;}

            /* parse (r,s) out of the embedded DER (skip push byte) */
            const unsigned char* der = s + 1;                    /* skip push length */
            /* DER: 30 len 02 rl r 02 sl s ; then +1 sighash */
            unsigned long dl = der[1];
            const unsigned char* rr = der + 4;                   /* r payload */
            unsigned long rl = der[3];
            const unsigned char* ss = rr + rl + 2;               /* s payload */
            unsigned long sl2 = *(rr + rl + 1);
            ck(dl == rl + sl2 + 4, "DER structure length consistent");
            uint64_t rlim[4], slim[4];
            for (int i = 0; i < 4; i++) rlim[i] = slim[i] = 0;
            for (int i = 0; i < (long)rl; i++) rlim[(rl-1-i)/8] |= ((uint64_t)rr[i]) << (((rl-1-i)%8)*8);
            for (int i = 0; i < (long)sl2; i++) slim[(sl2-1-i)/8] |= ((uint64_t)ss[i]) << (((sl2-1-i)%8)*8);
            uint64_t qx[4], qy[4];
            pubkey_parse(pub, 33, qx, qy);
            int v = ecdsa_verify(zl, rlim, slim, qx, qy);
            ck(v == 1, "signature embedded in signed tx verifies against sighash");
        }
    }

    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}

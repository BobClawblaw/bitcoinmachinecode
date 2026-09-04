/* test_pubkey.c -- verify asm pubkey_parse decompresses canonical secp256k1
 * public keys to correct affine coordinates, and rejects bad keys.
 * G pubkey: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
 * G affine: Gx=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
 *           Gy=483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
 */
#include <stdio.h>
#include <string.h>

extern int pubkey_parse(const unsigned char* pub, unsigned long plen,
                        unsigned long long qx[4], unsigned long long qy[4]);

static int fails=0;
static void cki(const char* l,int got,int exp){
    if(got==exp) printf("ok  : %s\n",l);
    else { printf("FAIL: %s (got %d exp %d)\n",l,got,exp); fails++; }
}

/* convert u64[4] LE limbs -> 32-byte big-endian */
static void limbs2be(const unsigned long long l[4], unsigned char be[32]){
    for(int i=0;i<4;i++){
        unsigned long long v=l[i];
        for(int j=0;j<8;j++){ be[31-(i*8+j)] = (unsigned char)(v&0xff); v>>=8; }
    }
}

static void test_pub(const char* label, const char* hex, const char* xexphex, const char* yexphex){
    unsigned char pub[65]; int n=(int)(strlen(hex))/2;
    for(int i=0;i<n;i++) sscanf(hex+2*i,"%2hhx",&pub[i]);
    unsigned long long qx[4],qy[4];
    int r=pubkey_parse(pub,n,qx,qy);
    cki(label, r, (n==33||n==65)?1:0);
    if(r){
        unsigned char xb[32], yb[32], xe[32], ye[32];
        limbs2be(qx,xb); limbs2be(qy,yb);
        for(int i=0;i<32;i++) sscanf(xexphex+2*i,"%2hhx",&xe[i]);
        for(int i=0;i<32;i++) sscanf(yexphex+2*i,"%2hhx",&ye[i]);
        if(memcmp(xb,xe,32)==0) printf("ok  : %s x-coord\n",label);
        else { printf("FAIL: %s x-coord\n",label); fails++; }
        if(memcmp(yb,ye,32)==0) printf("ok  : %s y-coord\n",label);
        else { printf("FAIL: %s y-coord\n",label); fails++; }
        /* recompute with parity flipped (0x03) -> y must be negated */
    }
}

int main(void){
    /* G (compressed, even y) */
    test_pub("G compressed 0x02",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    /* G (compressed, odd y representation: 0x03 -> y = p - Gy, parity 1) */
    test_pub("G compressed 0x03 (odd y)",
        "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777");
    /* G (uncompressed 0x04) */
    test_pub("G uncompressed 0x04",
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

    /* ---- negatives ---- */
    /* compressed x=5: x^3+7 is a quadratic non-residue => no realsqrt => reject */
    unsigned char p[33];
    const char* xh="020000000000000000000000000000000000000000000000000000000000000005";
    for(int i=0;i<33;i++){ unsigned int v; sscanf(xh+2*i,"%2x",&v); p[i]=(unsigned char)v; }
    unsigned long long qx[4],qy[4];
    int r=pubkey_parse(p,33,qx,qy);
    cki("non-residue x has no sqrt -> rejected", r, 0);
    /* wrong length */
    unsigned char s[10]={0}; s[0]=0x02;
    cki("bad length rejected", pubkey_parse(s,10,qx,qy), 0);
    /* uncompressed off-curve y (y+1 of G -> not on curve) */
    unsigned char u[65];
    const char* uh="0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                   "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b7";
    for(int i=0;i<65;i++){ unsigned int v; sscanf(uh+2*i,"%2x",&v); u[i]=(unsigned char)v; }
    cki("off-curve uncompressed rejected", pubkey_parse(u,65,qx,qy), 0);

    /* ---- CRY-2 (audit 2026-09-03): HYBRID public keys (prefix 0x06/0x07).
     * libsecp256k1 (Core's CPubKey::Verify path) ACCEPTS these; the parse
     * only checks the redundant parity byte. Core never sets STRICTENC for
     * block validation, so a legacy/P2SH/P2WSH-v0 spend with a valid
     * signature under a hybrid key is consensus-VALID in Core. The old parser
     * accepted only 0x04 -> false reject. G's y is even (ends 0xb8). ---- */
    {
        /* 0x06 || Gx || Gy : even prefix, Gy even -> parity MATCHES -> accept */
        unsigned char hy[65];
        const char* h06="0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        for(int i=0;i<65;i++){ unsigned int v; sscanf(h06+2*i,"%2x",&v); hy[i]=(unsigned char)v; }
        unsigned long long hx[4],hyq[4];
        int hr = pubkey_parse(hy,65,hx,hyq);
        cki("hybrid 0x06 with correct (even) parity ACCEPTS", hr, 1);
        if(hr){
            unsigned char xb[32],yb[32]; limbs2be(hx,xb); limbs2be(hyq,yb);
            unsigned char gx[32]={0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,
                0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,
                0x16,0xf8,0x17,0x98};
            unsigned char gy[32]={0x48,0x3a,0xda,0x77,0x26,0xa3,0xc4,0x65,0x5d,0xa4,0xfb,0xfc,
                0x0e,0x11,0x08,0xa8,0xfd,0x17,0xb4,0x48,0xa6,0x85,0x54,0x19,0x9c,0x47,0xd0,0x8f,
                0xfb,0x10,0xd4,0xb8};
            cki("  hybrid 0x06 x-coord == Gx", memcmp(xb,gx,32)==0, 1);
            cki("  hybrid 0x06 y-coord == Gy", memcmp(yb,gy,32)==0, 1);
        }
        /* 0x07 || Gx || Gy : odd prefix, Gy even -> parity MISMATCHES -> reject */
        const char* h07="0779be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        for(int i=0;i<65;i++){ unsigned int v; sscanf(h07+2*i,"%2x",&v); hy[i]=(unsigned char)v; }
        cki("hybrid 0x07 with mismatched parity rejected", pubkey_parse(hy,65,hx,hyq), 0);
    }

    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}

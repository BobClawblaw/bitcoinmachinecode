/* dbip32.c -- cross-arch differential driver for bitcoin_bip32 (both arches).
 * stdin records (u32 = 4-byte LE):
 *   0: seedlen seed                    -> bip32_master     -> 1B ret + 32B k + 32B c
 *   1: kpar[32] cpar[32] index         -> bip32_ckd_priv   -> 1B ret + 32B k + 32B c
 *   2: seedlen seed n indexes[n]       -> bip32_derive_path-> 1B ret + 32B k + 32B c
 *   3: pub[33]                         -> bip32_fingerprint-> 4B
 *   4: is_priv depth pfp[4] child keylen key
 *                                      -> bip32_extkey_serialize -> 1B ret + 78B
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
extern int  bip32_master(unsigned char k[32], unsigned char c[32],
                         const unsigned char* seed, long seedlen);
extern int  bip32_ckd_priv(unsigned char k[32], unsigned char c[32],
                           const unsigned char* kpar, const unsigned char* cpar,
                           unsigned index);
extern int  bip32_derive_path(unsigned char k[32], unsigned char c[32],
                              const unsigned char* seed, long seedlen,
                              const unsigned* indexes, long n);
extern void bip32_fingerprint(unsigned char fp[4], const unsigned char pub[33]);
extern int  bip32_extkey_serialize(unsigned char ser[78], int is_priv,
                                   unsigned char depth,
                                   const unsigned char parent_fp[4],
                                   unsigned child, const unsigned char c[32],
                                   const unsigned char* key, long keylen);
static unsigned char buf[65536];
static unsigned rd32(void){
    unsigned char b[4];
    if (fread(b,1,4,stdin)!=4) exit(2);
    return (unsigned)(b[0] | (b[1]<<8) | (b[2]<<16) | ((unsigned)b[3]<<24));
}
static void out32x(const unsigned char* k, const unsigned char* c, int r){
    unsigned char rb = (unsigned char)r;
    fwrite(&rb,1,1,stdout); fwrite(k,1,32,stdout); fwrite(c,1,32,stdout);
}
int main(void){
    unsigned char k[32], c[32], ser[78];
    for(;;){
        int op = getchar();
        if (op==EOF) break;
        if (op==0){
            unsigned sl = rd32();
            if (sl > 4096 || fread(buf,1,sl,stdin)!=sl) return 2;
            out32x(k, c, bip32_master(k, c, buf, (long)sl));
        } else if (op==1){
            unsigned char kpar[32], cpar[32];
            if (fread(kpar,1,32,stdin)!=32 || fread(cpar,1,32,stdin)!=32) return 2;
            unsigned idx = rd32();
            out32x(k, c, bip32_ckd_priv(k, c, kpar, cpar, idx));
        } else if (op==2){
            unsigned sl = rd32();
            if (sl > 4096 || fread(buf,1,sl,stdin)!=sl) return 2;
            unsigned n = rd32();
            if (n > 64) return 2;
            unsigned idx[64];
            for (unsigned i = 0; i < n; i++) idx[i] = rd32();
            out32x(k, c, bip32_derive_path(k, c, buf, (long)sl, idx, (long)n));
        } else if (op==3){
            unsigned char pub[33], fp[4];
            if (fread(pub,1,33,stdin)!=33) return 2;
            bip32_fingerprint(fp, pub);
            fwrite(fp,1,4,stdout);
        } else if (op==4){
            unsigned char pfp[4], cc[32];
            int ip = getchar();
            int dc = getchar();
            if (ip==EOF || dc==EOF || fread(pfp,1,4,stdin)!=4) return 2;
            unsigned child = rd32();
            if (fread(cc,1,32,stdin)!=32) return 2;
            unsigned kl = rd32();
            if (kl > 4096 || fread(buf,1,kl,stdin)!=kl) return 2;
            int r = bip32_extkey_serialize(ser, ip, (unsigned char)dc, pfp,
                                           child, cc, buf, (long)kl);
            unsigned char rb = (unsigned char)r;
            fwrite(&rb,1,1,stdout);
            fwrite(ser,1,78,stdout);
        } else return 2;
    }
    return 0;
}

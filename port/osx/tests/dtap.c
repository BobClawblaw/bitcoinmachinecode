/* dtap.c -- cross-arch differential driver for secp256k1_taproot (both arches).
 * stdin records (u32 = 4-byte LE):
 *   0: taglen tag msglen msg            -> tagged_hash256   -> 32B
 *   1: a[32] b[32]                      -> tap_branch_hash  -> 32B
 *   2: ver(1B) slen script              -> tap_leaf_hash    -> 4B ret + 32B
 *   3: ix[32] has_mr(1B) [mr[32]]       -> taproot_tweak_pubkey -> 4B ret + 32B
 *   4: clen control leaf[32]            -> tap_merkle_root  -> 4B ret + 32B
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
extern void tagged_hash256(unsigned char* out, const char* tag, unsigned long long taglen,
                           const unsigned char* msg, unsigned long long msglen);
extern void tap_branch_hash(unsigned char out[32], const unsigned char* a, const unsigned char* b);
extern long tap_leaf_hash(unsigned char out[32], unsigned char ver,
                          const unsigned char* script, unsigned long long slen);
extern long taproot_tweak_pubkey(unsigned char out_x[32], const unsigned char internal_x[32],
                                 const unsigned char* merkle_root);
extern long tap_merkle_root(unsigned char out[32], const unsigned char* leaf_hashes,
                            unsigned long long count, const unsigned char* control,
                            unsigned long long clen);
static unsigned char b1[70000], b2[200200];
static unsigned rd32(void){
    unsigned char b[4];
    if (fread(b,1,4,stdin)!=4) exit(2);
    return (unsigned)(b[0] | (b[1]<<8) | (b[2]<<16) | ((unsigned)b[3]<<24));
}
static void rdb(unsigned char* dst, unsigned n, unsigned cap){
    if (n > cap || fread(dst,1,n,stdin)!=n) exit(2);
}
static void w32(const unsigned char* p){ fwrite(p,1,32,stdout); }
int main(void){
    unsigned char out[32];
    for(;;){
        int op = getchar();
        if (op==EOF) break;
        if (op==0){
            unsigned tl = rd32(); rdb(b1, tl, 8000);
            unsigned ml = rd32(); rdb(b2, ml, 200000);
            tagged_hash256(out, (const char*)b1, tl, b2, ml);
            w32(out);
        } else if (op==1){
            unsigned char a[32], b[32];
            if (fread(a,1,32,stdin)!=32 || fread(b,1,32,stdin)!=32) return 2;
            tap_branch_hash(out, a, b);
            w32(out);
        } else if (op==2){
            int vc = getchar();
            unsigned sl = rd32(); rdb(b1, sl, 70000);
            long r = tap_leaf_hash(out, (unsigned char)vc, b1, sl);
            fwrite(&r,4,1,stdout);
            w32(out);
        } else if (op==3){
            /* file layout: ix[32], has_mr(1B), [mr[32]] */
            unsigned char ix[32], mr[32];
            if (fread(ix,1,32,stdin)!=32) return 2;
            int hm = getchar();
            long r;
            if (hm) { if (fread(mr,1,32,stdin)!=32) return 2; r = taproot_tweak_pubkey(out, ix, mr); }
            else    { r = taproot_tweak_pubkey(out, ix, 0); }
            fwrite(&r,4,1,stdout);
            w32(out);
        } else if (op==4){
            unsigned cl = rd32(); rdb(b2, cl, 8000);
            unsigned char leaf[32];
            if (fread(leaf,1,32,stdin)!=32) return 2;
            long r = tap_merkle_root(out, leaf, 1, cl ? b2 : 0, cl);
            fwrite(&r,4,1,stdout);
            w32(out);
        } else return 2;
    }
    return 0;
}

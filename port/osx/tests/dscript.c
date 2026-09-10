/* dscript.c -- cross-arch differential driver for bitcoin_script (both arches).
 * stdin records (u32 = 4-byte LE):
 *   0: siglen sig                     -> der_parse_sig -> 1B ret + 4B ht + 32B r + 32B s
 *   1: blen bytes                     -> be_to_limbs   -> 32B
 *   2: txlen tx idx pvlen pv          -> verify_p2pkh (work cap 65536) -> 1B ret
 * stdout: results in record order; streams must be byte-identical.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern int  der_parse_sig(const unsigned char* sig, unsigned long long slen,
                          unsigned long long r[4], unsigned long long s[4],
                          unsigned *hashtype);
extern void be_to_limbs(unsigned long long out[4], const unsigned char* bytes,
                        unsigned long long len);
extern int  verify_p2pkh(const unsigned char* tx, unsigned long long txlen,
                         unsigned long long input_index,
                         const unsigned char* prevout_script,
                         unsigned long long prevout_len,
                         unsigned char* work, unsigned long long cap);
static unsigned char b1[8192], b2[8192], work[65536];
static unsigned rd32(void){
    unsigned char b[4];
    if (fread(b,1,4,stdin)!=4) exit(2);
    return (unsigned)(b[0] | (b[1]<<8) | (b[2]<<16) | ((unsigned)b[3]<<24));
}
static int rdb(unsigned char* dst, unsigned n, unsigned cap){
    if (n > cap || fread(dst,1,n,stdin)!=n) exit(2);
    return n;
}
int main(void){
    unsigned long long r[4], s[4];
    for(;;){
        int op = getchar();
        if (op==EOF) break;
        if (op==0){
            unsigned n = rdb(b1, rd32(), 8000);
            memset(r,0,32); memset(s,0,32);   /* reject paths must not leak
                                                 uninitialized stack into the
                                                 stream -- dump is defined */
            unsigned ht = 0xdeadbeef;
            int ret = der_parse_sig(b1, n, r, s, &ht);
            unsigned char rb = (unsigned char)ret;
            fwrite(&rb,1,1,stdout);
            fwrite(&ht,4,1,stdout);
            fwrite(r,8,4,stdout);
            fwrite(s,8,4,stdout);
        } else if (op==1){
            unsigned n = rdb(b1, rd32(), 8000);
            unsigned long long out[4];
            be_to_limbs(out, b1, n);
            fwrite(out,8,4,stdout);
        } else if (op==2){
            unsigned tl = rd32(); rdb(b1, tl, 8000);
            unsigned idx = rd32();
            unsigned pl = rd32(); rdb(b2, pl, 8000);
            memset(work,0,sizeof work);
            int ret = verify_p2pkh(b1, tl, idx, b2, pl, work, sizeof work);
            unsigned char rb = (unsigned char)ret;
            fwrite(&rb,1,1,stdout);
            fwrite(work,1,64,stdout);   /* catch stray writes through work */
        } else return 2;
    }
    return 0;
}

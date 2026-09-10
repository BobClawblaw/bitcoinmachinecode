/* dsighash.c -- cross-arch differential driver for bitcoin_sighash (both arches).
 * stdin records (u32 fields are 4-byte LE):
 *   0: txlen tx inidx sclen script        -> sighash_all -> 1B ret + 32B out
 *   1: txlen tx nin sclen scriptcode ht   -> legacy_sighash -> 1B ret + 32B out
 *   2: blen blob                          -> script_op_len(blob) -> 8B u64
 *   3: dlen data                          -> script_push_encode -> 8B len + len B
 *   4: slen src nlen needle               -> script_find_and_delete -> 8B len + len B
 * preimg is a fresh 4096B buffer per record on both sides.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern int  sighash_all(unsigned char out32[32], const unsigned char* tx,
                        unsigned long txlen, unsigned long input_index,
                        const unsigned char* script, unsigned long script_len,
                        unsigned char* preimg, unsigned long cap);
extern int  legacy_sighash(unsigned char out32[32], const unsigned char* tx,
                           unsigned long txlen, unsigned long nIn,
                           const unsigned char* scriptCode, unsigned long scLen,
                           int32_t hashtype, unsigned char* preimg, unsigned long cap);
extern unsigned long long script_op_len(const unsigned char* pos, const unsigned char* end);
extern unsigned long long script_push_encode(unsigned char* dst, unsigned long long dstcap,
                                             const unsigned char* data, unsigned long long datalen);
extern unsigned long long script_find_and_delete(unsigned char* dst, unsigned long long dstcap,
                                                 const unsigned char* src, unsigned long long srclen,
                                                 const unsigned char* needle, unsigned long long needlelen);
static unsigned char tx[4096], sc[4096], blob[70000];
static unsigned char preimg[4096], out[32];
static unsigned char ob[70000];
static unsigned rd32(void){
    unsigned char b[4];
    if (fread(b,1,4,stdin)!=4) exit(2);
    return (unsigned)(b[0] | (b[1]<<8) | (b[2]<<16) | ((unsigned)b[3]<<24));
}
static void wr64(unsigned long long v){ fwrite(&v,1,8,stdout); }
int main(void){
    for(;;){
        int op = getchar();
        if (op==EOF) break;
        if (op==0 || op==1){
            unsigned tl = rd32();
            if (tl > 4096 || fread(tx,1,tl,stdin)!=tl) return 2;
            unsigned a = rd32(), sl = rd32();
            if (sl > 4096 || fread(sc,1,sl,stdin)!=sl) return 2;
            memset(preimg,0,sizeof preimg);
            int r;
            if (op==0){
                r = sighash_all(out, tx, tl, a, sc, sl, preimg, 4096);
            } else {
                unsigned ht = rd32();
                r = legacy_sighash(out, tx, tl, a, sc, sl, (int32_t)ht, preimg, 4096);
            }
            unsigned char rb = (unsigned char)r;
            fwrite(&rb,1,1,stdout);
            fwrite(out,1,32,stdout);
        } else if (op==2){
            unsigned bl = rd32();
            if (bl > 66000 || fread(blob,1,bl,stdin)!=bl) return 2;
            wr64(script_op_len(blob, blob+bl));
        } else if (op==3){
            unsigned dl = rd32();
            if (dl > 66000 || fread(blob,1,dl,stdin)!=dl) return 2;
            unsigned long long n = script_push_encode(ob, sizeof ob, blob, dl);
            wr64(n);
            if (n != 0xFFFFFFFFFFFFFFFFULL && n <= sizeof ob) fwrite(ob,1,n,stdout);
        } else if (op==4){
            /* file layout is srclen, src bytes, needlelen, needle bytes */
            unsigned sl2 = rd32();
            if (sl2 > 4096 || fread(blob,1,sl2,stdin)!=sl2) return 2;
            unsigned nl = rd32();
            unsigned char nd[4096];
            if (nl > 4096 || fread(nd,1,nl,stdin)!=nl) return 2;
            unsigned long long n = script_find_and_delete(ob, sizeof ob, blob, sl2, nd, nl);
            wr64(n);
            if (n != 0xFFFFFFFFFFFFFFFFULL && n <= sizeof ob) fwrite(ob,1,n,stdout);
        } else return 2;
    }
    return 0;
}

/* dsv.c -- cross-arch differential driver for hmac_sha512.
 * stdin: records of: keylen(4B LE) msglen(4B LE) key msg
 * output: 64-byte digest per record.
 * usage: dsv < vecs.bin > results.bin
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern void hmac_sha512(unsigned char out[64], const unsigned char* key, long keylen,
                        const unsigned char* msg, long msglen);
static unsigned char buf[4096], out[64];

static int rd(void *p, size_t n){ size_t g = fread(p,1,n,stdin); return g==n; }

int main(void){
    for(;;){
        uint32_t kl, ml;
        if (!rd(&kl,4) || !rd(&ml,4)) break;
        if (kl > 4096 || ml > 4096-256) { fprintf(stderr,"too big\n"); return 2; }
        if (!rd(buf, kl) || !rd(buf+256, ml)) break;
        hmac_sha512(out, buf, kl, buf+256, ml);
        fwrite(out, 1, 64, stdout);
    }
    fflush(stdout);
    return 0;
}

/* daddr.c -- cross-arch differential driver for bitcoin_addr (both arches).
 * stdin records:
 *   0: len(4B LE) in[len]        -> hash160 -> 20 bytes
 *   1: len(4B LE) payload[len]   -> base58check_encode -> 64 bytes of the
 *      out buffer (NUL-padded): catches refusal out[0]=0, string bytes AND
 *      any writes past the terminator.
 * stdout: results in record order; streams must be byte-identical.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern void hash160(unsigned char out[20], const void *in, long long len);
extern void base58check_encode(char *out, const unsigned char *payload, long long paylen);
static unsigned rd32(void){
    unsigned char b[4];
    if (fread(b,1,4,stdin)!=4) { fprintf(stderr,"eof\n"); exit(2); }
    return (unsigned)(b[0] | (b[1]<<8) | (b[2]<<16) | ((unsigned)b[3]<<24));
}
int main(void){
    static unsigned char in[4096];
    for(;;){
        int op = getchar();
        if (op==EOF) break;
        unsigned len = rd32();
        if (op==0){
            if (len > 4000) return 2;
            if (len && fread(in,1,len,stdin)!=len) return 2;
            unsigned char out[20];
            hash160(out, in, (long long)len);
            fwrite(out,1,20,stdout);
        } else if (op==1){
            /* paylen >= 0x80000000 is the unsigned-negative refusal case:
             * no payload bytes follow; feed a deterministic buffer. */
            if (len >= 0x80000000u){
                memset(in, 0xA5, 32);
            } else {
                if (len > 4000) return 2;
                if (len && fread(in,1,len,stdin)!=len) return 2;
            }
            char out[128];
            memset(out,'#',sizeof out);
            base58check_encode(out, in, (long long)(unsigned int)len);
            fwrite(out,1,128,stdout);
        } else return 2;
    }
    return 0;
}

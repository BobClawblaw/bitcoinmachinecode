/* dkeys.c -- cross-arch differential driver for bitcoin_keys (both arches).
 * stdin records:
 *   0: k[32] -> scalar_small_nonzero -> 1 byte retval
 *   1: k[32] -> scalar_to_pubkey    -> 33 bytes pub
 * stdout: results in record order; x86 and osx streams must be identical.
 */
#include <stdio.h>
#include <stdint.h>
extern int  scalar_small_nonzero(const unsigned char k[32]);
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char k[32]);
static int rd(void *v, size_t n){ return fread(v,1,n,stdin)==n; }
int main(void){
    unsigned char k[32], pub[33];
    for(;;){
        int op = getchar();
        if (op==EOF) break;
        if (!rd(k,32)) return 2;
        if (op==0){
            unsigned char r = (unsigned char)scalar_small_nonzero(k);
            fwrite(&r,1,1,stdout);
        } else if (op==1){
            scalar_to_pubkey(pub,k);
            fwrite(pub,1,33,stdout);
        } else return 2;
    }
    return 0;
}

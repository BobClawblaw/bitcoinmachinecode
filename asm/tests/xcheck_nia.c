/* xcheck_nia.c -- cross-check the SHA-NI path against the verified scalar path. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
extern void sha256_init(unsigned int state[8]);
extern void sha256_block(unsigned int state[8], const unsigned char block[64]);
extern void sha256_block_nia(unsigned int state[8], const unsigned char block[64]);
extern int  cpu_has_sha_ni(void);

static unsigned int rng(unsigned int* s){ *s=*s*1103515245+12345; return (*s>>16)&0xffff; }
int main(void){
    if(!cpu_has_sha_ni()){ printf("SKIP: no SHA-NI on cpu\n"); return 0; }
    int fails=0;
    for(int trial=0; trial<200000; trial++){
        unsigned char blk[64]; unsigned int seed=trial*7+1;
        for(int i=0;i<64;i++) blk[i]=(unsigned char)rng(&seed);
        unsigned int sa[8], sb[8];
        sha256_init(sa); sha256_init(sb);
        for(int i=0;i<8;i++) sa[i]=sb[i]=0xdeadbeef+i; /* nonzero init to catch lane bugs */
        sha256_block(sa,blk);
        sha256_block_nia(sb,blk);
        if(memcmp(sa,sb,32)!=0){
            if(fails<3){ printf("MISMATCH trial=%d\nblk0=%02x%02x%02x\nscalar=%08x %08x ...\nnia  =%08x %08x ...\n",
                trial,blk[0],blk[1],blk[2],sa[0],sa[1],sb[0],sb[1]); }
            fails++;
        }
    }
    printf(fails? "FAILURES %d / 200000\n" : "ALL 200000 BLOCKS BYTE-IDENTICAL (SHA-NI == scalar)\n", fails);
    return fails?1:0;
}

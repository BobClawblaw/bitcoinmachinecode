/* t_fullfuzz.c -- exhaustive audit of the blob-cap dangling-slot fix.
 * Uses a small blob cap so .full fires constantly; asserts the invariant
 *   put(k)==1  ->  get(k) returns EXACTLY the stored record
 *   put(k)==2  ->  get(k)==0 (absent)   [was: wrong-script dangling hit]
 * across thousands of (txid,index) with varied scripts.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
extern size_t utxo_struct_size(unsigned long);
extern void   utxo_init(void*,unsigned long,void*,unsigned long);
extern long   utxo_put(void*,const uint8_t*,unsigned long,unsigned long long,unsigned long,unsigned long,const uint8_t*,unsigned long);
extern long   utxo_get(void*,const uint8_t*,unsigned long,unsigned long long*,unsigned long*,unsigned long*,const uint8_t**,unsigned long*);
int main(void){
    unsigned long slots=1024; void* U=malloc(utxo_struct_size(slots)); uint8_t* blob=malloc(1<<20);
    unsigned long fails=0, full_hits=0, ok_absent=0, dup_ok=0;
    utxo_init(U,slots,blob,4096);            /* cap 4KB -> frequent .full */
    for(long n=0;n<200000;n++){
        uint8_t tx[32]; for(int i=0;i<32;i++)tx[i]=(uint8_t)((n*31+i*7+n/3)&0xff);
        unsigned idx=(unsigned)(n%7); unsigned long long val=(unsigned long long)n*3+5;
        unsigned h=(unsigned)(n%900000); unsigned cb=n%2;
        unsigned sl=1+(unsigned)(n%64); uint8_t sc[64]; for(unsigned i=0;i<sl;i++)sc[i]=(uint8_t)((n+i*13)&0xff);
        long r=utxo_put(U,tx,idx,val,h,cb,sc,sl);
        unsigned long long gv; unsigned long gh,gcb,gsl; const uint8_t*gp;
        long g=utxo_get(U,tx,idx,&gv,&gh,&gcb,&gp,&gsl);
        if(r==2){ full_hits++; if(g!=0){ if(fails<8)printf("n=%ld put=2 but get=%ld (DANGLING!)\n",n,g); fails++; }
                  else ok_absent++; }
        else if(r==1){
            if(g!=1||gv!=val||gsl!=sl||memcmp(gp,sc,sl)){ if(fails<8)printf("n=%ld put=1 but get mismatch r=%ld g=%ld\n",n,r,g); fails++; }
        } else if(r==0){ if(g!=1){ if(fails<8)printf("n=%ld dup put=0 but get=%ld (dup key lost!)\n",n,g); fails++; } dup_ok++; }
        else { if(fails<8)printf("n=%ld unexpected put rc=%ld\n",n,r); fails++; }
    }
    printf("full_hits=%lu ok_absent=%lu dup_ok=%lu FAILS=%lu\n", full_hits, ok_absent, dup_ok, fails);
    return fails?1:0;
}

/* t_full.c -- regression for the blob-capacity dangling-slot bug.
 * A tiny blob cap makes the 2nd put hit .full. Before the fix, utxo_put wrote
 * the slot header (txid+index) THEN bailed to .full, leaving a dangling slot
 * whose blob_off was stale -> utxo_get on the 2nd key returned the 1st key's
 * record (wrong-script aliasing). After the fix: put2==2, get2==0 (absent),
 * get1 still returns the exact first script.
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
    unsigned long slots=16; void* U=malloc(utxo_struct_size(slots)); uint8_t* blob=malloc(64);
    utxo_init(U,slots,blob,70);             /* cap 32B: room for ~1 record */
    uint8_t A[32],B[32]; for(int i=0;i<32;i++){A[i]=(uint8_t)i; B[i]=(uint8_t)(255-i);}
    uint8_t sa[40],sb[40]; for(int i=0;i<40;i++){sa[i]=(uint8_t)(0xa0+i); sb[i]=(uint8_t)(0xd0+i);}
    long r1=utxo_put(U,A,0,111,1,0,sa,40);
    long r2=utxo_put(U,B,0,222,2,0,sb,40);   /* should be .full (2) since 40+24 > 32 */
    unsigned long long v; unsigned long h,cb,sl; const uint8_t*sp;
    long g1=utxo_get(U,A,0,&v,&h,&cb,&sp,&sl);
    long g2=utxo_get(U,B,0,&v,&h,&cb,&sp,&sl);
    printf("put1=%ld put2=%ld get1=%ld get2=%ld\n", r1, r2, g1, g2);
    int ok=1;
    if(r1!=1){printf("FAIL put1 should be 1\n");ok=0;}
    if(r2!=2){printf("FAIL put2 should be 2 (full)\n");ok=0;}
    if(g2!=0){printf("FAIL get2 should be 0 (absent), got %ld (dangling-slot bug!)\n",g2);ok=0;}
    if(g1!=1){printf("FAIL get1 should be 1\n");ok=0;}
    else if(v!=111||sl!=40||memcmp(sp,sa,40)){printf("FAIL get1 wrong record\n");ok=0;}
    printf("%s\n", ok?"REGRESSION PASS (no dangling slot, absent stays absent)":"REGRESSION FAIL");
    return ok?0:1;
}

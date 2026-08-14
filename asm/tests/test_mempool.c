#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* test_mempool.c -- verify the asm mempool (put/get/dedup/count/roundtrip) */
extern int  mpool_struct_size(unsigned long slots);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern long mpool_put(void* mp, const unsigned char txid[32], const unsigned char* tx, unsigned long txlen);
extern const unsigned char* mpool_get(void* mp, const unsigned char txid[32], unsigned long* out_len);
extern long mpool_count(void* mp);

static int failures = 0;
static void ck(int cond, const char* what){ if(!cond){ printf("FAIL: %s\n", what); failures++; } else printf("ok  : %s\n", what); }

int main(void){
    unsigned long slots = 512;   /* room for the 300-entry bulk round-trip */
    size_t msz = mpool_struct_size(slots);
    unsigned char* mp = calloc(1, msz);
    unsigned char* blob = calloc(1, 1<<18);
    mpool_init(mp, slots, blob, 1<<18);

    /* three distinct txs with distinct txids */
    unsigned char tid1[32], tid2[32], tid3[32];
    unsigned char t1[64], t2[90], t3[40];
    unsigned i;
    for(i=0;i<32;i++){ tid1[i]=i; tid2[i]=i+7; tid3[i]=i+13; }
    for(i=0;i<64;i++) t1[i]=(unsigned char)(i*3);
    for(i=0;i<90;i++) t2[i]=(unsigned char)(i*5);
    for(i=0;i<40;i++) t3[i]=(unsigned char)(i*7);

    ck(mpool_count(mp)==0, "count 0 at start");
    ck(mpool_put(mp, tid1, t1, 64)==1, "put tid1 -> new (1)");
    ck(mpool_put(mp, tid2, t2, 90)==1, "put tid2 -> new (1)");
    ck(mpool_put(mp, tid3, t3, 40)==1, "put tid3 -> new (1)");
    ck(mpool_count(mp)==3, "count 3 after three puts");
    ck(mpool_put(mp, tid1, t1, 64)==0, "put tid1 again -> dup (0)");
    ck(mpool_count(mp)==3, "count still 3 after dup");

    /* get round-trips */
    unsigned long len=0;
    const unsigned char* p = mpool_get(mp, tid1, &len);
    ck(p!=0 && len==64, "get tid1 -> present, len 64");
    ck(p && memcmp(p,t1,64)==0, "tid1 bytes round-trip");
    p = mpool_get(mp, tid2, &len);
    ck(p!=0 && len==90 && memcmp(p,t2,90)==0, "tid2 bytes round-trip");
    p = mpool_get(mp, tid3, &len);
    ck(p!=0 && len==40 && memcmp(p,t3,40)==0, "tid3 bytes round-trip");

    /* miss */
    unsigned char miss[32]; for(i=0;i<32;i++) miss[i]=0xAA;
    p = mpool_get(mp, miss, &len);
    ck(p==0, "get unknown txid -> 0 (miss)");

    /* larger count to exercise probing (collisions); distinct txids */
    static unsigned char tids[512][32]; static unsigned char txb[512][64];
    for(i=0;i<300;i++){ for(int j=0;j<4;j++) tids[i][j]=(unsigned char)((i>>(8*j))&0xFF); for(int j=4;j<32;j++) tids[i][j]=0xAA; for(int j=0;j<64;j++) txb[i][j]=(unsigned char)(i*7+j); }
    for(i=0;i<300;i++){ long r=mpool_put(mp, tids[i], txb[i], 64); if(r!=1){ printf("FAIL: bulk put %u -> %ld\n",i,r); failures++; break; } }
    for(i=0;i<300;i++){ unsigned long l2=0; const unsigned char* pp=mpool_get(mp,tids[i],&l2); if(!pp || l2!=64 || memcmp(pp,txb[i],64)!=0){ printf("FAIL: bulk get %u\n",i); failures++; break; } }

    printf(failures? "\nFAILURES: %d\n" : "\nALL TESTS PASSED (%d failures)\n", failures);
    return failures?1:0;
}

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

    /* --- mpool_del (eviction, used by RBF policy) --- */
    {
        extern long mpool_del(void* mp, const unsigned char txid[32]);
        /* put a fourth tx, then delete it */
        unsigned char tid4[32], t4[50];
        for(i=0;i<32;i++) tid4[i]=(unsigned char)(i+3);
        for(i=0;i<50;i++) t4[i]=(unsigned char)(i+1);
        ck(mpool_put(mp, tid4, t4, 50)==1, "put tid4 -> new (1)");
        ck(mpool_get(mp, tid4, &len)!=0 && len==50, "tid4 present after put");
        ck(mpool_del(mp, tid4)==1, "del tid4 -> deleted (1)");
        ck(mpool_get(mp, tid4, &len)==0, "tid4 gone after del");
        ck(mpool_del(mp, tid4)==0, "del tid4 again -> not found (0)");
        ck(mpool_del(mp, miss)==0, "del unknown txid -> not found (0)");
        /* count decreased */
        ck(mpool_count(mp)==3, "count back to 3 after delete");
        /* the three original txs still intact */
        len=0; p = mpool_get(mp, tid1, &len);
        ck(p!=0 && len==64 && memcmp(p,t1,64)==0, "tid1 survives after delete of another");
        p = mpool_get(mp, tid2, &len);
        ck(p!=0 && len==90 && memcmp(p,t2,90)==0, "tid2 survives after delete of another");
    }

    /* larger count to exercise probing (collisions); distinct txids */
    static unsigned char tids[512][32]; static unsigned char txb[512][64];
    for(i=0;i<300;i++){ for(int j=0;j<4;j++) tids[i][j]=(unsigned char)((i>>(8*j))&0xFF); for(int j=4;j<32;j++) tids[i][j]=0xAA; for(int j=0;j<64;j++) txb[i][j]=(unsigned char)(i*7+j); }
    for(i=0;i<300;i++){ long r=mpool_put(mp, tids[i], txb[i], 64); if(r!=1){ printf("FAIL: bulk put %u -> %ld\n",i,r); failures++; break; } }
    for(i=0;i<300;i++){ unsigned long l2=0; const unsigned char* pp=mpool_get(mp,tids[i],&l2); if(!pp || l2!=64 || memcmp(pp,txb[i],64)!=0){ printf("FAIL: bulk get %u\n",i); failures++; break; } }

    /* ---- MEM-21 (audit 2026-09-03): an INCOHERENT slot must read as a miss
     *
     * mpool_get returned blob + blob_off with the slot's len and validated
     * neither. The pool is MAP_SHARED and daemon/tx_accept.c's verification
     * path reads it WITHOUT mp_lock, so a concurrent mpool_del in another
     * process can be mid-move when this reader matches: del copies a whole
     * 48-byte record with one mcopy, and the txid sits at +8..39 while
     * blob_off sits at +40, so there is a window where the NEW occupant's
     * txid has landed but its blob_off has not. The reader then pairs the new
     * `len` with the STALE `blob_off` of the slot being emptied.
     *
     * The audit reasoned this was harmless because "both fields are < cap".
     * That does not follow -- their SUM is unbounded, so the read runs off the
     * end of the blob mapping: a SIGSEGV in a forked serve child parsing
     * untrusted P2P input, not merely a wrong verdict.
     *
     * The race itself cannot be driven deterministically from a test, so the
     * BOUND is what is asserted here: a slot whose len/blob_off pair would
     * read past blob_cap must answer NULL. Reverting the check makes
     * mpool_get hand back a pointer past the end of the mapping, which the
     * read below then dereferences. */
    {
        unsigned long l = 0;
        /* tid1 is a live entry; corrupt its slot the way a torn del would.
         * Slot layout (bitcoin_mempool.asm header): +40 is the first slot,
         * 48 bytes each, [+0 len][+8 txid[32]][+40 blob_off]. Find it by txid
         * rather than assuming a probe position. */
        unsigned char* slot = NULL;
        for (unsigned long q = 0; q < slots; q++){
            unsigned char* cand = mp + 40 + q * 48;
            if (memcmp(cand + 8, tid1, 32) == 0){ slot = cand; break; }
        }
        ck(slot != NULL, "MEM-21 located tid1's slot");
        if (slot){
            unsigned long long saved_len = *(unsigned long long*)(slot + 0);
            unsigned long long saved_off = *(unsigned long long*)(slot + 40);

            /* a stale blob_off from a slot near the end of the blob, paired
             * with a live len -- each alone is < cap, the sum is not */
            *(unsigned long long*)(slot + 40) = (1UL << 18) - 8;
            *(unsigned long long*)(slot + 0)  = 64;
            ck(mpool_get(mp, tid1, &l) == NULL,
               "MEM-21 blob_off+len past blob_cap reads as a MISS, not a pointer");

            /* wrap: blob_off + len overflows 64 bits */
            *(unsigned long long*)(slot + 40) = 0xFFFFFFFFFFFFFFF0ULL;
            *(unsigned long long*)(slot + 0)  = 64;
            ck(mpool_get(mp, tid1, &l) == NULL,
               "MEM-21 a wrapping blob_off+len reads as a MISS");

            /* THE CONTROL'S OTHER HALF: restored, it must be found again --
             * a bound written >= instead of > would silently lose every
             * entry that ends exactly at blob_cap. */
            *(unsigned long long*)(slot + 0)  = saved_len;
            *(unsigned long long*)(slot + 40) = saved_off;
            const unsigned char* ok = mpool_get(mp, tid1, &l);
            ck(ok != NULL && l == 64 && memcmp(ok, t1, 64) == 0,
               "MEM-21 a coherent slot is still returned intact");

            /* and an entry ending EXACTLY at blob_cap is still valid */
            *(unsigned long long*)(slot + 40) = (1UL << 18) - 64;
            *(unsigned long long*)(slot + 0)  = 64;
            ck(mpool_get(mp, tid1, &l) != NULL,
               "MEM-21 an entry ending exactly at blob_cap is NOT rejected");
            *(unsigned long long*)(slot + 0)  = saved_len;
            *(unsigned long long*)(slot + 40) = saved_off;
        }
    }

    printf(failures? "\nFAILURES: %d\n" : "\nALL TESTS PASSED (%d failures)\n", failures);
    return failures?1:0;
}

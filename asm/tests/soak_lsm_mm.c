/* tests/soak_lsm_mm.c -- randomized differential soak for the mmap fast path.
 *
 * Interleaves put/del/get with flushes, compactions and reloads at a scale the
 * targeted tests do not reach, diffing EVERY get against the assembly path.
 * Built to hunt a data-dependent divergence, not to be pretty.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_tmpdir.h"

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const unsigned char txid[32],
                          unsigned index, unsigned long long value,
                          unsigned long height, unsigned long is_coinbase,
                          const unsigned char* script, unsigned slen);
extern long utxo_lsm_del(void* lst, void* u, const unsigned char txid[32], unsigned index);
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index,
                          unsigned long long* value, unsigned long* height,
                          unsigned long* is_coinbase,
                          const unsigned char** script, unsigned long* slen);
extern void utxo_lsm_close(void* lst);
extern long utxo_lsm_compact(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern void lsm_mm_set_enabled(int on);

struct LST {
    long log_fd, idx_fd;
    unsigned long long log_len, ckpt_log_off, ckpt_n;
    unsigned long long op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap;
    unsigned long long next_run_no;
    void* tomb_hash_buf; unsigned long long tomb_hash_mask;
};

#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
#define SLOTS          16384
#define BLOB           (32u<<20)
#define TOMB_CAP       512
#define MANIFEST_CAP   512
#define DESC_CAP       8192
#define SCRATCH_CAP    ((unsigned long long)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)
#define FILL           1200u
#define UNIVERSE       30000u

static unsigned long long rs = 0x243F6A8885A308D3ULL;
static unsigned rnd(void){ rs ^= rs<<13; rs ^= rs>>7; rs ^= rs<<17; return (unsigned)(rs>>32); }

static void make_txid(unsigned char* t, unsigned i) {
    for (int j = 0; j < 32; j++) t[j] = (unsigned char)(0x40 + j);
    t[0]=(unsigned char)(i&0xff); t[1]=(unsigned char)((i>>8)&0xff);
    t[2]=(unsigned char)((i>>16)&0xff);
    t[7]=(unsigned char)(i*31u); t[19]=(unsigned char)(i>>3);
}

typedef struct { long r; unsigned long long v; unsigned long h,cb; unsigned slen;
                 unsigned char script[128]; } res_t;

static void do_get(struct LST* l, void* u, unsigned i, unsigned idx, res_t* o){
    unsigned char t[32]; make_txid(t,i);
    const unsigned char* sp=NULL; unsigned long sl=0;
    unsigned long long v=0; unsigned long h=0,cb=0;
    memset(o,0,sizeof *o);
    o->r = utxo_lsm_get(l,u,t,idx,&v,&h,&cb,&sp,&sl);
    o->v=v; o->h=h; o->cb=cb; o->slen=sl;
    if(o->r==1 && sl && sl<=sizeof o->script) memcpy(o->script,sp,sl);
}
static int res_eq(const res_t*a,const res_t*b){
    if(a->r!=b->r||a->v!=b->v||a->h!=b->h||a->cb!=b->cb||a->slen!=b->slen) return 0;
    if(a->r==1&&a->slen&&a->slen<=sizeof a->script) return !memcmp(a->script,b->script,a->slen);
    return 1;
}

int main(int argc, char** argv){
    unsigned rounds = (argc>1)? (unsigned)atoi(argv[1]) : 3;
    tt_isolate();

    void* tomb=malloc((size_t)TOMB_CAP*36); void* man=malloc((size_t)MANIFEST_CAP*16);
    void* scr=malloc(SCRATCH_CAP); void* blob=malloc(BLOB);
    void* u=malloc(utxo_struct_size(SLOTS));
    if(!tomb||!man||!scr||!blob||!u){ printf("FAIL alloc\n"); return 1; }
    utxo_init(u,SLOTS,blob,BLOB);

    struct LST lst; memset(&lst,0,sizeof lst);
    lst.op_threshold=100000000ULL; lst.fill_threshold=FILL;
    lst.tomb_buf=tomb; lst.tomb_cap=TOMB_CAP;
    lst.manifest_buf=man; lst.manifest_cap=MANIFEST_CAP;
    lst.scratch_buf=scr; lst.scratch_cap=SCRATCH_CAP;
    if(utxo_lsm_init(&lst)!=1){ printf("FAIL init\n"); return 1; }

    unsigned char script[400];
    for(int j=0;j<400;j++) script[j]=(unsigned char)(j*7+1);

    unsigned long long ops=0, gets=0; unsigned mism=0;
    res_t a,b;

    for(unsigned round=0; round<rounds && mism==0; round++){
        /* mutate */
        for(unsigned k=0;k<20000;k++){
            unsigned i = rnd()%UNIVERSE, idx = rnd()&3, act = rnd()%100;
            unsigned char t[32]; make_txid(t,i);
            if(act<70){
                unsigned sl = 1 + (rnd()% (rnd()%8==0 ? 380u : 40u));  /* mostly small, sometimes big */
                if(utxo_lsm_put(&lst,u,t,idx,1000ULL+i*7+round,10+i,(i+round)&1,script,sl)<0){
                    printf("FAIL put i=%u round=%u\n",i,round); return 1; }
            } else if(act<85){
                utxo_lsm_del(&lst,u,t,idx);
            }
            ops++;
        }
        if((round%2)==1){ if(utxo_lsm_compact(&lst)<0){ printf("FAIL compact\n"); return 1; } }
        if((round%3)==2){
            utxo_lsm_close(&lst);
            memset(&lst,0,sizeof lst);
            lst.op_threshold=100000000ULL; lst.fill_threshold=FILL;
            lst.tomb_buf=tomb; lst.tomb_cap=TOMB_CAP;
            lst.manifest_buf=man; lst.manifest_cap=MANIFEST_CAP;
            lst.scratch_buf=scr; lst.scratch_cap=SCRATCH_CAP;
            utxo_init(u,SLOTS,blob,BLOB);
            if(utxo_lsm_reload(&lst,u)==-1){ printf("FAIL reload\n"); return 1; }
        }
        /* diff every key in the universe, both indices classes */
        for(unsigned i=0;i<UNIVERSE && mism==0;i++){
            unsigned idx = i&3;
            lsm_mm_set_enabled(1); do_get(&lst,u,i,idx,&a);
            lsm_mm_set_enabled(0); do_get(&lst,u,i,idx,&b);
            gets++;
            if(!res_eq(&a,&b)){
                printf("MISMATCH round=%u key=%u idx=%u manifest_n=%llu\n",
                       round,i,idx,(unsigned long long)lst.manifest_n);
                printf("   mmap{r=%ld v=%llu h=%lu cb=%lu sl=%u}\n",a.r,a.v,a.h,a.cb,a.slen);
                printf("   asm {r=%ld v=%llu h=%lu cb=%lu sl=%u}\n",b.r,b.v,b.h,b.cb,b.slen);
                mism++;
            }
        }
        printf("round %u: ops=%llu gets=%llu manifest_n=%llu next_run=%llu mismatches=%u\n",
               round,ops,gets,(unsigned long long)lst.manifest_n,
               (unsigned long long)lst.next_run_no,mism);
        fflush(stdout);
    }
    lsm_mm_set_enabled(1);
    utxo_lsm_close(&lst);
    if(mism){ printf("\nSOAK FAILED (%u mismatches)\n",mism); return 1; }
    printf("\nSOAK PASSED (%llu gets diffed, 0 mismatches)\n",gets);
    return 0;
}

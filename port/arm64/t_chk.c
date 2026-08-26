/* t_chk.c -- validate check_utxo_records: 0 viol on clean big table, >0 on corruption */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
extern size_t utxo_struct_size(unsigned long);
extern void   utxo_init(void*,unsigned long,void*,unsigned long);
extern long   utxo_put(void*,const uint8_t*,unsigned long,unsigned long long,unsigned long,unsigned long,const uint8_t*,unsigned long);
typedef struct { unsigned long long bo, len; const uint8_t* sc; } UREC;
static int cmprec(const void*a,const void*b){const UREC*A=a,*B=b;return A->bo<B->bo?-1:A->bo>B->bo;}
static long chk(const void* U){
    unsigned long mask=*(const unsigned long*)((const uint8_t*)U+8); unsigned long slots=mask+1;
    const uint8_t* blob=*(const uint8_t* const*)((const uint8_t*)U+16);
    unsigned long long fill=*(const unsigned long long*)((const uint8_t*)U+32), cap=*(const unsigned long long*)((const uint8_t*)U+24);
    UREC* r=malloc(slots*sizeof(UREC)); unsigned long long n=0;
    for(unsigned long long i=0;i<slots;i++){
        const uint8_t* s=(const uint8_t*)U+40+i*48; unsigned st; memcpy(&st,s+40,4);
        if(st==0xFFFFFFFFUL)continue;
        memcpy(&r[n].bo,s,8); memcpy(&r[n].len,blob+r[n].bo+16,8); r[n].sc=blob+r[n].bo+24; n++;
    }
    qsort(r,n,sizeof(UREC),cmprec); long viol=0;
    if(getenv("CHKDBG")){ printf("n=%llu:\n",n); for(unsigned long long i=0;i<6&&i<n;i++)printf("   [%llu] bo=%llu len=%llu\n",i,r[i].bo,r[i].len); }
    for(unsigned long long i=0;i<n;i++){
        if(r[i].len>cap||r[i].bo+24+r[i].len>fill) viol++;
        if(i+1<n && r[i+1].bo < r[i].bo+24+r[i].len) viol++;
    }
    free(r); return viol;
}
int main(){
    unsigned long slots=1<<16; void* U=malloc(utxo_struct_size(slots)); uint8_t* blob=malloc(1u<<26);
    utxo_init(U,slots,blob,1u<<26); uint8_t txid[32],scr[67];
    long vi;
    for(long b=0;b<20;b++){ /* 20 "blocks" x 3000 keys */
        for(long i=0;i<3000;i++){
            for(int k=0;k<32;k++) txid[k]=(uint8_t)(rand());
            unsigned sl=25+ (i%3)*21; for(unsigned k=0;k<sl;k++)scr[k]=(uint8_t)rand();
            vi=utxo_put(U,txid,(unsigned long)(i%5), (unsigned long long)i, (unsigned long)i, i%2, scr, sl);
            (void)vi;
        }
    }
    printf("utxo_count=%ld clean-check viol=%ld (expect 0)\n",(long)(*(unsigned long long*)U), chk(U));
    /* corrupt: set a slot's blob_off to a DIFFERENT live slot's blob_off (duplicate) */
    const uint8_t* bs=(const uint8_t*)U+40; unsigned long long bo0; unsigned tgt=0;
    /* first live slot's bo */
    while(tgt<slots){ unsigned st; memcpy(&st,bs+tgt*48+40,4); if(st!=0xFFFFFFFFUL){ memcpy(&bo0,bs+tgt*48,8); break; } tgt++; }
    /* a later live slot with a DIFFERENT bo -> alias it to bo0 */
    for(unsigned long long i=tgt+1;i<slots;i++){ unsigned st; memcpy(&st,bs+i*48+40,4);
        if(st!=0xFFFFFFFFUL){ unsigned long long bi; memcpy(&bi,bs+i*48,8);
            if(bi!=bo0){ memcpy((void*)(bs+i*48),&bo0,8); printf("corrupted slot %llu blob_off %llu -> %llu (dup)\n",i,bi,bo0); break; } } }
    printf("corrupted-check viol=%ld (expect >0)\n", chk(U));
    return 0;
}

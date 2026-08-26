/* t_repro.c -- reload the persistent UTXO snapshot and inspect the failing key.
 * Run from the data/ dir (where utxo.idx + utxo.dat live).
 * Target: prevout txid 248ca2dcc9f1ae1028366df277911784e149ed83f387ffd9f751aac5bfef7606 idx0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern size_t utxo_struct_size(unsigned long);
extern void   utxo_init(void*,unsigned long,void*,unsigned long);
extern long   utxo_store_init(void*);
extern long   utxo_store_reload(void*,void*);
extern long   utxo_get(void*,const uint8_t*,unsigned long,unsigned long long*,
                       unsigned long*,unsigned long*,const uint8_t**,unsigned long*);
extern long   utxo_walk_live(void*, void(*)(void*,const uint8_t*,unsigned long long,
                             unsigned long long,const uint8_t*,unsigned long), void*);
extern long   utxo_count(void*);

static void* U;
static void* ST;
static uint8_t* blob;
typedef struct { uint8_t key[36]; unsigned long long value,code; unsigned long slen; uint8_t script[520];} ENTRY;
static ENTRY* dumpv; static long nd, cap;

static void cb(void*c,const uint8_t*k,unsigned long long v,unsigned long long code,
               const uint8_t*s,unsigned long sl){
    (void)c; if(nd>=cap)return;
    memcpy(dumpv[nd].key,k,36); dumpv[nd].value=v; dumpv[nd].code=code; dumpv[nd].slen=sl;
    if(sl>520)sl=520; memcpy(dumpv[nd].script,s,sl); nd++;
}
static int hv(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return 0;}
static size_t h2b(const char*h,uint8_t*o){size_t n=strlen(h);for(size_t i=0;i<n/2;i++)o[i]=(uint8_t)((hv(h[2*i])<<4)|hv(h[2*i+1]));return n/2;}
static void pr(const uint8_t*d,size_t n){for(size_t i=0;i<n;i++)printf("%02x",d[i]);}

int main(int argc,char**argv){
    (void)argc;(void)argv;
    unsigned long slots=1ul<<22;
    U=malloc(utxo_struct_size(slots)); if(!U){printf("oom u\n");return 1;}
    blob=malloc(1ul<<28); if(!blob){printf("oom blob\n");return 1;}
    utxo_init(U,slots,blob,1ul<<28);
    ST=malloc(64); memset(ST,0,64);
    if(utxo_store_init(ST)!=1){printf("store init failed\n");return 1;}
    long nrc=utxo_store_reload(ST,U);
    printf("reload returned=%ld utxo_count=%ld\n",nrc,(long)utxo_count(U));

    /* target key */
    uint8_t t[32]; h2b("248ca2dcc9f1ae1028366df277911784e149ed83f387ffd9f751aac5bfef7606",t);
    unsigned long long val; unsigned long height,cb,slen; const uint8_t*scr;
    long r=utxo_get(U,t,0,&val,&height,&cb,&scr,&slen);
    printf("GET target idx0 -> %ld\n",r);
    if(r){ printf("  value=%llu height=%lu cb=%lu slen=%lu script=",val,height,cb,slen);
           pr(scr,slen>80?80:slen); if(slen>80)printf("..."); printf("\n"); }

    /* find which key owns the P2PK 410496b5... record */
    cap=1<<22; dumpv=malloc(cap*sizeof(ENTRY)); if(!dumpv){printf("oom dumpv\n");return 1;}
    nd=0; long nw=utxo_walk_live(U,cb,0);
    printf("walk emitted %ld\n",nw);
    long found=0;
    for(long i=0;i<nd;i++){
        if(dumpv[i].slen==67 && dumpv[i].script[0]==0x41 && dumpv[i].script[1]==0x96){
            printf("P2PK-aliased record owner: key="); pr(dumpv[i].key,36);
            printf(" value=%llu code=%llu slen=%lu script=",dumpv[i].value,dumpv[i].code,dumpv[i].slen);
            pr(dumpv[i].script,67); printf("\n"); found++;
        }
    }
    printf("total P2PK(0496b5..) owners found=%ld\n",found);

    /* also check: does the target txid exist at ANY index with the P2PKH? */
    long pkh=0;
    for(long i=0;i<nd;i++){
        if(memcmp(dumpv[i].key,t,32)==0){
            printf("target-txid entry idx=%02x%02x%02x%02x slen=%lu script=",
                   dumpv[i].key[32],dumpv[i].key[33],dumpv[i].key[34],dumpv[i].key[35],dumpv[i].slen);
            pr(dumpv[i].script,dumpv[i].slen>40?40:dumpv[i].slen); printf("\n");
            if(dumpv[i].slen==25 && dumpv[i].script[0]==0x76 && dumpv[i].script[1]==0xa9)pkh++;
        }
    }
    printf("target-txid P2PKH entries=%ld\n",pkh);
    return 0;
}

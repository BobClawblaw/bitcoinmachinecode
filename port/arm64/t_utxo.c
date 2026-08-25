/* t_utxo.c -- differential driver for the ported bitcoin_utxo.S.
 * ops per line:
 *   init <slots>
 *   put  <txidhex32> <index> <value> <height> <cb> <scripthex>
 *   get  <txidhex32> <index>     -> "get <found> <value> <height> <cb> <slen>"
 *   del  <txidhex32> <index>     -> "del <ret>"
 *   count                        -> "count <n>"
 *   walk                         -> "walk <n>" then each "<key36hex> <value> <code> <slen> <scripthex>"
 * After every mutating op the driver dumps the full sorted table via walk
 * ("D n" then D-entries) so the oracle can verify exact state.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern size_t utxo_struct_size(unsigned long);
extern void utxo_init(void*,unsigned long,void*,unsigned long);
extern long utxo_put(void*,const uint8_t*,unsigned long,unsigned long long,
                     unsigned long,unsigned long,const uint8_t*,unsigned long);
extern long utxo_get(void*,const uint8_t*,unsigned long,unsigned long long*,
                     unsigned long*,unsigned long*,const uint8_t**,unsigned long*);
extern long utxo_del(void*,const uint8_t*,unsigned long);
extern long utxo_count(void*);
extern long utxo_walk_live(void*, void(*)(void*,const uint8_t*,unsigned long long,
                     unsigned long long,const uint8_t*,unsigned long), void*);

static long NENTRIES=0;
static uint8_t entries[1<<20][48];   /* not used via walk cb? we capture in dict via sort */
static void* U;
static uint8_t blob[1<<23];
static void b2h(const uint8_t*d,size_t n,char*o);

typedef struct { uint8_t key[36]; unsigned long long value; unsigned long long code;
                 unsigned long slen; uint8_t script[520]; } ENTRY;
static ENTRY dump[1<<20];
static long nd;

static void cb(void*ctx,const uint8_t*key,unsigned long long value,
               unsigned long long code,const uint8_t*script,unsigned long slen){
    (void)ctx;
    if(nd>= (long)(sizeof dump/sizeof dump[0]))return;
    memcpy(dump[nd].key,key,36); dump[nd].value=value; dump[nd].code=code;
    dump[nd].slen=slen; if(slen>520)slen=520; memcpy(dump[nd].script,script,slen);
    nd++;
}
static int cmpk(const void*a,const void*b){return memcmp(((ENTRY*)a)->key,((ENTRY*)b)->key,36);}
static void dumpwalk(char*tag){
    nd=0; long n=utxo_walk_live(U,cb,0);
    qsort(dump,n,sizeof(ENTRY),cmpk);
    printf("%s %ld\n",tag,n);
    for(long i=0;i<n;i++){
        char kh[80]; b2h(dump[i].key,36,kh);
        printf("%s %llu %llu %lu ",kh,dump[i].value,dump[i].code,dump[i].slen);
        for(unsigned long j=0;j<dump[i].slen;j++)printf("%02x",dump[i].script[j]);
        printf("\n");
    }
}
static int hv(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return 0;}
static size_t h2b(const char*h,uint8_t*o,size_t m){size_t n=strlen(h);if(m<n/2)n=m*2;size_t i;for(i=0;i<n/2;i++)o[i]=(uint8_t)((hv(h[2*i])<<4)|hv(h[2*i+1]));return n/2;}
static void b2h(const uint8_t*d,size_t n,char*o){static const char*X="0123456789abcdef";size_t i;for(i=0;i<n;i++){o[2*i]=X[d[i]>>4];o[2*i+1]=X[d[i]&15];}o[2*n]=0;}

int main(){
    char line[140000]; uint8_t txid[32];
    while(fgets(line,sizeof line,stdin)){
        char op[16];
        if(sscanf(line,"%15s",op)!=1)continue;
        if(!strcmp(op,"init")){
            unsigned long slots; if(sscanf(line+4,"%lu",&slots)!=1)continue;
            U=malloc(utxo_struct_size(slots));
            utxo_init(U,slots,blob,sizeof blob);
            printf("init ok\n");
        } else if(!strcmp(op,"put")){
            char th[80],sh[4000]; unsigned long idx,height,cb_b; unsigned long long value;
            if(sscanf(line,"put %79s %lu %llu %lu %lu %3999s",th,&idx,&value,&height,&cb_b,sh)!=6)continue;
            h2b(th,txid,32); uint8_t sc[2000]; size_t sl=(sh[0]=='-')?0:h2b(sh,sc,sizeof sc);
            long r=utxo_put(U,txid,idx,value,height,cb_b,sc,sl);
            printf("put %ld\n",r);
            dumpwalk("D");
        } else if(!strcmp(op,"get")){
            char th[80]; unsigned long idx;
            if(sscanf(line,"get %79s %lu",th,&idx)!=2)continue;
            h2b(th,txid,32);
            unsigned long long value; unsigned long height,cb_b,slen; const uint8_t*scr;
            long r=utxo_get(U,txid,idx,&value,&height,&cb_b,&scr,&slen);
            if(!r){printf("get 0\n");}
            else{
                char oh[1100]; b2h(scr,slen>520?520:slen,oh);
                printf("get 1 %llu %lu %lu %lu %s\n",value,height,cb_b,slen,oh);
            }
        } else if(!strcmp(op,"del")){
            char th[80]; unsigned long idx;
            if(sscanf(line,"del %79s %lu",th,&idx)!=2)continue;
            h2b(th,txid,32); long r=utxo_del(U,txid,idx);
            printf("del %ld\n",r);
            dumpwalk("D");
        } else if(!strcmp(op,"count")){
            printf("count %ld\n",(long)utxo_count(U));
        } else if(!strcmp(op,"walk")){
            dumpwalk("walk");
        }
        fflush(stdout);
    }
    return 0;
}

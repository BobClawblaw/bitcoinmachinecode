/* t_ustore.c -- differential driver for the PORTED bitcoin_utxo_store.S
 * (persistent UTXO store: WAL + checkpoint + reload). Runs in the current
 * directory (caller chdir's to a scratch dir so utxo.dat/utxo.idx are local).
 * ops:
 *   init <slots>
 *   put  <txidhex32> <index> <value> <height> <cb> <scripthex|'-'>
 *   del  <txidhex32> <index>
 *   get  <txidhex32> <index>
 *   sync                (checkpoint)
 *   reload <slots>      (reload into a FRESH table; prints "reload <n>")
 *   close
 * Every mutating op prints result + a full sorted walk dump (D) like t_utxo.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

extern size_t utxo_struct_size(unsigned long);
extern void   utxo_init(void*,unsigned long,void*,unsigned long);
extern long   utxo_store_init(void*);
extern long   utxo_store_put(void*,void*,const uint8_t*,unsigned long,unsigned long long,
                             unsigned long,unsigned long,const uint8_t*,unsigned long);
extern long   utxo_store_del(void*,void*,const uint8_t*,unsigned long);
extern long   utxo_store_get(void*,void*,const uint8_t*,unsigned long,unsigned long long*,
                             unsigned long*,unsigned long*,const uint8_t**,unsigned long*);
extern long   utxo_store_count(void*,void*);
extern long   utxo_store_sync(void*,void*);
extern long   utxo_store_reload(void*,void*);
extern void   utxo_store_close(void*);
extern long   utxo_walk_live(void*, void(*)(void*,const uint8_t*,unsigned long long,
                             unsigned long long,const uint8_t*,unsigned long), void*);

static void* U;
static void* ST;
static uint8_t blob[1<<23];
typedef struct { uint8_t key[36]; unsigned long long value; unsigned long long code;
                 unsigned long slen; uint8_t script[520]; } ENTRY;
static ENTRY dumpv[1<<19];
static long nd;
static void cb(void*c,const uint8_t*k,unsigned long long v,unsigned long long code,const uint8_t*s,unsigned long sl){
    (void)c; if(nd>=(long)(sizeof dumpv/sizeof dumpv[0]))return;
    memcpy(dumpv[nd].key,k,36); dumpv[nd].value=v; dumpv[nd].code=code; dumpv[nd].slen=sl;
    if(sl>520)sl=520; memcpy(dumpv[nd].script,s,sl); nd++;
}
static int cmpk(const void*a,const void*b){return memcmp(((ENTRY*)a)->key,((ENTRY*)b)->key,36);}
static void dumpwalk(char*tag){
    nd=0; long n=utxo_walk_live(U,cb,0); qsort(dumpv,n,sizeof(ENTRY),cmpk);
    printf("%s %ld\n",tag,n);
    for(long i=0;i<n;i++){
        printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x %llu %llu %lu ",
          dumpv[i].key[0],dumpv[i].key[1],dumpv[i].key[2],dumpv[i].key[3],dumpv[i].key[4],dumpv[i].key[5],dumpv[i].key[6],dumpv[i].key[7],dumpv[i].key[8],dumpv[i].key[9],dumpv[i].key[10],dumpv[i].key[11],dumpv[i].key[12],dumpv[i].key[13],dumpv[i].key[14],dumpv[i].key[15],dumpv[i].key[16],dumpv[i].key[17],dumpv[i].key[18],dumpv[i].key[19],dumpv[i].key[20],dumpv[i].key[21],dumpv[i].key[22],dumpv[i].key[23],dumpv[i].key[24],dumpv[i].key[25],dumpv[i].key[26],dumpv[i].key[27],dumpv[i].key[28],dumpv[i].key[29],dumpv[i].key[30],dumpv[i].key[31],dumpv[i].key[32],dumpv[i].key[33],dumpv[i].key[34],dumpv[i].key[35],
          dumpv[i].value,dumpv[i].code,dumpv[i].slen);
        for(unsigned long j=0;j<dumpv[i].slen;j++)printf("%02x",dumpv[i].script[j]);
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
            U=malloc(utxo_struct_size(slots)); utxo_init(U,slots,blob,sizeof blob);
            ST=malloc(64); memset(ST,0,64);
            long r=utxo_store_init(ST);
            printf("init %ld\n",r);
        } else if(!strcmp(op,"put")){
            char th[80],sh[4000]; unsigned long idx,height,cb_b; unsigned long long value;
            if(sscanf(line,"put %79s %lu %llu %lu %lu %3999s",th,&idx,&value,&height,&cb_b,sh)!=6)continue;
            h2b(th,txid,32); uint8_t sc[2000]; size_t sl=(sh[0]=='-')?0:h2b(sh,sc,sizeof sc);
            long r=utxo_store_put(ST,U,txid,idx,value,height,cb_b,sc,sl);
            printf("put %ld\n",r); dumpwalk("D");
        } else if(!strcmp(op,"del")){
            char th[80]; unsigned long idx;
            if(sscanf(line,"del %79s %lu",th,&idx)!=2)continue;
            h2b(th,txid,32); long r=utxo_store_del(ST,U,txid,idx);
            printf("del %ld\n",r); dumpwalk("D");
        } else if(!strcmp(op,"get")){
            char th[80]; unsigned long idx;
            if(sscanf(line,"get %79s %lu",th,&idx)!=2)continue;
            h2b(th,txid,32);
            unsigned long long value; unsigned long height,cb_b,slen; const uint8_t*scr;
            long r=utxo_store_get(ST,U,txid,idx,&value,&height,&cb_b,&scr,&slen);
            if(!r) printf("get 0\n");
            else { char oh[1100]; b2h(scr,slen>520?520:slen,oh); printf("get 1 %llu %lu %lu %lu %s\n",value,height,cb_b,slen,oh); }
        } else if(!strcmp(op,"sync")){
            long r=utxo_store_sync(ST,U); printf("sync %ld\n",r);
        } else if(!strcmp(op,"reload")){
            unsigned long slots; if(sscanf(line,"reload %lu",&slots)!=1)continue;
            /* fresh table (reuses fresh buffers) */
            U=malloc(utxo_struct_size(slots)); utxo_init(U,slots,blob,sizeof blob);
                        long nrc=utxo_store_reload(ST,U);
            (void)nrc;
            printf("reload\n"); dumpwalk("D");
        } else if(!strcmp(op,"close")){
            utxo_store_close(ST); printf("close\n");
        }
        fflush(stdout);
    }
    return 0;
}

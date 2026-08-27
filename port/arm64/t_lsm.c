/* t_lsm.c -- differential driver for the PORTED bitcoin_utxo_lsm.S.
 * Runs in the current directory (caller chdir's to a scratch dir so the
 * WAL/run/manifest files land locally). Ops per line:
 *   init   <op_thr> <fill_thr> <tombcap> <mancap> <slots>
 *   put    <txidhex32> <index> <value> <height> <cb> <scripthex|'-'>
 *   del    <txidhex32> <index>
 *   get    <txidhex32> <index>
 *   count
 *   flush
 *   compact
 *   reload <slots>
 *   walk
 *   close
 * Every mutating op prints the result + "C <count>". flush/compact/reload
 * additionally print a full live walk dump ("W n" then entries) so the
 * oracle can verify the exact live set.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

extern size_t utxo_struct_size(unsigned long);
extern void   utxo_init(void*,unsigned long,void*,unsigned long);
extern long   utxo_lsm_init(void*);
extern long   utxo_lsm_put(void*,void*,const uint8_t*,unsigned long,unsigned long long,
                           unsigned long,unsigned long,const uint8_t*,unsigned long);
extern long   utxo_lsm_del(void*,void*,const uint8_t*,unsigned long);
extern long   utxo_lsm_get(void*,void*,const uint8_t*,unsigned long,unsigned long long*,
                           unsigned long*,unsigned long*,const uint8_t**,unsigned long*);
extern long   utxo_lsm_count(void*);
extern long   utxo_lsm_flush(void*,void*);
extern long   utxo_lsm_compact(void*);
extern long   utxo_lsm_reload(void*,void*);
extern long   utxo_lsm_reload_ro(void*,void*);
extern void   utxo_lsm_close(void*);
extern long   utxo_lsm_walk(void*,void*, void(*)(void*,const uint8_t*,unsigned long long,
                            unsigned long long,const uint8_t*,unsigned long), void*);

/* lst is 168 bytes = 21 qwords; asm reads raw byte offsets only. */
static uint64_t* LST;
#define L_K(_f) (*((uint64_t*)LST + (_f)))   /* _f in qword units */

static void* U;
static uint8_t blob[1<<23];
static uint8_t* SCRATCH;
static size_t SCRATCH_CAP;

typedef struct { uint8_t key[36]; unsigned long long value; unsigned long long code;
                 unsigned long slen; uint8_t script[520]; } ENTRY;
static ENTRY dump[1<<20];
static long nd;
static void cb(void*c,const uint8_t*k,unsigned long long value,unsigned long long code,
               const uint8_t*s,unsigned long sl){
    (void)c;
    if(nd>=(long)(sizeof dump/sizeof dump[0]))return;
    memcpy(dump[nd].key,k,36); dump[nd].value=value; dump[nd].code=code; dump[nd].slen=sl;
    if(sl>520)sl=520; memcpy(dump[nd].script,s,sl); nd++;
}
static int cmpk(const void*a,const void*b){return memcmp(((ENTRY*)a)->key,((ENTRY*)b)->key,36);}
static void dumpwalk(char*tag){
    nd=0; long n=utxo_lsm_walk(LST,U,cb,0);
    if(n<0){ printf("%s %ld\n",tag,n); return; }
    qsort(dump,n,sizeof(ENTRY),cmpk);
    printf("%s %ld\n",tag,n);
    for(long i=0;i<n;i++){
        printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x %llu %llu %lu ",
          dump[i].key[0],dump[i].key[1],dump[i].key[2],dump[i].key[3],dump[i].key[4],dump[i].key[5],dump[i].key[6],dump[i].key[7],
          dump[i].key[8],dump[i].key[9],dump[i].key[10],dump[i].key[11],dump[i].key[12],dump[i].key[13],dump[i].key[14],dump[i].key[15],
          dump[i].key[16],dump[i].key[17],dump[i].key[18],dump[i].key[19],dump[i].key[20],dump[i].key[21],dump[i].key[22],dump[i].key[23],
          dump[i].key[24],dump[i].key[25],dump[i].key[26],dump[i].key[27],dump[i].key[28],dump[i].key[29],dump[i].key[30],dump[i].key[31],
          dump[i].key[32],dump[i].key[33],dump[i].key[34],dump[i].key[35],
          dump[i].value,dump[i].code,dump[i].slen);
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
            unsigned long othr,fthr,tcap,mcap,slots;
            if(sscanf(line,"init %lu %lu %lu %lu %lu",&othr,&fthr,&tcap,&mcap,&slots)!=5)continue;
            U=malloc(utxo_struct_size(slots)); utxo_init(U,slots,blob,sizeof blob);
            LST=malloc(168); memset(LST,0,168);
            /* caller-owned config fields */
            L_K(6)=othr; L_K(7)=fthr;
            L_K(9)=tcap;               /* tomb_cap */
            uint8_t*tomb=malloc(tcap*36+32); L_K(8)=(uint64_t)tomb;
            L_K(14)=mcap;              /* manifest_cap */
            uint8_t*manb=malloc(mcap*16+16); L_K(13)=(uint64_t)manb;
            /* scratch: desc_cap >= fthr+tcap; desc_cap=(cap-BLOOM-SCRIPT)/128 */
            size_t need=(fthr+tcap+64)*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES + 4096;
            SCRATCH=malloc(need); SCRATCH_CAP=need; L_K(16)=(uint64_t)SCRATCH; L_K(17)=SCRATCH_CAP;
            long r=utxo_lsm_init(LST);
            printf("init %ld\n",r); printf("C %ld\n",(long)utxo_lsm_count(LST));
        } else if(!strcmp(op,"put")){
            char th[80],sh[4000]; unsigned long idx,height,cb_b; unsigned long long value;
            if(sscanf(line,"put %79s %lu %llu %lu %lu %3999s",th,&idx,&value,&height,&cb_b,sh)!=6)continue;
            h2b(th,txid,32); uint8_t sc[2000]; size_t sl=(sh[0]=='-')?0:h2b(sh,sc,sizeof sc);
            long r=utxo_lsm_put(LST,U,txid,idx,value,height,cb_b,sc,sl);
            printf("put %ld\n",r); printf("C %ld\n",(long)utxo_lsm_count(LST));
        } else if(!strcmp(op,"del")){
            char th[80]; unsigned long idx;
            if(sscanf(line,"del %79s %lu",th,&idx)!=2)continue;
            h2b(th,txid,32); long r=utxo_lsm_del(LST,U,txid,idx);
            printf("del %ld\n",r); printf("C %ld\n",(long)utxo_lsm_count(LST));
        } else if(!strcmp(op,"get")){
            char th[80]; unsigned long idx;
            if(sscanf(line,"get %79s %lu",th,&idx)!=2)continue;
            h2b(th,txid,32);
            unsigned long long value; unsigned long height,cb_b,slen; const uint8_t*scr;
            long r=utxo_lsm_get(LST,U,txid,idx,&value,&height,&cb_b,&scr,&slen);
            if(!r){printf("G 0\n");}
            else{ char oh[1100]; b2h(scr,slen>520?520:slen,oh);
                  printf("G 1 %llu %lu %lu %lu %s\n",value,height,cb_b,slen,oh); }
        } else if(!strcmp(op,"count")){
            printf("count %ld\n",(long)utxo_lsm_count(LST));
        } else if(!strcmp(op,"flush")){
            long r=utxo_lsm_flush(LST,U);
            printf("flush %ld\n",r); dumpwalk("W");
        } else if(!strcmp(op,"compact")){
            long r=utxo_lsm_compact(LST);
            printf("compact %ld\n",r); dumpwalk("W");
        } else if(!strcmp(op,"reload")||!strcmp(op,"reload_ro")){
            unsigned long slots; if(sscanf(line,"%*s %lu",&slots)!=1)continue;
            /* free old u buffers, fresh table */
            /* NOTE: previous U's slots/blob are malloc/static; use new fresh table */
            U=malloc(utxo_struct_size(slots)); utxo_init(U,slots,blob,sizeof blob);
            long r = !strcmp(op,"reload_ro") ? utxo_lsm_reload_ro(LST,U) : utxo_lsm_reload(LST,U);
            printf("%s %ld\n",op,r); dumpwalk("W");
        } else if(!strcmp(op,"walk")){
            dumpwalk("W");
        } else if(!strcmp(op,"udump")){
            /* u layout: +0 n, +8 slots(mask), +16 blob, +24 blob_cap, +32 fill,
               +40 slot[slots] (48B each): +0 blob_off +8 txid(32) +40 index */
            unsigned long n=*(unsigned long*)((char*)U+0);
            unsigned long nslots=*(unsigned long*)((char*)U+8);
            printf("UD n=%lu slots=%lu\n",n,nslots);
            unsigned long dup=0;
            for(unsigned long i=0;i<=nslots;i++){
                char*s=(char*)U+40+i*48;
                if(*(unsigned int*)(s+40)!=(unsigned)-1){
                    printf("U %lu bo=%lu idx=%u k=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                      i, *(unsigned long*)s, *(unsigned int*)(s+40),
                      (unsigned char)s[8],(unsigned char)s[9],(unsigned char)s[10],
                      (unsigned char)s[11],(unsigned char)s[12],(unsigned char)s[13],
                      (unsigned char)s[14],(unsigned char)s[15]);
                    dup++;
                }
            }
            printf("UD livecount=%lu\n",dup);
        } else if(!strcmp(op,"mark")){
            printf("MARK\n");
        } else if(!strcmp(op,"info")){
            printf("info mf=%lu mg=%lu mr=%lu op=%lu tl=%lu\n",
                   (unsigned long)L_K(15),(unsigned long)L_K(12),
                   (unsigned long)L_K(18),(unsigned long)L_K(5),(unsigned long)L_K(11));
        } else if(!strcmp(op,"close")){
            utxo_lsm_close(LST); printf("close\n");
        }
        fflush(stdout);
    }
    return 0;
}

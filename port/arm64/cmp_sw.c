/* cmp_sw.c -- feed hex txs on stdin; compare C strip_witness vs strip_witness_asm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
/* conflicting dup decl guards: we directly include the C file's decls */
extern long strip_witness(const uint8_t* tx, int64_t txlen, uint8_t* out, long cap);
extern long strip_witness_asm(const uint8_t* tx, int64_t txlen, uint8_t* out, long cap);
long mempool_resolve_confirmed_utxo(void* u, const uint8_t txid[32], unsigned long index,
    unsigned long long* value, const uint8_t** spk, unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen; abort(); }
static int hv(int c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
int main(void){
    char line[1<<22]; uint8_t* buf=malloc(2<<20); uint8_t *oc=malloc(2<<20),*oa=malloc(2<<20);
    while(fgets(line,sizeof line,stdin)){
        line[strcspn(line,"\n")]=0; int hl=strlen(line); if(hl%2){printf("bad\n");continue;}
        int n=hl/2; int bad=0;
        for(int i=0;i<n;i++){int a=hv(line[2*i]),b=hv(line[2*i+1]); if(a<0||b<0){bad=1;break;} buf[i]=(a<<4)|b;}
        if(bad){printf("badhex\n");continue;}
        memset(oc,0xCC,2<<20); memset(oa,0xCC,2<<20);
        long c=strip_witness(buf,n,oc,1<<20);
        long a=strip_witness_asm(buf,n,oa,1<<20);
        int same = (c==a) && (c<=0 || memcmp(oc,oa,(size_t)c)==0);
        printf("%s c=%ld a=%ld n=%d\n", same?"MATCH":"DIFF", c, a, n);
        if(!same){
            printf(" C:"); for(int i=0;i<(c>0?c:64)&&i<200;i++)printf("%02x",oc[i]); printf("\n");
            printf(" A:"); for(int i=0;i<(a>0?a:64)&&i<200;i++)printf("%02x",oa[i]); printf("\n");
        }
    }
    return 0;
}

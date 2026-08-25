/* t_bip143.c -- differential driver for segwit_v0_sighash_asm (BIP143).
 * lines: <txhex> <n_in> <nHashType> <amount> <schex>
 * prints: <prelen> <hash32hex> <preimage hex>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern long segwit_v0_sighash_asm(uint8_t out32[32], const uint8_t* tx,
                                  int64_t txlen, int64_t n_in, uint32_t nHashType,
                                  uint64_t amount,
                                  const uint8_t* scriptCode, uint64_t sclen,
                                  uint8_t* pre, long cap);

static int hv(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return 0;}
static size_t h2b(const char*h,uint8_t*o,size_t m){size_t n=strlen(h)/2;if(n>m)n=m;for(size_t i=0;i<n;i++)o[i]=(uint8_t)((hv(h[2*i])<<4)|hv(h[2*i+1]));return n;}
static void b2h(const uint8_t*b,size_t n,char*o){static const char*x="0123456789abcdef";for(size_t i=0;i<n;i++){o[2*i]=x[b[i]>>4];o[2*i+1]=x[b[i]&15];}o[2*n]=0;}

int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"usage: t_bip143 <cases>\n");return 2;}
    FILE*f=fopen(argv[1],"r");
    if(!f){perror("open");return 2;}
    char*line=NULL;size_t cap=0;
    static uint8_t tx[1<<20],sc[1<<20],pre[4<<20],out[32];
    while(getline(&line,&cap,f)>=0){
        char txh[1<<21],sch[1<<21];
        long long nIn;unsigned long long ht,amount;
        if(sscanf(line,"%2097151s %lld %llu %llu %2097151s",txh,&nIn,&ht,&amount,sch)!=5)continue;
        size_t txlen=(txh[0]=='-')?0:h2b(txh,tx,sizeof tx);
        size_t sclen=(sch[0]=='-')?0:h2b(sch,sc,sizeof sc);
        long r=segwit_v0_sighash_asm(out,tx,txlen,nIn,(uint32_t)ht,amount,sc,sclen,pre,4<<20);
        char hh[65];
        b2h(out,32,hh);
        printf("%ld %s\n",r,hh);
    }
    free(line);fclose(f);return 0;
}

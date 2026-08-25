/* t_checksig.c -- differential driver for sv_checksig_asm /
 * sv_checksig_witness_v0_asm.
 * lines: <legacy|witness> <txhex> <nIn> <amount> <schex> <pubhex> <sighex>
 * prints: <0|1>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern uint64_t sv_checksig_asm(void*, const uint8_t*, uint64_t,
                                const uint8_t*, uint64_t, const void*);
extern uint64_t sv_checksig_witness_v0_asm(void*, const uint8_t*, uint64_t,
                                           const uint8_t*, uint64_t, const void*);

static int hv(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return 0;}
static size_t h2b(const char*h,uint8_t*o,size_t m){size_t n=strlen(h)/2;if(n>m)n=m;for(size_t i=0;i<n;i++)o[i]=(uint8_t)((hv(h[2*i])<<4)|hv(h[2*i+1]));return n;}

int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"usage: t_checksig <cases>\n");return 2;}
    FILE*f=fopen(argv[1],"r");
    if(!f){perror("open");return 2;}
    char*line=NULL;size_t cap=0;
    static uint8_t tx[1<<20],sc[1<<20],pub[512],sig[4096],work[4<<20];
    struct { const uint8_t*p; size_t n;} slice;
    uint64_t ctx[8];
    while(getline(&line,&cap,f)>=0){
        char mode[16],txh[1<<21],sch[1<<21],pubh[1025],sigh[4097];
        long long nIn;unsigned long long amt;
        if(sscanf(line,"%15s %2097151s %lld %llu %2097151s %1024s %4096s",
                  mode,txh,&nIn,&amt,sch,pubh,sigh)!=7)continue;
        size_t txlen=(txh[0]=='-')?0:h2b(txh,tx,sizeof tx);
        size_t sclen=(sch[0]=='-')?0:h2b(sch,sc,sizeof sc);
        size_t publen=h2b(pubh,pub,sizeof pub);
        size_t siglen=h2b(sigh,sig,sizeof sig);
        slice.p=sc; slice.n=sclen;
        ctx[0]=(uint64_t)tx;       /* tx */
        ctx[1]=(uint64_t)txlen;
        ctx[2]=(uint64_t)nIn;      /* nIn */
        ctx[3]=(uint64_t)work;     /* work */
        ctx[4]=(uint64_t)sizeof work; /* workcap */
        ctx[5]=0;
        ctx[6]=0;
        ctx[7]=(uint64_t)amt;      /* amount */
        uint64_t r;
        if(!strcmp(mode,"legacy"))
            r=sv_checksig_asm((void*)ctx,sig,siglen,pub,publen,&slice);
        else
            r=sv_checksig_witness_v0_asm((void*)ctx,sig,siglen,pub,publen,&slice);
        printf("%llu\n",(unsigned long long)r);
    }
    free(line);fclose(f);return 0;
}

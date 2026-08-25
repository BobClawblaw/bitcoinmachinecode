#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
extern int cons_verify(const unsigned char* block, u64 len, unsigned char* scratch, u64 cap);
extern u64 tx_parse(u64 info[8], const unsigned char* tx, u64 len);
extern int pow_check(const unsigned char* hdr);
int main(void){
    FILE* f=fopen("/home/svc/bitcoinmachinecode/data/blk00000.dat","rb");
    if(!f){printf("no file\n");return 1;}
    fseek(f,0,SEEK_END); long fsize=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char* buf=malloc(sizeof(unsigned char)*(size_t)fsize);
    long hn = fread(buf,1,(size_t)fsize,f); fclose(f);
    /* find the first FULL block: guard with the ENTIRE file available */
    long n=hn;
    printf("file %ld bytes; pow=%d\n", n, (int)pow_check(buf));
    if(n<82){printf("too small\n");return 1;}
    u64 count; int cs;
    unsigned char c=buf[80];
    if(c<0xfd){count=c;cs=1;} else if(c==0xfd){count=(u64)buf[81]|(u64)buf[82]<<8;cs=3;}
    else if(c==0xfe){count=*(unsigned int*)(buf+81);cs=5;} else {count=*(u64*)(buf+81);cs=9;}
    u64 off=80+cs;
    unsigned long scan=0;
    for(u64 i=0;i<count;i++){
        u64 info[8]; memset(info,0,64);
        if((long)off>=n){printf("off past end i=%llu off=%llu n=%ld\n",(unsigned long long)i,(unsigned long long)off,n);return 1;} u64 r=tx_parse(info, buf+off, (long)n-off);
        if(!r){printf("tx %llu parse fail at off %llu\n",i,(unsigned long long)off);scan=1;break;}
        off+=info[0];
    }
    printf("count=%llu block1_len=%llu\n",(unsigned long long)count,(unsigned long long)off);
    if(scan && count>1){printf("use first sub-block only is not possible; ignore\n");return 1;}
    unsigned char* scratch=malloc(sizeof(unsigned char)*((size_t)count*32+4096));
    int ok=cons_verify(buf, off, scratch, count);
    printf("cons_verify(first real block) = %d (want 1)\n", ok);
    return 0;
}

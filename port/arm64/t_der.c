/* t_der.c -- differential driver for be_to_limbs + der_parse_sig.
 * Reads lines:  <mode> <hex-in>
 *   mode=limbs: be_to_limbs over 1..32-byte big-endian int -> 4 limbs hex
 *   mode=der:   der_parse_sig(sig hex) -> ret, r0..r3, s0..s3, dht
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern void be_to_limbs(uint64_t out[4], const uint8_t* bytes, uint64_t len);
extern int  der_parse_sig(const uint8_t* sig, uint64_t slen,
                          uint64_t r[4], uint64_t s[4], int* hashtype);

static int hexval(int c){
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}
static size_t hex2bin(const char*h,uint8_t*o,size_t m){
    size_t n=strlen(h)/2; if(n>m)n=m;
    for(size_t i=0;i<n;i++){o[i]=(uint8_t)((hexval(h[2*i])<<4)|hexval(h[2*i+1]));}
    return n;
}

int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"usage: t_der <cases>\n");return 2;}
    FILE*f=fopen(argv[1],"r");
    if(!f){perror("open");return 2;}
    char*line=NULL;size_t cap=0;
    uint8_t buf[512];uint64_t l[4]={0},r[4]={0},s[4]={0};
    int dht,ret;
    while(getline(&line,&cap,f)>=0){
        char mode[16],hex[1025];
        if(sscanf(line,"%15s %1024s",mode,hex)!=2)continue;
        size_t n = (hex[0]=='-') ? 0 : hex2bin(hex,buf,sizeof buf);
        if(!strcmp(mode,"limbs")){
            be_to_limbs(l,buf,n);
            printf("%016llx %016llx %016llx %016llx\n",
                   (unsigned long long)l[0],l[1],l[2],l[3]);
        } else if(!strcmp(mode,"der")){
            ret=der_parse_sig(buf,n,r,s,&dht);
            printf("%d %016llx %016llx %016llx %016llx "
                   "%016llx %016llx %016llx %016llx %d\n",
                   ret,(unsigned long long)r[0],r[1],r[2],r[3],
                   (unsigned long long)s[0],s[1],s[2],s[3],dht);
        }
    }
    free(line);fclose(f);return 0;
}

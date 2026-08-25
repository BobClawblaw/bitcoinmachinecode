/* t_codec.c -- differential driver for bitcoin_scriptcodec.S primitives.
 * lines:
 *   snum <len> <maxsize> <datahex>            -> scriptnum_decode
 *   sser <value>                              -> scriptnum_serialize bytes
 *   cb <datahex>                              -> cast_to_bool
 *   der <sighex>                              -> der_sig_strict
 *   minpush <opcode> <pushlen> <datahex>      -> check_minimal_push
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int64_t scriptnum_decode(uint64_t len,const uint8_t* data,uint64_t maxsize);
extern int cast_to_bool(uint64_t len,const uint8_t* data);
extern int der_sig_strict(const uint8_t* sig,uint64_t siglen);
extern int check_minimal_push(uint32_t opcode,uint64_t pushlen,const uint8_t* data);
extern uint64_t snum_overflow;

typedef struct { uint8_t* p; uint64_t len; } SNumOut;
extern SNumOut scriptnum_serialize(int64_t value); /* returned in x0,x1 */

static int hv(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return 0;}
static size_t h2b(const char*h,uint8_t*o,size_t m){size_t n=strlen(h)/2;if(n>m)n=m;for(size_t i=0;i<n;i++)o[i]=(uint8_t)((hv(h[2*i])<<4)|hv(h[2*i+1]));return n;}
static void b2h(const uint8_t*b,size_t n,char*o){static const char*x="0123456789abcdef";for(size_t i=0;i<n;i++){o[2*i]=x[b[i]>>4];o[2*i+1]=x[b[i]&15];}o[2*n]=0;}

int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"usage: t_codec <cases>\n");return 2;}
    FILE*f=fopen(argv[1],"r");
    if(!f){perror("open");return 2;}
    char*line=NULL;size_t cap=0;
    static uint8_t buf[4096];
    while(getline(&line,&cap,f)>=0){
        char mode[16],hex[4097];
        long long len,ms,v,op,pushlen;
        if(sscanf(line,"%15s",mode)!=1)continue;
        if(!strcmp(mode,"snum")){
            if(sscanf(line,"snum %lld %lld %4095s",&len,&ms,hex)!=3)continue;
            size_t n=(hex[0]=='-')?0:h2b(hex,buf,sizeof buf);
            int64_t r=scriptnum_decode((uint64_t)len,buf,(uint64_t)ms);
            printf("%lld %llu\n",(long long)r,(unsigned long long)snum_overflow);
        } else if(!strcmp(mode,"sser")){
            if(sscanf(line,"sser %lld",&v)!=1)continue;
            SNumOut so=scriptnum_serialize((int64_t)v);
            char o[257]; b2h(so.p,(size_t)so.len,o);
            printf("%s\n",o);
        } else if(!strcmp(mode,"cb")){
            if(sscanf(line,"cb %4095s",hex)!=1)continue;
            size_t n=(hex[0]=='-')?0:h2b(hex,buf,sizeof buf);
            printf("%d\n",cast_to_bool(n,buf));
        } else if(!strcmp(mode,"der")){
            if(sscanf(line,"der %4095s",hex)!=1)continue;
            size_t n=(hex[0]=='-')?0:h2b(hex,buf,sizeof buf);
            printf("%d\n",der_sig_strict(buf,n));
        } else if(!strcmp(mode,"minpush")){
            if(sscanf(line,"minpush %lld %lld %4095s",&op,&pushlen,hex)!=3)continue;
            size_t n=(hex[0]=='-')?0:h2b(hex,buf,sizeof buf);
            printf("%d\n",check_minimal_push((uint32_t)op,(uint64_t)pushlen,buf));
        }
    }
    free(line);fclose(f);return 0;
}

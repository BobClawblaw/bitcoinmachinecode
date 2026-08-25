#include <stdio.h>
#include <stdlib.h>
typedef unsigned long long u64;
extern void fe_pow(u64 out[4], const u64 base[4], const u64 exp[4]);
extern int pubkey_parse(const unsigned char* pub, u64 publen, u64 qx[4], u64 qy[4]);
static void rd(u64* o,char**p,int n){for(int i=0;i<n;i++){char b[20];int j=0;while(**p&&**p!=' '&&**p!='\n'&&j<16)b[j++]=*(*p)++;b[j]=0;o[i]=strtoull(b,0,16);while(**p==' ')(*p)++;}}
static void hexin(unsigned char* o, char**p, int n){int hi=0,lo=0;for(int i=0;i<n;i++){char a=(*p)[0],b=(*p)[1];int av=(a<='9')?a-'0':(a|32)-'a'+10;int bv=(b<='9')?b-'0':(b|32)-'a'+10;o[i]=(av<<4)|bv;(*p)+=2;}while(**p==' ')(*p)++;}
int main(void){
    char line[2048];
    while(fgets(line,sizeof line,stdin)){
        char*p=line; while(*p==' '||*p=='\t')p++;
        if(*p=='#'||*p=='\n')continue;
        if(line[0]=='P'){ /* pow: base exp(out4)e */ p++; p++; u64 base[4],e[4],o[4]; rd(base,&p,4);rd(e,&p,4);fe_pow(o,base,e);printf("%016llx %016llx %016llx %016llx\n",o[0],o[1],o[2],o[3]);}
        else { /* pub <len> <hex...> */ char op[8];int i=0;while(*p!=' '&&*p)op[i++]=*p++;op[i]=0;while(*p==' ')p++; int len=atoi(op+3); (void)len; unsigned char pub[65]; hexin(pub,&p, len>33?65: (len==33?33:0)); (void)0;
            u64 qx[4],qy[4]; int ok=pubkey_parse(pub, len, qx,qy);
            if(!ok) printf("BAD\n");
            else printf("%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",qx[0],qx[1],qx[2],qx[3],qy[0],qy[1],qy[2],qy[3]);
        }
    }
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
typedef unsigned long long u64;
extern int schnorr_verify(const unsigned char* sig, const unsigned char* pk,
                          const unsigned char* msg, int msglen);
static int hexval(char c){return (c<='9')?c-'0':(c|32)-'a'+10;}
static void hexrd(unsigned char* o,char**p,int n){for(int i=0;i<n;i++){char a=(*p)[0],b=(*p)[1];o[i]=(hexval(a)<<4)|hexval(b);(*p)+=2;}while(**p==' ')(*p)++;}
int main(void){
    char line[4096];
    while(fgets(line,sizeof line,stdin)){
        char*p=line; while(*p==' '||*p=='\t')p++;
        if(*p=='#'||*p=='\n')continue;
        unsigned char sig[64],pk[32],msg[512];
        hexrd(sig,&p,64); hexrd(pk,&p,32);
        int msglen=0;
        /* optional msg chars */
        while(*p==' ')p++;
        if(*p && *p!='\n'){
            /* hex msg terminated by newline/space */
            const char* q=p; int h=0;
            while(q[h] && q[h]!='\n' && q[h]!=' ')h++;
            hexrd(msg,&p,h/2); msglen=h/2;
        }
        printf("%d\n", schnorr_verify(sig,pk,msg,msglen));
    }
    return 0;
}

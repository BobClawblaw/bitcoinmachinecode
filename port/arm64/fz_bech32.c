/* fz_bech32.c -- differential driver for the bech32/bech32m codec.
 * Reads commands, one per line:
 *   conv <frombits> <tobits> <pad> <hexin>       -> prints ret <n> <hexout>
 *   enc  <spec> <hrp> <datalen> <hex5>           -> prints ret <len> <str>
 *   verify <spec> <hrp> <datalen> <hex5>         -> prints ret <0|1>
 *   dec  <str>                                   -> prints ret <n> <hrp> <hex5>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
extern void bech32_init(void);
extern long long bech32_convert_bits(unsigned char* o,const unsigned char* i,long long il,long long fb,long long tb,long long pad);
extern long long bech32_create_checksum(unsigned char o6[6],const char* hrp,long long hl,const unsigned char*d,long long dl,long long spec);
extern long long bech32_verify_checksum(const char* hrp,long long hl,const unsigned char*d,long long dl,long long spec);
extern long long bech32_encode(char* o,const char* hrp,long long hl,const unsigned char*d,long long dl,long long spec);
extern long long bech32_decode(unsigned char* o5,char* ohrp,long long hcap,const char* in);
static int hv(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static long long h2b(const char*h,unsigned char*o){long long n=strlen(h)/2;for(long long i=0;i<n;i++){o[i]=(hv(h[2*i])<<4)|hv(h[2*i+1]);}return n;}
static void b2h(const unsigned char*b,long long n,char*o2){static const char*h="0123456789abcdef";for(long long i=0;i<n;i++){o2[2*i]=h[b[i]>>4];o2[2*i+1]=h[b[i]&15];}o2[2*n]=0;}
int main(){
    bech32_init();
    char line[8192]; static unsigned char in[1024],out[2048]; static char ohrp[256];
    while(fgets(line,sizeof line,stdin)){
        if(!line[0]||line[0]=='\n')continue;
        char op[16],cs[16];
        if(line[0]=='c'){ /* conv */
            long long fb,tb,pad; char hx[2048];
            long long rn=sscanf(line,"%15s %lld %lld %lld %2047s",op,&fb,&tb,&pad,hx);
            if(rn<4) continue;
            long long il = (rn==5) ? h2b(hx,in) : 0;
            long long n=bech32_convert_bits(out,in,il,fb,tb,pad);
            char *ob=NULL; if(n>=0){ob=malloc(2*n+1);b2h(out,n,ob);}
            printf("conv %lld %s\n",n,ob?ob:"");
            free(ob);
        } else if(line[0]=='e'){ /* enc */
            long long spec,dl; char hrp[256]; char hx[2048];
            long long rn=sscanf(line,"%15s %lld %255s %lld %2047s",op,&spec,hrp,&dl,hx);
            if(rn<4) continue;
            long long dl2 = (rn==5) ? h2b(hx,in) : 0;
            char ob[4096];
            long long l=bech32_encode(ob,hrp,strlen(hrp),in,dl2,spec);
            printf("enc %lld %s\n",(long long)l,ob);
        } else if(line[0]=='v'){ /* verify */
            long long spec,dl; char hrp[256]; char hx[2048];
            if(sscanf(line,"%15s %lld %255s %lld %2047s",op,&spec,hrp,&dl,hx)!=5)continue;
            long long dl2=h2b(hx,in);
            long long r=bech32_verify_checksum(hrp,strlen(hrp),in,dl2,spec);
            printf("verify %lld\n",r);
        } else if(line[0]=='d'){ /* dec */
            char s[2048];
            if(sscanf(line,"%15s %2047s",op,s)!=2)continue;
            long long n=bech32_decode(out,ohrp,255,s);
            if(n<0){printf("dec -1\n");}
            else{char *ob=malloc(2*n+1);b2h(out,n,ob);printf("dec %lld %s %s\n",n,ohrp,ob);free(ob);}
        }
    }
    return 0;
}

/* t_undo.c -- differential driver for ported bitcoin_undo.S vs C oracle.
 * Same op stream -> same output; fuzzer runs both in scratch dirs and diffs.
 * ops: ap/ld/rp/rpt/dc/pf/pr   (see header comment above in git history)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef unsigned char u8;
extern long undo_append_record(long,const u8*,unsigned,unsigned long long,unsigned,unsigned,const u8*,unsigned short);
extern long undo_load(long, void*, long);
extern long undo_replay(long, int(*)(void*,const u8*,unsigned,unsigned long long,unsigned,unsigned,const u8*,unsigned short), void*);
extern long undo_replay_tolerant(long, int(*)(void*,const u8*,unsigned,unsigned long long,unsigned,unsigned,const u8*,unsigned short), void*, int*);
extern long undo_discard(long);
extern long undo_prune_from(long,long,long,long);
extern long undo_prune(long,long);
#define UMS 10056
static u8* dump;
static int cb(void*c,const u8*txid,unsigned idx,unsigned long long value,unsigned h,unsigned cbb,const u8*sc,unsigned short slen){
    (void)c;
    printf(" rec %s %u %llu %u %u %u ",txid,idx,value,h,cbb,slen);
    for(unsigned i=0;i<slen && i<10000;i++)printf("%02x",sc[i]);
    printf("\n"); return 1;
}
static int hv(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return 0;}
static size_t h2b(const char*h,uint8_t*o,size_t m){size_t n=strlen(h);if(m<n/2)n=m*2;size_t i;for(i=0;i<n/2;i++)o[i]=(uint8_t)((hv(h[2*i])<<4)|hv(h[2*i+1]));return n/2;}
int main(){
    dump=malloc(256*UMS); char line[140000];
    while(fgets(line,sizeof line,stdin)){
        char op[8];
        if(sscanf(line,"%7s",op)!=1)continue;
        if(!strcmp(op,"ap")){
            long h,uh,cbb; unsigned long long value; unsigned long idx; char th[80],sh[4000];
            if(sscanf(line,"ap %ld %79s %lu %llu %ld %ld %3999s",&h,th,&idx,&value,&uh,&cbb,sh)!=7)continue;
            uint8_t txid[32]; u8 sc[2000]; h2b(th,txid,32); size_t sl=(sh[0]=='-')?0:h2b(sh,sc,sizeof sc);
            long r=undo_append_record(h,txid,(unsigned)idx,value,(unsigned)uh,(unsigned)cbb,sc,(unsigned short)sl);
            printf("ap %ld\n",r);
        } else if(!strcmp(op,"ld")){
            long h, m; if(sscanf(line,"ld %ld %ld",&h,&m)!=2)continue;
            long n=undo_load(h,dump,m);
printf("ld %ld\n",n);
            for(long i=0;i<n&&i<m && i<256;i++){
                u8* r=dump+i*UMS; unsigned slen=*(unsigned short*)(r+54); if(slen>10000)slen=10000;
                printf(" rec %s %u %llu %u %u %u ",r,*(unsigned*)(r+32),*(unsigned long long*)(r+40),*(unsigned*)(r+48),r[52],slen);
                for(unsigned j=0;j<slen;j++)printf("%02x",r[56+j]);
                printf("\n");
            }
        } else if(!strcmp(op,"rp")){
            long h; if(sscanf(line,"rp %ld",&h)!=1)continue;
            long n=undo_replay(h,cb,0);
            printf("rp %ld\n",n);
        } else if(!strcmp(op,"rpt")){
            long h; if(sscanf(line,"rpt %ld",&h)!=1)continue;
            int torn=99; long n=undo_replay_tolerant(h,cb,0,&torn);
            printf("rpt %ld %d\n",n,torn);
        } else if(!strcmp(op,"dc")){
            long h; if(sscanf(line,"dc %ld",&h)!=1)continue;
            printf("dc %ld\n",undo_discard(h));
        } else if(!strcmp(op,"pf")){
            long a,b,c,d; if(sscanf(line,"pf %ld %ld %ld %ld",&a,&b,&c,&d)!=4)continue;
            printf("pf %ld\n",undo_prune_from(a,b,c,d));
        } else if(!strcmp(op,"pr")){
            long a,b; if(sscanf(line,"pr %ld %ld",&a,&b)!=2)continue;
            printf("pr %ld\n",undo_prune(a,b));
        }
        fflush(stdout);
    }
    return 0;
}

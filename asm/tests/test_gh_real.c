/* test_gh_real.c -- reproduce the live getheaders path deterministically:
 * reload the REAL archive into a store, build the hash index, run
 * node_serve_loop on a socketpair, and issue a getheaders for a real locator.
 * Run under gdb to see exactly why getheaders returns no reply. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
extern void idx_init(void*, unsigned long);
extern int  idx_put(void*, const unsigned char[32], long);
extern int  idx_get(void* idx, const unsigned char hash[32], long* height);
extern long node_serve_block(void* st, long h, void* out, long cap);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern long store_reload(void* st);
extern long p2p_write(int fd,const char*cmd,unsigned,const void*,unsigned);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern long node_serve_loop(int fd,int lfd,void*st,void*ht_idx,void*out,long cap);

int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: %s <datadir>\n",argv[0]); return 2; }
    chdir(argv[1]);
    static unsigned char store[4096];
    if(store_reload(store)!=1){ fprintf(stderr,"reload fail\n"); return 1; }
    int tip=*(int*)(store+24); printf("store tip=%d\n",tip);
    /* disk-based index with the LE reversal fix */
    size_t slots=8u<<20;
    unsigned char* ht=malloc(24+slots*48+64); idx_init(ht,slots);
    FILE*f=fopen("index.dat","rb"); if(!f){perror("idx");return 1;}
    fseek(f,0,SEEK_END); long n=ftell(f)/48; fseek(f,0,SEEK_SET);
    unsigned char rec[48]; long cnt=0;
    for(long h=0;h<n;h++){
        if(fread(rec,1,48,f)!=48)break;
        if(rec[0]==0&&rec[1]==0&&rec[2]==0&&rec[3]==0)continue;
        unsigned char le[32]; for(int k=0;k<32;k++)le[k]=rec[31-k];
        idx_put(ht,le,h); cnt++;
    }
    fclose(f); printf("indexed %ld\n",(long)cnt);

    /* locator: height-1 block hash. block_hash outputs the digest in display
     * byte order; the getheaders/inv wire hash is the reverse (raw/LE). Reverse
     * to match how getdata/inv carries hashes and how the index keys them. */
    unsigned char bh[32]; { unsigned char sb2[4096]; long L=node_serve_block(store,1,sb2,4096); block_hash(bh,sb2); }
    unsigned char loc[32]; for(int k=0;k<32;k++) loc[k]=bh[31-k];

    int sv[2]; socketpair(AF_UNIX,SOCK_STREAM,0,sv);
    if(fork()==0){
        close(sv[0]);
        int cfd=sv[1];
        unsigned char gh[69]; memset(gh,0,69);
        gh[0]=0x7f; gh[2]=1; gh[3]=0; gh[4]=1;
        memcpy(gh+5,loc,32);      /* locator = wire/LE hash */
        memset(gh+37,0,32);
        fprintf(stderr,"client: sending getheaders locator(disp)="); for(int i=0;i<32;i++)fprintf(stderr,"%02x",loc[31-i]); fprintf(stderr,"\n");
        p2p_write(cfd,"getheaders",10,gh,69);
        char cmd[12]; static unsigned char hp[300000]; unsigned pl=0;
        int r=p2p_read(cfd,cmd,hp,sizeof hp,&pl);
        fprintf(stderr,"client: got r=%d cmd=%.7s len=%u\n",r,cmd,pl);
        _exit(r>0?0:1);
    }else{
        close(sv[1]);
        static unsigned char out[1<<20];
        long s=node_serve_loop(sv[0],-1,store,ht,out,sizeof out);
        fprintf(stderr,"server: node_serve_loop returned %ld served\n",s);
        int st; wait(&st);
        return WIFEXITED(st)?WEXITSTATUS(st):1;
    }
}

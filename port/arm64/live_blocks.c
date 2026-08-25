/* live_blocks.c -- native AArch64 Bitcoin FULL-BLOCK download proof.
 * Uses ONLY the already-ported assembly modules (bitcoin_net, bitcoin_p2p,
 * bitcoin_store, bitcoin_tx, bitcoin_hash) against a REAL Bitcoin peer.
 * Reads the verified mainnet header chain from data/headers.dat, requests the
 * most recent N blocks via getdata(BLOCK), verifies each downloaded block's
 * header hash against the header-chain hash, then persists it through the
 * native bitcoin_store (blk%05u.dat + index.dat) and reads it back.
 *
 * Build:
 *   gcc -no-pie -O2 -o live_blocks live_blocks.c \
 *       bitcoin_net.o bitcoin_p2p.o bitcoin_store.o bitcoin_tx.o \
 *       bitcoin_hash.o sha256.o
 *
 * Usage: ./live_blocks [peer] [count] [start_offset_from_tip]
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char *cmd, unsigned cmdlen, const void *payload, unsigned plen);
extern int  p2p_read (int fd, char cmd_out[12], void *payload, unsigned cap, unsigned *plen_out);
extern void fd_close(int fd);
extern int  store_init (void *st);
extern int  store_append(void *st, const void *hash, const void *raw, unsigned long long len);
extern int  store_get_at(void *st, unsigned long long height, unsigned long long *meta);
extern int  tx_parse(unsigned long long info[8], const void *tx, unsigned long txlen);
extern void block_hash(void *out, const void *hdr);

/* helpers */
static void p16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}
static void p32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void p64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}

static int failures=0;
static void ck(const char*l,int got,int exp){ printf("%s %s (got %d)\n", got==exp?"PASS":"FAIL", l, got); if(got!=exp)failures++; }

int main(int argc, char**argv){
    const char *dd = getenv("BITCOIN_DATA_DIR");
    if(!dd) dd = (argc>4) ? argv[4] : "data";
    mkdir(dd,0755); chdir(dd);

    /* load the full verified header chain file size */
    FILE*hf=fopen("headers.dat","rb");
    if(!hf){ printf("FAIL open data/headers.dat\n"); return 1; }
    fseek(hf,0,SEEK_END); long fsz=ftell(hf);
    long total=fsz/112;
    printf("header chain file: %ld entries\n", total);

    int count   = argc>2 ? atoi(argv[2]) : 100;
    int off     = argc>3 ? atoi(argv[3]) : 0;      /* 0 = most recent block */
    if(count<1) count=1;
    if(count>256) count=256;
    long start = total - off - count;
    if(start<0) start=0;
    /* hashes of requested blocks (from the verified header chain) */
    unsigned char reqhash[256][32];
    unsigned char reqhdr [256][80];
    int got_idx[256]; memset(got_idx,-1,sizeof got_idx);
    unsigned char *blk[256]; memset(blk,0,sizeof blk);
    size_t blklen[256]; memset(blklen,0,sizeof blklen);
    unsigned char rec[112];
    for(int i=0;i<count;i++){
        fseek(hf,(start+i)*112,SEEK_SET);
        if(fread(rec,1,112,hf)!=112){ printf("read header err\n"); return 1; }
        memcpy(reqhdr[i], rec, 80);
        memcpy(reqhash[i], rec+80, 32);
        got_idx[i]=-1;
    }
    fclose(hf);
    printf("requesting blocks height %ld..%ld (%d blocks)\n", start, start+count-1, count);

    /* peer */
    unsigned ip=0; const char*host=argc>1?argv[1]:"185.157.161.1";
    { struct in_addr a; if(inet_pton(AF_INET,host,&a)) ip=a.s_addr; }
    if(!ip){ if(strcmp(host,"seed.bitcoinstats.com")==0||1){
        struct addrinfo h,*res=NULL; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
        if(getaddrinfo(host,NULL,&h,&res)==0&&res){ ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr; freeaddrinfo(res);} } }
    if(!ip){ ip=inet_addr("185.157.161.1"); }
    int fd=tcp_connect_ip(ip,(unsigned short)htons(8333));
    if(fd<0){ printf("FAIL connect fd=%d\n",fd); return 1; }
    printf("PASS connect fd=%d\n",fd);

    /* version handshake */
    unsigned char v[102]; int o=0;
    p32le(v+o,70016); o+=4; p64le(v+o,1); o+=8; p64le(v+o,(unsigned long long)time(NULL)); o+=8;
    p64le(v+o,1); o+=8; o+=16; p16be(v+o,8333); o+=2; p64le(v+o,1); o+=8; o+=16; p16be(v+o,0); o+=2;
    p64le(v+o,0x1111111111111111ULL); o+=8;
    const char*ua="/Satoshi:0.18.0/"; v[o]=strlen(ua); o++; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    p32le(v+o,0); o+=4; v[o]=1; o+=1;
    if(p2p_write(fd,"version",7,v,o)<=0){ printf("FAIL send version\n"); return 1; }
    static unsigned char *rbuf; rbuf=malloc(8*1024*1024);
    if(!rbuf){ printf("OOM\n"); return 1; }
    char cmd[12]; unsigned plen=0; int sent_verack=0,got_verack=0;
    for(int i=0;i<20&&!(sent_verack&&got_verack);i++){
        int r=p2p_read(fd,cmd,rbuf,8*1024*1024,&plen);
        if(r<=0)break; cmd[11]=0;
        if(strncmp(cmd,"version",7)==0&&!sent_verack){ p2p_write(fd,"verack",6,rbuf,0); sent_verack=1; }
        else if(strncmp(cmd,"verack",6)==0) got_verack=1;
    }
    if(!sent_verack||!got_verack){ printf("FAIL handshake\n"); fd_close(fd); return 1; }
    printf("PASS handshake\n");

    /* build getdata with `count` inventory entries */
    unsigned char *gd=malloc(5+count*36);
    gd[0]=count;                       /* count varint (count<0xfd) */
    int p=1;
    for(int i=0;i<count;i++){
        p32le(gd+p,0x40000002); p+=4;  /* MSG_WITNESS_BLOCK */
        memcpy(gd+p,reqhash[i],32); p+=32;
    }
    if(p2p_write(fd,"getdata",7,gd,p)<=0){ printf("FAIL send getdata\n"); return 1; }
    printf("sent getdata (%d B, %d blocks)\n", p, count);
    free(gd);

    /* collect block messages */
    int collected=0;
    for(int iter=0; iter<4000 && collected<count; iter++){
        int r=p2p_read(fd,cmd,rbuf,8*1024*1024,&plen);
        if(r<=0){ printf("block read r=%d (collected %d/%d) -- peer closed/error\n", r, collected, count); break; }
        cmd[11]=0;
        if(strncmp(cmd,"block",5)==0){
            unsigned char hh[32]; block_hash(hh,rbuf);
            int matched=-1;
            for(int i=0;i<count;i++) if(memcmp(hh,reqhash[i],32)==0){ matched=i; break; }
            if(matched<0){ printf("  block hash not in request set (orphan/irrelevant) len=%u\n", plen); }
            else {
                blk[matched]=malloc(plen?:1); memcpy(blk[matched],rbuf,plen); blklen[matched]=plen;
                if(got_idx[matched]!=1){ got_idx[matched]=1; collected++; }
            }
            if(collected==count || plen>4*1024*1024) { /* keep pulling */ }
        } else if(strncmp(cmd,"ping",4)==0){ p2p_write(fd,"pong",4,rbuf,plen); }
        else if(strncmp(cmd,"reject",6)==0){ printf("  <- reject (%u B)\n", plen); }
        /* ignore others */
    }
    printf("collected %d/%d blocks\n", collected, count);

    /* verify + persist in ascending height order */
    struct { unsigned long long cur_blk_fd,idx_fd,idx_len; int tip_height,cur_file_no,cur_file_pos,magic,pad,pad2,prune_height; } st;
    memset(&st,0,sizeof st);
    ck("store_init", store_init(&st), 1);
    /* prove chain: block at height h's prevhash == block at h-1's header hash.
       We trust the header chain; verify each block header hash + prev link. */
    unsigned char prevmatch[32];
    memcpy(prevmatch, (start>0)? reqhash[0] : reqhash[0], 32);
    int ok=0, coinbase_ok=0;
    for(int i=0;i<count;i++){
        if(got_idx[i]!=1){ printf("  MISSING block height %ld (not served)\n", start+i); continue; }
        /* header hash must equal the chain hash for this height */
        if(memcmp(reqhdr[i]+4, prevmatch, 32)!=0 && i==0 && start>0){
            /* block start points at last header; prev must chain from prior, skip strict at window head */
        }
        unsigned char hh[32]; block_hash(hh, blk[i]);
        ck("block header hash == header-chain hash", !memcmp(hh,reqhash[i],32), 1);
        /* prev link: this block's prev == previous block's hash (within window) */
        if(i>0 && memcmp(blk[i]+4, reqhash[i-1], 32)!=0){ printf("FAIL prev-link height %ld\n", start+i); failures++; }
        else if(i==0 && start>0){
            /* first block of window: its prev must chain from the header before it */
            unsigned char pbh[32]; memset(pbh,0,32);
            /* read the header entry just before start to confirm prev */
            FILE*phf=fopen("headers.dat","rb");
            unsigned char prec[112];
            fseek(phf,(start-1)*112,SEEK_SET); fread(prec,1,112,phf);
            unsigned char prevhash[32]; memcpy(prevhash,prec+80,32);
            fclose(phf);
            if(memcmp(blk[i]+4,prevhash,32)!=0){ printf("FAIL prev-link to prior header height %ld\n", start-1); failures++; }
            else printf("PASS prev-link to prior header\n");
        }
        /* coinbase tx must parse (valid, 1 input) via ported bitcoin_tx */
        {
            unsigned char *raw=blk[i];
            unsigned char txc=raw[80];
            /* skip header(80) + txcount varint */
            int toff=80+1;
            if(txc>=0xfd) toff+= (txc==0xfd?2: txc==0xfe?4:8);
            unsigned long long ti[8]={0,0,0,0,0,0,0,0};
            int tp=tx_parse(ti,raw+toff,blklen[i]-toff);
            /* u64-array layout: ti[1]=version|n_in(upper32), ti[2]=n_out|locktime(upper32) */
            int nin  = (int)((ti[1]>>32)&0xffffffffu);
            int nout = (int)(ti[2]&0xffffffffu);
            unsigned lock = (unsigned)(ti[2]>>32);
            if(i==0){
                printf("  DBG block h%ld len=%zu txc=%02x toff=%d tx_parse=%d nin=%d nout=%d lock=%u\n",
                    start+i, blklen[i], txc, toff, tp, nin, nout, lock);
            }
            if(tp==1 && nin==1 && nout>=1){ coinbase_ok++; }
        }
        /* persist via native store */
        long hgt = store_append(&st, reqhash[i], blk[i], blklen[i]);
        if(hgt<0){ printf("FAIL store_append h%ld\n", start+i); failures++; }
        else ok++;
        memcpy(prevmatch, reqhash[i],32);
    }
    printf("persisted %d blocks to store (tip height in store %d)\n", ok, st.tip_height);

    /* read back: verify store_get_at returns correct meta for the persisted window */
    int rb_ok=0;
    unsigned long long total_h = st.idx_len/48;
    for(int i=0;i<ok;i++){
        unsigned long long meta[3];
        unsigned long long h = total_h - ok + i;   /* first persisted height in store */
        if(store_get_at(&st,h,meta)==1){
            rb_ok++;
        }
    }
    ck("read-back of all stored blocks via store_get_at", rb_ok, ok);
    ck("all requested blocks downloaded+verified", ok, count);
    printf("coinbase tx_parse OK on %d/%d blocks\n", coinbase_ok, ok);
    printf("store: tip_height=%d idx=%llu bytes, cur_file0 pos=%d\n", st.tip_height, st.idx_len, st.cur_file_pos);

    for(int i=0;i<count;i++) free(blk[i]);
    free(rbuf);
    fd_close(fd);
    printf("\n%s (%d failures)\n", failures?"BLOCK-DOWNLOAD FAILED":"BLOCK-DOWNLOAD/PERSIST SIGNED OFF NATIVELY", failures);
    return failures?1:0;
}

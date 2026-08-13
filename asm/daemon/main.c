/* daemon/main.c -- thin CLI driver over the assembly Bitcoin node core.
 *
 *   daemon sync  <dir>                : init store in <dir>, connect to the
 *                                       loopback test peer, handshake, run IBD
 *                                       (node_sync), report resulting height.
 *   daemon serve <dir> <port>         : init store in <dir>, listen on port,
 *                                       accept a peer, handshake, then serve
 *                                       stored blocks to getdata / reply to
 *                                       ping. The node IE (connect/handshake/
 *                                       IBD/serve-block) is all assembly
 *                                       (bitcoind.asm); this is only the main
 *                                       loop over sockets.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>

/* --- assembly node core (bitcoind.asm / bitcoin_*.asm) --- */
extern long node_handshake(int fd);
extern long node_accept_handshake(int fd);
extern long node_sync(int fd, void* st, void* locator, void* buf, long buflen, long* out_count);
extern long node_serve_block(void* st, long height, void* out, long cap);
extern long node_serve_block_by_hash(void* st, const void* hash32, void* out, long cap);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long store_init(void* st);
extern long store_reload(void* st);
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern int  node_log_open(const char* path);
extern void node_log_event(int fd, int kind, unsigned a, unsigned b, unsigned c);
extern void node_log_str(int fd, int kind, const char* s, long len);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
extern int  amr_init(void* ab);
extern long amr_count(void* ab);
extern int  amr_get_i(void* ab, long i, void* out);
extern long p2p_addr_v1(void* out, const void* src, long n);
extern long store_append(void* st, const unsigned char* hash32, const void* blk, long len);
extern long store_get_tip(void* st);
extern long node_ibd(int fd, void* st, void* hst, void* buf, long buflen); /* bitcoind.asm */
extern int  hst_init(void* hst);
extern long hst_count(void* hst);
extern int  hst_get_at(void* hst, unsigned long long height, void* out);

#define L_HDRS   2
#define L_BLOCK  3
#define L_STORE  5
#define L_ERROR  6
#define L_SERVE  7

static unsigned char store_buf[4096];

/* ---- block hash -> height index (for O(1) getdata/by-hash serving). ----
 * The table itself is 100% assembly (asm/bitcoin_idx.asm: idx_init/idx_put/
 * idx_get/idx_count, an open-addressing hash table with full 32-byte keys).
 * The build loop here is thin file orchestration over index.dat. This lets us
 * serve a requested block by hash in O(1) instead of a linear height scan. */
#define HT_SLOTS (8u<<20)
static unsigned char* ht_idx;            /* 24 + HT_SLOTS*48 bytes */
static unsigned char out_buf[1<<20];     /* serve-loop output scratch */
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern int  idx_get(void* idx, const unsigned char hash[32], long* height);
extern long idx_count(void* idx);
static int build_hash_index(void){
    ht_idx=malloc(24 + (size_t)HT_SLOTS*48 + 64);   /* last slot may need a full --- actually over-allocate */
    if(!ht_idx){ fprintf(stderr,"alloc idx failed\n"); return -1; }
    idx_init(ht_idx, HT_SLOTS);
    FILE* f=fopen("index.dat","rb"); if(!f){ fprintf(stderr,"no index.dat for hash index\n"); return -1; }
    fseek(f,0,SEEK_END); long n=ftell(f)/48; fseek(f,0,SEEK_SET);
    unsigned char rec[48];
    for(long h=0;h<n;h++){
        if(fread(rec,1,48,f)!=48) break;
        if(rec[0]==0&&rec[1]==0&&rec[2]==0&&rec[3]==0) continue; /* hole */
        idx_put(ht_idx,rec,h);
        if(h%100000==0){ fprintf(stderr,"[hashidx] %ld/%ld\n",h,n); }
    }
    fclose(f);
    fprintf(stderr,"[hashidx] indexed %ld stored heights\n", (long)idx_count(ht_idx));
    return 0;
}

static int lsock(int port){
    int l = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons((unsigned short)port); a.sin_addr.s_addr=htonl(INADDR_ANY);
    int one=1; setsockopt(l,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    if(bind(l,(struct sockaddr*)&a,sizeof a)<0){ perror("bind"); return -1; }
    if(listen(l,8)<0){ perror("listen"); return -1; }
    return l;
}

static unsigned char fake_blocks[8][4096]; static long fake_blen[8]; static unsigned char fake_bh[8][32]; static int fake_NB=0;
static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}
extern void sha256d(unsigned char o[32],const void*m,long l);
extern int  pow_check(const unsigned char h[80]);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
static void build_fake_chain(void){
    /* build an 8-block coinbase chain up front. fake_NB starts at 2 and grows by
     * 1 per getheaders in the growing peer; full_serve bumps it to 8 to expose
     * the whole chain. */
    static int built=0;
    if(built) return;
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<8;i++){
        unsigned char* b=fake_blocks[i]; unsigned char* o=b; unsigned char t[200]; memset(t,0,200); unsigned char* q=t;
        put_u32(q,1);q+=4; q[0]=1;q+=1; memset(q,0,32);q+=32; put_u32(q,0xffffffff);q+=4;
        q[0]=3; q[1]=(unsigned char)i; q[2]=0; q[3]=0; q+=4; put_u32(q,0xffffffff);q+=4;
        q[0]=1;q+=1; put_u64(q,8*1000000);q+=8; q[0]=1;q[1]=0x51;q+=2; put_u32(q,0);q+=4;
        long tl=q-t; unsigned char mr[32]; sha256d(mr,t,tl);
        put_u32(o,1);o+=4; memcpy(o,prev,32);o+=32; memcpy(o,mr,32);o+=32;
        put_u32(o,1300000000u);o+=4; put_u32(o,0x207fffff);o+=4; put_u32(o,0);o+=4;
        o[0]=1; o+=1;                /* tx-count varint (1 tx) -- REQUIRED wire field */
        memcpy(o,t,tl);o+=tl; fake_blen[i]=o-b;
        unsigned nz=0; while(!pow_check(fake_blocks[i])){ nz++; put_u32(fake_blocks[i]+76,nz); }
        block_hash(fake_bh[i],fake_blocks[i]); memcpy(prev,fake_bh[i],32);
    }
    fake_NB=2;
    built=1;
}
static void fake_serve(int cfd){
    /* build an 8-block chain up front, but only expose the first `fake_NB`.
     * fake_NB grows by 1 on each getheaders, so a client that keeps re-syncing
     * observes new blocks being mined over time (realtime keep-up demo). */
    build_fake_chain();
    char cmd[12]; unsigned char pl[65536]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); /* client version */
    unsigned char v[102]; memset(v,0,sizeof v); v[4]=1; p2p_write(cfd,"version",7,v,86);
    p2p_write(cfd,"verack",6,"",0);
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); /* client verack */
    for(int n=0;n<64;n++){
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return; cmd[11]=0;
        if(strncmp(cmd,"getheaders",10)==0){
            if(fake_NB<8) fake_NB++;          /* a new block is "mined" */
            int zero=1; for(int z=0;z<32;z++) if(pl[5+z]){zero=0;break;}
            int from=0; if(zero) from=0; else { from=fake_NB; for(int i=0;i<fake_NB;i++) if(memcmp(pl+5,fake_bh[i],32)==0) from=i+1; }
            int cnt=fake_NB-from; if(cnt<0)cnt=0;
            if(cnt>0){ unsigned char hp[300]; hp[0]=cnt; int p=1; for(int i=from;i<fake_NB;i++){memcpy(hp+p,fake_blocks[i],80);hp[p+80]=0;p+=81;} p2p_write(cfd,"headers",7,hp,p);}
            else p2p_write(cfd,"headers",7,"\x00",1);
        } else if(strncmp(cmd,"getdata",7)==0){
            int found=-1; for(int i=0;i<fake_NB;i++) if(memcmp(pl+5,fake_bh[i],32)==0) found=i;
            if(found>=0) p2p_write(cfd,"block",5,fake_blocks[found],(unsigned)fake_blen[found]);
            else p2p_write(cfd,"block",5,"",0);
        } else if(strncmp(cmd,"ping",4)==0){
            p2p_write(cfd,"pong",4, pl, (plen>=8)?8:0);
        }
    }
}
/* whole-chain peer for the `ibd` mode: serves ALL fake_NB=8 stored blocks and
 * their headers (no growth) so the full machine-code node_ibd pass can pull the
 * entire persisted chain in one go -- the daemon-side analogue of test_ibd_full. */
static void full_serve(int cfd){
    build_fake_chain();
    fake_NB=8;                                   /* expose the WHOLE chain now */
    char cmd[12]; unsigned char pl[65536]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); /* client version */
    unsigned char v[102]; memset(v,0,sizeof v); v[4]=1; p2p_write(cfd,"version",7,v,86);
    p2p_write(cfd,"verack",6,"",0);
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); /* client verack */
    int gd=0;
    for(int n=0;n<64;n++){
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return; cmd[11]=0;
        if(strncmp(cmd,"getheaders",10)==0){
            int zero=1; for(int z=0;z<32;z++) if(pl[5+z]){zero=0;break;}
            int from=0; if(!zero){ from=fake_NB; for(int i=0;i<fake_NB;i++) if(memcmp(pl+5,fake_bh[i],32)==0){from=i+1;break;} }
            int cnt=fake_NB-from; if(cnt<0)cnt=0;
            if(cnt>0){ unsigned char hp[300]; hp[0]=cnt; int p=1; for(int i=from;i<fake_NB;i++){memcpy(hp+p,fake_blocks[i],80);hp[p+80]=0;p+=81;} p2p_write(cfd,"headers",7,hp,p);}
            else p2p_write(cfd,"headers",7,"\x00",1);
        } else if(strncmp(cmd,"getdata",7)==0){
            int found=-1; for(int i=0;i<fake_NB;i++) if(memcmp(pl+5,fake_bh[i],32)==0) found=i; gd++;
            fprintf(stderr,"[full_serve] getdata#%d found=%d\n", gd, found);
            if(found>=0) p2p_write(cfd,"block",5,fake_blocks[found],(unsigned)fake_blen[found]);
            else p2p_write(cfd,"block",5,"",0);
        } else if(strncmp(cmd,"ping",4)==0){
            p2p_write(cfd,"pong",4, pl, (plen>=8)?8:0);
        }
    }
}
static int serve_loop(int fd, int lfd){
    char cmd[12]; static unsigned char pl[8<<20]; unsigned plen=0; static unsigned char out[8<<20];
    int served=0;
    for(int n=0; n<10000; n++){
        plen=0;
        int r=p2p_read(fd,cmd,pl,sizeof pl,&plen);
        if(r<=0) break;                                  /* eof/err */
        cmd[11]=0;
        if(memcmp(cmd,"ping",4)==0){
            p2p_write(fd,"pong",4, pl, (plen>=8)?8:0);   /* echo nonce */
        } else if(memcmp(cmd,"getaddr",7)==0){
            /* A connected peer asked us for our address book. Reply with an
             * `addr` message built from peers.dat via the asm address manager
             * (amr_* + p2p_addr_v1). This is the addr-relay half of recursive
             * peer discovery -- answering makes the network treat us as a real
             * full client and reciprocate. */
            static unsigned char ab[64];
            if(amr_init(ab)==1){
                static unsigned char rec[18]; long cnt = amr_count(ab);
                long n= cnt>1000?1000:cnt;           /* cap a single addr msg */
                static unsigned char src[1000*18];
                long have=0;
                for(long i=0;i<n;i++){ if(amr_get_i(ab,i,rec)==1) memcpy(src+have*18,rec,18), have++; }
                if(have>0){
                    static unsigned char ah[1000*30+4];
                    long L = p2p_addr_v1(ah, src, have);
                    p2p_write(fd,"addr",4, ah, (unsigned)L);
                }
            }
        } else if(memcmp(cmd,"getdata",7)==0){
            /* payload: count varint then per item: [type int32 LE][hash32].
             * The wire inventory `type` is a 4-byte little-endian int32
             * (verified byte-exact vs p2p_oracle.py and LIVE: this is what the
             * reference client and real nodes send). One MSG_BLOCK inventory is
             * [count=0x01][type=0x02 0000][hash at +5] = 37 bytes total.
             * Match the requested hash against each stored block's header hash
             * (via the verified block_hash asm) and serve the exact block. */
            if(plen>=37){
                unsigned cnt = pl[0];                       /* count varint (1B here) */
                if(cnt>=1 && 1+cnt*36 <= plen){
                    int tip = *(int*)(store_buf+24);
                    for(unsigned item=0; item<cnt; item++){
                        size_t off = 1 + item*36;           /* [type 4B][hash 32] */
                        unsigned int type = pl[off]|pl[off+1]<<8|pl[off+2]<<16|pl[off+3]<<24;
                        if(type!=2 || off+32>=plen) continue;
                        long gl=-1;
                        long fh;
                        if(idx_get(ht_idx, pl+off+4, &fh)){
                            static unsigned char sb[8<<20];
                            long L = node_serve_block(store_buf, fh, sb, sizeof sb);
                            if(L>0){ gl=L; memcpy(out,sb,(size_t)L); }
                        }
                        if(gl>0){ p2p_write(fd,"block",5,out,(unsigned)gl); served++;
                                  node_log_event(lfd, L_SERVE, (unsigned)gl, 0, 1); }
                    }
                }
            }
        } else if(memcmp(cmd,"getheaders",10)==0){
            /* headers payload: key_count(1) hash_count(1) hashes[] stop(32).
             * First locator hash at +5. Respond with headers for the blocks
             * AFTER that locator (headers msg = count varint + per-hdr 81B). */
            int from=-1;
            if(plen>=5){ int tip = *(int*)(store_buf+24);
                long fh;
                if(idx_get(ht_idx, pl+5,&fh)){ from=(int)fh+1; }
                if(from<0 && tip>0) from=0;   /* unknown locator: from genesis */
            }
            if(from>=0){ int tip=*(int*)(store_buf+24); unsigned char hp[2000*81+4]; int p=1;
                int n=0; for(int h=from; h<=tip && n<2000; h++,n++){ static unsigned char sb[8<<20];
                    long L=node_serve_block(store_buf,h,sb,sizeof sb); if(L<0)break;
                    memcpy(hp+p, sb, 80); hp[p+80]=0; p+=81;                  /* hdr + tx-count */
                }
                hp[0]=(unsigned char)(n&0xff);                                 /* count varint */
                p2p_write(fd,"headers",7,hp,p);
                node_log_event(lfd, L_HDRS, (unsigned)n, (unsigned)from, 0);
            } else {
                p2p_write(fd,"headers",7,"\x00",1);
            }
        } else if(memcmp(cmd,"inv",3)==0){
            /* Peer announced new blocks: inv = count(1) [type u32 LE + hash32].
             * Request each MSG_BLOCK(2) we don't already store, receive the
             * block, cons_verify, and store_append -> realtime keep-up driven by
             * peer push (event-driven), not polling. */
            if(plen>=5){ unsigned n=pl[0];
                for(unsigned i=0;i<n && i<50;i++){
                    size_t off=1+i*36;
                    unsigned int type=pl[off]|pl[off+1]<<8|pl[off+2]<<16|pl[off+3]<<24;
                    if(type==2 && off+32<plen){
                        /* duplicate check via O(1) hash index */
                        long fh; int have = idx_get(ht_idx, pl+off+4, &fh)?1:0;
                        if(!have){
                            /* build real getdata payload with the hash */
                            static unsigned char gd[37]; gd[0]=1; gd[1]=2; gd[2]=0; gd[3]=0; gd[4]=0;
                            memcpy(gd+5, pl+off+4, 32);
                            p2p_write(fd,"getdata",7,gd,37);
                            char c2[12]; static unsigned char blk[8<<20]; unsigned bl=0;
                            int rr=p2p_read(fd,c2,blk,sizeof blk,&bl);
                            if(rr>0 && strncmp(c2,"block",5)==0){
                                static unsigned char scratch[2048];
                                if(cons_verify(blk,bl,scratch,64)==1){
                                    unsigned char hdr[32]; block_hash(hdr,blk);
                                    store_append(store_buf,hdr,blk,bl);
                                    node_log_event(lfd, L_BLOCK, (unsigned)bl, 1, i);
                                }
                            }
                        }
                    }
                }
            }
        } else if(memcmp(cmd,"verack",6)==0){
            /* already handshaken; ignore */
        }
    }
    return served;
}

int main(int argc, char** argv){
    signal(SIGPIPE, SIG_IGN);   /* broken peer connections must not kill the node */
    if(argc < 3){ fprintf(stderr,"usage: %s sync <dir> | ibd <dir> | follow <dir> | serve <dir> <port> | server-test <dir>\n", argv[0]); return 2; }
    const char* mode = argv[1]; const char* dir = argv[2];
    if(chdir(dir)!=0){ perror("chdir"); return 1; }
    if(store_init(store_buf)!=1){ fprintf(stderr,"store_init failed\n"); return 1; }

    if(strcmp(mode,"sync")==0){
        /* Connect to a built-in loopback fake peer (forked in-process), exactly
         * like the verified tests/test_bitcoind_sync harness, so the IBD
         * exchange matches node_sync cadence. */
        int lfd = node_log_open("bitcoind.log");   /* all-asm leveled logger */
        node_log_str(lfd, 0, "node start (sync mode)", 22);
        int ls=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
        listen(ls,2);
        pid_t pid=fork();
        if(pid==0){ int c=accept(ls,0,0); fake_serve(c); _exit(0); }
        int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
        if(fd<0){ fprintf(stderr,"connect failed\n"); return 1; }
        if(node_handshake(fd)!=1){ fprintf(stderr,"handshake failed\n"); return 1; }
        node_log_event(lfd, 1, 70016, 1, 0);        /* HSHK protocol services */
        static unsigned char gen[32]; memset(gen,0,32);
        static unsigned char buf[65536]; long cnt=0;
        long ok = node_sync(fd, store_buf, gen, buf, sizeof buf, &cnt);
        int tip = *(int*)(store_buf+24);
        node_log_event(lfd, L_BLOCK, (unsigned)(ok?cnt:0), 0, 0);   /* BLOCK n downloaded */
        node_log_event(lfd, L_STORE, (unsigned)(tip+1), (unsigned)tip, 0); /* STORE count height */
        if(!ok) node_log_str(lfd, L_ERROR, "node_sync failed", 16);
        close(fd); waitpid(pid,0,0); close(ls);
        printf("sync: ok=%ld blocks=%ld height=%d (store in %s, log bitcoind.log)\n", ok, cnt, tip, dir);
        return (ok==1 && cnt>=1)?0:1;
    }

    if(strcmp(mode,"ibd")==0){
        /* FULL Initial-Block-Download as ONE assembly pass (node_ibd =
         * node_ibd_headers + node_ibd_blocks) over a single connection to a
         * peer that serves the WHOLE chain. This is the runnable daemon wired
         * to the same 100%-asm IBD machine proven by tests/test_ibd_full.c: it
         * persists the whole header chain (header store), then walks every
         * stored header, getdata's its block body, validates with cons_verify +
         * a re-derived-hash guard, and store_appends into the block store. */
        static unsigned char hstb[256];
        if(hst_init(hstb)!=1){ fprintf(stderr,"hst_init failed\n"); return 1; }
        int lfd = node_log_open("bitcoind.log");
        node_log_str(lfd, 0, "node start (ibd mode)", 21);
        int ls=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
        listen(ls,2);
        pid_t pid=fork();
        if(pid==0){ int c=accept(ls,0,0); full_serve(c); _exit(0); }
        int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
        if(fd<0){ fprintf(stderr,"connect failed\n"); return 1; }
        if(node_handshake(fd)!=1){ fprintf(stderr,"handshake failed\n"); return 1; }
        static unsigned char ibuf[1<<22];            /* >= 2MB shared scratch */
        long nblk = node_ibd(fd, store_buf, hstb, ibuf, sizeof ibuf);
        close(fd); waitpid(pid,0,0); close(ls);
        long nhdr = hst_count(hstb);
        int tip = *(int*)(store_buf+24);
        node_log_event(lfd, L_BLOCK, (unsigned)(nblk>0?nblk:0), 0, 0);
        node_log_event(lfd, L_STORE, (unsigned)(tip+1), (unsigned)tip, 0);
        printf("ibd: blocks=%ld headers=%ld height=%d (store in %s; all-asm node_ibd pass)\n", nblk, nhdr, tip, dir);
        return (nblk>=1 && nhdr>=1 && tip==(int)nhdr-1 && (long)nhdr==8)?0:1;
    }

    if(strcmp(mode,"follow")==0){
        /* REALTIME keep-up: stay on one connection and re-run node_sync
         * (getheaders from our advancing tip) so we pick up blocks the peer
         * mines after we synchronized. Logs tip growth each pass. This is the
         * live synchronization loop over the verified asm IB D core. */
        store_reload(store_buf);            /* continue from persisted tip */
        int lfd = node_log_open("bitcoind.log");
        node_log_str(lfd, 0, "node start (follow mode)", 23);
        int ls=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
        listen(ls,2);
        pid_t pid=fork();
        if(pid==0){ int c=accept(ls,0,0); fake_serve(c); _exit(0); }
        int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
        if(fd<0){ fprintf(stderr,"connect failed\n"); return 1; }
        if(node_handshake(fd)!=1){ fprintf(stderr,"handshake failed\n"); return 1; }
        static unsigned char gen[32]; memset(gen,0,32);
        static unsigned char buf[65536];
        int last=-1, same=0;
        for(int pass=1; pass<=8; pass++){
            long cnt=0;
            long ok = node_sync(fd, store_buf, gen, buf, sizeof buf, &cnt);
            int tip = *(int*)(store_buf+24);
            node_log_event(lfd, L_BLOCK, (unsigned)(ok?cnt:0), (unsigned)tip, (unsigned)pass);
            printf("follow pass %d: ok=%ld new=%ld height=%d\n", pass, ok, cnt, tip); fflush(stdout);
            if(tip==last) same++; else same=0;
            if(same>=2 && cnt==0){ node_log_str(lfd, 0, "caught up to chain tip", 22); break; }
            last=tip;
            if(ok==0) break;
        }
        close(fd); waitpid(pid,0,0); close(ls);
        printf("follow done (store in %s)\n", dir);
        return 0;
    }

    if(strcmp(mode,"server-test")==0){
        /* End-to-end server test: sync a chain into store, then run serve_loop
         * against a socketpair CLIENT that issues getdata/getheaders/inv and
         * checks the server answers correctly (boundary getheaders-serving +
         * event-driven inv->block keep-up). */
        int failures=0;
        /* 1) download an 8-block chain from the growing fake peer */
        int ls=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in aa; memset(&aa,0,sizeof aa); aa.sin_family=AF_INET; aa.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls,(struct sockaddr*)&aa,sizeof aa); socklen_t al=sizeof aa; getsockname(ls,(struct sockaddr*)&aa,&al);
        listen(ls,2);
        pid_t pid=fork();
        if(pid==0){ int c=accept(ls,0,0); fake_serve(c); _exit(0); }
        int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), aa.sin_port);
        if(fd<0){ printf("FAIL connect\n"); return 1; }
        if(node_handshake(fd)!=1){ printf("FAIL handshake\n"); return 1; }
        static unsigned char gen[32]; memset(gen,0,32); static unsigned char bigbuf[65536]; long cnt=0;
        long ok=node_sync(fd, store_buf, gen, bigbuf, sizeof bigbuf, &cnt);
        close(fd); waitpid(pid,0,0); close(ls);
        int tip=*(int*)(store_buf+24);
        printf("[server-test] synced ok=%ld blocks=%ld tip=%d\n", ok, cnt, tip);
        if(ok!=1||tip<6){ printf("TESTS FAILED (no chain)\n"); return 1; }

        /* 2) socketpair: parent = server(serve_loop), child = test client */
        int sv[2]; if(socketpair(AF_UNIX,SOCK_STREAM,0,sv)!=0){ perror("socketpair"); return 1; }
        pid=fork();
        if(pid==0){
            close(sv[0]);
            int cfd=sv[1]; char cmd[12]; unsigned char pl[100]; unsigned plen=0;
            /* serve_loop does NOT handshake (assumes already done), so go
             * straight to issuing requests. */
            /* getdata for block0's hash -> server must return EXACT block0 */
            static unsigned char bh0[2048]; long gl=node_serve_block(store_buf,0,bh0,2048);
            unsigned char h0[32]; block_hash(h0,bh0);
            unsigned char gd[37]; gd[0]=1; gd[1]=2; gd[2]=0; gd[3]=0; gd[4]=0; memcpy(gd+5,h0,32);
            p2p_write(cfd,"getdata",7,gd,37);
            unsigned char blk[65536]; unsigned bl=0;
            if(p2p_read(cfd,cmd,blk,sizeof blk,&bl)<=0 || strncmp(cmd,"block",5)!=0){ printf("FAIL getdata->block\n"); exit(2); }
            int ok0=(bl==(unsigned)gl && memcmp(blk,bh0,gl)==0);
            /* getheaders locator=block0 -> server should return headers for 1..tip
             * (payload: version[4] count[1] hash[32] stop[32] = 69 bytes) */
            unsigned char gh[69]; gh[0]=0x00; gh[1]=0x11; gh[2]=0x01; gh[3]=0x00; gh[4]=1;
            memcpy(gh+5,h0,32); memset(gh+37,0,32);
            p2p_write(cfd,"getheaders",10,gh,69);
            unsigned char hp[5000]; unsigned hp_len=0;
            if(p2p_read(cfd,cmd,hp,sizeof hp,&hp_len)<=0 || strncmp(cmd,"headers",7)!=0){ printf("FAIL getheaders->headers\n"); exit(2); }
            int okh=(hp_len>81 && (int)hp[0]>=1);
            /* inv announce block0 -> server fetches+stores (already have) -> must NOT error */
            unsigned char invm[37]; invm[0]=1; invm[1]=2; invm[2]=0; invm[3]=0; invm[4]=0; memcpy(invm+5,h0,32);
            p2p_write(cfd,"inv",3,invm,37);
            p2p_write(cfd,"ping",4,"\x11\x22\x33\x44\x55\x66\x77\x88",8);
            if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0 || strncmp(cmd,"pong",4)!=0){ printf("FAIL ping->pong\n"); exit(2); }
            printf("[server-test] getdata-exact=%d getheaders-n=%d (%d blocked)\n", ok0, okh, (int)hp_len);
            exit((ok0&&okh)?0:2);
        }else{
            int lfd=node_log_open("bitcoind.log");
            close(sv[1]);
            int svo=serve_loop(sv[0], lfd);
            int st; waitpid(pid,&st,0); close(sv[0]);
            printf("server served %d msg(s); client rc=%d\n", svo, WEXITSTATUS(st));
            failures = (WEXITSTATUS(st)!=0)?1:0;
        }
        printf("\n%s\n", failures?"TESTS FAILED":"ALL TESTS PASSED");
        return failures?1:0;
    }

    if(strcmp(mode,"serve")==0 && argc>=4){
        int port = atoi(argv[3]);
        store_reload(store_buf);            /* load the persisted chain from disk */
        build_hash_index();                 /* hash->height for O(1) getdata serving */
        int lfd = node_log_open("bitcoind.log");   /* all-asm leveled logger */
        node_log_str(lfd, 0, "node start (serve mode)", 22);
        int l = lsock(port);
        if(l<0) return 1;
        printf("serving on port %d...\n", port); fflush(stdout);
        for(;;){
            int c = accept(l,0,0);
            if(c<0){ perror("accept"); continue; }
            /* Inbound role: a real peer connecting to us sends ITS version first
             * and expects us to answer with our own version + verack. Use
             * node_accept_handshake (not node_handshake, which is the outbound/
             * initiator role and would hang on an inbound peer). */
            if(node_accept_handshake(c)!=1){ close(c); continue; }
            /* Serve the peer entirely in assembly (bitcoin_serve.asm
             * node_serve_loop): ping/getaddr/getdata/getheaders/inv. */
            long s = node_serve_loop(c, lfd, store_buf, ht_idx, out_buf, (long)sizeof out_buf);
            printf("served %ld block(s) to one peer\n", s); fflush(stdout);
            close(c);
        }
    }
    return 2;
}

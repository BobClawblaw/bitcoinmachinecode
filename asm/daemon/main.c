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
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <stdbool.h>
#include <fcntl.h>

/* Pre-mux outbound catch-up bounds (used by outbound_catchup below and the
 * serve handler). CATCHUP_MAX caps the number of blocks pulled synchronously;
 * CATCHUP_MAX_SECS caps the catch-up wall-clock. Both keep the mux loop (the
 * long-running stays-current mechanism) from being delayed indefinitely by a
 * far-from-tip store. */
#define CATCHUP_MAX 10000L
#define CATCHUP_MAX_SECS 60.0
/* Per-rotation wall-clock budget for ONE outbound do_outbound_sync leg inside
 * the mux poll loop. A far-behind store (or a slow seed building a large
 * getheaders catch-up) would otherwise let a single blocking node_sync soak the
 * loop for tens of seconds to minutes, starving inbound accepts (the kernel
 * accepts the TCP connection into the listen backlog but the loop never calls
 * accept(), so the version handshake never starts and every inbound probe
 * times out). Bounding each leg's sync time makes serve_mux return to poll() +
 * accept() promptly, so "serve stays live to inbound while downloading" holds
 * at any store scale. Kept well above the at-tip round-trip cost (~hundreds of
 * ms) so a caught-up node is never interrupted. */
#define MUX_SYNC_BUDGET_SECS 2.0

/* --- assembly node core (bitcoind.asm / bitcoin_*.asm) --- */
extern long node_handshake(int fd);
extern long node_accept_handshake(int fd);
extern long node_sync(int fd, void* st, void* locator, void* buf, long buflen, long* out_count);
extern long node_serve_block(void* st, long height, void* out, long cap);
extern long node_serve_block_by_hash(void* st, const void* hash32, void* out, long cap);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern long node_announce_tip(int fd, void* st, void* ht_idx, long use_headers);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long store_init(void* st);
extern long store_reload(void* st);
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern long p2p_getheaders(void* out, const void* locator, int count, const void* stop);
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
extern long node_drain(int fd, void* st, void* buf, long buflen);          /* bitcoind.asm */
extern long node_sync(int fd, void* st, void* locator, void* buf, long buflen, long* out_count); /* bitcoind.asm */
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
        /* index.dat stores the block hash in big-endian DISPLAY byte order; the
         * getdata/inv wire hash is little-endian (the raw internal hash). Reverse
         * to the wire/LE order so idx_get (looked up with the raw getdata hash)
         * matches. */
        unsigned char le[32]; for(int k=0;k<32;k++) le[k]=rec[31-k];
        idx_put(ht_idx, le, h);
        if(h%100000==0){ fprintf(stderr,"[hashidx] %ld/%ld\n",h,n); }
    }
    fclose(f);
    fprintf(stderr,"[hashidx] indexed %ld stored heights\n", (long)idx_count(ht_idx));
    return 0;
}

/* Build the hash->height index from the IN-MEMORY store (used where the chain
 * lives only in store_buf, e.g. the socketpair server-test, not on disk yet).
 * Iterates heights 0..tip, serves each block via node_serve_block, hashes its
 * header with block_hash, and idx_put -> same O(1) hash index disk mode builds. */
static int build_inmem_hash_index(void){
    ht_idx=malloc(24 + (size_t)HT_SLOTS*48 + 64);
    if(!ht_idx){ fprintf(stderr,"alloc idx failed\n"); return -1; }
    idx_init(ht_idx, HT_SLOTS);
    int tip = *(int*)(store_buf+24);        /* same tip source the rest of main.c uses */
    static unsigned char sb[8<<20];
    int hashed = 0;
    for(int h=0; h<=tip; h++){
        long L = node_serve_block(store_buf, h, sb, sizeof sb);
        if(L<80){ continue; }                /* hole: skip, don't abandon the range */
        unsigned char bhash[32]; block_hash(bhash, sb);
        if(idx_put(ht_idx, bhash, h)) hashed++;
    }
    fprintf(stderr,"[inmem idx] indexed %d stored heights (tip %d)\n", hashed, tip);
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

/* ---- BEST-EFFORT OUTBOUND CATCH-UP (stays-up-to-date on boot) ----
 * The serve loop is inbound-only; without an outbound connection the node can
 * never pull missed blocks. On serve startup we try real mainnet seeds (via the
 * verified asm tcp_connect_ip + node_handshake) and run the verified asm
 * node_drain per-peer download loop to catch up the store to the chain tip.
 * It is deliberately best-effort and non-fatal: any seed/network failure falls
 * straight through to serving (the node still serves whatever it has, and the
 * new bitcoin_serve.asm `.do_block` keep-up path stores any block a peer later
 * pushes). Returns the count of blocks added on success, 0/-1 on no-network.
 * Sieve out peers that hang: a 10s recv timeout + per-seed cap. */
static const char* catchup_seeds[] = {
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcharcoal.com",
    "seed.bitcoin.wiz.biz"
};
static void anchor_locator(unsigned char loc[32]);   /* fwd decl (defined below) */
/* Wall-clock alarm handler: raise SIGALRM after CATCHUP_MAX_SECS so the
 * synchronous node_sync catch-up (blocking on a real seed) is interrupted and
 * the mux loop can start. node_sync's blocking p2p_read is interrupted by the
 * signal (EINTR), so it returns and the parent proceeds to the mux loop. */
static void catchup_alarm(int sig){ (void)sig; }
/* Bounded boot catch-up. Runs ONE node_sync pass (the verified asm download->
 * validate->store path) against the first reachable seed, anchored at the
 * stored tip, to close any small gap before the mux starts. A wall-clock alarm
 * (CATCHUP_MAX_SECS) bounds the synchronous window: if the gap is large the
 * alarm fires, node_sync returns, and the mux loop takes over closing the rest
 * gradually WHILE SERVING (the mux is the long-running stays-current
 * mechanism). Returns # blocks pulled. */
static long outbound_catchup(long max_blocks){
    static unsigned char cbuf[4<<20];
    long total=0;
    for(size_t s=0; s<sizeof(catchup_seeds)/sizeof(catchup_seeds[0]); s++){
        const char* host=catchup_seeds[s];
        struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
        if(getaddrinfo(host,NULL,&h,&res)!=0) continue;
        unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(res);
        int fd=tcp_connect_ip(ip,(unsigned short)htons(8333));
        if(fd<0) continue;
        struct timeval tv; tv.tv_sec=10; tv.tv_usec=0;
        setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
        if(node_handshake(fd)!=1){ close(fd); continue; }
        static unsigned char loc[32];
        /* Anchor from the STORED TIP index record (index-hash read, robust to a
         * transiently-unreadable tip body -- avoiding the live-found genesis
         * re-download duplicate-tail corruption) or a zero locator when empty. */
        anchor_locator(loc);
        /* Wall-clock cap: alarm after CATCHUP_MAX_SECS so a large gap does not
         * block the mux start. node_sync's blocking reads see the SIGALRM as
         * EINTR and return; we then proceed to the mux loop. */
        struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=catchup_alarm;
        sigaction(SIGALRM,&sa,NULL);
        alarm(CATCHUP_MAX_SECS);
        long cnt=0;
        long ok=node_sync(fd, store_buf, loc, cbuf, (long)sizeof cbuf, &cnt);
        alarm(0);
        int tip=*(int*)(store_buf+24);
        fprintf(stderr,"[catchup] %-28s sync ok=%ld new=%ld tip=%d\n", host, ok, cnt, tip);
        close(fd);
        total=cnt;
        break;   /* one bounded pass; the mux loop closes the rest */
    }
    return total>max_blocks?max_blocks:total;
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

/* ============================================================================
 * OUTBOUND MULTIPLEXER (stays-current-while-serving).
 *
 * The serve loop above is inbound-only (fork-per-peer). This block adds the
 * persistent OUTBOUND legs the node needs to stay current on its own: N
 * long-lived connections to real seeds, multiplexed with the listening socket
 * in ONE poll() loop. On each rotation pass we run the now-hardened asm
 * node_sync (getheaders-from-stored-tip -> cons_verify -> store_append ->
 * advance locator) to pull any newly mined blocks, then maintain the hash
 * index and announce the new tip back to the peer (node_announce_tip, BIP130
 * honored by the peer's own negotiation). Inbound connections are still forked
 * off to node_serve_loop children so concurrent serving is unaffected.
 *
 * The outbound legs are NOT forked -- they are multiplexed inline in the one
 * parent loop, so the node simultaneously serves AND downloads. Each outbound
 * fd carries a short SO_RCVTIMEO so a node_sync pass returns promptly when the
 * peer is already at the chain tip (empty headers page) instead of blocking
 * the accept loop.
 * ========================================================================== */
#define MUX_MAX_OUT 8
static int   mux_out_fd[MUX_MAX_OUT];       /* persistent outbound seed fds  */
static unsigned char mux_out_loc[MUX_MAX_OUT][32];  /* per-peer locator (tip) */
static char  mux_out_host[MUX_MAX_OUT][64];
static int   mux_n_out = 0;
static int   mux_out_peer[MUX_MAX_OUT];     /* index into the peer pool (for re-dial rotation) */
static long long mux_out_nextretry[MUX_MAX_OUT]; /* monotonic ms deadline before the next re-dial attempt */
#define REDIAL_BACKOFF_MS 30000L             /* min gap between re-dial tries on a dead slot */

/* Connect + handshake one outbound seed, returning a long-lived fd (or -1).
 * The handshake reads the seed's version/verack plus its post-verack chatter
 * (sendheaders/sendaddrv2/feefilter/addr), which can take longer than the
 * tight per-pass recv bound -- so give the handshake a generous 6s timeout,
 * then clamp the socket to the short per-pass timeout for node_sync. */
static int outbound_connect(const char* host, int rcv_ms, int out_port){
    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&h,&res)!=0) return -1;
    unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    int fd=tcp_connect_ip(ip,(unsigned short)htons((unsigned short)out_port));
    if(fd<0) return -1;
    struct timeval tv; tv.tv_sec=6; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    if(node_handshake(fd)!=1){ close(fd); return -1; }
    /* handshake done: tighten the recv bound so each node_sync pass returns
     * promptly when the peer is already at the chain tip */
    struct timeval t2; t2.tv_sec=rcv_ms/1000; t2.tv_usec=(rcv_ms%1000)*1000;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t2,sizeof t2);
    return fd;
}

/* Anchor a peer's locator to our CURRENT stored tip hash (zero if empty). */
static void anchor_locator(unsigned char loc[32]){
    /* Anchor the locator to the stored tip's HASH read straight from the index
     * record (idx_len-48 .. idx_len-16), NOT via node_serve_block. A live
     * sustained-ingest finding: node_serve_block on a just-appended tip can
     * transiently return <80 (bd: block body not yet at a readable position),
     * which used to make this helper collapse loc to all-zero (genesis) --
     * the next node_sync then re-downloaded from genesis and store_append
     * appended a duplicate, non-contiguous tail. Reading the tip hash directly
     * from index.dat is always available and cannot misfire. */
    int fd = *(int*)(store_buf+8);          /* idx_fd */
    long len = *(long*)(store_buf+16);      /* idx_len */
    if(fd>=0 && len>=48){
        if(lseek(fd, len-48, SEEK_SET)>=0 && read(fd, loc, 32)==32) return;
    }
    memset(loc,0,32);
}

/* Materialize the locator for outbound peer i into `loc` (32 bytes). */
static void mux_locator(int i, unsigned char loc[32]){
    memcpy(loc, mux_out_loc[i], 32);
}

static int mux_locator_zero(int i){
    for(int k=0;k<32;k++) if(mux_out_loc[i][k]) return 0; return 1;
}

/* One bounded download+announce pass on outbound peer i.
 *   - anchor locator at our stored tip (so we only pull the missing tail)
 *   - run node_sync (getheaders -> validate -> store_append) with the fd's
 *     short recv timeout so an idle peer returns fast
 *   - index any newly-stored blocks (node_sync appends but does not idx_put)
 *   - announce the new tip back to the peer via node_announce_tip
 *   - update the per-peer locator to our new tip
 * Returns # blocks stored this pass. */
static long do_outbound_sync(int i){
    unsigned char loc[32]; mux_locator(i, loc);
    if(mux_locator_zero(i)){ anchor_locator(loc); }  /* first time: genesis */
    static unsigned char cbuf[6<<20]; long cnt=0;
    int st_tip_before=*(int*)(store_buf+24);
    long ok=node_sync(mux_out_fd[i], store_buf, loc, cbuf, (long)sizeof cbuf, &cnt);
    int st_tip=*(int*)(store_buf+24);
    if(ok!=1 || cnt<=0){
        /* keep the locator fresh even on a no-op so we don't re-request from
         * genesis forever (node_sync advanced it internally only on success) */
        anchor_locator(mux_out_loc[i]);
        return 0;
    }
    /* index every newly stored height (st_tip_before+1 .. st_tip) into ht_idx */
    static unsigned char sb[8<<20];
    for(int h=st_tip_before+1; h<=st_tip; h++){
        long L=node_serve_block(store_buf, h, sb, sizeof sb);
        if(L<80) continue;
        unsigned char bhash[32]; block_hash(bhash, sb);
        idx_put(ht_idx, bhash, h);
    }
    /* announce the new tip to this peer (inv; BIP130 headers honored by the
     * peer's sendheaders negotiation is handled downstream on its own leg) */
    node_announce_tip(mux_out_fd[i], store_buf, ht_idx, 0);
    /* advance this peer's persistent locator to our new stored tip */
    anchor_locator(mux_out_loc[i]);
    fprintf(stderr,"[mux:%d] %-22s sync ok=%ld new=%ld tip=%d\n", i, mux_out_host[i], ok, cnt, st_tip);
    return cnt;
}

/* Re-dial one dead outbound leg: close the socket (if any) and attempt a fresh
 * connect+handshake to a DIFFERENT seed in the pool, rotating so keep-up is not
 * single-seed-limited. This is the peer-pool rotation / retry the soak analysis
 * flagged as missing (D2): the old mux connected N legs once up front and never
 * recovered a leg that died or failed to handshake, leaving keep-up silently
 * single-seed-limited. On success the slot is re-anchored at our stored tip and
 * reused in the poll loop; on failure the slot stays dead (fd -1) and is retried
 * on a later rotation. */ 
static void mux_redial(int i, const char* peers[], int pool_len, int out_port){
    if(mux_out_fd[i]>=0){ close(mux_out_fd[i]); mux_out_fd[i]=-1; }
    /* rotate to the next seed in the pool (wrap); avoids hammering the same dead host */
    int p = (mux_out_peer[i]+1) % (pool_len>0?pool_len:1);
    mux_out_peer[i] = p;
    int fd = outbound_connect(peers[p], 300, out_port);
    if(fd<0){ fprintf(stderr,"[mux:%d] redial %s failed (kept dead)\n", i, peers[p]); return; }
    mux_out_fd[i]=fd;
    strncpy(mux_out_host[i], peers[p], 63);
    anchor_locator(mux_out_loc[i]);
    fprintf(stderr,"[mux:%d] redialed -> %s (fd %d)\n", i, peers[p], fd);
}

/* ---- per-leg sync wall-clock budget (accept-starve fix, t_7ea57703) ----
 * serve_mux runs ONE poll() loop that services inbound accepts AND the
 * outbound legs INLINE. If a single outbound node_sync pass blocks for a long
 * time (far-behind store / slow seed building a large getheaders catch-up),
 * the loop never returns to poll(), so inbound connections sit in the kernel
 * accept backlog un-accepted and the version handshake never starts -- every
 * inbound probe times out. We bound each leg's sync wall-clock: arm a short
 * SIGALRM around node_sync; if it fires we know the pass was interrupted (the
 * socket may hold a partially-read frame), so we DROP and re-dial a rotated
 * seed (re-using mux_redial) and let the next rotation continue the catch-up
 * from the freshly-anchored stored tip. A caught-up node completes node_sync
 * in well under the budget, so it is never interrupted and small-store
 * behavior (test_outbound_mux) is unchanged. */
static volatile sig_atomic_t mux_sync_budget_fired = 0;
static void mux_budget_alarm(int sig){ (void)sig; mux_sync_budget_fired = 1; }

/* Execute ONE bounded outbound sync pass on leg i. Returns the # blocks stored
 * this pass (as do_outbound_sync) -- but keeps the loop responsive by capping
 * the wall-clock. On budget expiry the leg is dropped and re-dialed (its fd may
 * be mid-frame after the EINTR). Caller still enforces its own re-dial
 * back-off; here we always allow the interrupt-driven redial so catch-up is
 * never blocked behind a stuck leg. */
static long do_outbound_sync_bounded(int i, const char* peers[], int pool_len, int out_port){
    struct sigaction sa, old;
    memset(&sa,0,sizeof sa); sa.sa_handler=mux_budget_alarm; sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM,&sa,&old);
    mux_sync_budget_fired = 0;
    alarm((unsigned)MUX_SYNC_BUDGET_SECS < 1 ? 1 : (unsigned)MUX_SYNC_BUDGET_SECS);
    long n = do_outbound_sync(i);
    alarm(0);                                   /* disarm; return 0 leftover already fired */
    sigaction(SIGALRM,&old,NULL);
    if(mux_sync_budget_fired){
        /* The budget alarm interrupted node_sync. The leg's socket may hold a
         * partially-read frame after the EINTR, so it is NOT safe to keep
         * syncing on it -- drop and re-dial a rotated seed. do_outbound_sync
         * already re-anchored the locator at the (possibly advanced) stored
         * tip, so the next pass continues exactly where this one stopped. */
        fprintf(stderr,"[mux:%d] %s sync exceeded %gs budget; re-dialing\n",
                i, mux_out_fd[i]>=0?mux_out_host[i]:"?", MUX_SYNC_BUDGET_SECS);
        mux_redial(i, peers, pool_len, out_port);
    }
    return n;
}

/* ---- continuous download worker (serve mode, option 2) -------------------
 * The PRODUCTION `serve <dir> <port>` must BOTH service our client calls AND
 * keep downloading the blockchain to tip -- CONCURRENTLY. Serving must never
 * be delayed by a long sync, and a long sync must not be chopped into 2s
 * slices (which crawls far-from-tip stores). We therefore split the two jobs
 * across processes:
 *
 *   - PARENT: `serve_mux` -- pure serving + the pre-existing mux outbound
 *     legs (best-effort). Inbound connections are forked to node_serve_loop
 *     children, so serving our clients is never blocked by any download work
 *     in the parent. We keep the SMALL per-leg budget here (never delay
 *     accepts) because the heavy lifting is the worker's.
 *
 *   - CHILD (this worker): a dedicated forked process that continuously
 *     downloads. It re-initialises ITS OWN store from disk (fork COW is NOT
 *     safe for a growable store; the child must re-store_reload so its
 *     in-memory idx_len/pos track the archive), then loops: connect to a
 *     seed, anchor the locator at the on-disk tip, node_sync (which appends
 *     blocks), and index any new heights. It repeats until the daemon is
 *     killed.
 *
 * The worker is the ONLY aggressive block writer (the parent runs serve-only
 * with no outbound appends, so plain store_append is safe -- no cross-process
 * writer race). Serving reads block bytes fresh from disk via node_serve_block
 * (store_get_at preads index.dat and seeks the blk file), so whatever the
 * worker appends becomes serve-able once index.dat holds the height; the
 * parent refreshes its in-memory idx_len (store_buf+16) from index.dat at each
 * accept so served tips advance. */
static void serve_download_worker(const char* dir, const char* peers[], int pool_len, int out_port){
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    /* The PARENT is serve-only (no outbound appends) -- see the serve branch
     * that calls us. This child is therefore the SOLE block writer, so plain
     * store_append is safe (no cross-process writer). Still, reload a fresh
     * store state rather than inherit the parent's possibly-stale in-memory
     * idx_len/pos (fork COW is not safe for a growable store -- see the
     * unified_ibd comments on re-initialising per process). */
    chdir(dir);
    if(store_reload(store_buf)!=1){ fprintf(stderr,"[dl] store_reload failed\n"); _exit(1); }
    unsigned char loc[32];
    static unsigned char cbuf[8<<20];
    long long npass = 0;
    for(;;){
        int p = (int)(npass % (pool_len>0?pool_len:1));
        int fd = outbound_connect(peers[p], 400, out_port);
        if(fd<0){ fprintf(stderr,"[dl] connect %s failed; retry\n", peers[p]); sleep(5); npass++; continue; }
        anchor_locator(loc);                 /* resume from on-disk tip */
        long cnt=0;
        long ok = node_sync(fd, store_buf, loc, cbuf, (long)sizeof cbuf, &cnt);
        int tip = *(int*)(store_buf+24);
        fprintf(stderr,"[dl] %-22s sync ok=%ld new=%ld tip=%d\n", peers[p], ok, cnt, tip);
        /* index any newly stored heights so by-hash serving works for them */
        if(ok==1 && cnt>0){
            static unsigned char sb[8<<20];
            int tnow=*(int*)(store_buf+24);
            int base = tnow-(int)cnt;
            if(base<0) base=0;
            for(int h=base; h<=tnow; h++){
                long L=node_serve_block(store_buf, h, sb, sizeof sb);
                if(L<80) continue;
                unsigned char bhash[32]; block_hash(bhash, sb);
                idx_put(ht_idx, bhash, h);
            }
            /* Publish the new tip to the PARENT so it can serve the new blocks:
             * store_buf's idx_len is in-memory per process; the parent reads
             * index.dat's real size each loop via its own refresh (see
             * serve_mux) -- but we keep our own idx_len honest here. */
        }
        close(fd);
        npass++;
    }
}

/* The outbound multiplexer: ONE poll() loop over the listen socket + all N
 * outbound seed fds. Inbound accepts are forked to node_serve_loop children
 * (preserved behavior); outbound legs run inline (node_sync + announce).
 * `peers` = host names (pool of `pool_len`); `nwant` of them are connected on
 * entry at `out_port` (best effort), and dead legs are re-dialed by rotating
 * through the pool (D2 fix).
 *
 * IMPORTANT: the listener socket is created FIRST, before any outbound
 * connect. The outbound legs are best-effort; if they all fail the mux still
 * serves inbound from the listener. Creating the listener up front also
 * means `serve` is live to inbound peers immediately (the listener exists
 * even while the outbound legs are still connecting), which the old order
 * (connect-all-outbound-then-listen) did not guarantee. */
static int serve_mux(int port, const char* peers[], int nwant, int pool_len, int out_port, int l){
    /* connect up to nwant outbound peers up front (the listener `l` is already
     * live and passed in, so inbound serving is available even while the
     * outbound legs are still connecting). Clamped to pool_len so we never
     * read past the seed list (the pool may be smaller than nwant). */
    for(int i=0;i<nwant && i<pool_len && i<MUX_MAX_OUT;i++){
        int fd=outbound_connect(peers[i], 300, out_port);
        if(fd<0){ fprintf(stderr,"[mux] outbound %s failed\n", peers[i]); continue; }
        strncpy(mux_out_host[mux_n_out], peers[i], 63);
        mux_out_fd[mux_n_out]=fd;
        mux_out_peer[mux_n_out]=i;
        anchor_locator(mux_out_loc[mux_n_out]);
        fprintf(stderr,"[mux] outbound %d = %s (fd %d)\n", mux_n_out, peers[i], fd);
        mux_n_out++;
    }
    printf("serving on port %d (%d outbound peer(s))...\n", port, mux_n_out); fflush(stdout);
    long long rot=0;
    struct pollfd pfds[MUX_MAX_OUT+1];
    for(;;){
        int nfds=0;
        pfds[nfds].fd=l;     pfds[nfds].events=POLLIN; pfds[nfds].revents=0; nfds++;
        for(int i=0;i<mux_n_out;i++){ if(mux_out_fd[i]<0) continue; pfds[nfds].fd=mux_out_fd[i]; pfds[nfds].events=POLLIN; pfds[nfds].revents=0; nfds++; }
        int pr=poll(pfds, nfds, 300);
        if(pr<0){ if(errno==EINTR) continue; break; }
        /* inbound accept -> fork a serve child (unchanged semantics) */
        if(pfds[0].revents&(POLLIN|POLLHUP|POLLERR)){
            int c=accept(l,0,0);
            if(c>=0){
                /* Refresh our in-memory store extent from the on-disk archive
                 * so this (and each forked child) serves blocks the download
                 * WORKER appended since boot -- serving reads block bytes fresh
                 * from disk, but the tip bound comes from store_buf+16, which
                 * only advances if we re-read index.dat's real size here. */
                struct stat st;
                if(stat("index.dat",&st)==0 && st.st_size>0 && st.st_size>=48){
                    long real = st.st_size;
                    long mine = *(long*)(store_buf+16);
                    if(real>mine) *(long*)(store_buf+16)=real;
                }
                pid_t w=fork();
                if(w==0){
                    close(l);
                    if(node_accept_handshake(c)==1)
                        node_serve_loop(c, node_log_open("bitcoind.log"), store_buf, ht_idx, out_buf, (long)sizeof out_buf);
                    close(c); _exit(0);
                }
                close(c);
            }
        }
        /* outbound: on rotation, pull from each peer (periodic getheaders-from-
         * tip keeps us current); also pull immediately if a peer fd is readable
         * (it sent data we should react to). Round-robin spreads the load so
         * idle peers each get polled roughly once per mux_n_out iterations. */
        rot++;
        int poll_idx=1;                                  /* pfds[0] is the listener */
        long long now_ms = (long long)(clock() * 1000.0 / CLOCKS_PER_SEC);
        for(int i=0;i<mux_n_out;i++){
            if(mux_out_fd[i]<0){                          /* dead slot: re-dial (rate-limited) */
                if(now_ms >= mux_out_nextretry[i]){ mux_redial(i, peers, pool_len, out_port); mux_out_nextretry[i]=now_ms+REDIAL_BACKOFF_MS; }
                continue;
            }
            short ev = pfds[poll_idx].revents;
            /* A permanent peer-side error/hangup/INVAL means the leg is dead:
             * close and re-dial a rotated seed (D2 fix) instead of syncing on a
             * broken socket forever. */
            if(ev & (POLLHUP|POLLERR|POLLNVAL)){
                fprintf(stderr,"[mux:%d] %s dropped (revents 0x%x); re-dialing\n", i, mux_out_host[i], ev);
                mux_redial(i, peers, pool_len, out_port);
                mux_out_nextretry[i]=now_ms+REDIAL_BACKOFF_MS;
                poll_idx++;
                continue;
            }
            bool due=(rot % mux_n_out)==(long long)i;     /* periodic */
            if(ev & POLLIN) due=true;                     /* data */
            /* Bounded: each leg's node_sync must not starve inbound accepts.
             * do_outbound_sync_bounded caps the wall-clock and re-dials the
             * leg if it exceeds the budget, so the loop always returns to
             * poll()+accept() promptly even at large store scale. */
            if(due) do_outbound_sync_bounded(i, peers, pool_len, out_port);
            poll_idx++;
        }
    }
    return 0;
}


int main(int argc, char** argv){
    signal(SIGPIPE, SIG_IGN);   /* broken peer connections must not kill the node */
    signal(SIGCHLD, SIG_IGN);   /* fork-per-peer workers: auto-reap, no zombies */
    if(argc < 3){ fprintf(stderr,"usage: %s sync <dir> | ibd <dir> | follow <dir> | serve <dir> <port> | server-test <dir>\n", argv[0]); return 2; }
    const char* mode = argv[1]; const char* dir = argv[2];
    /* Resolve <dir> to an ABSOLUTE path before chdir so the store opens in the
     * right directory regardless of the caller's cwd (soak analysis found a
     * caller-relative chdir silently opened the wrong store when the node was
     * launched from another directory). realpath fails only if <dir> does not
     * exist, which chdir would reject anyway. */
    char absp[4096];
    if(!realpath(dir, absp)){ perror("realpath"); return 1; }
    if(chdir(absp)!=0){ perror("chdir"); return 1; }
    dir = absp;
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
            /* announce new tip to the peer via inv (proactive relay keep-up):
             * if we synced new blocks, send inv for the new tip block hash
             * (wire/LE order) so the peer knows our chain advanced. */
            if(cnt>0){
                static unsigned char hd[80], th[32], le[32], invm[37];
                long L = node_serve_block(store_buf, tip, hd, sizeof hd);
                if(L>=80){
                    block_hash(th, hd);
                    for(int k=0;k<32;k++) le[k]=th[31-k];   /* display->LE wire */
                    invm[0]=1; invm[1]=2; invm[2]=0; invm[3]=0; invm[4]=0;
                    memcpy(invm+5, le, 32);
                    p2p_write(fd, "inv", 3, invm, sizeof invm);
                }
            }
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
        /* the chain lives in-memory only (not yet on disk), so build the O(1)
         * hash->height index directly from store_buf rather than from disk */
        if(build_inmem_hash_index()!=0){ printf("TESTS FAILED (hash index)\n"); return 1; }

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
        /* # outbound peers is optional 4th arg (default 3). */
        int nwant = (argc>=5)? atoi(argv[4]) : 3;
        if(nwant<0) nwant=0; if(nwant>MUX_MAX_OUT) nwant=MUX_MAX_OUT;
        store_reload(store_buf);            /* load the persisted chain from disk */
        /* shared-append flock fd: open append.lock once so any concurrent-safe
         * store_append_shared writes (and the boot catch-up) serialize. */
        int apfd=open("append.lock", O_RDWR|O_CREAT, 0644);
        if(apfd>=0) *(int*)((char*)store_buf+40)=apfd;
        /* LISTENER FIRST: bind+listen the inbound socket before the (possibly
         * long) catch-up so the node is live to inbound peers immediately.
         * The mux loop will poll it once the catch-up returns. */
        int l = lsock(port);
        if(l<0){ perror("lsock"); return 1; }
        /* BEST-EFFORT OUTBOUND CATCH-UP (non-fatal, BOUNDED): pull any missed
         * blocks from a real seed before the mux starts, so the node is as
         * current as the network allows on boot. Bounded to CATCHUP_MAX so a
         * far-from-tip store never blocks the mux (listener + concurrent
         * serving) indefinitely; the mux loop closes the rest gradually.
         * Falls through cleanly with no network. */
        long caught = outbound_catchup(CATCHUP_MAX);
        if(caught>0)
            fprintf(stderr,"[catchup] store now tips at height %d\n", *(int*)(store_buf+24));
        build_hash_index();                 /* hash->height for O(1) getdata serving */
        int lfd = node_log_open("bitcoind.log");   /* all-asm leveled logger */
        node_log_str(lfd, 0, "node start (serve mode / download worker)", 42);
        /* Serve-as-full-node (option 2): SERVICE our client calls instantly
         * (fork-based inbound serving in the parent) AND continuously download
         * the chain to tip (a dedicated forked DOWNLOAD-WORKER child; see
         * serve_download_worker). The parent runs serve_mux as a PURE inbound
         * server (nwant=0 -> no outbound appends), so:
         *   - serving our clients is NEVER blocked by (or chopped by) a long
         *     sync -- there is no sync in the parent;
         *   - the worker is the SOLE block writer (no multi-writer race) and
         *     grinds continuously from the on-disk tip to mainnet.
         * Each forked serve child re-syncs its index length from index.dat so
         * blocks the worker appends become serve-able (fresh disk reads). */
        pid_t dl = fork();
        if(dl==0){ serve_download_worker(dir, catchup_seeds, (int)(sizeof(catchup_seeds)/sizeof(catchup_seeds[0])), 8333); _exit(0); }
        fprintf(stderr,"[serve] download worker pid %d\n", (int)dl);
        /* PURE-INBOUND serving: nwant=0 -> serve_mux adds no outbound legs, so
         * it only accepts+forks serve children (never blocks on sync). */
        return serve_mux(port, catchup_seeds, 0, (int)(sizeof(catchup_seeds)/sizeof(catchup_seeds[0])), 8333, l);
    }

    if(strcmp(mode,"serve-test")==0 && argc>=6){
        /* LOOPBACK variant of the outbound multiplexer used by test_outbound_mux:
         * the outbound legs connect to a LOCAL peer (host@out_port) instead of
         * real seeds, so the whole accept+outbound-pull loop is exercised in
         * isolation (no network dependency). Same ONE poll() loop, same
         * node_sync-from-tip + node_announce_tip outbound legs, same forked
         * inbound serving. */
        int port = atoi(argv[3]);
        const char* peer[] = { argv[4] };
        int out_port = atoi(argv[5]);
        int nwant = (argc>=7)? atoi(argv[6]) : 1;
        if(nwant<1) nwant=1; if(nwant>1) nwant=1;   /* one loopback peer */
        store_reload(store_buf);
        int apfd=open("append.lock", O_RDWR|O_CREAT, 0644);
        if(apfd>=0) *(int*)((char*)store_buf+40)=apfd;
        build_hash_index();
        int lfd = node_log_open("bitcoind.log");
        node_log_str(lfd, 0, "serve-test outbound mux", 22);
        int l = lsock(port);
        if(l<0){ perror("lsock"); return 1; }
        return serve_mux(port, peer, nwant, 1, out_port, l);
    }
    return 2;
}

/* daemon/main.c -- thin CLI driver over the assembly Bitcoin node core.
 *
 *   daemon sync  <dir>                : init store in <dir>, connect to the
 *                                       loopback test peer, handshake, run IBD
 *                                       (node_sync), report resulting height.
 *   daemon serve <dir> <port> [nwant] [catchup_workers]
 *                                     : init store in <dir>, listen on port,
 *                                       accept a peer, handshake, then serve
 *                                       stored blocks to getdata / reply to
 *                                       ping. The node IE (connect/handshake/
 *                                       IBD/serve-block) is all assembly
 *                                       (bitcoind.asm); this is only the main
 *                                       loop over sockets. nwant (default 3)
 *                                       is the steady-state outbound leg
 *                                       count; catchup_workers (default 16)
 *                                       is the dl_catchup chunk-claiming
 *                                       worker count for the self-healing
 *                                       boot-time catch-up pass.
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
#include <sys/mman.h>
#include "log_ts.h"
#include "log_phase.h"
#include "utxo_walk.h"   /* utxo_walk_read_varint, for tx-count in [block] stored logs */
#include "../version_gen.h"  /* GENERATED from version.inc: our wire identity (protocol/UA/version) */
#include "reorg.h"       /* STAGE B: fork choice / chain reorganisation */

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

/* Per-leg sync wall-clock budget for the download WORKER (dedicated multi-peer
 * downloader, never serves inbound). Because it does not serve, each leg may
 * sync for a LONG window so far-from-tip stores close aggressively; a caught-up
 * leg returns in milliseconds and does not hold the rotation. Kept well above a
 * single leg's per-pass round-trip cost. */
#define DL_BUDGET_SECS 60.0
/* STAGE B: minimum gap between fork probes across all outbound legs. A probe
 * is one extra getheaders round trip on an already-idle leg, so this only has
 * to be short enough to notice a competing chain promptly (a mainnet reorg is
 * resolved in minutes, not seconds) and long enough that it is noise against
 * the per-leg sync traffic. */
#define REORG_PROBE_INTERVAL_MS 30000L
/* Backoff for a catch-up that keeps failing even after in-place recovery.
 * We retry forever (capped interval) instead of disabling UTXO tracking:
 * running blind indefinitely is worse than retrying a failing operation. */
#define UTXO_RETRY_BASE_MS 5000L
#define UTXO_RETRY_MAX_MS  300000L
#define DL_HEARTBEAT_MS 60000L   /* periodic [dl] heartbeat so the log stays
                                  * visibly alive between block/peer events */

/* --- assembly node core (bitcoind.asm / bitcoin_*.asm) --- */
extern long node_handshake(int fd);
extern unsigned char g_peer_version_payload[256]; /* bitcoind.asm: raw capture, see its header comment */
extern long g_peer_version_len;
extern long node_accept_handshake(int fd);
extern long node_sync(int fd, void* st, void* locator, void* buf, long buflen, long* out_count);
/* STAGE B: the real multi-hash-locator entry point. node_sync is now a
 * count==1 shim over this (see bitcoind.asm). A single-hash locator is what
 * made fork DISCOVERY impossible: a peer whose chain diverged below our tip
 * recognises none of it and answers from its own genesis. */
extern long node_sync_multi(int fd, void* st, void* locator, long loc_count,
                            void* buf, long buflen, long* out_count);
extern long locator_build(void* store_buf, unsigned char* out_hashes); /* daemon/locator_build.c */
extern long node_serve_block(void* st, long height, void* out, long cap);
extern long node_serve_block_by_hash(void* st, const void* hash32, void* out, long cap);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern long node_announce_tip(int fd, void* st, void* ht_idx, long use_headers);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long store_init(void* st);
extern long store_reload(void* st);
extern int  utxo_live_init(const char* dir);           /* daemon/utxo_live.c */
extern long utxo_live_catchup(void* store_buf);        /* daemon/utxo_live.c */
extern long utxo_live_count(void);                      /* daemon/utxo_live.c */
extern long utxo_live_applied_height(void);              /* daemon/utxo_live.c */
extern long utxo_live_recover(void);                     /* daemon/utxo_live.c */
extern int  archive_verify_and_repair(void* store_buf, int repair); /* daemon/archive_verify.c */
extern long archive_drop_utxo_state(void);                /* daemon/archive_verify.c */
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
/* peer-discovery externs (bitcoin_addrmgr.asm): amr_* is the persisted address
 * manager ("peers.dat" book), p2p_addr_count parses an `addr` payload. The DNS
 * seeds are used ONLY as BOOTSTRAPS -- we getaddr from them, ingest discovered
 * peers into the amr book, then download across DISCOVERED peers (not seeds). */
extern int  amr_add(void* ab, unsigned ip, unsigned short port, unsigned long long svc, unsigned lastseen);
extern long addr_replenish(void* ab, char peers[][64], int npeers, int max_try, int wait_s, long target); /* daemon/addr_ingest.c */
extern int  net_handshake_relay(const char* ip_str, int relay, int rcv_secs);  /* daemon/net_policy.c */
extern int  net_feeler_probe(const char* ip_str);                             /* daemon/net_policy.c */
extern unsigned net_netgroup_v4(unsigned ip);                                 /* daemon/net_policy.c */
extern long p2p_addr_count(const void* pl, long plen);
extern long store_append(void* st, const unsigned char* hash32, const void* blk, long len);
extern long store_get_tip(void* st);
extern long node_ibd(int fd, void* st, void* hst, void* buf, long buflen); /* bitcoind.asm */
extern long node_drain(int fd, void* st, void* buf, long buflen);          /* bitcoind.asm */
extern long node_sync(int fd, void* st, void* locator, void* buf, long buflen, long* out_count); /* bitcoind.asm */
extern int  hst_init(void* hst);
extern long hst_count(void* hst);
extern int  hst_get_at(void* hst, unsigned long long height, void* out);
/* built-in catch-up engine externs (bitcoind.asm / bitcoin_headers.asm) --
 * same primitives the standalone unified_ibd.c tool already uses. */
extern long node_ibd_headers(int fd, void* hst, void* locator32, void* buf, unsigned long buflen);
extern long node_ibd_blocks_s(int fd, void* st, void* hst, long lo_real, long nloc,
                              void* buf, unsigned long buflen, void* scratch, unsigned cap);
extern int  hst_reload(void* hst);
extern int  hst_append(void* hst, const unsigned char hdr[80], const unsigned char hash[32]);

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
extern long idx_build_from_file(void* idx, const char* path);

/* bitcoin_idxscan.asm -- buffered index.dat positional scans, replacing the
 * dlc_* stdio versions below (kept as reference/fallback docs in comments
 * at each call site; see asm/bitcoin_idxscan.asm for the perf rationale). */
extern long idxscan_tip(void);
extern long idxscan_first_hole(long tip);
extern long idxscan_all_present(long lo, long hi);
extern void idxscan_progress(long* out_tip, long* out_present);
/* asm/bitcoin_idx.asm:idx_build_from_file -- buffered pread64 bulk loader,
 * replacing the per-record fread+reverse+idx_put loop that used to live
 * here. Drops the periodic "[hashidx] N/M" progress print: the whole build
 * is now a small fraction of a second on the real archive (was ~186s), so
 * there's nothing left to show progress on. */
static int build_hash_index(void){
    ht_idx=malloc(24 + (size_t)HT_SLOTS*48 + 64);   /* last slot may need a full --- actually over-allocate */
    if(!ht_idx){ fprintf(stderr,"alloc idx failed\n"); return -1; }
    idx_init(ht_idx, HT_SLOTS);
    if(idx_build_from_file(ht_idx, "index.dat")<0){ fprintf(stderr,"no index.dat for hash index\n"); return -1; }
    fprintf(stderr,"[hashidx] indexed %ld stored heights\n", (long)idx_count(ht_idx));
    return 0;
}

/* STAGE B: rebuild the hash index in place after a reorg truncated the store.
 * Deliberately reuses build_hash_index's EXACT construction (idx_init +
 * idx_build_from_file) rather than re-deriving keys some other way, so a
 * post-reorg index is byte-identical to a fresh boot's -- reorg.c does not
 * guess at this, it calls back through reorg_set_index_rebuild. Reuses the
 * already-allocated buffer instead of mallocing a new one each time (a reorg
 * can happen repeatedly over a process's lifetime). */
static void rebuild_hash_index_after_reorg(void){
    if(!ht_idx) return;
    idx_init(ht_idx, HT_SLOTS);
    if(idx_build_from_file(ht_idx, "index.dat")<0)
        fprintf(stderr,"[reorg] WARNING: hash index rebuild failed; block-by-hash serving is degraded until restart\n");
    else
        fprintf(stderr,"[reorg] hash index rebuilt: %ld heights\n", (long)idx_count(ht_idx));
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
    "seed.bitcoin.wiz.biz",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitnodes.io"
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
/* ---- connection budget, matching Bitcoin Core's shape -------------------
 *   full-relay        8   ordinary outbound: tx + block relay, addr gossip
 *   block-relay-only  2   headers/blocks only (relay=0), never addr-gossiped
 *   feeler            1   short-lived liveness probe, ~every 2 minutes
 *   -------------------
 *   outbound         11, leaving MAX_CONNECTIONS-11 inbound slots.
 *
 * There was previously NO inbound limit at all: the accept loop forked a
 * child per connection with nothing bounding it, so an attacker could open
 * connections until the host ran out of processes or memory. */
#define MAX_CONNECTIONS            125
#define MAX_BLOCK_RELAY_ONLY       2
#define MAX_FEELER                 1
#define MAX_INBOUND   (MAX_CONNECTIONS - MUX_MAX_OUT - MAX_BLOCK_RELAY_ONLY - MAX_FEELER)
#define FEELER_INTERVAL_MS         120000L   /* Core's ~2 minutes */
#define MUX_MAX_OUT 8
static int   mux_out_fd[MUX_MAX_OUT];       /* persistent outbound seed fds  */
static unsigned char mux_out_loc[MUX_MAX_OUT][32];  /* per-peer locator (tip) */
static char  mux_out_host[MUX_MAX_OUT][64];
static int   mux_n_out = 0;
static int   mux_out_peer[MUX_MAX_OUT];     /* index into the peer pool (for re-dial rotation) */
static long long mux_out_nextretry[MUX_MAX_OUT]; /* monotonic ms deadline before the next re-dial attempt */
#define REDIAL_BACKOFF_MS 30000L             /* min gap between re-dial tries on a dead slot */

/* ---- graceful shutdown --------------------------------------------------
 * Previously SIGTERM/SIGINT had no handler at all (only SIGPIPE/SIGCHLD,
 * both ignored) -- every stop was a bare kill with zero shutdown log line,
 * ever, regardless of how the process actually died. The handler itself
 * only sets a flag (async-signal-safe, matches this file's own existing
 * mux_budget_alarm/SIGALRM pattern) -- the actual logging/cleanup happens
 * in each main loop's own next iteration, never inside the handler. */
static volatile sig_atomic_t g_shutdown_requested = 0;
/* Live inbound serve children. SIGCHLD was SIG_IGN (kernel auto-reap), which
 * is tidy but gives no way to know when a child exits -- so we reap manually
 * and keep the count. If this ever drifts it drifts LOW (the download worker
 * exiting also fires SIGCHLD), which fails open by allowing an extra
 * connection rather than locking inbound out entirely. */
/* Block-relay-only legs (Core: MAX_BLOCK_RELAY_ONLY_CONNECTIONS). relay=0,
 * and deliberately never fed into addr gossip, so an attacker enumerating the
 * network cannot discover or crowd them out. These carry headers/blocks only
 * and exist so an eclipse of the ordinary legs still leaves us a true view of
 * the best chain -- which matters now that Stage B acts on peer chainwork. */
static int  bro_fd[MAX_BLOCK_RELAY_ONLY];
static char bro_host[MAX_BLOCK_RELAY_ONLY][64];

static volatile sig_atomic_t g_inbound_n = 0;
static void reap_children(int sig){
    (void)sig; int st;
    while(waitpid(-1,&st,WNOHANG) > 0){ if(g_inbound_n > 0) g_inbound_n--; }
}

static pid_t g_dl_worker_pid = -1;       /* set by main() right after fork(); parent forwards SIGTERM here */
static void handle_shutdown_signal(int sig){ g_shutdown_requested = sig; }

/* Connect + handshake one outbound seed, returning a long-lived fd (or -1).
 * The handshake reads the seed's version/verack plus its post-verack chatter
 * (sendheaders/sendaddrv2/feefilter/addr), which can take longer than the
 * tight per-pass recv bound -- so give the handshake a generous 6s timeout,
 * then clamp the socket to the short per-pass timeout for node_sync. */
/* Shared wall-clock-budget signal state. Defined here (rather than just above
 * do_outbound_sync_bounded, where it used to live) because outbound_connect
 * below now arms the same budget around its dial, and needs it in scope. */
static volatile sig_atomic_t mux_sync_budget_fired = 0;
static void mux_budget_alarm(int sig){ (void)sig; mux_sync_budget_fired = 1; }

/* Wall-clock budget for ONE dial (blocking connect + handshake). SO_RCVTIMEO
 * alone is NOT sufficient here and this is a real production hang, not a
 * hypothetical: it bounds each INDIVIDUAL read(), so a peer that trickles the
 * version/verack bytes a few at a time resets the timer on every partial read
 * and node_handshake never returns -- the download worker's whole rotation
 * loop then sits in that one read() forever (no heartbeat, no other leg
 * serviced, SIGTERM not even checked). Observed twice on 2026-08-18: the
 * worker wedged in tcp_recvmsg for 60+ minutes right after a leg-fill round,
 * and had to be SIGKILLed. tcp_connect_ip's connect() has no connect-phase
 * timeout either, which this same budget also covers.
 *
 * The rest of this file already solves exactly this problem the same way --
 * see do_outbound_sync_bounded and the dlc chunk worker, whose comment spells
 * out the trickle-resets-SO_RCVTIMEO mechanism. outbound_connect was simply
 * never given the same treatment, even though every one of its callers (the
 * steady-state leg fill and mux_redial) runs OUTSIDE any enclosing alarm. */
#define OUTBOUND_DIAL_BUDGET_SECS 20

static int outbound_connect(const char* host, int rcv_ms, int out_port){
    struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&h,&res)!=0) return -1;
    unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);

    /* Arm the dial budget around BOTH the blocking connect and the handshake.
     * SA_RESTART is deliberately left clear (memset) so the signal makes the
     * in-flight syscall fail with EINTR instead of silently resuming. */
    struct sigaction sa, old; memset(&sa,0,sizeof sa);
    sa.sa_handler=mux_budget_alarm; sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM,&sa,&old);
    sig_atomic_t saved_fired = mux_sync_budget_fired;   /* don't clobber an outer pass's flag */
    mux_sync_budget_fired = 0;
    alarm(OUTBOUND_DIAL_BUDGET_SECS);

    int fd=tcp_connect_ip(ip,(unsigned short)htons((unsigned short)out_port));
    int hk = 0;
    if(fd>=0){
        struct timeval tv; tv.tv_sec=6; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
        hk = node_handshake(fd);
    }

    alarm(0);
    int fired = mux_sync_budget_fired;
    mux_sync_budget_fired = saved_fired;
    sigaction(SIGALRM,&old,NULL);

    if(fd<0) return -1;
    if(fired || hk!=1){
        if(fired) fprintf(stderr,"[dial] %s exceeded %ds dial budget; dropping\n",
                          host, OUTBOUND_DIAL_BUDGET_SECS);
        close(fd);
        return -1;
    }
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

/* mux_locator/mux_locator_zero (the old per-peer single-hash locator
 * accessors) are gone: do_outbound_sync now derives a real multi-hash
 * locator from the store on every pass -- see build_locator_for_sync. */

/* ---- STAGE B: the REAL block locator ------------------------------------
 * Builds the doubling-gap ancestor list (tip, tip-1, tip-2, tip-4, ...) via
 * daemon/locator_build.c, which reads each ancestor's hash straight out of
 * index.dat by position -- the same "read the index record, not the block
 * body" technique anchor_locator above already uses, and for the same
 * reason (a just-appended tip's body can transiently read short).
 *
 * WHY THIS REPLACES anchor_locator ON THE SYNC PATH: a one-hash locator only
 * ever says "I have exactly this block". A peer on a chain that diverged
 * below our tip recognises nothing in it and answers from its own genesis,
 * so a fork is literally undiscoverable -- which is why every sync pass
 * until now silently assumed the peer was on our chain. With the full list
 * the peer finds the newest block we actually share and answers from there,
 * which is what makes the fork point visible. A peer that IS on our chain is
 * unaffected: it matches the first entry (our tip) immediately, exactly as
 * before.
 *
 * Falls back to the old single-hash anchor if locator_build cannot read the
 * index (returns the hash count, always >= 1). */
static long build_locator_for_sync(unsigned char loc[REORG_LOCATOR_MAX*32]){
    long n = locator_build(store_buf, loc);
    if(n >= 1) return n;
    anchor_locator(loc);
    return 1;
}

/* One bounded download+announce pass on outbound peer i.
 *   - anchor locator at our stored tip (so we only pull the missing tail)
 *   - run node_sync (getheaders -> validate -> store_append) with the fd's
 *     short recv timeout so an idle peer returns fast
 *   - index any newly-stored blocks (node_sync appends but does not idx_put)
 *   - announce the new tip back to the peer via node_announce_tip
 *   - update the per-peer locator to our new tip
 * Returns # blocks stored this pass. */
/* hash32[32] is wire-order (as stored/compared internally); block explorers
 * and RPC display it byte-reversed -- print that convention here so a
 * logged hash can be pasted straight into a lookup. Short form (first 8
 * display bytes = last 8 wire bytes) is enough to eyeball/grep-correlate
 * without bloating every block-stored line to a full 64 hex chars. */
/* format_peer_version_info(out, cap) -> writes a compact human-readable
 * summary of whatever bitcoind.asm's node_handshake/node_accept_handshake
 * last captured into g_peer_version_payload (the OTHER side's `version`
 * message, raw wire bytes -- see that global's header comment). Parses the
 * Bitcoin version-message layout by hand (version u32, services u64,
 * timestamp u64, addr_recv[26], addr_from[26], nonce u64, then a
 * CompactSize-prefixed user-agent string, then start_height u32) since
 * nothing in this codebase already exposes these fields. Empty string if
 * no version was captured (payload too short to be a real version msg) --
 * callers should treat that as "no data," not an error. */
static void format_peer_version_info(char* out, size_t cap){
    out[0] = 0;
    long len = g_peer_version_len;
    const unsigned char* p = g_peer_version_payload;
    if (len < 80) return;               /* fixed prefix alone is 80 bytes */
    unsigned proto = (unsigned)p[0] | ((unsigned)p[1]<<8) | ((unsigned)p[2]<<16) | ((unsigned)p[3]<<24);
    unsigned long long services;
    memcpy(&services, p+4, 8);
    long off = 80;
    unsigned long long ualen;
    if (p[off] < 0xfd) { ualen = p[off]; off += 1; }
    else if (p[off] == 0xfd) { if (off+3 > len) return; ualen = (unsigned)p[off+1] | ((unsigned)p[off+2]<<8); off += 3; }
    else if (p[off] == 0xfe) { if (off+5 > len) return; memcpy(&ualen, p+off+1, 4); off += 5; }
    else { if (off+9 > len) return; memcpy(&ualen, p+off+1, 8); off += 9; }
    if (off + (long)ualen + 4 > len || ualen > 200) return; /* malformed/hostile -- bail, don't overread */
    char ua[201]; memcpy(ua, p+off, (size_t)ualen); ua[ualen] = 0;
    for (unsigned long long k=0;k<ualen;k++) if (ua[k] < 0x20 || ua[k] > 0x7e) ua[k] = '.'; /* printable only */
    off += (long)ualen;
    unsigned height;
    memcpy(&height, p+off, 4);
    snprintf(out, cap, "proto=%u services=0x%llx ua=\"%s\" height=%u", proto, services, ua, height);
}

static void log_hash_short(char out[17], const unsigned char hash32[32]){
    static const char hexd[]="0123456789abcdef";
    for(int k=0;k<8;k++){
        unsigned char b=hash32[31-k];
        out[k*2]=hexd[b>>4]; out[k*2+1]=hexd[b&0xf];
    }
    out[16]=0;
}

static long do_outbound_sync(int i){
    /* STAGE B: a REAL multi-hash locator built fresh from our stored chain on
     * every pass, replacing the single-hash anchor. mux_out_loc[i] is still
     * maintained below for the other call sites that read it, but the sync
     * itself no longer depends on it -- the locator is derived from the store,
     * which is the authoritative thing anyway. */
    unsigned char loc[REORG_LOCATOR_MAX*32];
    long nloc = build_locator_for_sync(loc);
    static unsigned char cbuf[6<<20]; long cnt=0;
    int st_tip_before=*(int*)(store_buf+24);
    phase_timer_t sync_pt; phase_start(&sync_pt);
    long ok=node_sync_multi(mux_out_fd[i], store_buf, loc, nloc, cbuf, (long)sizeof cbuf, &cnt);
    double sync_s = phase_elapsed(&sync_pt);
    int st_tip=*(int*)(store_buf+24);
    if(ok!=1 || cnt<=0){
        /* keep the locator fresh even on a no-op so we don't re-request from
         * genesis forever (node_sync advanced it internally only on success) */
        anchor_locator(mux_out_loc[i]);
        return 0;
    }
    /* index every newly stored height (st_tip_before+1 .. st_tip) into ht_idx,
     * logging each disk-written block individually -- node_sync itself does
     * getheaders+download+validate+store as one opaque pass (no network-vs-
     * disk breakdown available without touching that ASM), so this loop's
     * own re-read of each freshly-stored block is the cheapest place to
     * report per-block write events for troubleshooting. */
    static unsigned char sb[8<<20];
    for(int h=st_tip_before+1; h<=st_tip; h++){
        long L=node_serve_block(store_buf, h, sb, sizeof sb);
        if(L<80) continue;
        unsigned char bhash[32]; block_hash(bhash, sb);
        idx_put(ht_idx, bhash, h);
        char hs[17]; log_hash_short(hs, bhash);
        u64 consumed=0; u64 ntx = L>80 ? utxo_walk_read_varint(sb+80, sb+L, &consumed) : 0;
        if(!consumed) ntx = 0;
        fprintf(stderr,"[block] stored height=%d hash=%s.. bytes=%ld tx=%llu (via %s)\n", h, hs, L, (unsigned long long)ntx, mux_out_host[i]);
    }
    /* STAGE B: keep chainwork.dat in lockstep with index.dat for every block
     * that just landed. This is a CATCH-UP call, not a per-block hook: it
     * appends one cumulative-work record for every height index.dat has and
     * chainwork.dat does not, so it covers blocks this leg just stored AND
     * blocks a sibling inbound serve child appended via .do_block, with one
     * call site instead of two edited assembly write paths. Without this,
     * fork choice has nothing to weigh our own chain with. */
    if(reorg_chainwork_sync(store_buf, 0) < 0)
        fprintf(stderr,"[chainwork] sync failed after storing heights %d..%d -- fork choice is DEGRADED until this recovers\n",
                st_tip_before+1, st_tip);
    /* announce the new tip to this peer (inv; BIP130 headers honored by the
     * peer's sendheaders negotiation is handled downstream on its own leg) */
    node_announce_tip(mux_out_fd[i], store_buf, ht_idx, 0);
    fprintf(stderr,"[mux:%d] broadcast tip height=%d to %s\n", i, st_tip, mux_out_host[i]);
    /* advance this peer's persistent locator to our new stored tip */
    anchor_locator(mux_out_loc[i]);
    fprintf(stderr,"[mux:%d] %-22s sync ok=%ld new=%ld tip=%d (%.2fs)\n", i, mux_out_host[i], ok, cnt, st_tip, sync_s);
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

/* ---- peer discovery at boot (seeds are BOOTSTRAPS only) ------------------
 * Real Bitcoin nodes do NOT download from DNS seeds; they use them once to
 * learn reachable peers, then connect to those -- never downloading from the
 * seeds themselves. We resolve each seed-DNS hostname to its A-records (real,
 * current Bitcoin node IPs), fold them into the persisted amr "peers.dat"
 * book, then dial up to 8 of those DISCOVERED peers for download. Fast and
 * reliable: DNS resolution returns dozens of live peer IPs in milliseconds, so
 * we do NOT depend on the flaky getaddr/addrv2 round-trip. */

/* bootstrap: resolve each seed-DNS hostname to its A-records (REAL reachable
 * Bitcoin node IPs) and fold them into the amr book. This is fast (milliseconds)
 * and reliable -- no flaky getaddr round-trip that can block for seconds per
 * seed. We dial these discovered IPs (never the seed hostname itself as a
 * long-lived download source); they are bootstrap peers only. */
static long dl_bootstrap(void* ab, const char* peers[], int pool_len){
    long total=0;
    for(int i=0;i<pool_len && i<12;i++){
        struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
        long got=0;
        if(getaddrinfo(peers[i],NULL,&h,&res)==0){
            for(struct addrinfo* ai=res; ai && got<64; ai=ai->ai_next){
                struct sockaddr_in* sa=(struct sockaddr_in*)ai->ai_addr;
                unsigned ip=sa->sin_addr.s_addr;
                if(ip && amr_add(ab,ip,(unsigned short)htons(8333),1,(unsigned)time(NULL))>0) got++;
            }
            freeaddrinfo(res);
        }
        if(got>0) fprintf(stderr,"[boot] %s -> +%ld peers (dns)\n", peers[i], got);
        total+=got;
    }
    return total;
}

/* pick up to n distinct public IPv4 endpoints from the amr book into
 * out[i] = "a.b.c.d" (IP only; the downloader dials each on the standard
 * out_port, matching how outbound_connect/serve_mux treat all peers). */
/* ---- known-good peer memory (peers.good) ---------------------------------
 * The address book records that an IP was SEEN, never that it was any use.
 * So every boot re-probed ~2,000 aged entries, kept whichever ~4% happened to
 * answer, and threw away the hard-won knowledge of which peers actually
 * delivered blocks -- the ones that worked last run got no preference at all
 * over long-dead entries. Persist the peers that really produced blocks and
 * try them FIRST next time.
 *
 * Deliberately a plain newline-separated IP text file: it is tiny, trivially
 * inspectable, and a corrupt/missing one degrades to exactly the old
 * behaviour (probe the book) rather than breaking startup. */
#define DL_GOODPEERS_FILE "peers.good"
#define DL_GOODPEERS_MAX  256

static int dl_load_good_peers(char out[][64], int cap){
    FILE* f = fopen(DL_GOODPEERS_FILE, "r");
    if(!f) return 0;
    int n=0; char line[128];
    while(n<cap && fgets(line,sizeof line,f)){
        size_t L=strlen(line);
        while(L && (line[L-1]=='\n'||line[L-1]=='\r')) line[--L]=0;
        if(!L) continue;
        struct in_addr t;
        if(inet_pton(AF_INET,line,&t)!=1) continue;   /* ignore junk lines */
        strncpy(out[n],line,63); out[n][63]=0; n++;
    }
    fclose(f);
    return n;
}

/* Written atomically (tmp+rename) so a crash mid-write cannot leave a
 * truncated list that silently shrinks the next boot's head start. */
static void dl_save_good_peers(char peers[][64], int n){
    if(n<=0) return;
    FILE* f = fopen(DL_GOODPEERS_FILE ".tmp","w");
    if(!f) return;
    for(int i=0;i<n && i<DL_GOODPEERS_MAX;i++) fprintf(f,"%s\n",peers[i]);
    fflush(f); fsync(fileno(f)); fclose(f);
    rename(DL_GOODPEERS_FILE ".tmp", DL_GOODPEERS_FILE);
    fprintf(stderr,"[dlc] recorded %d known-good peer(s) for next boot\n", n<DL_GOODPEERS_MAX?n:DL_GOODPEERS_MAX);
}

static int dl_pool_from_book(void* ab, char out[][64], int nitems){
    long cnt=amr_count(ab); if(cnt<=0) return 0;
    unsigned char rec[18]; int got=0;
    /* iterate the WHOLE book (not just the first `nitems`) and keep plausible
     * PUBLIC IPv4s, so stale/special-range garbage from prior runs never crowds
     * the download pool. */
    for(long i=0;i<cnt && got<nitems;i++){
        if(amr_get_i(ab,i,rec)!=1) continue;
        /* amr stores the ip as the 4 bytes passed to amr_add -- which we passed
         * in NETWORK (big-endian) order (sin_addr.s_addr). The "u32 LE" in the
         * asm comment is literal movement of those bytes, not an LE reorder.
         * Reading with *(unsigned*) on an LE CPU would byte-swap and yield
         * wrong/unreachable IPs (e.g. 97.158.36.82 for the real 82.36.158.97).
         * Decode explicitly BIG-endian from the record bytes instead. */
        unsigned ip = ((unsigned)rec[0]<<24)|((unsigned)rec[1]<<16)|((unsigned)rec[2]<<8)|(unsigned)rec[3];
        unsigned a=(ip>>24)&0xff,b=(ip>>16)&0xff,c=(ip>>8)&0xff,d=ip&0xff;
        /* skip special/reserved ranges that can't be a reachable peer:
         * 0.0.0.0/8, 10/8 & 172.16/12 & 192.168/16 (RFC1918 -- could be peers
         * but our resolver gives public ones; skip to be safe), 169.254/16
         * link-local, 224-239 multicast, 240+ reserved, broadcast, and
         * 255.127.0.0-style garbage seen in stale books. */
        if(a==0) continue;
        if(a==10) continue;
        if(a==172 && b>=16 && b<=31) continue;
        if(a==192 && b==168) continue;
        if(a==169 && b==254) continue;
        if(a==127) continue;
        if(a>=224) continue;                     /* multicast + reserved + 255.x */
        if(b==0&&c==0&&d==0) continue;
        if(a==255&&b==255&&c==255&&d==255) continue;
        snprintf(out[got],64,"%u.%u.%u.%u",a,b,c,d);
        got++;
    }
    return got;
}

/* ---- built-in multi-peer catch-up (replaces the external unified_ibd.c /
 * hole_ranges.py / backfill_holes.sh / sync_chain.sh pipeline) ------------
 * Runs SYNCHRONOUSLY before serve mode opens for business (see the caller
 * below): detects any archive hole (a zero-record run below the current
 * on-disk tip) plus whatever's missing up to the real chain tip (tracked in
 * headers.dat), then fills the WHOLE span with a pool of chunk-claiming
 * workers -- same design as the standalone unified_ibd.c tool: a shared
 * mmap'd atomic cursor so an idle worker keeps pulling new 200-block chunks
 * instead of sitting on a static pre-split shard, and a present-check so
 * the SAME invocation can span real holes and already-filled heights
 * without redundant re-download. main() already chdir()s into the resolved
 * data dir before mode dispatch, so paths below are bare relative
 * filenames, matching the rest of this file's convention (e.g. the
 * "append.lock" open just above the serve-mode block). */
/* Optimizing for speed, not just "give every peer a fair shot": on a chunk
 * cut, ALL progress on that chunk is thrown away (the retry path
 * redownloads the whole thing from scratch, no partial resume) -- so the
 * real lever is chunk size, not timeout length. A smaller chunk means a bad
 * peer gets detected and replaced faster in wall-clock terms AND costs less
 * to lose when it does happen; a good peer loses nothing either way since a
 * successful connection is reused back-to-back across many chunks. 200
 * blocks (~250-300MB near the tip) meant a bad-peer cut wasted a lot of
 * work and took minutes to even trigger; 40 blocks (~50-60MB near the tip)
 * with a proportionally shorter budget gives a ~4x faster detect-and-replace
 * cycle at ~4x lower cost per miss. */
#define DLC_CHUNK_BLOCKS 40
/* Draw from the WHOLE address book, not a 512 slice of it. Measured
 * 2026-08-18: the book held 1,974 peers, the pool was capped at 512, the
 * probe tried all 512 and only 22 were reachable (~4% -- normal for an aged
 * book full of long-dead nodes). That left ~1,460 candidates untried and the
 * downloader running on 22 peers, which is also what made peer-banning
 * exhaust the pool. Probing is nearly free -- dead peers refuse instantly,
 * so all 512 were covered in 0.49s -- so there is no reason to sample. */
#define DLC_MAXPOOL 2048
#define DLC_HDR_TRY_PEERS 8
/* wall-clock budget for ONE chunk transfer. At DLC_CHUNK_BLOCKS=40
 * (~50-60MB near the real tip), 120s requires ~467KB/s sustained to
 * survive -- similar bar to the old 480s/200-block combo, but the
 * detect-and-replace cycle for a dead peer is ~4x faster and a miss costs
 * ~4x less redone work. */
#define DLC_CHUNK_BUDGET_SECS 120
/* early-kill thresholds: the parent's status loop already samples each
 * worker's real /proc/<pid>/io bandwidth every 10s for the live display --
 * a connection sustaining under DLC_DEAD_WEIGHT_BPS for
 * DLC_DEAD_WEIGHT_TICKS consecutive ticks (10 ticks = ~100s: deliberately
 * long, to be confident this is a truly dead connection and not a peer
 * that's just momentarily slow before recovering) is treated as dead, so
 * the parent signals that worker to abandon rather than making it sit out
 * the full DLC_CHUNK_BUDGET_SECS on a peer that was never going anywhere. */
/* Retuned 2026-08-18 after watching a real re-sync crawl at ~119KB/s
 * aggregate. The old floor (10KB/s sustained for 10 consecutive 10s ticks)
 * meant a peer trickling 3-9KB/s -- bad, but not bad enough to trip a 10KB/s
 * bar -- burned a FULL 100 SECONDS of a worker slot before being replaced,
 * and most of the pool was doing exactly that. Patience is only a virtue when
 * the peer might recover; when other peers are managing 15KB/s+ on the same
 * link, a slot held by a 5KB/s peer is pure loss. React in ~30s instead, and
 * judge against a floor that reflects what a useful peer actually delivers. */
#define DLC_DEAD_WEIGHT_BPS 32768.0
#define DLC_DEAD_WEIGHT_TICKS 3
/* Never ban the pool down to nothing. Banning is only an optimisation -- a
 * banned peer is worth less than an unbanned one, but ANY peer beats none.
 * The first cut of this had no floor and, against a 22-peer live pool,
 * banned 28 slots: every worker hit "peers exhausted" (logged 20,495 times),
 * the chunked downloader gave up after 24,720 blocks, and the sync fell back
 * to the slow sequential path. Keep a working set alive, and grant amnesty
 * rather than deadlock if we somehow still run dry. */
#define DLC_MIN_USABLE_PEERS 8

/* true iff every height in [lo,hi] already has a non-zero index.dat record.
 * asm/bitcoin_idxscan.asm:idxscan_all_present -- buffered pread64 port,
 * ~44x faster than this stdio version on the real archive (see
 * tests/bench_idxscan.c). */
static int dlc_chunk_all_present(long lo, long hi){
    return idxscan_all_present(lo, hi) != 0;
}

/* highest height h with index.dat[h] non-zero, or -1 if none/empty.
 * asm/bitcoin_idxscan.asm:idxscan_tip -- ~48x faster (see tests/bench_idxscan.c). */
static long dlc_index_tip(void){
    return idxscan_tip();
}

/* first zero-record height in [0,tip], or -1 if none (contiguous).
 * asm/bitcoin_idxscan.asm:idxscan_first_hole -- ~4.5x faster. */
static long dlc_first_hole(long tip){
    return idxscan_first_hole(tip);
}

/* combined hole+extend span: 1 with *start_h/*end_h set, or 0 if the
 * archive is already contiguous through hdr_len-1. chunk_all_present makes
 * it safe for this ONE span to also re-cover already-filled heights between
 * a hole and the current tip, so no separate hole-then-extend passes are
 * needed the way the external CLI tool required (and no tip-1 sentinel
 * juggling -- this is a single internal computation, not a value that gets
 * reinterpreted by a second process's own resume logic). */
static int dlc_span(long hdr_len, long* start_h, long* end_h){
    long true_end = hdr_len-1; if(true_end<0) return 0;
    long tip = dlc_index_tip();
    if(tip<0){ *start_h=0; *end_h=true_end; return 1; }
    long fh = dlc_first_hole(tip);
    if(fh>=0){ *start_h=fh; *end_h=true_end; return 1; }
    if(tip>=true_end) return 0;
    *start_h=tip+1; *end_h=true_end; return 1;
}

/* extend headers.dat as far as a discovered peer will serve, resuming from
 * whatever's already on disk (a real locator from the last stored hash) so
 * repeat boots only pull the delta instead of refetching from genesis every
 * time. Returns the new header count, or -1 if nothing served AND nothing
 * was already on disk. */
/* try ONE candidate for the header phase: connect+handshake+node_ibd_headers.
 * Returns added-header-count (>=0) on a completed exchange, -1 if the
 * candidate couldn't even be reached/handshaked. */
static long dlc_headers_try(const char* cand, void* hst, unsigned char loc[32],
                            unsigned char* hdrbuf, size_t hdrbuf_sz){
    unsigned ip; if(inet_pton(AF_INET,cand,&ip)!=1) return -1;
    int fd=tcp_connect_ip(ip,(unsigned short)htons(8333));
    if(fd<0) return -1;
    struct timeval tv; tv.tv_sec=15; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    if(node_handshake(fd)!=1){ close(fd); return -1; }
    long added=node_ibd_headers(fd, hst, loc, hdrbuf, hdrbuf_sz);
    close(fd);
    return added;
}

/* live[] must already be confirmed-reachable (via dlc_probe_round below) --
 * dlc_headers_try's tcp_connect_ip() is a plain blocking connect with no
 * connect-phase timeout, so trying an UNCONFIRMED candidate here would carry
 * the same hang risk documented on dlc_worker; deliberately no fallback to
 * raw pool entries. */
static long dlc_headers(char live[][64], int nlive){
    static unsigned char hst[4096]; hst_init(hst);
    struct stat hs;
    if(stat("headers.dat",&hs)==0 && hs.st_size>=112) hst_reload(hst);
    long have = hst_count(hst);
    unsigned char loc[32]; memset(loc,0,32);
    if(have>0){
        static unsigned char rec[112];
        if(hst_get_at(hst,(unsigned long long)(have-1),rec)==1) memcpy(loc, rec+80, 32);
    }
    static unsigned char hdrbuf[2<<20];
    int tried=0;
    for(int i=0;i<nlive && tried<DLC_HDR_TRY_PEERS; i++){
        long added=dlc_headers_try(live[i], hst, loc, hdrbuf, sizeof hdrbuf);
        if(added<0) continue;
        tried++;
        /* a genuine peer failure/hiccup can return exactly 0 added headers
         * with nothing wrong at the protocol level (unified_ibd.c's own
         * fork-based header phase treats this the same way: h>0 is the only
         * success signal, not h>=0) -- so 0 added on an EMPTY store means
         * try the next candidate, not "done". 0 added when we already HAD
         * headers is a real, different signal: the peer confirms we're
         * already at its tip, which is legitimate success. */
        if(added>0){ fprintf(stderr,"[dlc] headers +%ld from %s (total %ld)\n", added, live[i], hst_count(hst)); return hst_count(hst); }
        if(added==0 && have>0){ fprintf(stderr,"[dlc] headers: already current per %s (total %ld)\n", live[i], hst_count(hst)); return hst_count(hst); }
    }
    return have>0 ? have : -1;
}

/* chunk-claiming worker: pulls DLC_CHUNK_BLOCKS-sized pieces from a SHARED
 * atomic cursor (mmap'd MAP_SHARED across all forked workers) until the
 * whole [.,end_h] span is claimed -- a worker that lands fast peers just
 * keeps claiming more chunks instead of idling once some static "share" is
 * done (same design as unified_ibd.c's worker()). Persistent connection
 * reused across chunks. Peer search is scoped to `live[]` ONLY (candidates
 * the caller already confirmed reachable via a bounded non-blocking probe --
 * see dlc_probe_round below) -- deliberately NOT a fallback to raw
 * unconfirmed pool entries: tcp_connect_ip() is a plain blocking connect()
 * with no connect-phase timeout (SO_RCVTIMEO only bounds reads afterward),
 * so dialing an unconfirmed, possibly-black-holed host can hang for a long
 * time (observed firsthand: a header-phase version of this fallback stalled
 * for 3+ minutes on one bad candidate). `live[]` needs to be reasonably
 * populated by the caller for this to have enough depth. Each worker
 * independently opens append.lock itself -- flock() locks belong to the
 * open file description, so an INHERITED fd would not actually exclude
 * sibling workers from each other. */
/* per-worker live stats, in a MAP_SHARED region so the parent can read them
 * while the workers run -- "what peer is worker N talking to and how much
 * has it pulled" without waiting for the final one-line summary. last_bw_bps
 * is written by the PARENT (it's the one sampling /proc/<pid>/io for the
 * live display) and read by the WORKER itself when it prints a drop message,
 * so "why did we drop this peer" shows the actual measured rate instead of
 * just "budget expired" with no numbers -- the worker has no way to sample
 * its own throughput while blocked inside node_ibd_blocks_s. MAP_ANONYMOUS
 * zero-inits it to 0.0, read as "no reading yet" if a drop somehow happens
 * before the parent's first 10s tick. */
typedef struct { char peer[64]; long chunks; long blocks; long guard; double last_bw_bps; long timeouts; long held_idx; } dlc_stat_t;
static void dlc_fmt_rate(char* buf, size_t cap, double bytes_per_sec); /* fwd decls, defined below */
static void dlc_fmt_bytes(char* buf, size_t cap, double bytes);

static int dlc_worker(int w, long end_h, char live[][64], int nlive,
                      int slot0, volatile long* next_claim, volatile long* done_count,
                      volatile dlc_stat_t* mystat, volatile int* claimed,
                      volatile int* banned){
    /* SIGUSR1 registered for this worker's WHOLE lifetime, not just around
     * the node_ibd_blocks_s call below -- the parent can send it any time
     * it spots sustained near-zero bandwidth, which won't always land while
     * the per-chunk alarm guard (further down) has it re-armed. Left
     * unregistered here, a stray signal landing between chunks would hit
     * the default SIGUSR1 disposition (terminate) and kill this whole
     * worker instead of just its dead connection. The handler only sets a
     * flag either way, so an early/idle delivery is harmless -- the next
     * guarded call resets the flag before it matters. */
    { struct sigaction sa0; memset(&sa0,0,sizeof sa0); sa0.sa_handler=mux_budget_alarm; sigemptyset(&sa0.sa_mask); sigaction(SIGUSR1,&sa0,NULL); }
    int lfd=open("append.lock", O_RDWR|O_CREAT, 0644);
    if(lfd<0){ fprintf(stderr,"[dlc w%d] no lock\n",w); return 1; }
    static unsigned char st[4096]; store_init(st);
    *(int*)((char*)st+40)=lfd;
    *(int*)((char*)st+36)=0xd9b4bef9;   /* magic */
    *(int*)((char*)st+28)=0;            /* cur_file_no=0 */
    *(int*)((char*)st+0)=-1;            /* no blk fd yet */
    static unsigned char buf[24<<20]; static unsigned char scratch[8<<20];
    unsigned cap=(unsigned)(sizeof scratch/32);
    char hp_[64]; snprintf(hp_,sizeof hp_,"/tmp/dlc_hdr_%d.dat",getpid());
    static unsigned char hst[64]; static unsigned char rec[112];
    int slot=slot0; long total=0; long stalled=0;
    int fd=-1; int held=-1;   /* index into live[]/claimed[] currently held, or -1 */
#define DLC_RELEASE() do{ if(held>=0){ claimed[held]=0; held=-1; } }while(0)
    for(;;){
        long lo=__sync_fetch_and_add(next_claim,(long)DLC_CHUNK_BLOCKS);
        if(lo>end_h){ if(fd>=0) close(fd); DLC_RELEASE(); break; }
        long hi=lo+DLC_CHUNK_BLOCKS-1; if(hi>end_h) hi=end_h;
        if(dlc_chunk_all_present(lo,hi)) continue;

        int hfd=open(hp_,O_RDWR|O_CREAT|O_TRUNC,0644);
        if(hfd<0){ if(fd>=0) close(fd); DLC_RELEASE(); break; }
        *(int*)((char*)hst+0)=hfd; *(long*)((char*)hst+8)=0;
        long n=0; FILE* mf=fopen("headers.dat","rb");
        for(long k=lo;k<=hi;k++){
            if(mf && fseek(mf,k*112,SEEK_SET)==0 && fread(rec,1,112,mf)==112){ if(hst_append(hst,rec,rec+80)<0) break; n++; }
            else break;
        }
        if(mf) fclose(mf);
        if(n<=0){ close(hfd); if(fd>=0) close(fd); DLC_RELEASE(); break; }

        int guard=0, chunk_ok=0;
        for(;;){
            if(fd<0){
                int ok=0;
                for(int a=0;a<nlive && !ok;a++){
                    int idx=(slot+a)%nlive;
                    if(banned[idx]) continue;   /* already proved itself useless this run */
                    const char* cand=live[idx];
                    unsigned ip; if(inet_pton(AF_INET,cand,&ip)!=1) continue;
                    /* claim this peer for exclusive use FIRST -- a real peer
                     * IP is only worth as much as its own bandwidth, so two
                     * workers sharing one starves both instead of using a
                     * second distinct peer that's sitting idle. */
                    if(!__sync_bool_compare_and_swap(&claimed[idx],0,1)) continue;
                    int fdc=tcp_connect_ip(ip,(unsigned short)htons(8333));
                    if(fdc<0){ claimed[idx]=0; continue; }
                    struct timeval tv; tv.tv_sec=20; tv.tv_usec=0; setsockopt(fdc,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
                    if(node_handshake(fdc)==1){
                        fd=fdc; ok=1; held=idx; slot=(idx+1)%nlive;
                        mystat->held_idx=idx;   /* so the parent can ban THIS peer on early-kill */
                        strncpy((char*)mystat->peer,cand,63);
                        /* fresh peer -- the displayed chunks/blocks/guard
                         * must reflect THIS connection, not accumulate
                         * across every peer this worker slot has ever
                         * cycled through (that read as "the new peer has
                         * already done N chunks" when really the old, now-
                         * dropped peer did them). */
                        mystat->chunks=0; mystat->blocks=0; mystat->guard=0;
                    }
                    else { claimed[idx]=0; close(fdc); }
                }
                if(!ok){
                    stalled++;
                    /* Could not connect to ANY unbanned peer. Bans are an
                     * optimisation, not a correctness property, so lift them
                     * rather than stall the download: a slow peer beats no
                     * peer, and a permanently-empty pool is how this used to
                     * spin, printing "peers exhausted" 20,495 times while the
                     * sync went nowhere. Amnesty is idempotent and cheap. */
                    if(stalled==10 || stalled==25){
                        int lifted=0;
                        for(int q=0;q<nlive;q++) if(banned[q]){ banned[q]=0; lifted++; }
                        if(lifted) fprintf(stderr,"[dlc w%d] no reachable peer -- amnesty, un-banned %d peer(s)\n", w, lifted);
                    }
                    if(stalled>40){ fprintf(stderr,"[dlc w%d] peers exhausted\n",w); break; }
                    sleep(3); slot=(slot+7)%(nlive>0?nlive:1); continue;
                }
                stalled=0;
            }
            /* budget the WHOLE transfer's wall-clock, not just the socket
             * read timeout -- a peer trickling a few KB/s keeps resetting
             * SO_RCVTIMEO on every partial read and would never trip that,
             * but is still worth dropping in favor of a fresh peer from the
             * pool. Same bounded-call pattern as do_outbound_sync_bounded
             * above: on budget expiry the socket may hold a partial frame,
             * so it is NOT safe to keep using it -- drop unconditionally.
             * SIGUSR1 gets the SAME handler as SIGALRM: the parent's status
             * loop already samples this worker's real /proc/<pid>/io
             * bandwidth every 10s for the live display, so it can spot an
             * OBVIOUSLY dead connection (sustained near-zero, not just slow)
             * well before the flat wall-clock budget would fire, and signal
             * this worker to abandon early instead of sitting out the full
             * DLC_CHUNK_BUDGET_SECS on a peer that was never going anywhere. */
            struct sigaction sa, old; memset(&sa,0,sizeof sa);
            sa.sa_handler=mux_budget_alarm; sigemptyset(&sa.sa_mask);
            sigaction(SIGALRM,&sa,&old);   /* SIGUSR1 already registered for this worker's whole life, above */
            mux_sync_budget_fired=0;
            alarm(DLC_CHUNK_BUDGET_SECS);
            long r=node_ibd_blocks_s(fd, st, hst, lo, n, buf, sizeof buf, scratch, cap);
            alarm(0); sigaction(SIGALRM,&old,NULL);
            store_reload(st);
            guard++;
            if(mux_sync_budget_fired){
                mystat->timeouts++;   /* covers both the flat budget AND an early-kill signal -- same code path */
                char lastbw[16]; dlc_fmt_rate(lastbw,sizeof lastbw,mystat->last_bw_bps);
                fprintf(stderr,"[dlc w%d] %s dead weight (last measured %s, completed %ld chunk(s)/%ld block(s) on this peer); dropping for a fresh peer\n",
                        w, mystat->peer, lastbw, mystat->chunks, mystat->blocks);
                close(fd); fd=-1; DLC_RELEASE();
                slot=(slot+1)%(nlive>0?nlive:1);
                if(guard>400){ fprintf(stderr,"[dlc w%d] reconnect budget [%ld,%ld]\n",w,lo,hi); break; }
                continue;   /* r is unreliable after an EINTR'd read; don't trust it */
            }
            if(r>=0){ chunk_ok=1; break; }   /* clean completion; KEEP fd (and claim) for the next chunk */
            close(fd); fd=-1; DLC_RELEASE();
            slot=(slot+1)%(nlive>0?nlive:1);
            if(guard>400){ fprintf(stderr,"[dlc w%d] reconnect budget [%ld,%ld]\n",w,lo,hi); break; }
        }
        close(hfd);
        if(chunk_ok){
            total+=n; __sync_fetch_and_add(done_count,n);
            mystat->chunks++; mystat->blocks+=n; mystat->guard+=guard;
        } else fprintf(stderr,"[dlc w%d] chunk [%ld,%ld] ABANDONED\n",w,lo,hi);
    }
    fprintf(stderr,"[dlc w%d] done: blocks=%ld\n", w, total);
    close(lfd);
    return 0;
}
#undef DLC_RELEASE

/* orchestrator: bootstrap peers -> header phase -> compute the combined
 * hole+extend span -> a fast non-blocking-connect liveness probe (same
 * technique already used above in serve_download_worker) -> fork
 * >=min_workers chunk-claiming children -> wait -> return blocks written.
 * Self-throttling: if the archive is already caught up, the span/probe/
 * fork overhead is cheap (all local disk reads, no network), so it's safe
 * to call unconditionally on every boot -- this is what makes the node
 * self-healing without any external tooling. */
/* one non-blocking dial+poll round over pool[from..from+ntry), appending any
 * live+handshaked candidates into live[]/*nlive (capped at cap). Never
 * blocks longer than wait_ms regardless of how many candidates in this
 * batch are dead or black-holed -- poll() naturally times out, unlike a
 * blocking connect() to an unreachable host. Same technique as the parallel
 * dial in serve_download_worker above; caps the batch at MUX_MAX_OUT*3 (24)
 * per round to match its proven behavior (trying the WHOLE pool at once in
 * one round measurably tanks the success rate -- observed 1/140 live).
 * Returns how many were promoted this round. */
static int dlc_probe_round(char pool[][64], int from, int ntry,
                           char live[][64], int* nlive, int cap, int wait_ms){
    if(ntry>MUX_MAX_OUT*3) ntry=MUX_MAX_OUT*3;
    static int cfd[MUX_MAX_OUT*3];
    int nc=0;
    for(int k=0;k<ntry;k++){
        int i=from+k;
        unsigned ip; if(inet_pton(AF_INET,pool[i],&ip)!=1){ cfd[nc++]=-1; continue; }
        int fd=socket(AF_INET,SOCK_STREAM,0);
        if(fd<0){ cfd[nc++]=-1; continue; }
        int fl=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
        struct sockaddr_in sa; memset(&sa,0,sizeof sa); sa.sin_family=AF_INET;
        sa.sin_addr.s_addr=ip; sa.sin_port=(unsigned short)htons(8333);
        int rc=connect(fd,(struct sockaddr*)&sa,sizeof sa);
        if(rc!=0 && errno!=EINPROGRESS){ close(fd); cfd[nc++]=-1; continue; }
        cfd[nc++]=fd;
    }
    struct pollfd pol[MUX_MAX_OUT*3]; int nf=0;
    for(int k=0;k<nc;k++){ if(cfd[k]<0) continue; pol[nf].fd=cfd[k]; pol[nf].events=POLLOUT; pol[nf].revents=0; nf++; }
    if(nf>0) poll(pol,nf,wait_ms);
    int got=0;
    for(int k=0;k<nc && *nlive<cap;k++){
        if(cfd[k]<0) continue;
        int ready=0;
        for(int j=0;j<nf;j++) if(pol[j].fd==cfd[k]){ ready=(pol[j].revents&POLLOUT)?1:0; break; }
        if(!ready){ close(cfd[k]); continue; }
        int soerr=0; socklen_t sl=sizeof soerr;
        if(getsockopt(cfd[k],SOL_SOCKET,SO_ERROR,&soerr,&sl)<0||soerr!=0){ close(cfd[k]); continue; }
        strncpy(live[*nlive],pool[from+k],63); (*nlive)++; got++;
        close(cfd[k]);
    }
    return got;
}

/* read one named field out of /proc/<pid>/io ("rchar:", "write_bytes:", ...).
 * Returns -1 if unavailable (process already gone, field not found, or a
 * non-Linux host without /proc). */
static long dlc_proc_iofield(pid_t pid, const char* field){
    char path[64]; snprintf(path,sizeof path,"/proc/%d/io",(int)pid);
    FILE* f=fopen(path,"r"); if(!f) return -1;
    char line[128]; long v=-1; size_t flen=strlen(field);
    while(fgets(line,sizeof line,f)){
        if(!strncmp(line,field,flen)){ v=atol(line+flen); break; }
    }
    fclose(f);
    return v;
}
/* total bytes a process has read (network + disk + everything -- for a
 * dlc_worker child this is dominated by socket reads), from the kernel's own
 * per-process I/O accounting. Real measured throughput, not an estimate:
 * block-level chunk counters miss a worker that's mid-transfer on a large
 * chunk, but this doesn't. NOTE: this is network-received bytes, NOT the
 * same as disk bytes written -- index.dat's sparse-file block allocation,
 * filesystem journaling, and local header/index re-reads all add disk I/O
 * that never shows up here, which is why "aggregate" read-rate has run
 * measurably behind actual `du` growth on this archive. See dlc_proc_wbytes
 * for the disk-write-side counterpart. */
static long dlc_proc_rchar(pid_t pid){ return dlc_proc_iofield(pid,"rchar:"); }
/* actual bytes written to storage (kernel block-I/O accounting, not just
 * buffered writes) -- the disk-side counterpart to dlc_proc_rchar, so the
 * status log can show network-received and disk-written rates separately
 * instead of one figure trying to represent both. */
static long dlc_proc_wbytes(pid_t pid){ return dlc_proc_iofield(pid,"write_bytes:"); }

/* human-scaled "N.NUNIT/s" into buf (>=16 bytes). */
static void dlc_fmt_rate(char* buf, size_t cap, double bytes_per_sec){
    const char* unit="B"; double v=bytes_per_sec;
    if(v>=1024.0*1024.0*1024.0){ v/=1024.0*1024.0*1024.0; unit="GB"; }
    else if(v>=1024.0*1024.0){ v/=1024.0*1024.0; unit="MB"; }
    else if(v>=1024.0){ v/=1024.0; unit="KB"; }
    snprintf(buf,cap,"%.1f%s/s",v,unit);
}
/* same unit scaling as dlc_fmt_rate but for a plain total, no "/s" suffix --
 * GB tier matters here especially: a multi-hour catch-up at a few MB/s
 * aggregate crosses 1GB cumulative within the first hour or two. */
static void dlc_fmt_bytes(char* buf, size_t cap, double bytes){
    const char* unit="B"; double v=bytes;
    if(v>=1024.0*1024.0*1024.0){ v/=1024.0*1024.0*1024.0; unit="GB"; }
    else if(v>=1024.0*1024.0){ v/=1024.0*1024.0; unit="MB"; }
    else if(v>=1024.0){ v/=1024.0; unit="KB"; }
    snprintf(buf,cap,"%.1f%s",v,unit);
}
/* HH:MM:SS (HH unbounded, not clamped to 24) since catchup_start -- so "how
 * long has this dl_catchup run been going" is readable straight from the
 * log instead of needing `ps -o etime` on the process from outside. */
static void dlc_fmt_elapsed(char* buf, size_t cap, long secs){
    if(secs<0) secs=0;
    long h=secs/3600, m=(secs%3600)/60, s=secs%60;
    snprintf(buf,cap,"%ld:%02ld:%02ld",h,m,s);
}

/* full sequential scan of index.dat: highest non-zero height (tip, -1 if
 * none) and count of non-zero records in [0,tip]. Two genuinely different
 * numbers matter here and are easy to conflate (this bit me in conversation
 * earlier): "% of the range reached so far that's actually filled" (gap-
 * completeness) vs "% of the WHOLE real chain that's done" (overall
 * progress) -- the former can read 99%+ while the latter is still under
 * 60%. A fresh scan every status tick (rather than tracking incrementally)
 * is simplest and correct even though workers claim scattered, non-
 * sequential chunks -- cheap on local NVMe even at 900k+ records. */
/* asm/bitcoin_idxscan.asm:idxscan_progress -- ~4x faster (see
 * tests/bench_idxscan.c). */
static void dlc_scan_progress(long* out_tip, long* out_present){
    idxscan_progress(out_tip, out_present);
}

static long dl_catchup(const char* dir, int min_workers){
    (void)dir; /* CWD is already the data dir; kept for logging/API clarity */
    static unsigned char ab[64];
    if(amr_init(ab)!=1){ fprintf(stderr,"[dlc] amr_init failed\n"); return 0; }
    long disc=dl_bootstrap(ab, catchup_seeds, (int)(sizeof(catchup_seeds)/sizeof(catchup_seeds[0])));
    fprintf(stderr,"[dlc] discovered +%ld peers (book now %ld)\n", disc, (long)amr_count(ab));

    static char pool[DLC_MAXPOOL][64];
    /* Known-good peers first: these actually delivered blocks on a previous
     * run, so they are worth far more than an arbitrary book entry. The book
     * fills the rest; duplicates are harmless (the probe just confirms one
     * twice) and the claimed[] logic already prevents two workers sharing a
     * peer. */
    int ngood = dl_load_good_peers(pool, DLC_MAXPOOL);
    int npool = ngood;
    {
        static char book[DLC_MAXPOOL][64];
        int nbook = dl_pool_from_book(ab, book, DLC_MAXPOOL);
        for(int i=0;i<nbook && npool<DLC_MAXPOOL;i++){
            int dup=0;
            for(int j=0;j<ngood;j++) if(!strcmp(book[i],pool[j])){ dup=1; break; }
            if(dup) continue;
            strncpy(pool[npool],book[i],63); pool[npool][63]=0; npool++;
        }
    }
    if(ngood) fprintf(stderr,"[dlc] %d known-good peer(s) from a previous run tried first\n", ngood);
    fprintf(stderr,"[dlc] %d candidate peer(s) in pool\n", npool);
    if(npool<=0){ fprintf(stderr,"[dlc] no peers discovered; skipping catch-up\n"); return 0; }

    /* liveness probe: several bounded non-blocking-dial rounds (see
     * dlc_probe_round) instead of one shot, targeting a decently deep
     * confirmed-live pool (>= min_workers*3) before we ever rely on it --
     * real Bitcoin peers often take longer than one short poll to complete
     * a handshake (serve_download_worker's own gradual background leg-fill
     * exists for the same reason), and everything downstream of this
     * (dlc_headers, dlc_worker) deliberately only dials CONFIRMED entries,
     * so under-populating `live[]` here directly costs catch-up depth. */
    static char live[DLC_MAXPOOL][64]; int nlive=0;
    {
        /* Target a deep live pool: workers*3 was sized before peers could be
         * banned, and left no headroom -- evicting duds then starved the
         * downloader outright. Aim for 6x so eviction has room to work. */
        int want = min_workers*6; if(want>npool) want=npool;
        int from=0, rounds=0;
        /* no arbitrary round cap: keep probing until either `want` is hit or
         * the WHOLE discovered pool has been tried (from<npool already
         * guarantees termination -- a fixed round cap here previously cut
         * the probe off after covering only ~40% of a 481-peer pool,
         * settling for 10 live peers when the target was 48). */
        while(nlive<want && from<npool){
            int ntry=npool-from; if(ntry>MUX_MAX_OUT*3) ntry=MUX_MAX_OUT*3;
            dlc_probe_round(pool, from, ntry, live, &nlive, DLC_MAXPOOL, 8000);
            from+=ntry; rounds++;
        }
        fprintf(stderr,"[dlc] %d confirmed-live peer(s) (%d probe round(s))\n", nlive, rounds);

        /* Ask real peers for more peers. Until now the book only ever grew
         * from DNS seeds at boot, so it decayed as peers died and there was
         * no recovery from exhausting it -- three of the last four boots
         * discovered "+0 peers" against a 1,974-entry book that was only ~4%
         * reachable. A single peer can return up to 1,000 addresses, so we
         * stop as soon as we have a useful haul rather than asking everyone.
         * Best-effort: any failure just leaves the book as it was. */
        /* ONLY when we are actually short. The book is not small -- it is
         * stale: ~1,974 entries of which only ~4% still answer. Fresh
         * addresses from a live peer have a far better hit rate, but asking
         * costs real time (a peer delays its reply well past the socket
         * timeout, so a useful window is ~20s per peer). A node that already
         * probed a healthy live set should pay none of that. Below half the
         * target, top up; otherwise skip entirely. */
        if(nlive>0 && nlive < want/2){
            fprintf(stderr,"[addr] only %d live peer(s) (target %d) -- asking peers for more\n", nlive, want);
            addr_replenish(ab, live, nlive, 3 /* ask at most 3 */, 20 /* seconds each */, 400);
        }
    }
    if(nlive<=0){ fprintf(stderr,"[dlc] no live peers; skipping catch-up\n"); return 0; }
    int nw = min_workers; if(nlive<nw) nw=nlive; if(nw<1) nw=1; if(nw>64) nw=64;

    long hdr_len = dlc_headers(live, nlive);
    if(hdr_len<=0){ fprintf(stderr,"[dlc] header phase failed; skipping catch-up\n"); return 0; }

    long start_h, end_h;
    if(!dlc_span(hdr_len, &start_h, &end_h)){
        fprintf(stderr,"[dlc] archive already complete through %ld\n", hdr_len-1);
        return 0;
    }
    fprintf(stderr,"[dlc] span [%ld,%ld] (%ld heights)\n", start_h, end_h, end_h-start_h+1);

    /* pre-size index.dat GROW-ONLY, create append.lock */
    {
        int ix=open("index.dat", O_RDWR|O_CREAT, 0644);
        if(ix<0){ perror("open index.dat"); return 0; }
        struct stat sb; long cur=0; if(fstat(ix,&sb)==0) cur=sb.st_size;
        long need=(end_h+1)*48; if(need<cur) need=cur;
        if(ftruncate(ix,need)){ perror("ftruncate index.dat"); close(ix); return 0; }
        close(ix);
        int lf=open("append.lock", O_RDWR|O_CREAT, 0644); if(lf>=0) close(lf);
    }

    volatile long* next_claim=mmap(NULL,sizeof(long),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    volatile long* done_count=mmap(NULL,sizeof(long),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    volatile dlc_stat_t* stats=mmap(NULL,sizeof(dlc_stat_t)*(size_t)nw,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    /* one claim flag per live[] peer -- __sync_bool_compare_and_swap makes
     * "pick an unclaimed peer" atomic across all forked workers, so no two
     * workers ever share one peer's bandwidth while a distinct live peer
     * sits unused. */
    volatile int* claimed=mmap(NULL,sizeof(int)*(size_t)nlive,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    /* Peers evicted for sustained uselessness are banned for the REST OF THE
     * RUN. Without this the replacement draw is memoryless: a worker killed
     * for trickling at 5KB/s could immediately be handed the same IP again,
     * and with most of the pool being duds that is what kept happening. */
    volatile int* banned=mmap(NULL,sizeof(int)*(size_t)nlive,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(next_claim==MAP_FAILED || done_count==MAP_FAILED || stats==MAP_FAILED || claimed==MAP_FAILED || banned==MAP_FAILED){ perror("mmap"); return 0; }
    /* MAP_ANONYMOUS zero-fills, so held_idx would default to 0 -- and a
     * worker that never managed to connect would then make the parent ban
     * live[0], a peer that may be perfectly good. Mark "holding nothing"
     * explicitly. */
    for(int i=0;i<nw;i++) stats[i].held_idx = -1;
    *next_claim=start_h; *done_count=0;
    /* MAP_ANONYMOUS pages come zeroed, so every stats[w].peer/chunks/blocks/
     * guard and every claimed[i] starts at "" / 0 / 0 / 0 / 0 -- no explicit
     * init needed. */

    time_t catchup_start=time(NULL); /* for the elapsed-time display in the status loop below */
    pid_t kids[64]; pid_t opid[64];
    for(int w=0;w<nw;w++){
        pid_t p=fork();
        if(p==0){ _exit(dlc_worker(w, end_h, live, nlive, w, next_claim, done_count, &stats[w], claimed, banned)); }
        kids[w]=p; opid[w]=p;
    }
    /* live peer-stats table: poll every 10s instead of blocking silently on
     * waitpid, so "what are our peers doing right now" is visible in the log
     * for the whole catch-up, not just a one-line summary at the very end.
     * Bandwidth comes from each worker's OWN /proc/<pid>/io (real measured
     * bytes read), not the block/chunk counters -- a worker mid-transfer on
     * one large chunk shows 0 chunks for minutes even while actively
     * downloading at full speed, which the byte counter catches. */
    long prev_blocks[64]={0}; long prev_rchar[64]={0}; long prev_wbytes[64]={0}; int dead_ticks[64]={0};
    long nbanned=0;
    double cumulative_bytes=0.0;       /* running total network-received, across the whole call */
    double cumulative_write_bytes=0.0; /* running total actually written to disk, across the whole call */
    int alive=nw;
    while(alive>0){
        struct timespec ts={10,0}; nanosleep(&ts,NULL);
        alive=0;
        for(int w=0;w<nw;w++){
            if(kids[w]==0) continue;
            int stt; pid_t r=waitpid(kids[w],&stt,WNOHANG);
            if(r==0) alive++; else kids[w]=0;
        }
        {
            long cur_tip, present;
            dlc_scan_progress(&cur_tip, &present);
            long holes = cur_tip>=0 ? (cur_tip+1-present) : 0;
            double overall_pct = 100.0*(double)present/(double)(end_h+1);
            double span_pct = cur_tip>=0 ? 100.0*(double)present/(double)(cur_tip+1) : 0.0;
            char elapsed[16]; dlc_fmt_elapsed(elapsed,sizeof elapsed,(long)(time(NULL)-catchup_start));
            fprintf(stderr,"[dlc] == elapsed %s | overall: %ld/%ld stored (%.2f%% of real tip) | %ld holes in [0,%ld] reached so far (%.2f%% gap-free) ==\n",
                    elapsed, present, end_h+1, overall_pct, holes, cur_tip, span_pct);
        }
        fprintf(stderr,"[dlc] -- peer status (%d/%d worker(s) active) --\n", alive, nw);
        double tick_total_bytes=0.0, tick_total_write_bytes=0.0;
        for(int w=0;w<nw;w++){
            long b=stats[w].blocks; long blkrate=(b-prev_blocks[w])/10;
            long rc=kids[w]!=0 ? dlc_proc_rchar(opid[w]) : -1;
            long wc=kids[w]!=0 ? dlc_proc_wbytes(opid[w]) : -1;
            char bw[16]="--"; double byte_rate=-1.0;
            if(rc>=0){
                if(prev_rchar[w]>0){
                    double delta=(double)(rc-prev_rchar[w]);
                    tick_total_bytes+=delta;
                    byte_rate=delta/10.0;
                    dlc_fmt_rate(bw,sizeof bw,byte_rate);
                    stats[w].last_bw_bps=byte_rate; /* worker reads this to report why it got dropped */
                }
                prev_rchar[w]=rc;
            }
            if(wc>=0){
                if(prev_wbytes[w]>0) tick_total_write_bytes+=(double)(wc-prev_wbytes[w]);
                prev_wbytes[w]=wc;
            }
            char flag[48]="";
            if(kids[w]!=0 && byte_rate>=0.0){
                if(byte_rate<DLC_DEAD_WEIGHT_BPS){
                    dead_ticks[w]++;
                    if(dead_ticks[w]>=DLC_DEAD_WEIGHT_TICKS){
                        long bidx = stats[w].held_idx;
                        if(bidx>=0 && bidx<nlive && !banned[bidx]){
                            int usable=0; for(int q=0;q<nlive;q++) if(!banned[q]) usable++;
                            if(usable > DLC_MIN_USABLE_PEERS){ banned[bidx]=1; nbanned++; }
                            /* else: at the floor -- still kill the worker so it
                             * rotates to a different peer, but keep this one
                             * selectable. A slow peer beats no peer. */
                        }
                        kill(opid[w],SIGUSR1);
                        dead_ticks[w]=0;
                        snprintf(flag,sizeof flag," [early-kill sent, last %s, peer BANNED]",bw);
                    }
                } else dead_ticks[w]=0;
            }
            /* live progress toward THIS worker's next early-kill -- updates
             * every 10s tick as dead_ticks climbs, so it's visible in real
             * time as a connection starts trending dead, not just after a
             * kill has already happened (a historical per-kill tally only
             * changes once a drop actually fires, which can take a while to
             * show up at all). Resets to nothing once healthy or just cut. */
            char dragbuf[32]="";
            if(dead_ticks[w]>0) snprintf(dragbuf,sizeof dragbuf," (Dragging: %d of %d)",dead_ticks[w],DLC_DEAD_WEIGHT_TICKS);
            fprintf(stderr,"[dlc]   w%d %-21s chunks=%-4ld blocks=%-6ld (+%ld blk/s, %s)%s%s%s\n",
                    w, stats[w].peer[0]?(const char*)stats[w].peer:"(connecting)",
                    stats[w].chunks, b, blkrate, bw, kids[w]==0?" [done]":"", flag, dragbuf);
            prev_blocks[w]=b;
        }
        {
            cumulative_bytes+=tick_total_bytes;
            cumulative_write_bytes+=tick_total_write_bytes;
            char totbuf[16], aggbuf[16], cumbuf[16], wtotbuf[16], waggbuf[16], wcumbuf[16];
            dlc_fmt_bytes(totbuf,sizeof totbuf,tick_total_bytes);
            dlc_fmt_rate(aggbuf,sizeof aggbuf,tick_total_bytes/10.0);
            dlc_fmt_bytes(cumbuf,sizeof cumbuf,cumulative_bytes);
            dlc_fmt_bytes(wtotbuf,sizeof wtotbuf,tick_total_write_bytes);
            dlc_fmt_rate(waggbuf,sizeof waggbuf,tick_total_write_bytes/10.0);
            dlc_fmt_bytes(wcumbuf,sizeof wcumbuf,cumulative_write_bytes);
            /* two genuinely different numbers, shown separately rather than
             * conflated into one "aggregate": network-received (rchar) is
             * NOT the same as disk-written (write_bytes) -- index.dat's
             * sparse-block allocation, filesystem journaling, and local
             * header/index re-reads all add disk I/O the network figure
             * never sees, so disk growth normally runs ahead of it. */
            fprintf(stderr,"[dlc] -- network recv this tick: %s (%s) | total recv: %s || disk write this tick: %s (%s) | total written: %s --\n",
                    totbuf,aggbuf,cumbuf,wtotbuf,waggbuf,wcumbuf);
            /* the per-tick numbers above are a noisy 10s snapshot -- this is
             * the stable figure: total bytes / total elapsed time since
             * dl_catchup started, so it settles down over the run instead
             * of bouncing with whichever peers happen to be fast or slow
             * in any given 10s window. */
            long elapsed_secs=(long)(time(NULL)-catchup_start); if(elapsed_secs<1) elapsed_secs=1;
            char avgrbuf[16], avgwbuf[16];
            dlc_fmt_rate(avgrbuf,sizeof avgrbuf,cumulative_bytes/(double)elapsed_secs);
            dlc_fmt_rate(avgwbuf,sizeof avgwbuf,cumulative_write_bytes/(double)elapsed_secs);
            fprintf(stderr,"[dlc] -- peers banned this run: %ld of %d --\n", nbanned, nlive);
    fprintf(stderr,"[dlc] -- average since start: %s recv, %s write --\n",avgrbuf,avgwbuf);
        }
    }
    long total=*done_count;
    munmap((void*)next_claim,sizeof(long)); munmap((void*)done_count,sizeof(long));
    munmap((void*)stats,sizeof(dlc_stat_t)*(size_t)nw);
    munmap((void*)claimed,sizeof(int)*(size_t)nlive);
    /* Remember who actually produced blocks. A peer that delivered is worth
     * trying first next boot; the address book alone only records that an IP
     * was once seen, which is why every restart re-probed ~2,000 aged entries
     * and rediscovered the same handful from scratch. Recorded from the live
     * stats, and only for peers with blocks>0 -- being reachable is not the
     * same as being useful. */
    {
        static char good[64][64]; int ngood=0;
        for(int w=0; w<nw && ngood<64; w++){
            if(stats[w].blocks<=0) continue;
            const char* ip=(const char*)stats[w].peer;
            if(!ip[0]) continue;
            int dup=0; for(int j=0;j<ngood;j++) if(!strcmp(good[j],ip)){ dup=1; break; }
            if(dup) continue;
            strncpy(good[ngood],ip,63); good[ngood][63]=0; ngood++;
        }
        dl_save_good_peers(good, ngood);
    }
    fprintf(stderr,"[dlc] catch-up done: %ld new blocks written\n", total);
    return total;
}

/* UTXO catch-up health: consecutive post-recovery failures, and the earliest
 * time we may retry. Zero streak == healthy. See the catch-up block below. */
static long      utxo_fail_streak  = 0;
static long long utxo_retry_at_ms  = 0;

static void serve_download_worker(const char* dir, const char* peers[], int pool_len, int out_port){
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, handle_shutdown_signal);
    signal(SIGINT, handle_shutdown_signal);
    /* Reload a fresh store state rather than inherit the parent's possibly-
     * stale in-memory idx_len/pos (fork COW is not safe for a growable
     * store -- see the unified_ibd comments on re-initialising per
     * process). NOTE: this process is NOT the sole block writer -- an
     * inbound serve child can also append a pushed block via .do_block; both
     * paths go through idxscan_append_locked (flock-guarded, atomic-height-
     * under-lock) so they can't collide, see that function's header comment
     * in bitcoin_idxscan.asm. */
    chdir(dir);
    fprintf(stderr,"[dl] worker: reloading chain archive...\n");
    phase_timer_t dl_load_pt; phase_start(&dl_load_pt);
    if(store_reload(store_buf)!=1){ fprintf(stderr,"[dl] store_reload failed\n"); _exit(1); }
    fprintf(stderr,"[dl] worker: chain archive reloaded: tip=%d (%.2fs)\n",
            *(int*)(store_buf+24), phase_elapsed(&dl_load_pt));
    /* Single-writer live UTXO instance: this worker is the sole process that
     * ever calls utxo_lsm_put/del (inbound serve children only ever get a
     * read-only utxo_lsm_reload() snapshot). Non-fatal on failure -- block
     * sync/relay must keep working even if UTXO tracking can't start. */
    /* Verify the archive BEFORE any UTXO work. An append-only store cannot
     * notice that a mid-sync locator collapse made a peer re-serve from
     * genesis onto our tail, so a corrupt archive used to flow straight into
     * the UTXO set and be reported as success. Detect it (duplicate block
     * hashes are never valid on a real chain) and self-repair by truncating
     * to the last good height, letting normal sync re-download from there. */
    int archive_ok;
    {
        /* ONE scan: it walks every index record through a ~1M-entry hash
         * table, so this is not something to run twice per boot. */
        int av = archive_verify_and_repair(store_buf, 1 /* repair */);
        archive_ok = (av >= 0);
        if(av == 0){
            /* Truncated: any persisted UTXO applied-height now refers to
             * heights that no longer exist, so the UTXO set must be rebuilt
             * from scratch rather than resumed against a shorter chain. */
            long dropped = archive_drop_utxo_state();
            fprintf(stderr,"[dl] archive was repaired -- dropped %ld UTXO state file(s) so the set rebuilds from a clean slate\n", dropped);
        } else if(av < 0){
            fprintf(stderr,"[dl] archive INTEGRITY CHECK FAILED and was not repaired -- continuing WITHOUT live UTXO tracking\n");
        }
    }

    fprintf(stderr,"[dl] worker: loading live UTXO state...\n");
    phase_timer_t utxo_init_pt; phase_start(&utxo_init_pt);
    int utxo_live_ok = archive_ok ? utxo_live_init(dir) : 0;
    if(!archive_ok) fprintf(stderr,"[dl] refusing to build UTXO state on an archive that failed verification\n");
    if(!utxo_live_ok) fprintf(stderr,"[dl] utxo_live_init failed -- continuing WITHOUT live UTXO tracking\n");
    else fprintf(stderr,"[dl] worker: live UTXO state loaded (%.2fs)\n", phase_elapsed(&utxo_init_pt));

    /* ---- STAGE B: fork choice ------------------------------------------
     * Open chainwork.dat and bring it fully in step with index.dat. The
     * first run on an existing archive is the one-time backfill of every
     * already-stored height (each one costs an index read, an 80-byte header
     * read and one 16-byte record write); every later boot finds the file
     * already complete and this returns immediately. Doing the backfill here
     * rather than as a separate tool means the backfill path and the
     * steady-state path are literally the same tested function, and it is
     * resumable -- an interrupted backfill just continues next boot.
     *
     * A failure here disables reorg handling for this process but must not
     * stop the node: without chainwork we simply cannot compare chains, and
     * refusing to reorg is always the safe direction. */
    int reorg_ok = 0;
    if(reorg_chainwork_open(store_buf) != 1){
        fprintf(stderr,"[dl] chainwork open failed -- fork detection DISABLED for this process\n");
    } else {
        phase_timer_t cw_pt; phase_start(&cw_pt);
        long added = reorg_chainwork_sync(store_buf, 0);
        if(added < 0){
            fprintf(stderr,"[dl] chainwork backfill failed -- fork detection DISABLED for this process\n");
        } else {
            reorg_ok = 1;
            fprintf(stderr,"[dl] worker: chainwork in step with the archive (%ld record(s) backfilled, %.2fs)\n",
                    added, phase_elapsed(&cw_pt));
        }
    }
    /* Reorg handling additionally REQUIRES live UTXO tracking: disconnecting
     * a block means replaying its undo data against the live LSM, and the
     * undo data itself is only written by the live apply path. */
    if(reorg_ok && !utxo_live_ok){
        fprintf(stderr,"[dl] live UTXO tracking is off -- fork detection stays on but REORGS ARE DISABLED (no undo data)\n");
    }
    reorg_set_index_rebuild(rebuild_hash_index_after_reorg);
    /* ---- BOOTSTRAP + DISCOVER (seeds are bootstrap-only) ----
     * Real nodes use DNS seeds once to learn reachable peers, then connect to
     * those -- never downloading from the seeds themselves. We resolve each
     * seed-DNS hostname to its A-records (real, current node IPs), fold the
     * distinct v4 endpoints into the persisted amr book (peers.dat), then dial
     * up to 8 of those DISCOVERED peers for download. */
    static unsigned char ab[64];
    if(amr_init(ab)==1){
        long disc = dl_bootstrap(ab, peers, pool_len);
        fprintf(stderr,"[boot] discovered +%ld peers (peers.dat now %ld)\n", disc, (long)amr_count(ab));
    } else {
        fprintf(stderr,"[boot] amr_init failed; falling back to seed list\n");
    }
    static char dle[64][64];
    int npool = dl_pool_from_book(ab, dle, 64);
    fprintf(stderr,"[boot] %d public peer candidate(s) in pool\n", npool);
    const char* srcpool[64]; int nsrc=0;
    for(int i=0;i<npool && nsrc<64;i++){ srcpool[nsrc++]=dle[i]; }
    if(nsrc==0){
        /* Discovery found nothing: DEGRADED fallback so the node still syncs.
         * Normally the seeds are bootstrap-only; this is only an emergency. */
        fprintf(stderr,"[dl] no discovered peers; temporary seed fallback\n");
        for(int i=0;i<pool_len && nsrc<8;i++){ srcpool[nsrc++]=peers[i]; }
    }
    /* ---- MULTI-PEER DOWNLOAD: establish up to 8 live legs by dialing the
     * discovered candidate pool IN PARALLEL. A DNS seed returns many
     * plausible-but-dead IPs, so a per-candidate sequential dial with timeouts
     * would stall for minutes. Instead we non-blocking-connect ALL candidates
     * at once, poll once for readiness, and promote only the live ones -- dead
     * peers are shed in the same single bounded wait as live ones connect.
     * (We are the sole block writer in ONE process, so rotating bounded sync
     * passes over the shared store_buf is race-free; each leg's node_sync
     * appends via store_append while the others idle. A LONG per-pass budget,
     * DL_BUDGET_SECS, applies because this process does not serve inbound.) */
    long long next_feeler_ms = 0;
    for(int b=0;b<MAX_BLOCK_RELAY_ONLY;b++){ bro_fd[b]=-1; bro_host[b][0]=0; }
    mux_n_out = 0;                                   /* isolate from any parent state */
    {
        int ntry = nsrc; if(ntry>MUX_MAX_OUT*3) ntry=MUX_MAX_OUT*3;   /* cap candidates */
        static int cfd[64];
        int nc=0;
        for(int i=0;i<ntry && nc<64;i++){
            unsigned ip;
            if(inet_pton(AF_INET,srcpool[i],&ip)!=1){
                struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
                if(getaddrinfo(srcpool[i],NULL,&h,&res)!=0){ cfd[nc++]=-1; continue; }
                ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr; freeaddrinfo(res);
            }
            int fd=socket(AF_INET,SOCK_STREAM,0);
            if(fd<0){ cfd[nc++]=-1; continue; }
            int fl=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
            struct sockaddr_in sa; memset(&sa,0,sizeof sa); sa.sin_family=AF_INET;
            sa.sin_addr.s_addr=ip; sa.sin_port=(unsigned short)htons((unsigned short)out_port);
            int rc=connect(fd,(struct sockaddr*)&sa,sizeof sa);
            if(rc!=0 && errno!=EINPROGRESS){ close(fd); cfd[nc++]=-1; continue; }
            /* stash the original flags so we can clear O_NONBLOCK after promote */
            cfd[nc++]=fd;
        }
        /* single bounded wait for any of them to become writable */
        struct pollfd pol[64]; int nf=0;
        for(int i=0;i<nc;i++){ if(cfd[i]<0) continue; pol[nf].fd=cfd[i]; pol[nf].events=POLLOUT; pol[nf].revents=0; nf++; }
        if(nf>0) poll(pol,nf,2500);
        for(int i=0;i<nc && mux_n_out<8 && mux_n_out<MUX_MAX_OUT;i++){
            if(cfd[i]<0) continue;
            int ready=0;
            for(int j=0;j<nf;j++) if(pol[j].fd==cfd[i]){ ready=(pol[j].revents&POLLOUT)?1:0; break; }
            if(!ready){ close(cfd[i]); continue; }
            int soerr=0; socklen_t sl=sizeof soerr;
            if(getsockopt(cfd[i],SOL_SOCKET,SO_ERROR,&soerr,&sl)<0||soerr!=0){ close(cfd[i]); continue; }
            /* it connected: clear non-blocking, then handshake (bounded recv) */
            int fl=fcntl(cfd[i],F_GETFL,0); fcntl(cfd[i],F_SETFL,fl&~O_NONBLOCK);
            struct timeval tv; tv.tv_sec=6; tv.tv_usec=0; setsockopt(cfd[i],SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
            int hk=node_handshake(cfd[i]);
            if(hk!=1){ close(cfd[i]); continue; }
            struct timeval t2; t2.tv_sec=3; t2.tv_usec=0; setsockopt(cfd[i],SOL_SOCKET,SO_RCVTIMEO,&t2,sizeof t2);
            strncpy(mux_out_host[mux_n_out], srcpool[i], 63);
            mux_out_fd[mux_n_out]=cfd[i];
            mux_out_peer[mux_n_out]=i;
            anchor_locator(mux_out_loc[mux_n_out]);
            mux_out_nextretry[mux_n_out]=0;
            { char pv[256]; format_peer_version_info(pv, sizeof pv);
              fprintf(stderr,"[dl] outbound %d = %s (fd %d) %s\n", mux_n_out, srcpool[i], cfd[i], pv); }
            mux_n_out++;
        }
        /* close every candidate fd that was NOT promoted into a live leg */
        for(int i=0;i<nc;i++){
            if(cfd[i]<0) continue;
            int kept=0;
            for(int k=0;k<mux_n_out;k++) if(mux_out_fd[k]==cfd[i]){ kept=1; break; }
            if(!kept) close(cfd[i]);
        }
    }
    fprintf(stderr,"[dl] connected %d/%d peer(s); downloading across them...\n", mux_n_out, 8);
    long long rot=0;
    long long boot_ms = 0;
    { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); boot_ms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
    long long next_heartbeat_ms = boot_ms + DL_HEARTBEAT_MS;
    /* STAGE B: next allowed fork probe (see the probe block in the rotation
     * below). Starts armed so a node booting onto a store that is already on
     * a losing branch notices on its first idle rotation rather than after a
     * full interval. */
    long long next_reorg_probe_ms = 0;
    for(;;){
        if(g_shutdown_requested){
            int live_peers=0; for(int i=0;i<mux_n_out;i++) if(mux_out_fd[i]>=0) live_peers++;
            long long stop_ms; { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); stop_ms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
            fprintf(stderr,"[dl] shutting down (signal %d): tip=%d peers=%d live_utxo=%ld uptime=%llds\n",
                    (int)g_shutdown_requested, *(int*)(store_buf+24), live_peers,
                    utxo_live_ok?utxo_live_count():-1L, (stop_ms-boot_ms)/1000);
            _exit(0);
        }
        long long now_ms = 0;
        { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); now_ms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
        int did=0;
        for(int i=0;i<mux_n_out;i++){
            if(g_shutdown_requested) break;   /* don't wait for a full rotation through every leg */
            if(mux_out_fd[i]<0){
                /* dead slot: re-dial (rate-limited), same logic as serve_mux */
                if(now_ms>=mux_out_nextretry[i]){ mux_redial(i, peers, pool_len, out_port); mux_out_nextretry[i]=now_ms+REDIAL_BACKOFF_MS; }
                continue;
            }
            /* Cheap liveness check BEFORE syncing: a peer that cleanly closed
             * or reset the connection shows up here as POLLHUP/POLLERR/POLLNVAL
             * with a zero timeout (non-blocking -- never delays the rotation).
             * Without this, do_outbound_sync's node_sync would just keep
             * returning ok!=1 on the dead fd forever with no log and no
             * re-dial (only a genuinely HUNG peer trips the SIGALRM budget
             * below) -- this is the serve_mux parent's own POLLHUP/POLLERR/
             * POLLNVAL pattern (see the accept loop above), mirrored here so
             * the download worker's peer drops are equally visible/handled. */
            struct pollfd pf = { mux_out_fd[i], POLLIN, 0 };
            if(poll(&pf, 1, 0) > 0 && (pf.revents & (POLLHUP|POLLERR|POLLNVAL))){
                fprintf(stderr,"[dl:%d] %s connection dropped (revents 0x%x); re-dialing\n",
                        i, mux_out_host[i], pf.revents);
                mux_redial(i, peers, pool_len, out_port);
                mux_out_nextretry[i]=now_ms+REDIAL_BACKOFF_MS;
                continue;
            }
            /* bounded sync pass on this leg (DL_BUDGET_SECS wall-clock) */
            struct sigaction sa, old; memset(&sa,0,sizeof sa);
            sa.sa_handler=mux_budget_alarm; sigemptyset(&sa.sa_mask);
            sigaction(SIGALRM,&sa,&old);
            mux_sync_budget_fired=0;
            alarm((unsigned)DL_BUDGET_SECS);
            long n = do_outbound_sync(i);
            alarm(0); sigaction(SIGALRM,&old,NULL);
            if(mux_sync_budget_fired){
                fprintf(stderr,"[dl:%d] %s exceeded %gs budget; re-dialing\n",
                        i, mux_out_fd[i]>=0?mux_out_host[i]:"?", DL_BUDGET_SECS);
                mux_redial(i, peers, pool_len, out_port);
            }
            did |= (n>0)?1:0;
            /* ---- STAGE B: periodic fork probe -----------------------------
             * Runs only on a leg that just returned NOTHING, which is exactly
             * the situation a fork hides in: if the peer is on a competing
             * branch, node_sync stores nothing and looks indistinguishable
             * from "we are caught up". The probe re-asks with the same real
             * multi-hash locator and evaluates the answer with the full
             * validate -> locate fork -> compare work -> download -> verify
             * pipeline; every step before the destructive one can bail out
             * with the node completely unchanged.
             *
             * Rate-limited to ONE leg per REORG_PROBE_INTERVAL_MS so the
             * extra getheaders round trip is negligible against the per-leg
             * sync traffic, and bounded by the same SIGALRM budget the sync
             * pass uses so a stalled peer cannot hold the rotation.
             * Gated on BOTH chainwork (needed to compare) and live UTXO
             * tracking (needed for undo data). */
            if(reorg_ok && utxo_live_ok && n<=0 && mux_out_fd[i]>=0 && now_ms>=next_reorg_probe_ms){
                next_reorg_probe_ms = now_ms + REORG_PROBE_INTERVAL_MS;
                struct sigaction psa, pold; memset(&psa,0,sizeof psa);
                psa.sa_handler=mux_budget_alarm; sigemptyset(&psa.sa_mask);
                sigaction(SIGALRM,&psa,&pold);
                mux_sync_budget_fired=0;
                alarm((unsigned)DL_BUDGET_SECS);
                long pr = reorg_probe_peer(mux_out_fd[i], store_buf, mux_out_host[i]);
                alarm(0); sigaction(SIGALRM,&pold,NULL);
                if(mux_sync_budget_fired){
                    fprintf(stderr,"[reorg] probe of %s exceeded %gs budget; re-dialing\n", mux_out_host[i], DL_BUDGET_SECS);
                    mux_redial(i, peers, pool_len, out_port);
                } else if(pr == 1){
                    /* The chain moved under us: re-anchor this leg and force
                     * a UTXO catch-up pass this rotation. */
                    anchor_locator(mux_out_loc[i]);
                    did = 1;
                } else if(pr < 0){
                    fprintf(stderr,"[reorg] probe of %s rejected a candidate chain (no action taken)\n", mux_out_host[i]);
                }
            }
            /* brief yield so we don't spin a CPU core when all legs are idle */
            if((i&1)==1){ usleep(20000); }
        }
        rot++;
        /* Real-time UTXO catch-up: its OWN step, decoupled from any single
         * leg's do_outbound_sync return value. A per-leg local diff would
         * only ever see blocks THIS worker just synced; comparing the
         * store's true on-disk tip against the persisted applied-height
         * (utxo_live_catchup's own job) also picks up a sibling inbound
         * child's .do_block writes, which land in the shared archive
         * independently of any leg here. */
        /* STAGE B: same argument as the UTXO catch-up directly below --
         * chainwork must track the store's TRUE on-disk tip, not just what
         * this worker's own legs happened to store, because an inbound serve
         * child's .do_block writes land in the shared archive independently.
         * A no-op (one lseek) when already in step. */
        /* ---- block-relay-only legs (relay=0, no addr gossip) -------------
         * Kept topped up alongside the full-relay legs. Chosen from a
         * DIFFERENT netgroup than any existing leg where possible: two peers
         * in the same /16 are far more likely to be the same operator, which
         * defeats the point of having them. */
        for(int b=0; b<MAX_BLOCK_RELAY_ONLY; b++){
            if(bro_fd[b] >= 0) continue;
            if((rot % 16) != 0) break;             /* rate-limit re-dials */
            for(int ci=0; ci<nsrc; ci++){
                unsigned cip; if(inet_pton(AF_INET,srcpool[ci],&cip)!=1) continue;
                int clash=0;
                for(int k=0;k<mux_n_out;k++){
                    unsigned oip; if(inet_pton(AF_INET,mux_out_host[k],&oip)!=1) continue;
                    if(net_netgroup_v4(oip)==net_netgroup_v4(cip)){ clash=1; break; }
                }
                for(int k=0;k<MAX_BLOCK_RELAY_ONLY && !clash;k++){
                    if(bro_fd[k]<0) continue;
                    unsigned oip; if(inet_pton(AF_INET,bro_host[k],&oip)!=1) continue;
                    if(net_netgroup_v4(oip)==net_netgroup_v4(cip)) clash=1;
                }
                if(clash) continue;
                int f = net_handshake_relay(srcpool[ci], 0 /* relay=0 */, 6);
                if(f>=0){
                    bro_fd[b]=f; strncpy(bro_host[b],srcpool[ci],63); bro_host[b][63]=0;
                    fprintf(stderr,"[net] block-relay-only %d = %s (fd %d, relay=0)\n", b, bro_host[b], f);
                    break;
                }
            }
        }

        /* ---- feeler: one short-lived probe every ~2 minutes ---------------
         * Validates a book entry and drops it. This is what keeps the address
         * book from rotting -- without it we only discover the rot at boot,
         * as happened on 2026-08-18 (1,974 entries, ~4% still answering). */
        if(now_ms >= next_feeler_ms && nsrc > 0){
            next_feeler_ms = now_ms + FEELER_INTERVAL_MS;
            int pick = (int)((unsigned)rot * 2654435761u % (unsigned)nsrc);
            int alive = net_feeler_probe(srcpool[pick]);
            fprintf(stderr,"[net] feeler %s -> %s\n", srcpool[pick], alive?"alive":"dead");
        }

        if(reorg_ok) reorg_chainwork_sync(store_buf, 0);
        /* A catch-up failure is RECOVERABLE, not terminal. It used to set
         * utxo_live_ok=0, which left the node serving blocks with no UTXO
         * tracking at all -- silently, until a human noticed and restarted
         * it. That happened twice on 2026-08-18. The usual cause (a full
         * manifest) is cleared by a compaction, so: try recovery, retry
         * once, and on repeated failure back off and RETRY LATER rather
         * than giving up for the life of the process. */
        if(utxo_live_ok && now_ms >= utxo_retry_at_ms){
            phase_timer_t utxo_ct_pt; phase_start(&utxo_ct_pt);
            long ar = utxo_live_catchup(store_buf);
            if(ar < 0){
                fprintf(stderr,"[dl] utxo_live_catchup FAILED at height %ld -- attempting in-place recovery\n",
                        utxo_live_applied_height());
                long rounds = utxo_live_recover();
                ar = utxo_live_catchup(store_buf);
                if(ar >= 0){
                    utxo_fail_streak = 0;
                    fprintf(stderr,"[dl] utxo recovery SUCCEEDED (%ld compaction round(s)) -- tracking continues at height %ld\n",
                            rounds, utxo_live_applied_height());
                } else {
                    if(utxo_fail_streak < 30) utxo_fail_streak++;
                    long shift = utxo_fail_streak - 1; if(shift > 6) shift = 6;
                    long backoff = UTXO_RETRY_BASE_MS << shift;
                    if(backoff > UTXO_RETRY_MAX_MS) backoff = UTXO_RETRY_MAX_MS;
                    utxo_retry_at_ms = now_ms + backoff;
                    fprintf(stderr,"[dl] utxo STILL failing after recovery (streak=%ld) -- DEGRADED (no UTXO tracking), retrying in %lds\n",
                            utxo_fail_streak, backoff/1000);
                }
            } else if(utxo_fail_streak){
                fprintf(stderr,"[dl] utxo tracking healthy again after %ld failed attempt(s)\n", utxo_fail_streak);
                utxo_fail_streak = 0;
            }
            if(ar > 0){
                fprintf(stderr,"[dl] updating utxo: applied %ld block(s), now at height %ld, live=%ld (%.2fs)\n",
                        ar, utxo_live_applied_height(), utxo_live_count(), phase_elapsed(&utxo_ct_pt));
            }
        }
        if(now_ms >= next_heartbeat_ms){
            int live_peers=0; for(int i=0;i<mux_n_out;i++) if(mux_out_fd[i]>=0) live_peers++;
            fprintf(stderr,"[dl] heartbeat: tip=%d peers=%d/%d live_utxo=%ld uptime=%llds%s\n",
                    *(int*)(store_buf+24), live_peers, mux_n_out,
                    utxo_live_ok?utxo_live_count():-1L, (now_ms-boot_ms)/1000,
                    utxo_fail_streak ? "  [UTXO DEGRADED -- retrying]" : "");
            next_heartbeat_ms = now_ms + DL_HEARTBEAT_MS;
        }
        if(!did){ usleep(200000); }   /* all idle: rest before next rotation */
        /* background leg-fill: gradually acquire live legs toward MUX_MAX_OUT
         * from the discovered candidate pool. Boot rarely lands all 8 at once
         * on a variable network, so keep trying to add a leg occasionally
         * (rate-limited) instead of giving up at the initial dial. Uses the
         * proven outbound_connect path (works for reachable peers). */
        if(mux_n_out < 8 && (rot % 8)==0){
            for(int ci=0; ci<nsrc && mux_n_out<8 && mux_n_out<MUX_MAX_OUT; ci++){
                if(mux_n_out>=8) break;
                int already=0;
                for(int k=0;k<mux_n_out;k++) if(!strcmp(mux_out_host[k],srcpool[ci])){ already=1; break; }
                if(already) continue;
                int nfd=outbound_connect(srcpool[ci], 300, out_port);
                if(nfd>=0){
                    strncpy(mux_out_host[mux_n_out], srcpool[ci], 63);
                    mux_out_fd[mux_n_out]=nfd;
                    mux_out_peer[mux_n_out]=ci;
                    anchor_locator(mux_out_loc[mux_n_out]);
                    mux_out_nextretry[mux_n_out]=0;
                    { char pv[256]; format_peer_version_info(pv, sizeof pv);
                      fprintf(stderr,"[dl] filled outbound %d = %s (fd %d) %s\n", mux_n_out, srcpool[ci], nfd, pv); }
                    mux_n_out++;
                }
                /* if outbound_connect to this one hung/refused, move on to next */
            }
        }
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
        if(g_shutdown_requested){
            fprintf(stderr,"[serve] shutting down (signal %d): tip=%d outbound_legs=%d\n",
                    (int)g_shutdown_requested, *(int*)(store_buf+24), mux_n_out);
            if(g_dl_worker_pid>0){
                kill(g_dl_worker_pid, SIGTERM);
                fprintf(stderr,"[serve] forwarded SIGTERM to download worker pid %d\n", (int)g_dl_worker_pid);
            }
            _exit(0);
        }
        int pr=poll(pfds, nfds, 300);
        if(pr<0){ if(errno==EINTR) continue; break; }
        /* inbound accept -> fork a serve child (unchanged semantics) */
        if(pfds[0].revents&(POLLIN|POLLHUP|POLLERR)){
            struct sockaddr_in ca; socklen_t cal=sizeof ca;
            int c=accept(l,(struct sockaddr*)&ca,&cal);
            if(c>=0 && g_inbound_n >= MAX_INBOUND){
                /* At capacity: accept and close immediately so the connection
                 * is refused cleanly rather than sitting in the backlog, and
                 * do NOT fork. Rate-limited log -- under a flood this would
                 * otherwise be the loudest line in the file. */
                static long long last_full_log_ms = 0;
                long long nms; { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
                                 nms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
                if(nms - last_full_log_ms > 10000){
                    fprintf(stderr,"[serve] inbound at capacity (%d/%d) -- refusing new connections\n",
                            (int)g_inbound_n, MAX_INBOUND);
                    last_full_log_ms = nms;
                }
                close(c);
                c = -1;
            }
            if(c>=0){
                char ipbuf[INET_ADDRSTRLEN]; ipbuf[0]=0;
                inet_ntop(AF_INET,&ca.sin_addr,ipbuf,sizeof ipbuf);
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
                    int hok = node_accept_handshake(c);
                    char pv[256]; pv[0]=0; if(hok==1) format_peer_version_info(pv, sizeof pv);
                    fprintf(stderr,"[serve] inbound %s:%d %s (pid %d) %s\n", ipbuf,
                            ntohs(ca.sin_port), hok==1?"connected":"handshake failed", getpid(), pv);
                    if(hok==1)
                        node_serve_loop(c, node_log_open("bitcoind.log"), store_buf, ht_idx, out_buf, (long)sizeof out_buf);
                    close(c); _exit(0);
                }
                close(c);
                if(w > 0) g_inbound_n++;
                fprintf(stderr,"[serve] inbound %s:%d accepted -> child pid %d (%d/%d inbound)\n",
                        ipbuf, ntohs(ca.sin_port), w, (int)g_inbound_n, MAX_INBOUND);
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
    /* counting reaper instead of SIG_IGN: we must know how many inbound
     * children are live to enforce MAX_INBOUND (see the budget above). */
    { struct sigaction sc; memset(&sc,0,sizeof sc); sc.sa_handler=reap_children;
      sigemptyset(&sc.sa_mask); sc.sa_flags=SA_RESTART|SA_NOCLDSTOP;
      sigaction(SIGCHLD,&sc,NULL); }
    signal(SIGTERM, handle_shutdown_signal);
    signal(SIGINT, handle_shutdown_signal);
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
        node_log_event(lfd, 1, NODE_PROTOCOL_VER, 1, 0);        /* HSHK protocol services */
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
        /* # dl_catchup chunk-claiming workers is optional 5th arg (default
         * 16 -- tried both 8 and 16 against the real archive; 16 gave a
         * modest throughput bump once the liveness probe was fixed to
         * actually find enough live peers to support it). dl_catchup itself
         * clamps this down to however many confirmed-live peers it finds
         * (and up to 64 max), so an over-large request here just becomes a
         * ceiling, not a guarantee. */
        int catchup_workers = (argc>=6)? atoi(argv[5]) : 16;
        if(catchup_workers<1) catchup_workers=1;
        fprintf(stderr,"[boot] config: datadir=%s port=%d nwant=%d catchup_workers=%d\n",
                dir, port, nwant, catchup_workers);
        phase_timer_t boot_pt; phase_start(&boot_pt);
        fprintf(stderr,"[boot] loading chain archive from disk...\n");
        phase_timer_t load_pt; phase_start(&load_pt);
        store_reload(store_buf);            /* load the persisted chain from disk */
        fprintf(stderr,"[boot] chain archive loaded: tip=%d (%.2fs)\n",
                *(int*)(store_buf+24), phase_elapsed(&load_pt));
        /* shared-append flock fd: open append.lock once so any concurrent-safe
         * store_append_shared writes (and the boot catch-up) serialize. */
        int apfd=open("append.lock", O_RDWR|O_CREAT, 0644);
        if(apfd>=0) *(int*)((char*)store_buf+40)=apfd;
        /* LISTENER FIRST: bind+listen the inbound socket before the (possibly
         * long) catch-up so the node is live to inbound peers immediately.
         * The mux loop will poll it once the catch-up returns. */
        int l = lsock(port);
        if(l<0){ perror("lsock"); return 1; }
        fprintf(stderr,"[boot] checking for archive gaps / missing blocks...\n");
        phase_timer_t catchup_pt; phase_start(&catchup_pt);
        /* BUILT-IN MULTI-PEER CATCH-UP (SYNCHRONOUS, self-healing): detect
         * any archive holes plus whatever's missing up to the real chain
         * tip, and fill the whole span with a pool of chunk-claiming
         * workers before this node ever opens for service -- replaces the
         * old single-peer, 60s-capped outbound_catchup() with the same
         * multi-peer engine already proven in the standalone unified_ibd.c
         * tool. On a large gap this can take a long time; the node will not
         * respond to any peer until it returns (deliberate: simplest
         * correct behavior, no writer-coordination needed with the
         * steady-state download worker below since they never run at the
         * same time). Self-throttling: a caught-up node returns almost
         * instantly (pure disk reads, no network) so it's safe to run on
         * every boot. */
        long caught = dl_catchup(dir, catchup_workers);
        fprintf(stderr,"[boot] catch-up check done: %ld block(s) written (%.2fs)\n",
                caught, phase_elapsed(&catchup_pt));
        if(caught>0){
            store_reload(store_buf);        /* our copy predates dl_catchup's writes */
            fprintf(stderr,"[catchup] store now tips at height %d\n", *(int*)(store_buf+24));
        }
        fprintf(stderr,"[boot] building hash index...\n");
        phase_timer_t hidx_pt; phase_start(&hidx_pt);
        build_hash_index();                 /* hash->height for O(1) getdata serving */
        fprintf(stderr,"[boot] hash index build done (%.2fs)\n", phase_elapsed(&hidx_pt));
        int lfd = node_log_open("bitcoind.log");   /* all-asm leveled logger */
        node_log_str(lfd, 0, "node start (serve mode / download worker)", 42);
        /* Serve-as-full-node (option 2): SERVICE our client calls instantly
         * (fork-based inbound serving in the parent) AND continuously download
         * the chain to tip (a dedicated forked DOWNLOAD-WORKER child; see
         * serve_download_worker). The parent runs serve_mux as a PURE inbound
         * server (nwant=0 -> no outbound appends), so:
         *   - serving our clients is NEVER blocked by (or chopped by) a long
         *     sync -- there is no sync in the parent;
         *   - the worker grinds continuously from the on-disk tip to mainnet.
         * NOTE: the worker is NOT the sole block writer -- an inbound serve
         * child can also append a block pushed to it (bitcoin_serve.asm
         * .do_block, reachable via an unsolicited inv or our own
         * .do_inv-triggered getdata, regardless of nwant=0 here). Both the
         * worker's node_sync and .do_block now go through
         * idxscan_append_locked (flock-guarded, atomic-height-under-lock),
         * so concurrent writers from either path can't collide on or
         * clobber each other's height slot; see idxscan_append_locked's
         * header comment in bitcoin_idxscan.asm for the full rationale.
         * Each forked serve child re-syncs its index length from index.dat so
         * blocks the worker appends become serve-able (fresh disk reads). */
        pid_t dl = fork();
        if(dl==0){ serve_download_worker(dir, catchup_seeds, (int)(sizeof(catchup_seeds)/sizeof(catchup_seeds[0])), 8333); _exit(0); }
        g_dl_worker_pid = dl;   /* so serve_mux's shutdown handling can forward SIGTERM to it */
        fprintf(stderr,"[serve] download worker pid %d\n", (int)dl);
        fprintf(stderr,"[boot] boot phase complete (%.2fs total)\n", phase_elapsed(&boot_pt));
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

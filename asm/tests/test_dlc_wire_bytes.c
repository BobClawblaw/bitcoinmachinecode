/* tests/test_dlc_wire_bytes.c -- defect A of the run-28 bench-fidelity batch
 * (2026-09-19): the parallel downloader's sent bytes were never counted.
 *
 * getnettotals.totalbytessent and every download worker's getpeerinfo
 * bytessent stayed at 0 for a whole IBD: run 27 requested ~73 GB of blocks
 * and reported ~0 sent. The parent published `d->bytes_sent = 0` for each
 * worker, the worker's stats slot had no sent counter at all, and nothing
 * counted the header phase's sockets either. The receive side came from the
 * worker process's rchar (file reads included) and restarted every call.
 *
 * The real dl_catchup (daemon/main.c as a TU, test_dlc_interleave's shape)
 * downloads NB blocks from two loopback fixture peers. Each fixture
 * connection records, when it ends, what ITS kernel says crossed the socket:
 * tcpi_bytes_received (everything the node sent it) and tcpi_bytes_acked
 * (everything it sent the node). What is pinned:
 *   - node_status_t.dl_wire_sent == the sum of every fixture connection's
 *     bytes_received, EXACTLY (the node's own count of its sent bytes is the
 *     peers' count of what they received);
 *   - dl_wire_recv == the sum of their bytes_acked, exactly;
 *   - getnettotals reports both;
 *   - while the download runs, a published download peer carries
 *     bytessent > 0 with a "getdata" entry in bytessent_per_msg and a "block"
 *     entry in bytesrecv_per_msg (sampled from g_node_status by a thread).
 *
 * Watched to FAIL with the fix reverted (dl_wire_note returning 0 and the
 * publish's `bytes_sent = 0` restored): dl_wire_sent stays 0 against the
 * fixtures' count, and no sampled dlpeer ever shows bytessent > 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "test_tmpdir.h"

extern void utxo_live_close(void);
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main

static int failures = 0;
static void ckm(const char* l, int cond){
    if (cond) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; }
}

/* the fixture's own account of each connection, shared across its forks */
typedef struct { long accepted, finished; long long rx, tx; } fx_t;
static fx_t* g_fx;
/* the stable uapi prefix of struct tcp_info (the same local mirror the
 * daemon's leg sweep reads by offset) */
struct fx_tcp_info {
    unsigned char  _s[7];
    unsigned int   rto, ato, snd_mss, rcv_mss;
    unsigned int   unacked, sacked, lost, retrans, fackets;
    unsigned int   last_data_sent, last_ack_sent, last_data_recv, last_ack_recv;
    unsigned int   pmtu, rcv_ssthresh, rtt, rttvar, snd_ssthresh, snd_cwnd, advmss, reordering;
    unsigned int   rcv_rtt, rcv_space, total_retrans;
    unsigned long long pacing_rate, max_pacing_rate, bytes_acked, bytes_received;
};
static void fx_tally(int c){
    struct fx_tcp_info ti; socklen_t tl = sizeof ti; memset(&ti, 0, sizeof ti);
    if (getsockopt(c, IPPROTO_TCP, TCP_INFO, &ti, &tl) == 0){
        /* the kernel's bytes_received advances with rcv_nxt, and the node's
         * FIN takes one sequence number: fp_serve returns only on that EOF,
         * so every connection here carries exactly one byte that no data
         * made (a bare probe connection reads rx=1) */
        __sync_fetch_and_add(&g_fx->rx, ti.bytes_received > 0 ? (long long)ti.bytes_received - 1 : 0LL);
        __sync_fetch_and_add(&g_fx->tx, (long long)ti.bytes_acked);
    }
    __sync_fetch_and_add(&g_fx->finished, 1L);
}

/* ---- the chain: the REAL mainnet genesis block at height 0 (dlc_headers
 * seeds headers.dat with g_chainp->genesis and asks peers onward from its
 * hash), then NB-1 coinbase-only blocks at min difficulty. The daemon's
 * chain params are mainnet with the powLimit gate UNARMED (only
 * chainparams_select arms it), the same footing every apply-path fixture
 * stands on. Timestamps rise by one so the header floor (> MTP) holds. */
#define NB 300
#define MAXBLK 512
static unsigned char blocks[NB][MAXBLK];
static long blen[NB];
static unsigned char bh[NB][32];

static const unsigned char GENESIS_HDR[80] = {
    0x01,0x00,0x00,0x00,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
    0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a,
    0x29,0xab,0x5f,0x49, 0xff,0xff,0x00,0x1d, 0x1d,0xac,0x2b,0x7c };
static const unsigned char GENESIS_CB[204] = {
    0x01,0x00,0x00,0x00, 0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xff,0xff,0xff,0xff, 0x4d,
    0x04,0xff,0xff,0x00,0x1d,0x01,0x04,0x45,0x54,0x68,0x65,0x20,0x54,0x69,0x6d,0x65,
    0x73,0x20,0x30,0x33,0x2f,0x4a,0x61,0x6e,0x2f,0x32,0x30,0x30,0x39,0x20,0x43,0x68,
    0x61,0x6e,0x63,0x65,0x6c,0x6c,0x6f,0x72,0x20,0x6f,0x6e,0x20,0x62,0x72,0x69,0x6e,
    0x6b,0x20,0x6f,0x66,0x20,0x73,0x65,0x63,0x6f,0x6e,0x64,0x20,0x62,0x61,0x69,0x6c,
    0x6f,0x75,0x74,0x20,0x66,0x6f,0x72,0x20,0x62,0x61,0x6e,0x6b,0x73,
    0xff,0xff,0xff,0xff,
    0x01,
    0x00,0xf2,0x05,0x2a,0x01,0x00,0x00,0x00, 0x43,
    0x41,0x04,0x67,0x8a,0xfd,0xb0,0xfe,0x55,0x48,0x27,0x19,0x67,0xf1,0xa6,0x71,0x30,
    0xb7,0x10,0x5c,0xd6,0xa8,0x28,0xe0,0x39,0x09,0xa6,0x79,0x62,0xe0,0xea,0x1f,0x61,
    0xde,0xb6,0x49,0xf6,0xbc,0x3f,0x4c,0xef,0x38,0xc4,0xf3,0x55,0x04,0xe5,0x1e,0xc1,
    0x12,0xde,0x5c,0x38,0x4d,0xf7,0xba,0x0b,0x8d,0x57,0x8a,0x4c,0x70,0x2b,0x6b,0xf1,
    0x1d,0x5f,0xac,
    0x00,0x00,0x00,0x00 };

/* single-coinbase block (tests/test_ibd_full.c's builder, timestamp per height) */
static long build_cb_block(unsigned char* b, const unsigned char prev[32], unsigned hgt){
    unsigned char* o=b;
    unsigned char t[200]; memset(t,0,sizeof t);
    unsigned char* q=t;
    put_u32(q,1); q+=4;
    q[0]=1; q+=1;
    memset(q,0,32); q+=32;
    put_u32(q,0xffffffff); q+=4;
    q[0]=3; q[1]=(unsigned char)hgt; q[2]=(unsigned char)(hgt>>8); q[3]=(unsigned char)(hgt>>16); q+=4;
    put_u32(q,0xffffffff); q+=4;
    q[0]=1; q+=1;
    put_u64(q, 8*1000000ULL); q+=8;
    q[0]=1; q[1]=0x51; q+=2;
    put_u32(q,0); q+=4;
    long tlen = q - t;
    unsigned char mr[32]; sha256d(mr, t, tlen);
    put_u32(o,1); o+=4;
    memcpy(o,prev,32); o+=32;
    memcpy(o,mr,32); o+=32;
    put_u32(o,1231006505u + hgt); o+=4;
    put_u32(o,0x207fffff); o+=4;
    put_u32(o,0); o+=4;
    o[0]=1; o+=1;
    memcpy(o,t,(size_t)tlen); o+=tlen;
    return (long)(o - b);
}
static void build_chain(void){
    memcpy(blocks[0], GENESIS_HDR, 80); blocks[0][80] = 1; memcpy(blocks[0]+81, GENESIS_CB, 204);
    blen[0] = 285; block_hash(bh[0], blocks[0]);
    for(int i=1;i<NB;i++){
        blen[i]=build_cb_block(blocks[i], bh[i-1], (unsigned)i);
        unsigned nz=0; while(!pow_check(blocks[i])){ nz++; put_u32(blocks[i]+76,nz); }
        block_hash(bh[i], blocks[i]);
    }
}

/* ---- the fake peer ------------------------------------------------------ */
static int fp_version(int cfd){
    unsigned char v[128]; int o=0;
    put_u32(v+o,70016); o+=4; put_u64(v+o,9); o+=8; put_u64(v+o,(unsigned long long)time(NULL)); o+=8;
    put_u64(v+o,1); o+=8; memset(v+o,0,16); o+=16; v[o++]=0x20; v[o++]=0x8d;   /* addr_recv: NODE_NETWORK|NODE_WITNESS in ours */
    put_u64(v+o,9); o+=8; memset(v+o,0,16); o+=16; v[o++]=0x20; v[o++]=0x8d;   /* addr_from */
    put_u64(v+o,0x1234567ULL); o+=8;                                              /* nonce */
    v[o++]=0;                                                                     /* UA: empty */
    put_u32(v+o,NB-1); o+=4;                                                      /* start_height */
    v[o++]=1;                                                                     /* relay */
    return p2p_write(cfd,"version",7,v,(unsigned)o) > 0;
}
static int g_reverse = 0;   /* answer each getdata backwards (see the getdata handler) */
static int find_hash(const unsigned char* h){ for(int k=0;k<NB;k++) if(!memcmp(bh[k],h,32)) return k; return -1; }
/* one connection: handshake, header pages, blocks with a per-block delay */
static void fp_serve(int cfd, long delay_us){
    static unsigned char rb[1<<16]; static unsigned char out[1 + 2000*81];
    char cmd[12]; unsigned plen=0; int sent_version=0;
    for(;;){
        /* ACK at once (not sticky: re-armed per read). The node writes a
         * message's header and payload separately, so with Nagle on its
         * side the payload waits for our ACK of the header -- a 40 ms
         * delayed-ACK stall per getdata, which would turn this fixture
         * into a 25 blk/s peer whatever the delay below says. */
        { int qa=1; setsockopt(cfd,IPPROTO_TCP,TCP_QUICKACK,&qa,sizeof qa); }
        plen=0; if(p2p_read(cfd,cmd,rb,sizeof rb,&plen)<=0) return;
        cmd[11]=0;
        if(!strncmp(cmd,"version",7)){
            if(!sent_version){ fp_version(cfd); p2p_write(cfd,"verack",6,"",0); sent_version=1; }
        } else if(!strncmp(cmd,"getheaders",10)){
            /* version(4) + count varint + hashes: serve onward from the first hash we know */
            if(plen < 5) continue;
            unsigned cnt = rb[4]; const unsigned char* p = rb+5; int idx=-1;
            for(unsigned k=0;k<cnt && (p+32) <= rb+plen;k++,p+=32){ idx = find_hash(p); if(idx>=0) break; }
            int start = idx<0 ? 0 : idx+1;
            int n = NB - start; if(n>2000) n=2000; if(n<0) n=0;
            int o;
            if(n>=253){ out[0]=0xfd; out[1]=(unsigned char)(n&0xff); out[2]=(unsigned char)((n>>8)&0xff); o=3; }
            else { out[0]=(unsigned char)n; o=1; }
            for(int i=0;i<n;i++){ memcpy(out+o, blocks[start+i], 80); out[o+80]=0; o+=81; }
            p2p_write(cfd,"headers",7,out,(unsigned)o);
        } else if(!strncmp(cmd,"getdata",7)){
            if(plen < 1) continue;
            unsigned cnt = rb[0];
            /* REVERSE mode (2026-09-06): a peer is free to answer a getdata in
             * ANY order, and the BIP152/BIP130 rules say nothing about it. The
             * downloader stored blocks in arrival order, so an out-of-order
             * answer put block h+1 on disk while h was missing -- and the
             * connect loop, which walks heights upward through those writes,
             * then refused a valid block with a false bad-txns-BIP30 (a real
             * sync died at height 48,585). Every fixture peer here used to
             * answer in request order, which is why no test saw it. */
            for(unsigned j=0;j<cnt;j++){
                unsigned k = g_reverse ? (cnt-1-j) : j;
                const unsigned char* p = rb + 1 + (size_t)k*36;
                if(p+36 > rb+plen) continue;
                int f = find_hash(p+4);
                if(delay_us) usleep((useconds_t)delay_us);
                p2p_write(cfd,"block",5, f>=0?blocks[f]:(const unsigned char*)"", f>=0?(unsigned)blen[f]:0);
            }
        } else if(!strncmp(cmd,"ping",4)){
            p2p_write(cfd,"pong",4,rb,(plen>=8)?8:0);
        }
        /* verack, wtxidrelay, sendaddrv2, sendcmpct: nothing to answer */
    }
}
/* a listener on one loopback address (its own process group, so the whole
 * fixture -- listener + per-connection children -- dies with one kill) */
static pid_t start_peer(unsigned ip_host, unsigned short* port_out, long delay_us){
    g_reverse = getenv("BMC_TEST_PEER_REVERSE") ? 1 : 0;
    int ls=socket(AF_INET,SOCK_STREAM,0); int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(ip_host); a.sin_port=0;
    if(bind(ls,(struct sockaddr*)&a,sizeof a)!=0){ perror("bind"); return -1; }
    socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al); *port_out = ntohs(a.sin_port);
    listen(ls,32);
    pid_t p=fork();
    if(p==0){
        setpgid(0,0); signal(SIGPIPE,SIG_IGN); signal(SIGCHLD,SIG_IGN);
        for(;;){ int c=accept(ls,0,0); if(c<0) continue;
                 { int nd=1; setsockopt(c,IPPROTO_TCP,TCP_NODELAY,&nd,sizeof nd); }   /* request/response per block: no Nagle stall */
                 __sync_fetch_and_add(&g_fx->accepted, 1L);
                 pid_t q=fork(); if(q==0){ close(ls); fp_serve(c,delay_us); fx_tally(c); close(c); _exit(0); }
                 close(c); }
    }
    close(ls);
    return p;
}


/* ---- the sampler: what getpeerinfo would have published, every few ms ---- */
static volatile int g_stop = 0;
static long long g_max_dl_sent = 0, g_max_getdata = 0, g_max_block = 0, g_max_dl_recv = 0;
static long g_samples = 0;
static void* sampler(void* arg){
    (void)arg;
    int gi = rpc_msg_index("getdata", 7), bi = rpc_msg_index("block", 5);
    while(!g_stop){
        for(int w = 0; w < 64; w++){
            volatile rpc_peer_t* d = &g_node_status->dlpeers[w];
            if(!d->used) continue;
            if(d->bytes_sent > g_max_dl_sent) g_max_dl_sent = d->bytes_sent;
            if(d->bytes_recv > g_max_dl_recv) g_max_dl_recv = d->bytes_recv;
            if(d->sent_per_msg[gi] > g_max_getdata) g_max_getdata = d->sent_per_msg[gi];
            if(d->recv_per_msg[bi] > g_max_block) g_max_block = d->recv_per_msg[bi];
        }
        g_samples++;
        usleep(2000);
    }
    return 0;
}

int main(void){
    { extern void utxo_live_test_force_sizing(int); utxo_live_test_force_sizing(0); }
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    build_chain();
    printf("chain built: %d blocks\n", NB);
    tt_isolate();
    g_fx = mmap(NULL, sizeof *g_fx, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    g_node_status = mmap(NULL, sizeof *g_node_status, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if(g_fx == MAP_FAILED || g_node_status == MAP_FAILED){ printf("FAIL mmap\n"); return 2; }

    /* two peers, 3 ms per block: the download spans about a second, long
     * enough for the sampler to see the workers' peers published */
    unsigned short ports[2]; pid_t peers[2];
    for(int i=0;i<2;i++){ peers[i] = start_peer(0x7f000001u + (unsigned)i, &ports[i], 3000); if(peers[i] < 0) return 2; }
    g_cfg.connect_only = 1; g_cfg.n_connect = 2;
    for(int i=0;i<2;i++){ snprintf(g_cfg.connectn[i], sizeof g_cfg.connectn[i], "127.0.0.%d", i+1); g_cfg.connectn_port[i] = ports[i]; }
    g_cfg.dead_weight_ticks = 1000000; g_cfg.min_usable_peers = 0;
    utxo_live_set_shutdown_flag(&g_shutdown_requested);
    { extern void utxo_live_set_apply_hook(void (*)(void)); utxo_live_set_apply_hook(dl_apply_hook); }
    { extern void utxo_live_set_reject_fn(long (*)(void*, long, const unsigned char[32], const char*)); utxo_live_set_reject_fn(dl_reject_block); }

    tt_subdir("dl");
    memset(store_buf, 0, sizeof store_buf);
    ckm("store_init", store_init(store_buf) == 1);
    ckm("utxo_live_init", utxo_live_init(".") == 1);
    g_utxo_live_on = 1;
    g_dl_last_seen_tip = (int)node_public_tip(store_buf);
    g_dlc_interleave = 1; g_dlc_connect_budget_ms = 500; g_dlc_idle_ms = 30;

    pthread_t th; pthread_create(&th, 0, sampler, 0);
    long got = dl_catchup(".", 2);
    g_stop = 1; pthread_join(th, 0);
    ckm("dl_catchup wrote every block", got == NB);

    /* every fixture connection has to have ended and tallied: the node's
     * sockets are closed by now (helpers exited, the header phase is over),
     * so each fixture child reads EOF and records its TCP_INFO */
    for(int i = 0; i < 500 && g_fx->finished < g_fx->accepted; i++) usleep(10000);
    printf("     fixture: %ld connection(s) accepted, %ld tallied; peers received %lld B, sent %lld B\n",
           g_fx->accepted, g_fx->finished, g_fx->rx, g_fx->tx);
    printf("     node:    dl_wire_sent %lld B, dl_wire_recv %lld B\n",
           (long long)g_node_status->dl_wire_sent, (long long)g_node_status->dl_wire_recv);
    printf("     sampled dlpeers (%ld samples): max bytessent %lld, max bytesrecv %lld, max getdata %lld, max block %lld\n",
           g_samples, g_max_dl_sent, g_max_dl_recv, g_max_getdata, g_max_block);
    ckm("every fixture connection tallied", g_fx->accepted > 0 && g_fx->finished == g_fx->accepted);
    ckm("the peers received something (the header phase and the getdata)", g_fx->rx > 0);
    ckm("dl_wire_sent == what the peers' kernels received, exactly", g_node_status->dl_wire_sent == g_fx->rx);
    ckm("dl_wire_recv == what the peers sent and the node's kernel acknowledged, exactly", g_node_status->dl_wire_recv == g_fx->tx);
    /* a getdata costs 36 bytes per block plus its header: NB blocks cannot cost less */
    ckm("dl_wire_sent covers a getdata entry for every block (>= NB*36)", g_node_status->dl_wire_sent >= (long long)NB * 36);
    ckm("a published download peer carried bytessent > 0 while the download ran", g_max_dl_sent > 0);
    ckm("...with a getdata entry in its bytessent_per_msg", g_max_getdata > 0);
    ckm("...and a block entry in its bytesrecv_per_msg", g_max_block > 0);
    ckm("...and its bytesrecv is the wire count (at least the block entry)", g_max_dl_recv >= g_max_block && g_max_block > 0);

    /* the RPC a benchmark reads */
    {
        rpc_node_set_status(g_node_status);
        rj_val* r = NULL; long ec = 0; const char* em = NULL;
        int rc = rpc_node_dispatch("getnettotals", NULL, &r, &ec, &em);
        rj_val* ts = r ? rj_obj_get(r, "totalbytessent") : NULL;
        rj_val* tr = r ? rj_obj_get(r, "totalbytesrecv") : NULL;
        long long s = ts ? strtoll(ts->str, NULL, 10) : -1, v = tr ? strtoll(tr->str, NULL, 10) : -1;
        printf("     getnettotals: totalbytessent %lld totalbytesrecv %lld\n", s, v);
        ckm("getnettotals.totalbytessent == what the peers received", rc == 1 && s == g_fx->rx);
        ckm("getnettotals.totalbytesrecv == what the peers sent", rc == 1 && v == g_fx->tx);
        rj_free(r);
    }

    utxo_live_close(); g_utxo_live_on = 0;
    for(int i=0;i<2;i++){ kill(-peers[i], SIGKILL); waitpid(peers[i], 0, 0); }
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}

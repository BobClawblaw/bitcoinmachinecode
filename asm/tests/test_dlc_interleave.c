/* tests/test_dlc_interleave.c -- step 1 of
 * docs/audits/UTXO_INLINE_BUILD_PERF_SCOPE.md (2026-09-06): the parallel
 * downloader connects the UTXO set INSIDE its download loop.
 *
 * The real dl_catchup (daemon/main.c, included as a TU the way
 * test_dial_budget does) runs against three fake peers on loopback -- the
 * fixture shape of tests/test_ibd_full.c: version/verack, header pages off
 * the getheaders locator, block bodies off getdata, with a per-block delay
 * so the download takes a measurable time. Three chunk-claiming helpers
 * pull 40-block chunks from three peers, so heights land OUT OF ORDER:
 * chunk [40,79] can be complete while [0,39] is still in flight.
 *
 * A thread samples (blocks stored, connected height) every few ms for the
 * whole call. What is pinned:
 *   - interleave ON (the default): the connected height RISES while blocks
 *     are still missing from the archive -- a sample with applied >= 0 and
 *     stored < N; at the download gate (dl_catchup returned) the lag between
 *     the contiguous prefix and the connected tip is 0 (the final pass), and
 *     the progress line carries "applied=N lag=M"; the drain afterwards has
 *     nothing left to connect.
 *   - NEGATIVE CONTROL, interleave OFF (g_dlc_interleave = 0, the seam): the
 *     connected height stays at its starting value (-1) in EVERY sample and
 *     at the gate; the drain then connects all N -- the pre-step-1 shape,
 *     download first, connect after.
 *
 * Watched to FAIL before the change: the pre-step-1 monitor loop (nanosleep
 * 10 s, reap, print) leaves applied at -1 through the whole download --
 * "applied rose during the download" and "lag 0 at the gate" fail, and the
 * progress line has no applied= field.
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
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void ckm(const char* l, int cond){
    if (cond) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; }
}
/* put_u32 / put_u64 (little-endian) come from the included main.c */

/* ---- the chain: the REAL mainnet genesis block at height 0 (dlc_headers
 * seeds headers.dat with g_chainp->genesis and asks peers onward from its
 * hash), then NB-1 coinbase-only blocks at min difficulty. The daemon's
 * chain params are mainnet with the powLimit gate UNARMED (only
 * chainparams_select arms it), the same footing every apply-path fixture
 * stands on. Timestamps rise by one so the header floor (> MTP) holds. */
#define NB 600
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
                 pid_t q=fork(); if(q==0){ close(ls); fp_serve(c,delay_us); close(c); _exit(0); }
                 close(c); }
    }
    close(ls);
    return p;
}

/* ---- the sampler: (blocks stored, connected height) every few ms ---- */
typedef struct { long present, applied; long long t_ms; } sample_t;
#define MAXS 200000
static sample_t g_s[MAXS]; static volatile long g_ns = 0; static volatile int g_stop = 0;
static long count_present(int fd){
    static unsigned char rec[NB*48]; long n = pread(fd, rec, sizeof rec, 0) / 48, present = 0;
    for(long i=0;i<n;i++){ int nz=0; for(int j=0;j<48;j++) if(rec[i*48+j]){ nz=1; break; } present += nz; }
    return present;
}
static void* sampler(void* arg){
    int fd = *(int*)arg;
    while(!g_stop && g_ns < MAXS){
        long i = g_ns;
        g_s[i].present = count_present(fd); g_s[i].applied = utxo_live_applied_height(); g_s[i].t_ms = dlc_now_ms();
        g_ns = i + 1;
        usleep(3000);
    }
    return 0;
}

/* stderr -> file around one dl_catchup, so the progress line can be checked */
static int g_saved_stderr = -1;
static void capture_begin(const char* path){
    fflush(stderr); g_saved_stderr = dup(2);
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644); dup2(fd, 2); close(fd);
}
static char* capture_end(const char* path){
    fflush(stderr); dup2(g_saved_stderr, 2); close(g_saved_stderr);
    FILE* f = fopen(path, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char* buf = malloc((size_t)n + 1); size_t got = fread(buf, 1, (size_t)n, f); fclose(f); buf[got] = 0;
    return buf;
}
static const char* last_line_with(const char* text, const char* needle){
    const char* best = 0; const char* p = text;
    while((p = strstr(p, needle))){ best = p; p++; }
    if(!best) return 0;
    while(best > text && best[-1] != '\n') best--;
    return best;
}
static void print_line(const char* l){ if(!l){ printf("     (none)\n"); return; } const char* e = strchr(l,'\n'); printf("     %.*s\n", (int)(e ? e-l : (long)strlen(l)), l); }
/* echo the fixture's own account of the run (peers, span, per-worker rates) */
static void echo_lines_with(const char* text, const char* needle, int max){
    const char* p = text; int n = 0;
    while (*p && n < max){
        const char* e = strchr(p, '\n'); size_t len = e ? (size_t)(e - p) : strlen(p);
        if (memmem(p, len, needle, strlen(needle))){ printf("     %.*s\n", (int)len, p); n++; }
        if (!e) break;
        p = e + 1;
    }
}

/* one full download against the three peers; returns dl_catchup's result */
static long run_download(const char* tag, int interleave, long* out_gate_applied, char** out_log){
    tt_subdir(tag);
    memset(store_buf, 0, sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);
    g_utxo_live_on = 1;                         /* the worker's mirror of utxo_live_ok */
    g_dl_last_seen_tip = (int)node_public_tip(store_buf);
    g_dlc_interleave = interleave;
    g_dlc_connect_budget_ms = 500; g_dlc_idle_ms = 30;   /* the scope's 8 s / 2 s, scaled to a seconds-long download */
    int ifd = open("index.dat", O_RDONLY);
    g_ns = 0; g_stop = 0;
    pthread_t th; pthread_create(&th, 0, sampler, &ifd);
    capture_begin("dlc.log");
    long got = dl_catchup(".", 3);
    *out_log = capture_end("dlc.log");
    g_stop = 1; pthread_join(th, 0); close(ifd);
    *out_gate_applied = utxo_live_applied_height();
    return got;
}

int main(void){
    /* 2026-09-09: a fresh datadir takes the dbcache-sized bulk memtable by
     * itself now; this test is about the interleave and its lag assertions
     * are timing-sensitive under the gate's load, so it keeps the small
     * memtable its expectations were written against. */
    { extern void utxo_live_test_force_sizing(int); utxo_live_test_force_sizing(0); }
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    build_chain();
    printf("chain built: %d blocks, genesis %02x%02x..\n", NB, bh[0][31], bh[0][30]);
    tt_isolate();

    /* three peers on 127.0.0.1/2/3, 4 ms per block: ~1 s per download */
    unsigned short ports[3]; pid_t peers[3];
    for(int i=0;i<3;i++){ peers[i] = start_peer(0x7f000001u + (unsigned)i, &ports[i], 4000); if(peers[i] < 0) return 2; }
    g_cfg.connect_only = 1; g_cfg.n_connect = 3;
    for(int i=0;i<3;i++){ snprintf(g_cfg.connectn[i], sizeof g_cfg.connectn[i], "127.0.0.%d", i+1); g_cfg.connectn_port[i] = ports[i]; }
    g_cfg.dead_weight_ticks = 1000000; g_cfg.min_usable_peers = 0;
    utxo_live_set_shutdown_flag(&g_shutdown_requested);
    { extern void utxo_live_set_apply_hook(void (*)(void)); utxo_live_set_apply_hook(dl_apply_hook); }
    { extern void utxo_live_set_reject_fn(long (*)(void*, long, const unsigned char[32], const char*)); utxo_live_set_reject_fn(dl_reject_block); }

    /* ---------------- interleave ON ---------------- */
    printf("\n-- interleave on: connect inside the download loop\n");
    {
        long gate_applied; char* log;
        long got = run_download("on", 1, &gate_applied, &log);
        echo_lines_with(log, "confirmed-live", 1); echo_lines_with(log, "[dlc] headers", 1); echo_lines_with(log, "[dlc] span", 1);
        echo_lines_with(log, "[dlc]   w", 3); echo_lines_with(log, "done: blocks", 3);
        ck("dl_catchup wrote every block", got, NB);
        long present_gate = 0; { int fd = open("index.dat", O_RDONLY); present_gate = count_present(fd); close(fd); }
        ck("archive complete at the gate", present_gate, NB);
        /* 2026-09-08: three workers, one committer -- the archive's (file, offset)
         * must increase with height. Before the committer the workers appended
         * in arrival order and this was the boot check's "NOT laid out
         * monotonically (first break at height 41)". */
        { extern long archive_layout_monotonic(long upto);
          long first_break = archive_layout_monotonic(idxscan_tip());
          ck("archive laid out monotonically after a 3-worker download (first break -1)", first_break, -1);
          const char* cl = last_line_with(log, "committer:"); print_line(cl);
          ck("the committer reported its chunks", cl != 0, 1); }
        /* the gate: everything stored, and the lag is what ONE budget-bounded
         * pass leaves behind -- bounded by a chunk here, never a download's
         * worth (the pre-step-1 loop left all NB) */
        printf("     connected tip at the gate: %ld (lag %ld)\n", gate_applied, (NB-1) - gate_applied);
        ckm("the connected tip at the gate is within a chunk of the archive tip (lag bounded)", (NB-1) - gate_applied <= DLC_CHUNK_BLOCKS);
        ckm("...and far past where the pre-step-1 loop left it (-1)", gate_applied >= NB - 1 - DLC_CHUNK_BLOCKS);
        /* the sample trace: did applied rise while blocks were still missing? */
        long ns = g_ns, first_rise = -1, best_gap = -1, ooo = 0;
        for(long i=0;i<ns;i++){
            if(g_s[i].applied >= 0 && g_s[i].present < NB){
                if(first_rise < 0) first_rise = i;
                long gap = NB - g_s[i].present; if(gap > best_gap) best_gap = gap;
            }
            /* stored but not contiguous: present > applied+1 means a later chunk landed first */
            if(g_s[i].present > g_s[i].applied + 1 + 40) ooo++;
        }
        printf("     %ld samples over %lld ms; first sample with applied>=0 while incomplete: #%ld", ns, ns ? g_s[ns-1].t_ms - g_s[0].t_ms : 0, first_rise);
        if(first_rise >= 0) printf(" (stored %ld, applied %ld)", g_s[first_rise].present, g_s[first_rise].applied);
        printf("; max blocks still missing while connected: %ld; out-of-order samples: %ld\n", best_gap, ooo);
        ckm("the connected height ROSE DURING the download (before the last block landed)", first_rise >= 0);
        ckm("...and by a margin, not just the last block", best_gap >= 40);
        ckm("blocks arrived out of order (some sample had > a chunk stored beyond the connected tip)", ooo > 0);
        const char* pl = last_line_with(log, "[dlc] == elapsed");
        print_line(pl);
        { long pa = -9, plag = -9;
          if(pl){ const char* a = strstr(pl, "applied="); if(a) sscanf(a, "applied=%ld lag=%ld", &pa, &plag); }
          printf("     progress line parsed: applied=%ld lag=%ld\n", pa, plag);
          ckm("the progress line carries applied=N lag=M", pl && pa >= 0 && plag >= 0);
          ckm("...with applied + lag == the contiguous prefix at that tick (the archive was complete: 599)", pa + plag == NB - 1); }
        { const char* sl = last_line_with(log, "block(s) during the download"); print_line(sl);
          long ct = -9; if(sl){ const char* c = strstr(sl, "connected tip "); if(c) sscanf(c, "connected tip %ld", &ct); }
          ckm("the download-end summary reports the connected tip at the gate", sl && ct == gate_applied); }
        /* 2026-09-08: in IBD (this fixture's timestamps are old) the choke
         * point prints one line saying the per-block lines are off, not a
         * line per batch -- either is proof it fired before the gate */
        ckm("the choke point fired during the download (a new-block line, or the once-only IBD line, before the gate)",
            strstr(log, "[dl] new block: height=") != NULL || strstr(log, "[dl] per-block lines and tip announcements are off") != NULL);
        ck("the drain afterwards connects exactly the gate lag", utxo_live_catchup(store_buf), (NB-1) - gate_applied);
        ck("connected tip == NB-1 after the drain", utxo_live_applied_height(), NB-1);
        ck("live count == NB-1 (the genesis coinbase is not in the set, as in Core)", utxo_live_count(), NB-1);
        free(log);
        utxo_live_close(); g_utxo_live_on = 0;
    }

    /* ---------------- NEGATIVE CONTROL: interleave OFF ---------------- */
    printf("\n-- interleave off (the seam): the pre-step-1 loop\n");
    {
        long gate_applied; char* log;
        long got = run_download("off", 0, &gate_applied, &log);
        ck("dl_catchup wrote every block", got, NB);
        ck("connected tip at the gate is still the starting value (-1)", gate_applied, -1);
        long ns = g_ns, moved = 0;
        for(long i=0;i<ns;i++) if(g_s[i].applied != -1) moved++;
        printf("     %ld samples; %ld with applied != -1\n", ns, moved);
        ck("applied stayed at its starting value in EVERY sample until the gate", moved, 0);
        const char* pl = last_line_with(log, "[dlc] == elapsed");
        print_line(pl);
        ckm("the progress line says the interleave is off", pl && strstr(pl, "(interleave off)"));
        ckm("no block was connected during the download (no new-block line)", strstr(log, "[dl] new block: height=") == NULL);
        ck("the drain afterwards connects all NB (download first, connect after)", utxo_live_catchup(store_buf), NB);
        ck("connected tip == NB-1 after the drain", utxo_live_applied_height(), NB-1);
        free(log);
        utxo_live_close(); g_utxo_live_on = 0;
    }

    for(int i=0;i<3;i++){ kill(-peers[i], SIGKILL); waitpid(peers[i], 0, 0); }
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}

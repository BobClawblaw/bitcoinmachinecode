/* tests/test_dlc_header_probe.c -- the header phase asks several peers for
 * the first page and syncs from the fastest (2026-10-05, plan B5).
 *
 * The real dlc_headers (daemon/main.c, included as a TU the way
 * test_dlc_peer_parse does) runs against four fake peers on loopback, each
 * with its own delay before the first page, an optional stall after N pages
 * and an optional first page that does not link. Pinned:
 *   - the probe names every candidate's rate and the fastest leads: the
 *     whole chain comes from it;
 *   - a leader that stops answering after a page is given up and the next
 *     candidate completes the chain (before: the phase ended on the stalled
 *     peer's partial chain);
 *   - a candidate whose first page does not link to our locator is ranked
 *     last and never leads;
 *   - bmc.dlshape=core: no probe, the first live peer serves (Core's single
 *     header-sync peer);
 *   - B12's ranges (2026-10-08): with anchors at 4,000, 8,000 and 12,000 the
 *     probed peers fetch the three ranges in parallel; the ranges are stored
 *     through the same checks and the sequential fetch takes the rest; a
 *     wrong anchor gives its range up and only shortens what is stored; a
 *     prefix held below -minimumchainwork is carried into the sequential
 *     fetch (3 pages from height 8,000, not 7 from genesis); the pool's
 *     announced height bounds the anchors; a peer that slows on its range
 *     has it taken back for a waiting peer; bmc.dlshape=core runs no ranges.
 *   - B12 (2026-10-07): a leader that answers its first page fast and then
 *     slows under half the runner-up's probed rate is switched; the runner-up
 *     continues from where it stopped -- the stored pages kept and, with the
 *     -minimumchainwork floor armed, the held (unstored) pages carried -- and
 *     serves only the rest of the chain, counted page by page at the peer.
 *
 * B12 watched to FAIL with the switch's break removed (the slow leader
 * serves the whole chain), with the hold not carried (the runner-up refetches
 * from genesis: 7 pages, not 4) and with the stored pages rolled back on a
 * switch.
 *
 * B12's ranges watched to FAIL with the ranges call removed, with the
 * range's end-of-range anchor check removed (the wrong anchor's range is
 * stored), with the replay's hold not carried (the sequential fetch
 * refetches from genesis) and with the straggler takeback removed.
 *
 * Watched to FAIL with the probe call removed (the first candidate leads
 * whatever its speed), with the stall branch removed (the chain ends at the
 * stalled page) and with the probe's link check removed (the bad page's
 * peer leads).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_tmpdir.h"

#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void ckm(const char* l, int cond){ if (cond) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; } }

/* ---- the chain: mainnet genesis, then NB-1 headers at min difficulty (the
 * test TU's chain params are mainnet with the powLimit gate unarmed, the
 * footing test_dlc_interleave stands on); timestamps rise by one so the
 * header floor (> MTP) holds. 14,000 = six full pages after genesis and a
 * short one, enough for a switch partway. */
#define NB 14000
static unsigned char hdrs[NB][80];
static unsigned char bh[NB][32];
static const unsigned char GENESIS_HDR[80] = {
    0x01,0x00,0x00,0x00,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
    0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a,
    0x29,0xab,0x5f,0x49, 0xff,0xff,0x00,0x1d, 0x1d,0xac,0x2b,0x7c };
static void build_chain(void){
    memcpy(hdrs[0], GENESIS_HDR, 80); block_hash(bh[0], hdrs[0]);
    for(int i=1;i<NB;i++){
        unsigned char* h = hdrs[i];
        put_u32(h, 1); memcpy(h+4, bh[i-1], 32); memset(h+36, (unsigned char)i, 32);
        put_u32(h+68, 1231006505u + (unsigned)i); put_u32(h+72, 0x207fffff); put_u32(h+76, 0);
        unsigned nz=0; while(!pow_check(h)){ nz++; put_u32(h+76, nz); }
        block_hash(bh[i], h);
    }
}

/* ---- the fake peer: handshake, then header pages off the locator ---------- */
typedef struct { long first_delay_ms; int stall_after_pages; int bad_link; int slow_after_pages; long slow_page_ms;
                 long slow_conn_ms; } fp_opts_t;   /* slow_conn_ms: every page on this peer's 2nd and later connections (B12 ranges) */
static volatile int* g_served;   /* MAP_SHARED: header pages each peer has sent, probe included (B12) */
static int fp_version(int cfd){
    unsigned char v[128]; int o=0;
    put_u32(v+o,70016); o+=4; put_u64(v+o,9); o+=8; put_u64(v+o,(unsigned long long)time(NULL)); o+=8;
    put_u64(v+o,1); o+=8; memset(v+o,0,16); o+=16; v[o++]=0x20; v[o++]=0x8d;
    put_u64(v+o,9); o+=8; memset(v+o,0,16); o+=16; v[o++]=0x20; v[o++]=0x8d;
    put_u64(v+o,0x1234567ULL); o+=8;
    v[o++]=0;
    put_u32(v+o,NB-1); o+=4;
    v[o++]=1;
    return p2p_write(cfd,"version",7,v,(unsigned)o) > 0;
}
static int find_hash(const unsigned char* h){ for(int k=0;k<NB;k++) if(!memcmp(bh[k],h,32)) return k; return -1; }
static void fp_serve(int cfd, const fp_opts_t* op, int who, int conn){
    static unsigned char rb[1<<16]; static unsigned char out[3 + 2000*81];
    char cmd[12]; unsigned plen=0; int sent_version=0; int pages=0;
    for(;;){
        plen=0; if(p2p_read(cfd,cmd,rb,sizeof rb,&plen)<=0) return;
        cmd[11]=0;
        if(!strncmp(cmd,"version",7)){
            if(!sent_version){ fp_version(cfd); p2p_write(cfd,"verack",6,"",0); sent_version=1; }
        } else if(!strncmp(cmd,"getheaders",10)){
            if(plen < 5) continue;
            unsigned cnt = rb[4]; const unsigned char* p = rb+5; int idx=-1;
            for(unsigned k=0;k<cnt && (p+32) <= rb+plen;k++,p+=32){ idx = find_hash(p); if(idx>=0) break; }
            if(op->stall_after_pages && pages >= op->stall_after_pages){ sleep(60); return; }   /* served its pages, then silence */
            if(pages == 0 && op->first_delay_ms) usleep((useconds_t)(op->first_delay_ms * 1000));
            if(op->slow_after_pages && pages >= op->slow_after_pages) usleep((useconds_t)(op->slow_page_ms * 1000));
            if(op->slow_conn_ms && conn > 0) usleep((useconds_t)(op->slow_conn_ms * 1000));
            int start = idx<0 ? 0 : idx+1;
            int n = NB - start; if(n>2000) n=2000; if(n<0) n=0;
            int o;
            if(n>=253){ out[0]=0xfd; out[1]=(unsigned char)(n&0xff); out[2]=(unsigned char)((n>>8)&0xff); o=3; }
            else { out[0]=(unsigned char)n; o=1; }
            for(int i=0;i<n;i++){ memcpy(out+o, hdrs[start+i], 80); out[o+80]=0; o+=81; }
            if(op->bad_link && n > 0) memset(out + (n>=253 ? 3 : 1) + 4, 0xEE, 32);   /* the first header's prev is nothing we hold */
            p2p_write(cfd,"headers",7,out,(unsigned)o);
            pages++; __sync_fetch_and_add(&g_served[who], 1);
        } else if(!strncmp(cmd,"ping",4)){
            p2p_write(cfd,"pong",4,rb,(plen>=8)?8:0);
        }
    }
}
static long g_announce = 0;   /* what every fake peer's version claims, as the ranking handshakes would record it */
static pid_t start_peer(unsigned ip_host, unsigned short* port_out, const fp_opts_t* op, int who){
    int ls=socket(AF_INET,SOCK_STREAM,0); int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(ip_host); a.sin_port=0;
    if(bind(ls,(struct sockaddr*)&a,sizeof a)!=0){ perror("bind"); return -1; }
    socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al); *port_out = ntohs(a.sin_port);
    listen(ls,32);
    pid_t p=fork();
    if(p==0){
        setpgid(0,0); signal(SIGPIPE,SIG_IGN); signal(SIGCHLD,SIG_IGN);
        int conn=0;
        for(;;){ int c=accept(ls,0,0); if(c<0) continue;
                 { int nd=1; setsockopt(c,IPPROTO_TCP,TCP_NODELAY,&nd,sizeof nd); }
                 pid_t q=fork(); if(q==0){ close(ls); fp_serve(c,op,who,conn); close(c); _exit(0); }
                 conn++; close(c); }
    }
    close(ls);
    return p;
}
static void stop_peers(pid_t* p, int n){ for(int i=0;i<n;i++) if(p[i]>0){ kill(-p[i], SIGKILL); kill(p[i], SIGKILL); } for(int i=0;i<n;i++) if(p[i]>0) waitpid(p[i],0,0); }

/* stderr -> file around one dlc_headers, so its lines can be checked */
static int g_saved_stderr = -1;
static void capture_begin(const char* path){ fflush(stderr); g_saved_stderr = dup(2); int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644); dup2(fd, 2); close(fd); }
static char* capture_end(const char* path){
    fflush(stderr); dup2(g_saved_stderr, 2); close(g_saved_stderr);
    FILE* f = fopen(path, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char* buf = malloc((size_t)n + 1); size_t got = fread(buf, 1, (size_t)n, f); fclose(f); buf[got] = 0;
    return buf;
}
static const char* line_with(const char* text, const char* needle){
    const char* p = strstr(text, needle); if(!p) return 0;
    while(p > text && p[-1] != '\n') p--;
    return p;
}
static void print_line(const char* l){ if(!l){ printf("     (none)\n"); return; } const char* e = strchr(l,'\n'); printf("     %.*s\n", (int)(e ? e-l : (long)strlen(l)), l); }
/* "[dlc] headers +N from PEER (total T)": the peer the chain came from */
static int served_by(const char* log, const char* peer){
    const char* l = line_with(log, "[dlc] headers +"); if(!l) return 0;
    const char* e = strchr(l, '\n'); size_t len = e ? (size_t)(e-l) : strlen(l);
    char buf[64]; snprintf(buf, sizeof buf, "from %s ", peer);
    return memmem(l, len, buf, strlen(buf)) != 0;
}

/* one header phase against four peers; returns dlc_headers' result */
static long run_phase(const char* tag, const fp_opts_t* ops, char peer[4][DL_POOL_SLOT], char** out_log){
    tt_subdir(tag);
    memset(store_buf, 0, sizeof store_buf);
    unsigned short ports[4]; pid_t pids[4];
    for(int i=0;i<4;i++) g_served[i] = 0;
    for(int i=0;i<4;i++){ pids[i] = start_peer(0x7f000001u + (unsigned)i, &ports[i], &ops[i], i); if(pids[i] < 0) return -2; }
    static char live[4][DL_POOL_SLOT]; memset(live, 0, sizeof live);
    for(int i=0;i<4;i++){ snprintf(live[i], DL_POOL_SLOT, "127.0.0.%d:%u", i+1, (unsigned)ports[i]); memcpy(peer[i], live[i], DL_POOL_SLOT); }
    for(int i=0;i<DLC_MAXPOOL;i++) g_live_announced[i] = i < 4 ? g_announce : 0;
    capture_begin("hdr.log");
    long got = dlc_headers(live, 4);
    *out_log = capture_end("hdr.log");
    stop_peers(pids, 4);
    return got;
}

/* ---- an armed -minimumchainwork floor for the hold-carry case: the chain
 * clears it at height FLOOR_H (genesis's work + 2 per min-difficulty header) */
extern void block_work(unsigned char*, unsigned); extern void chainwork_add(unsigned char*, const unsigned char*, const unsigned char*);
extern long chainwork_cmp(const unsigned char a[16], const unsigned char b[16]);
extern void reorg_set_min_chain_work(const unsigned char be32[32]);
#define FLOOR_H 10000
static unsigned char g_floor_work[16];
static int floor_at_h(const unsigned char work[16]){ return chainwork_cmp(work, g_floor_work) >= 0; }
static void arm_floor(int on){
    if(!on){ unsigned char z[32]; memset(z, 0, 32); reorg_set_min_chain_work(z); lowwork_set_floor_fn(NULL); return; }
    unsigned char w[16]; memset(g_floor_work, 0, 16);
    for(int i=0;i<=FLOOR_H;i++){ unsigned bits = hdrs[i][72] | (hdrs[i][73]<<8) | (hdrs[i][74]<<16) | ((unsigned)hdrs[i][75]<<24); block_work(w, bits); chainwork_add(g_floor_work, g_floor_work, w); }
    unsigned char be[32]; memset(be, 0, 32); be[31] = 1; reorg_set_min_chain_work(be);   /* armed; the test's floor fn decides */
    lowwork_set_floor_fn(floor_at_h);
}

int main(void){
    signal(SIGPIPE, SIG_IGN);
    g_served = mmap(NULL, 4 * sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    build_chain();
    printf("chain built: %d headers\n", NB);
    tt_isolate();
    g_cfg.dead_weight_ticks = 1000000; g_cfg.min_usable_peers = 0;
    g_dlc_hr_n_test = 0;                                  /* B12's ranges: off until their own cases below */
    char peer[4][DL_POOL_SLOT]; char* log;

    printf("\n-- the fastest first page leads\n");
    { fp_opts_t ops[4] = { {300,0,0}, {50,0,0}, {600,0,0}, {900,0,0} };
      g_cfg.dl_shape_core = 0;
      long got = run_phase("fastest", ops, peer, &log);
      print_line(line_with(log, "[dlc] header probe")); print_line(line_with(log, "[dlc] headers +"));
      ck("the whole chain was fetched", got, NB);
      ckm("the probe line names all four candidates", line_with(log, "[dlc] header probe") && strstr(log, peer[0]) && strstr(log, peer[1]) && strstr(log, peer[2]) && strstr(log, peer[3]));
      { char lead[128]; snprintf(lead, sizeof lead, "-- %s leads", peer[1]); ckm("the 50 ms peer leads", strstr(log, lead) != 0); }
      ckm("the chain came from the 50 ms peer", served_by(log, peer[1]));
      free(log); }

    printf("\n-- the leader stops answering after one page: the next candidate takes over\n");
    { fp_opts_t ops[4] = { {200,0,0}, {20,1,0}, {300,0,0}, {400,0,0} };
      g_cfg.dl_shape_core = 0;
      long got = run_phase("stall", ops, peer, &log);
      print_line(line_with(log, "[dlc] header probe")); print_line(line_with(log, "stopped answering")); print_line(line_with(log, "[dlc] headers +"));
      { char lead[128]; snprintf(lead, sizeof lead, "-- %s leads", peer[1]); ckm("the 20 ms peer led the probe", strstr(log, lead) != 0); }
      ckm("the stall was named", line_with(log, "stopped answering after +2000") != 0);
      ck("the whole chain was still fetched", got, NB);
      ckm("the chain came from the next candidate, the 200 ms peer", served_by(log, peer[0]));
      free(log); }

    printf("\n-- a first page that does not link is ranked last\n");
    { fp_opts_t ops[4] = { {10,0,1}, {100,0,0}, {500,0,0}, {700,0,0} };
      g_cfg.dl_shape_core = 0;
      long got = run_phase("badlink", ops, peer, &log);
      print_line(line_with(log, "[dlc] header probe")); print_line(line_with(log, "[dlc] headers +"));
      ck("the whole chain was fetched", got, NB);
      { char bad[128]; snprintf(bad, sizeof bad, "%s page does not link", peer[0]); ckm("the bad page's peer is named as not linking", strstr(log, bad) != 0); }
      { char lead[128]; snprintf(lead, sizeof lead, "-- %s leads", peer[1]); ckm("the 100 ms peer leads, not the faster bad one", strstr(log, lead) != 0); }
      ckm("the chain came from the 100 ms peer", served_by(log, peer[1]));
      free(log); }

    printf("\n-- bmc.dlshape=core: one header peer, no probe\n");
    { fp_opts_t ops[4] = { {300,0,0}, {20,0,0}, {20,0,0}, {20,0,0} };
      g_cfg.dl_shape_core = 1;
      long got = run_phase("core", ops, peer, &log);
      print_line(line_with(log, "[dlc] headers +"));
      ck("the whole chain was fetched", got, NB);
      ckm("no probe ran", line_with(log, "[dlc] header probe") == 0);
      ckm("the first live peer served, Core's single pick", served_by(log, peer[0]));
      g_cfg.dl_shape_core = 0;
      free(log); }

    /* B12: the leader answers its first page in 20 ms and every page after
     * its first in 300 ms (0.5 MB/s); the runner-up's probe page took 100 ms
     * (~1.6 MB/s), so the bar is ~0.8 MB/s. With a 2-page window the leader is
     * judged after pages 0-1 (~1 MB/s, kept) and 1-2 (~0.5 MB/s, switched):
     * three pages, through height 6,000, then the runner-up serves the four
     * that remain -- plus its one probe page. */
    g_dlc_hdr_switch_pages = 2;
    printf("\n-- B12: the leader slows after its first page: the runner-up continues, the stored pages kept\n");
    { fp_opts_t ops[4] = { {100,0,0,0,0}, {20,0,0,1,300}, {400,0,0,0,0}, {600,0,0,0,0} };
      g_cfg.dl_shape_core = 0;
      long got = run_phase("switch", ops, peer, &log);
      print_line(line_with(log, "[dlc] header probe")); print_line(line_with(log, "fell to")); print_line(line_with(log, "[dlc] headers +"));
      { char lead[128]; snprintf(lead, sizeof lead, "-- %s leads", peer[1]); ckm("the 20 ms peer led the probe", strstr(log, lead) != 0); }
      ckm("the switch was named, at height 6000 with 6000 stored kept", line_with(log, "switching at height 6000 (+6000 stored, 0 page(s) held") != 0);
      ck("the whole chain was fetched", got, NB);
      ckm("the rest of the chain came from the runner-up, the 100 ms peer", served_by(log, peer[0]));
      ckm("  as +7999 headers: nothing was refetched", line_with(log, "[dlc] headers +7999 from") != 0);
      ck("the runner-up sent its probe page and the 4 after height 6000", g_served[0], 5);
      ck("the slow leader sent its probe page and 3", g_served[1], 4);
      ckm("no hold to drop", line_with(log, "hold is dropped") == 0);
      free(log); }

    printf("\n-- B12 with the floor armed: the switch carries the held pages\n");
    { fp_opts_t ops[4] = { {100,0,0,0,0}, {20,0,0,1,300}, {400,0,0,0,0}, {600,0,0,0,0} };
      g_cfg.dl_shape_core = 0; arm_floor(1);
      long got = run_phase("carry", ops, peer, &log);
      arm_floor(0);
      print_line(line_with(log, "fell to")); print_line(line_with(log, "crossed -minimumchainwork")); print_line(line_with(log, "[dlc] headers +"));
      ckm("the switch carried 3 held pages, nothing stored yet", line_with(log, "switching at height 6000 (+0 stored, 3 page(s) held and carried)") != 0);
      ckm("the runner-up continued the hold (no drop)", line_with(log, "hold is dropped") == 0);
      ckm("the chain crossed the floor holding 4 pages (3 carried + 1)", line_with(log, "crossed -minimumchainwork -- storing 4 held page(s)") != 0);
      ck("the whole chain was fetched", got, NB);
      ckm("it came from the runner-up", served_by(log, peer[0]));
      ck("the runner-up sent its probe page and the 4 after height 6000, not 7 from genesis", g_served[0], 5);
      free(log); }
    g_dlc_hdr_switch_pages = DLC_HDR_SWITCH_PAGES;

    /* ---- B12's ranges: anchors at 4,000 / 8,000 / 12,000 --------------------
     * Every peer answers its probe page at its own delay and every page after
     * in 40 ms. Range pages: (0,4000] and (4000,8000] and (8000,12000] are two
     * pages each; the sequential fetch takes 12,001..13,999 (one short page). */
    static char ahex[3][65]; static struct hdr_anchor anc[3];
    for(int a=0;a<3;a++){ int h=(a+1)*4000; for(int q=0;q<32;q++) snprintf(ahex[a]+2*q, 3, "%02x", bh[h][31-q]); anc[a].height=h; anc[a].hash=ahex[a]; }
    g_dlc_hr_anchors_test = anc; g_dlc_hr_n_test = 3; g_announce = NB-1;
    int sum;

    printf("\n-- B12 ranges: three ranges in parallel, stored through the checks, the rest sequential\n");
    { fp_opts_t ops[4] = { {60,0,0,1,40}, {20,0,0,1,40}, {40,0,0,1,40}, {80,0,0,1,40} };
      g_cfg.dl_shape_core = 0;
      long got = run_phase("ranges", ops, peer, &log);
      print_line(line_with(log, "header ranges: 3 range")); print_line(line_with(log, "header ranges: 3 of")); print_line(line_with(log, "stored through the checks")); print_line(line_with(log, "[dlc] headers +"));
      ckm("three ranges from height 0 to 12000 across four peers", line_with(log, "header ranges: 3 range(s) from height 0 to 12000 (anchors every 4000) across 4 peer(s)") != 0);
      ckm("all three finished, 1..12000 contiguous", line_with(log, "header ranges: 3 of 3 range(s)") != 0 && line_with(log, "heights 1..12000 are contiguous") != 0);
      ckm("+12000 stored through the checks", line_with(log, "header ranges: +12000 stored through the checks (total 12001)") != 0);
      ckm("the sequential fetch took the last 1999", line_with(log, "[dlc] headers +1999 from") != 0);
      ck("the whole chain was fetched", got, NB);
      { int busy=0; for(int i=0;i<4;i++) if(g_served[i] > 1) busy++; ckm("more than one peer served range pages", busy >= 2); }
      sum=0; for(int i=0;i<4;i++) sum+=g_served[i];
      ck("pages served: 4 probe + 6 range + 1 sequential", sum, 11);
      { int fd=open("headers.dat",O_RDONLY); unsigned char rec[112]; int same=1;
        for(int h=0;h<NB && same;h+=997){ if(pread(fd,rec,112,(off_t)h*112)!=112 || memcmp(rec+80,bh[h],32)) same=0; }
        if(pread(fd,rec,112,(off_t)(NB-1)*112)!=112 || memcmp(rec+80,bh[NB-1],32)) same=0;
        close(fd); ckm("headers.dat holds the chain, height for height", same); }
      free(log); }

    printf("\n-- B12 ranges: a wrong anchor gives its ranges up and only shortens what is stored\n");
    { memset(ahex[1], 'e', 64); ahex[1][64]=0;            /* the 8,000 anchor names no block */
      fp_opts_t ops[4] = { {60,0,0,1,40}, {20,0,0,1,40}, {40,0,0,1,40}, {80,0,0,1,40} };
      long got = run_phase("ranges-bad", ops, peer, &log);
      for(int q=0;q<32;q++) snprintf(ahex[1]+2*q, 3, "%02x", bh[8000][31-q]);
      print_line(line_with(log, "header ranges: 1 of")); print_line(line_with(log, "header ranges: range")); print_line(line_with(log, "stored through the checks")); print_line(line_with(log, "[dlc] headers +"));
      ckm("only the first range finished: 1..4000 contiguous", line_with(log, "header ranges: 1 of 3 range(s)") != 0 && line_with(log, "heights 1..4000 are contiguous -- the sequential fetch continues from there") != 0);
      ckm("the wrong anchor's range was given up after 3 peers tried it", line_with(log, "header ranges: range 1 (heights 4001..8000) was given up after 3 attempt(s)") != 0);
      ckm("+4000 stored through the checks", line_with(log, "header ranges: +4000 stored through the checks (total 4001)") != 0);
      ck("the whole chain was fetched", got, NB);
      { int fd=open("headers.dat",O_RDONLY); unsigned char rec[112]; int ok8 = pread(fd,rec,112,(off_t)8000*112)==112 && !memcmp(rec+80,bh[8000],32); close(fd);
        ckm("height 8000 holds the real block, not the anchor's", ok8); }
      free(log); }

    printf("\n-- B12 ranges with the floor armed and the pool announcing 9000: two ranges held, the hold carried\n");
    { g_announce = 9000;                                   /* the 12,000 anchor is past the pool's claim */
      fp_opts_t ops[4] = { {60,0,0,1,40}, {20,0,0,1,40}, {40,0,0,1,40}, {80,0,0,1,40} };
      arm_floor(1);
      long got = run_phase("ranges-hold", ops, peer, &log);
      arm_floor(0); g_announce = NB-1;
      print_line(line_with(log, "header ranges: 2 range")); print_line(line_with(log, "stored through the checks")); print_line(line_with(log, "crossed -minimumchainwork")); print_line(line_with(log, "[dlc] headers +"));
      ckm("two ranges, to 8000 (the announcement bounds the anchors)", line_with(log, "header ranges: 2 range(s) from height 0 to 8000") != 0);
      ckm("nothing stored, held through height 8000", line_with(log, "header ranges: +0 stored through the checks (total 1), the rest held below -minimumchainwork through height 8000") != 0);
      ckm("the sequential fetch continued the hold (no drop)", line_with(log, "hold is dropped") == 0);
      ckm("the chain crossed the floor storing the 4 carried pages", line_with(log, "crossed -minimumchainwork -- storing 4 held page(s)") != 0);
      ck("the whole chain was fetched", got, NB);
      sum=0; for(int i=0;i<4;i++) sum+=g_served[i];
      ck("pages served: 4 probe + 4 range + 3 sequential from height 8000 (not 7 from genesis)", sum, 11);
      free(log); }

    printf("\n-- B12 ranges: a peer that slows on its range has it taken back\n");
    { /* six one-page ranges (anchors every 2,000); peer 4 answers its probe
       * at once and every page on its range connection in 3 s: the three
       * fast peers each take one range (a 20-60 ms first page) while peer 4
       * takes a fourth and holds it */
      static char a6hex[6][65]; static struct hdr_anchor a6[6];
      for(int a=0;a<6;a++){ int h=(a+1)*2000; for(int q=0;q<32;q++) snprintf(a6hex[a]+2*q, 3, "%02x", bh[h][31-q]); a6[a].height=h; a6[a].hash=a6hex[a]; }
      g_dlc_hr_anchors_test = a6; g_dlc_hr_n_test = 6;
      fp_opts_t ops[4] = { {60,0,0,1,40}, {20,0,0,1,40}, {40,0,0,1,40}, {80,0,0,0,0,3000} };
      g_dlc_hr_straggle_min_ms = 500;
      long got = run_phase("ranges-straggle", ops, peer, &log);
      g_dlc_hr_straggle_min_ms = 5000; g_dlc_hr_anchors_test = anc; g_dlc_hr_n_test = 3;
      print_line(line_with(log, "taken back")); print_line(line_with(log, "header ranges: 6 of"));
      { char tb[160]; snprintf(tb, sizeof tb, "held by %s for", peer[3]); ckm("the slow peer's range was taken back", strstr(log, tb) != 0 && line_with(log, "taken back for a waiting peer") != 0); }
      ckm("all six ranges finished", line_with(log, "header ranges: 6 of 6 range(s)") != 0);
      ck("the whole chain was fetched", got, NB);
      free(log); }

    printf("\n-- B12 ranges: bmc.dlshape=core runs none\n");
    { fp_opts_t ops[4] = { {60,0,0,1,40}, {20,0,0,1,40}, {40,0,0,1,40}, {80,0,0,1,40} };
      g_cfg.dl_shape_core = 1;
      long got = run_phase("ranges-core", ops, peer, &log);
      g_cfg.dl_shape_core = 0;
      ck("the whole chain was fetched", got, NB);
      ckm("no ranges", line_with(log, "header ranges") == 0);
      free(log); }
    g_dlc_hr_n_test = -1; g_announce = 0;

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}

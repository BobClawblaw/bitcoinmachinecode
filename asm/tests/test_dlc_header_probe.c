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
 *     header-sync peer).
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
 * header floor (> MTP) holds. 4,500 = two full pages and a short one. */
#define NB 4500
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
typedef struct { long first_delay_ms; int stall_after_pages; int bad_link; } fp_opts_t;
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
static void fp_serve(int cfd, const fp_opts_t* op){
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
            int start = idx<0 ? 0 : idx+1;
            int n = NB - start; if(n>2000) n=2000; if(n<0) n=0;
            int o;
            if(n>=253){ out[0]=0xfd; out[1]=(unsigned char)(n&0xff); out[2]=(unsigned char)((n>>8)&0xff); o=3; }
            else { out[0]=(unsigned char)n; o=1; }
            for(int i=0;i<n;i++){ memcpy(out+o, hdrs[start+i], 80); out[o+80]=0; o+=81; }
            if(op->bad_link && n > 0) memset(out + (n>=253 ? 3 : 1) + 4, 0xEE, 32);   /* the first header's prev is nothing we hold */
            p2p_write(cfd,"headers",7,out,(unsigned)o);
            pages++;
        } else if(!strncmp(cmd,"ping",4)){
            p2p_write(cfd,"pong",4,rb,(plen>=8)?8:0);
        }
    }
}
static pid_t start_peer(unsigned ip_host, unsigned short* port_out, const fp_opts_t* op){
    int ls=socket(AF_INET,SOCK_STREAM,0); int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(ip_host); a.sin_port=0;
    if(bind(ls,(struct sockaddr*)&a,sizeof a)!=0){ perror("bind"); return -1; }
    socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al); *port_out = ntohs(a.sin_port);
    listen(ls,32);
    pid_t p=fork();
    if(p==0){
        setpgid(0,0); signal(SIGPIPE,SIG_IGN); signal(SIGCHLD,SIG_IGN);
        for(;;){ int c=accept(ls,0,0); if(c<0) continue;
                 { int nd=1; setsockopt(c,IPPROTO_TCP,TCP_NODELAY,&nd,sizeof nd); }
                 pid_t q=fork(); if(q==0){ close(ls); fp_serve(c,op); close(c); _exit(0); }
                 close(c); }
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
    for(int i=0;i<4;i++){ pids[i] = start_peer(0x7f000001u + (unsigned)i, &ports[i], &ops[i]); if(pids[i] < 0) return -2; }
    static char live[4][DL_POOL_SLOT]; memset(live, 0, sizeof live);
    for(int i=0;i<4;i++){ snprintf(live[i], DL_POOL_SLOT, "127.0.0.%d:%u", i+1, (unsigned)ports[i]); memcpy(peer[i], live[i], DL_POOL_SLOT); }
    for(int i=0;i<DLC_MAXPOOL;i++) g_live_announced[i] = 0;
    capture_begin("hdr.log");
    long got = dlc_headers(live, 4);
    *out_log = capture_end("hdr.log");
    stop_peers(pids, 4);
    return got;
}

int main(void){
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    build_chain();
    printf("chain built: %d headers\n", NB);
    tt_isolate();
    g_cfg.dead_weight_ticks = 1000000; g_cfg.min_usable_peers = 0;
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

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}

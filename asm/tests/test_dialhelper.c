/* tests/test_dialhelper.c -- anonymity-network dials run in a helper child
 * and hand the connected socket back.
 *
 * Every dial path in the download worker runs inline in its rotation, and
 * an onion or I2P dial costs tens of seconds, so three of them in a row
 * starved the heartbeat and tripped the deploy guard. dh_start() forks a
 * child that runs the ordinary outbound_connect (connect + version
 * handshake) and returns the socket over a socketpair with SCM_RIGHTS plus
 * the handshake facts; dh_poll() collects it without blocking; the leg is
 * installed exactly as an inline fill would install it.
 *
 * The functions are static in daemon/main.c; include the TU (the
 * test_dial_budget pattern). The peer is a fake that completes the version
 * handshake; the timeout case dials a blackholed address. */
#include <stdio.h>
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }

/* ---- the in-order committer's recording append and a direct chunk writer ---- */
static long g_rec_h[512]; static int g_rec_n = 0; static int g_rec_ok = 1; static long g_present_below = -1;
static long rec_append(void* st, long h, const unsigned char hash[32], const unsigned char* raw, unsigned len){
    (void)st; if (g_rec_n < 512) g_rec_h[g_rec_n] = h; g_rec_n++;
    if (len != 100 || raw[0] != (unsigned char)(h & 0xff) || raw[99] != (unsigned char)(h & 0xff) || hash[0] != (unsigned char)(h & 0xff) || hash[31] != (unsigned char)(h & 0xff)) g_rec_ok = 0;
    return h;
}
static int present_below(long h){ return h < g_present_below; }
static int g_synced_n = 0; static void rec_synced(void* st){ (void)st; g_synced_n++; }
/* write stage/c<lo>.chunk directly in the committer's record format: n blocks of 100 bytes, byte pattern = height */
static long stage_chunk(long lo, int n){
    char path[64]; snprintf(path, sizeof path, "stage/c%ld.chunk", lo);
    FILE* f = fopen(path, "wb"); if (!f) return -1; long total = 0;
    for (int i = 0; i < n; i++){ long h = lo + i; unsigned len = 100; unsigned char hash[32], raw[100];
        memset(hash, (int)(h & 0xff), 32); memset(raw, (int)(h & 0xff), 100);
        fwrite(&h, 8, 1, f); fwrite(&len, 4, 1, f); fwrite(hash, 32, 1, f); fwrite(raw, 100, 1, f); total += 44 + 100; }
    fclose(f); return total;
}
static void put_u16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}
static void put_u32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
/* a peer that completes the handshake and then lingers */
static void fake_peer(int cfd){
    unsigned char rbuf[4096]; char cmd[12]; unsigned plen=0;
    if (p2p_read(cfd,cmd,rbuf,sizeof(rbuf),&plen)<=0) return;      /* our version */
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016);o+=4; put_u64le(v+o,0x409);o+=8; put_u64le(v+o,(unsigned long long)time(NULL));o+=8;
    put_u64le(v+o,1);o+=8; o+=16; put_u16be(v+o,8333);o+=2;
    put_u64le(v+o,1);o+=8; o+=16; put_u16be(v+o,0);o+=2;
    put_u64le(v+o,0x4444444444444444ULL);o+=8; const char*u="/fakepeer:0.1/"; v[o]=strlen(u);o++;memcpy(v+o,u,strlen(u));o+=strlen(u);
    put_u32le(v+o,900000);o+=4; v[o]=1;o++;
    p2p_write(cfd,"version",7,v,o);
    p2p_write(cfd,"verack",6,"",0);
    for(int i=0;i<6;i++) if (p2p_read(cfd,cmd,rbuf,sizeof(rbuf),&plen)<=0) break;   /* wtxidrelay, sendaddrv2, verack, ... */
    sleep(3);
}
/* a peer that completes the handshake, then answers the first getheaders
 * with a canned headers page (mode 0: 2 headers continuing OUR tip; mode 1:
 * 2 headers continuing an unrelated hash; mode 2: a ping first, then the
 * page from an EARLIER locator point overlapping one header we hold plus
 * one new). The page is built by the test before the fork, so the child
 * shares it. */
static unsigned char g_hpage[4096]; static unsigned g_hpage_len;
static void fake_header_peer(int cfd){
    unsigned char rbuf[8192]; char cmd[12]; unsigned plen=0;
    if (p2p_read(cfd,cmd,rbuf,sizeof(rbuf),&plen)<=0) return;      /* our version */
    unsigned char v[102]; int o=0;
    put_u32le(v+o,70016);o+=4; put_u64le(v+o,0x409);o+=8; put_u64le(v+o,(unsigned long long)time(NULL));o+=8;
    put_u64le(v+o,1);o+=8; o+=16; put_u16be(v+o,8333);o+=2;
    put_u64le(v+o,1);o+=8; o+=16; put_u16be(v+o,0);o+=2;
    put_u64le(v+o,0x4444444444444444ULL);o+=8; const char*u="/fakepeer:0.1/"; v[o]=strlen(u);o++;memcpy(v+o,u,strlen(u));o+=strlen(u);
    put_u32le(v+o,900000);o+=4; v[o]=1;o++;
    p2p_write(cfd,"version",7,v,o);
    p2p_write(cfd,"verack",6,"",0);
    for(int i=0;i<40;i++){
        if (p2p_read(cfd,cmd,rbuf,sizeof(rbuf),&plen)<=0) return;
        if (!strncmp(cmd,"getheaders",12)){
            if (g_hpage[0] == 0xff){ unsigned char nonce[8]={1,2,3,4,5,6,7,8}; p2p_write(cfd,"ping",4,nonce,8); }
            p2p_write(cfd,"headers",7,g_hpage+1,g_hpage_len-1);
            sleep(2); return;
        }
    }
}
static void mk_hdr(unsigned char h[80], const unsigned char prev[32], int tag){ memset(h,0,80); h[0]=1; memcpy(h+4,prev,32); h[36]=(unsigned char)tag;
    /* VAL-5 (audit 2026-09-03): dlc_fetch_headers now pow_check-gates every
     * header before hst_append -- these fixtures exercise the FETCH logic, so
     * mine a nonce until the header satisfies its own (regtest-powLimit)
     * target. The harness never selects a chain, so pow_pow_limit_bits stays
     * disarmed and only the hash-vs-target comparison is in play. */
    h[72]=0xff; h[73]=0xff; h[74]=0x7f; h[75]=0x20;   /* LE 0x207fffff */
    for (unsigned nz=0; nz<4000000u; nz++){
        h[76]=nz; h[77]=nz>>8; h[78]=nz>>16; h[79]=nz>>24;
        if (pow_check(h)) return;
    } }
static void mk_page(int ping, int n, unsigned char (*hdrs)[80]){ unsigned o=0; g_hpage[o++]= ping?0xff:0x00; g_hpage[o++]=(unsigned char)n; for(int i=0;i<n;i++){ memcpy(g_hpage+o,hdrs[i],80); o+=80; g_hpage[o++]=0; } g_hpage_len=o; }

int main(void){
    int l = socket(AF_INET, SOCK_STREAM, 0); int one = 1; setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); sa.sin_port = 0;
    if (bind(l, (struct sockaddr*)&sa, sizeof sa) != 0 || listen(l, 4) != 0){ perror("listen"); return 1; }
    socklen_t al = sizeof sa; getsockname(l, (struct sockaddr*)&sa, &al); int port = ntohs(sa.sin_port);
    pid_t fp = fork();
    if (fp == 0){ int c = accept(l, NULL, NULL); if (c >= 0) fake_peer(c); _exit(0); }
    char host[64]; snprintf(host, sizeof host, "127.0.0.1:%d", port);
    node_config_load("/nonexistent/bitcoin.conf");

    printf("== 1. a background dial lands as a leg ==\n");
    ok(dh_start(host, port) == 1, "helper started");
    ok(dh_inflight_count() == 1, "one dial in flight");
    dh_result_t r; int fd = -1; char h[128]; int got = 0;
    for (int i = 0; i < 300 && !got; i++){ got = dh_poll(&r, &fd, h, sizeof h); if (!got) usleep(50000); }
    ok(got, "a result arrived (non-blocking polls)");
    ok(r.ok == 1 && fd >= 0, "the dial succeeded and the socket crossed the process boundary");
    ok(r.vlen >= 80 && r.vpayload[0] == 0x80 && r.vpayload[1] == 0x11, "the peer's version payload came with it (proto 70016)");
    ok(!strcmp(h, host), "...for the host we asked for");
    ok(dh_inflight_count() == 0, "the slot is free again");
    int before = mux_n_out;
    ok(dh_install_leg(h, fd, &r) == 1 && mux_n_out == before + 1, "installed as an outbound leg");
    ok(!strcmp(mux_out_host[mux_n_out - 1], host) && mux_out_fd[mux_n_out - 1] == fd, "...with its host and fd recorded");
    { char pv[256]; format_peer_version_info(pv, sizeof pv); ok(strstr(pv, "fakepeer") != 0, "getpeerinfo-style version text reflects the peer"); }
    ok(dh_install_leg(h, fd, &r) == 0, "a second install of the same host is refused (dedupe)");
    close(mux_out_fd[mux_n_out - 1]); mux_out_fd[mux_n_out - 1] = -1;

    printf("== 2. a dial that never completes is given up, not waited for ==\n");
    dial_helper_test_set_timeout_ms(1500);
    ok(dh_start("198.51.100.1:8333", 8333) == 1, "helper started against a blackhole");
    got = 0; struct timespec a, b; clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < 200 && !got; i++){ got = dh_poll(&r, &fd, h, sizeof h); if (!got) usleep(50000); }
    clock_gettime(CLOCK_MONOTONIC, &b);
    double secs = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
    ok(got && r.ok == 0 && fd < 0 && !strcmp(r.why, "timeout"), "reported as a timeout with no socket");
    ok(secs >= 1.0 && secs <= 4.0, "...within the helper timeout, while the worker kept rotating");
    ok(dh_inflight_count() == 0, "the slot is free again");

    printf("== 3. capacity ==\n");
    dial_helper_test_set_timeout_ms(1500);
    ok(dh_start("198.51.100.2:8333", 8333) == 1 && dh_start("198.51.100.3:8333", 8333) == 1, "two helpers may run at once");
    ok(dh_start("198.51.100.4:8333", 8333) == 1 && dh_start("198.51.100.5:8333", 8333) == 1, "...and four (2026-09-10: every dial is a helper now, DH_MAX 4)");
    ok(dh_start("198.51.100.6:8333", 8333) == 0, "a fifth is refused (DH_MAX)");
    ok(dh_inflight_net(BMC_NET_IPV4) == 1, "in-flight lookup by network");
    for (int i = 0; i < 200; i++){ if (dh_poll(&r, &fd, h, sizeof h) && dh_inflight_count() == 0) break; usleep(50000); }
    for (int i = 0; i < 100 && dh_inflight_count(); i++){ dh_poll(&r, &fd, h, sizeof h); usleep(50000); }
    ok(dh_inflight_count() == 0, "both drained");

    printf("== 4. the reserved-slot chooser rotates through the network's candidates ==\n");
    { const char* pool[5] = {
          "fdtfjxpnlcqbbhlch7qixrmpfc3ocfwjj4bjs4lp4j54shhn7hvyxyyd.onion:8333",
          "1.2.3.4:8333",
          "fnslq4qq7nyyo2apypq4toakk2ueudetenjsmcyqe27bsg5dtx4udsad.onion:8333",
          "qpjbnsqyxjppaiejqfbrepb7rrv6pvwx2qianvuhkcuwsk5qon27gjid.onion:8333",
          "37bwoizdeha4fl2f3mylqfyzwqtaiebsmjlvwejwbtomywhgieca.b32.i2p:0" };
      int a = dh_reserved_pick(0, BMC_NET_TORV3, pool, 5);
      int b = dh_reserved_pick(0, BMC_NET_TORV3, pool, 5);
      int c = dh_reserved_pick(0, BMC_NET_TORV3, pool, 5);
      int d = dh_reserved_pick(0, BMC_NET_TORV3, pool, 5);
      ok(a == 0 && b == 2 && c == 3 && d == 0, "successive picks walk the onion entries and wrap (0, 2, 3, 0) -- never the same dead address twice in a row");
      /* a host a live leg holds is skipped */
      int slot = mux_n_out; snprintf(mux_out_host[slot], sizeof mux_out_host[slot], "%s", pool[2]); mux_out_fd[slot] = 0; mux_n_out = slot + 1;
      int e = dh_reserved_pick(0, BMC_NET_TORV3, pool, 5);
      ok(e == 3, "...and skips the onion a live leg already holds");
      mux_out_fd[slot] = -1; mux_n_out = slot;
      ok(dh_reserved_pick(1, BMC_NET_I2P, pool, 5) == 4, "the i2p cursor is independent");
      ok(dh_reserved_pick(0, BMC_NET_CJDNS, pool, 5) == -1, "no candidate of a network the pool lacks");
      ok(dh_reserved_pick(0, BMC_NET_TORV3, pool, 0) == -1, "an empty pool"); }

    printf("== 5. a getheaders answer that does not connect to our tip is discarded (incident 2026-09-01) ==\n");
    { char td[] = "/tmp/bmc_hdrs_XXXXXX"; if (!mkdtemp(td)){ perror("mkdtemp"); return 1; }
      char cwd0[512]; if (!getcwd(cwd0, sizeof cwd0)) cwd0[0] = 0;
      if (chdir(td) != 0){ perror("chdir"); return 1; }
      static unsigned char hst[4096]; hst_init(hst);
      /* two chained headers: h0, h1 (prev = hash(h0)) */
      unsigned char h0[80], h1[80], hh0[32], hh1[32]; memset(h0, 0, 80); h0[0] = 1; block_hash(hh0, h0);
      memset(h1, 0, 80); h1[0] = 1; memcpy(h1 + 4, hh0, 32); block_hash(hh1, h1);
      ok(hst_append(hst, h0, hh0) >= 0 && hst_append(hst, h1, hh1) >= 0 && hst_count(hst) == 2, "two chained headers appended (store on disk: headers.dat)");
      ok(dlc_headers_connect_ok(hst, 1, hh0), "the header at position 1 connects to the tip we asked from");
      unsigned char other[32]; memset(other, 0xab, 32);
      ok(!dlc_headers_connect_ok(hst, 1, other), "...and NOT to some other hash (a genesis-first answer)");
      ok(dlc_headers_connect_ok(hst, 0, other), "a fresh store accepts anything (nothing to connect to)");
      dlc_headers_rollback(hst, 1);
      ok(hst_count(hst) == 1, "rollback drops the appended header: the store is back at 1");
      { struct stat st; ok(stat("headers.dat", &st) == 0 && st.st_size == 112, "...and headers.dat is back to 112 bytes"); }
      /* the guard is about WHERE an answer attaches, never about how much follows (2026-09-02) */
      ok(dlc_headers_sane(0, 1), "a fresh store takes an answer from height 1 -- the whole chain may follow");
      ok(dlc_headers_sane(50000, 50000), "a node restarted mid-sync takes an answer at its tip, however long");
      ok(dlc_headers_sane(965018, 965018 - 100000), "an answer 100k below the tip is still a continuation");
      ok(!dlc_headers_sane(965018, 1), "the incident: an answer from genesis against 965k held is refused");
      ok(!dlc_headers_sane(965018, 965018 - 100001), "...as is one more than DLC_HDR_SANE_MAX below the tip");
      /* dead weight (2026-09-02): the byte floor alone banned honest peers
       * serving tiny early blocks. Retuned 2026-09-04 to an OR: the block
       * floor (<10 blocks/tick) binds at every chain depth, and the byte
       * floor decides once the block floor is satisfied. */
      /* the seven corners, at the ABSOLUTE floor: unchanged in meaning */
      { double F = (double)g_cfg.dead_weight_bps;
      ok(dlc_dead_weight(2000.0, 0, F), "2 KB/s and no blocks this tick: dead weight");
      ok(dlc_dead_weight(2000.0, 9, F), "2 KB/s and 9 blocks: still dead weight (byte floor binds at any depth)");
      ok(dlc_dead_weight(2000.0, 50, F), "2 KB/s and 50 blocks: dead weight too (a block rate can launder bytes)");
      ok(!dlc_dead_weight(50000.0, 50, F), "50 KB/s and 50 blocks: pulling its weight, not banned");
      ok(!dlc_dead_weight(1500000.0, 1, F), "1.5 MB/s and one block: fine near the tip");
      ok(dlc_dead_weight(40000.0, 1, F), "40 KB/s and one block: marginal bytes AND stalled blocks");
      ok(!dlc_dead_weight(200000.0, 1, F), "200 KB/s and one block: big blocks, not stalled");
      ok(!dlc_dead_weight(-1.0, 0, F), "no rate sample yet: not judged"); }
      /* 2026-09-06: the floor is RELATIVE to the pool's median. The absolute
       * 32 KB/s floor, calibrated for megabyte blocks, declared every healthy
       * worker dead at height 50,000 where a block is 200 bytes and a serial
       * fetch is round-trip bound (~9 KB/s): 655 evictions in 30 min, 181 of
       * them peers that had served two full chunks. Watched to fail first
       * with dlc_effective_floor returning the absolute floor always. */
      { double F = (double)g_cfg.dead_weight_bps;
      ok(dlc_effective_floor(0.0) == F, "no median yet: the absolute floor (callers skip the kill anyway)");
      ok(dlc_effective_floor(5.6 * 1024.0) == 0.25 * 5.6 * 1024.0, "pool median 5.6 KB/s (early chain): floor is a quarter of it, 1.4 KB/s");
      ok(dlc_effective_floor(1000000.0) == F, "pool median ~1 MB/s (later): the absolute floor takes over unchanged");
      ok(dlc_effective_floor(100.0) == 512.0, "a pathological median cannot push the floor below 512 B/s");
      double early = dlc_effective_floor(5.6 * 1024.0);
      ok(!dlc_dead_weight(9.0 * 1024.0, 12, early), "the run-7 case: 9 KB/s and 12 blocks at height 50k is HEALTHY, not dead weight");
      ok(dlc_dead_weight(300.0, 1, early), "0.3 KB/s and one block at the same floor: genuinely dead, still killed"); }
      /* 2026-09-07: boundary rotation. With the flat chunk budget gone (PR
       * #68) nothing removed a delivering-but-slow peer: the floor is 32 KB/s
       * at the tail, so a 250 KB/s peer against an 800 KB/s median held its
       * slot for the run. The verdict is taken at the chunk boundary, with
       * nothing in flight: under half the pool median -> a fresh peer. */
      { ok(dlc_rotate_after_chunk(300.0*1024, 800.0*1024), "300 KB/s over a clean chunk vs an 800 KB/s median: rotate (under half)");
        ok(!dlc_rotate_after_chunk(450.0*1024, 800.0*1024), "450 KB/s vs 800: keep (over half)");
        ok(!dlc_rotate_after_chunk(300.0*1024, 0.0), "no median published yet: keep");
        ok(!dlc_rotate_after_chunk(-1.0, 800.0*1024), "no chunk rate (chunk too short to judge): keep");
        ok(dlc_rotate_after_chunk(5.0*1024, 12.0*1024), "early chain, 5 KB/s vs a 12 KB/s median: rotate -- the bar is relative at every depth");
        /* ETA in DD:HH:MM:SS at the recent block rate */
        char e[24];
        dlc_fmt_eta(e,sizeof e,0);      ok(!strcmp(e,"00:00:00:00"), "eta 0 s -> 00:00:00:00");
        dlc_fmt_eta(e,sizeof e,86399);  ok(!strcmp(e,"00:23:59:59"), "eta 86,399 s -> 00:23:59:59");
        dlc_fmt_eta(e,sizeof e,90061);  ok(!strcmp(e,"01:01:01:01"), "eta 90,061 s -> 01:01:01:01 (DD:HH:MM:SS)");
        dlc_fmt_eta(e,sizeof e,-1);     ok(!strcmp(e,"--:--:--:--"), "no rate yet -> --:--:--:--");
        long t = dlc_eta_secs(213000, 41833, 3600.0);
        ok(t >= 18329 && t <= 18331, "213,000 blocks left at run 9's 41,833/h: 5:05:30 (18,330 s)");
        ok(dlc_eta_secs(0, 41833, 3600.0) == 0, "nothing left: 0");
        ok(dlc_eta_secs(1000, 0, 600.0) == -1, "no blocks in the window: no estimate"); }
      if (cwd0[0]) (void)!chdir(cwd0); }

    printf("== 6. the boot header fetch: exponential locator, per-page checks ==\n");
    { char td2[] = "/tmp/bmc_hfetch_XXXXXX"; if (!mkdtemp(td2)){ perror("mkdtemp"); return 1; }
      char cwd1[512]; if (!getcwd(cwd1, sizeof cwd1)) cwd1[0] = 0;
      if (chdir(td2) != 0){ perror("chdir"); return 1; }
      static unsigned char hst[4096]; hst_init(hst);
      unsigned char h0[80], h1[80], h2[80], x1[80], x2[80], hh0[32], hh1[32], hh2[32], other[32];
      memset(other, 0xcd, 32); memset(hh0, 0, 32);
      mk_hdr(h0, hh0, 0x10); block_hash(hh0, h0); hst_append(hst, h0, hh0);          /* we hold one header */
      mk_hdr(h1, hh0, 0x11); block_hash(hh1, h1); mk_hdr(h2, hh1, 0x12); block_hash(hh2, h2);
      mk_hdr(x1, other, 0x21); unsigned char xh1[32]; block_hash(xh1, x1); mk_hdr(x2, xh1, 0x22);
      #define HFETCH(mode_ping, n, hdrs, label_ok, cond) do{ \
          int l2 = socket(AF_INET, SOCK_STREAM, 0); int one2 = 1; setsockopt(l2, SOL_SOCKET, SO_REUSEADDR, &one2, sizeof one2); \
          struct sockaddr_in sa2; memset(&sa2, 0, sizeof sa2); sa2.sin_family = AF_INET; sa2.sin_addr.s_addr = htonl(INADDR_LOOPBACK); \
          bind(l2, (struct sockaddr*)&sa2, sizeof sa2); listen(l2, 4); socklen_t al2 = sizeof sa2; getsockname(l2, (struct sockaddr*)&sa2, &al2); \
          mk_page(mode_ping, n, hdrs); pid_t fp2 = fork(); if (fp2 == 0){ int c = accept(l2, NULL, NULL); if (c >= 0) fake_header_peer(c); _exit(0); } \
          char host2[64]; snprintf(host2, sizeof host2, "127.0.0.1:%d", ntohs(sa2.sin_port)); \
          int fd2 = -1; for (int k = 0; k < 50 && fd2 < 0; k++){ fd2 = socket(AF_INET, SOCK_STREAM, 0); if (connect(fd2, (struct sockaddr*)&sa2, sizeof sa2) != 0){ close(fd2); fd2 = -1; usleep(20000); } } \
          long res = -2; if (fd2 >= 0 && node_handshake(fd2) == 1) res = dlc_fetch_headers(fd2, hst, host2); \
          if (fd2 >= 0) close(fd2); \
          kill(fp2, SIGKILL); waitpid(fp2, NULL, 0); close(l2); \
          ok((cond), label_ok); (void)res; }while(0)
      { unsigned char hp[2][80]; memcpy(hp[0], h1, 80); memcpy(hp[1], h2, 80);
        long res_a = -2; HFETCH(0, 2, hp, "a page continuing our tip: both headers appended (count 3)", (res_a = res) == 2 && hst_count(hst) == 3); }
      { unsigned char xp[2][80]; memcpy(xp[0], x1, 80); memcpy(xp[1], x2, 80);
        HFETCH(0, 2, xp, "a page continuing an UNRELATED hash (a genesis-first answer): refused, store unchanged (count 3)", res == -1 && hst_count(hst) == 3); }
      { /* a peer one block behind: answers from our previous header; overlap identical, one new */
        unsigned char h3[80]; mk_hdr(h3, hh2, 0x13);
        unsigned char op[2][80]; memcpy(op[0], h2, 80); memcpy(op[1], h3, 80);
        HFETCH(1, 2, op, "a page from an earlier locator point (after a ping): the overlap matches, only the new header is appended (count 4)", res == 1 && hst_count(hst) == 4); }
      { /* a fork: overlaps our height 2 with a DIFFERENT block */
        unsigned char f2[80]; mk_hdr(f2, hh1, 0x99); unsigned char fp_[1][80]; memcpy(fp_[0], f2, 80);
        HFETCH(0, 1, fp_, "a page that forks from our chain at a held height: refused, store unchanged (count 4)", res == -1 && hst_count(hst) == 4); }
      { /* a peer BEHIND us (2026-09-08): answers from an earlier locator point
         * with a page that ends below our tip -- every header one we hold.
         * Before the fix the overlap verified, nothing was appended, and the
         * fetch returned 0 ("already current"); on a full page the loop asked
         * the same locator again and production walked 415 identical pages
         * from a node ~100k blocks behind. Now: -1, the next peer is tried. */
        unsigned char h3b[80]; mk_hdr(h3b, hh2, 0x13);          /* == our height 3 (mk_hdr is deterministic) */
        unsigned char bp2[2][80]; memcpy(bp2[0], h2, 80); memcpy(bp2[1], h3b, 80);
        HFETCH(0, 2, bp2, "a page from an earlier locator point that ends BELOW our tip (a peer behind us): refused (-1), store unchanged (count 4)", res == -1 && hst_count(hst) == 4); }
      { /* VAL-5 (audit 2026-09-03): a header that CHAINS to our tip but fails
         * its own PoW must never be appended. Deterministic construction:
         * nBits exponent 4 / mantissa 1 -> target = 256, i.e. ~2^-248 of all
         * hashes pass, so nonce 0 fails and no realistic mining succeeds;
         * the nBits itself is well-formed (passes the VAL-11 range gates --
         * this exercises the hash-vs-target rejection, not a malformed-bits
         * one). Before the fix this header was hst_append'ed on linkage
         * alone: the first live peer could fill headers.dat with garbage. */
        unsigned char top_rec[112];
        if (hst_get_at(hst, (unsigned long long)(hst_count(hst) - 1), top_rec) == 1){
          unsigned char bad[80]; memset(bad, 0, 80);
          bad[0]=1; memcpy(bad+4, top_rec+80, 32); bad[36]=0x77;
          bad[72]=0x01; bad[73]=0x00; bad[74]=0x00; bad[75]=0x04;   /* 0x04000001: target=256 */
          unsigned char bp_[1][80]; memcpy(bp_[0], bad, 80);
          HFETCH(0, 1, bp_, "a tip-chaining header with FAILING PoW: refused, store unchanged (count 4)", res == -1 && hst_count(hst) == 4);
        } }
      #undef HFETCH
      if (cwd1[0]) (void)!chdir(cwd1); }

    printf("== 7. EMA speed-ranked claim order + peers.good speed file ==\n");
    { /* dlc_pick_peer is the whole claim-order decision; the CAS loop around
       * it is unchanged, so the corners here are: fastest-first, claimed/
       * banned skipped, and the fresh-sync fallback to plain rotation. */
      volatile int cl[4] = {0,0,0,0}, bn[4] = {0,0,0,0};
      volatile double em[4] = {10.0, 5.0, 9.0, 0.0};
      ok(dlc_pick_peer(4, 0, em, cl, bn, 0.0) == 0, "ema [10,5,9,0]: picks the fastest peer (0)");
      cl[0] = 1;
      ok(dlc_pick_peer(4, 0, em, cl, bn, 0.0) == 2, "...then the second fastest once 0 is claimed (2)");
      bn[2] = 1; bn[3] = 1;
      ok(dlc_pick_peer(4, 0, em, cl, bn, 0.0) == 1, "claimed/banned slots are skipped even when the fallback runs: takes the only free one (1)");
      bn[1] = 1;
      ok(dlc_pick_peer(4, 0, em, cl, bn, 0.0) == -1, "claimed+banned leaves nothing: exhausted");
      cl[0]=0; bn[1]=0; bn[2]=0; bn[3]=0;
      ok(dlc_pick_peer(4, 0, em, cl, bn, 0.0) == 0, "unclaiming makes 0 pickable again");
      /* 2026-09-07: the boundary-rotation bar. A worker that just dropped a
       * 300 KB/s peer against an 800 KB/s median must not get it straight
       * back because every untried peer has ema 0. */
      { volatile int c2[4] = {0,0,0,0}, b2[4] = {0,0,0,0};
        volatile double e2[4] = {800.0, 300.0, 0.0, 0.0};
        ok(dlc_pick_peer(4, 0, e2, c2, b2, 400.0) == 0, "bar 400, ema [800,300,untried,untried]: the fastest peer clears the bar (0)");
        c2[0] = 1;
        ok(dlc_pick_peer(4, 0, e2, c2, b2, 400.0) == 2, "...0 claimed: the 300 KB/s peer is under the bar, so someone UNTRIED is picked (2), not the known-slow one");
        ok(dlc_pick_peer(4, 0, e2, c2, b2, 0.0) == 1, "...the same state with no bar (old rule): the known 300 KB/s peer (1)");
        c2[2] = 1; c2[3] = 1;
        ok(dlc_pick_peer(4, 0, e2, c2, b2, 400.0) == 1, "...nobody untried left: the best there is, even under the bar (1), never no peer");
        b2[1] = 1;
        ok(dlc_pick_peer(4, 0, e2, c2, b2, 400.0) == -1, "...and banned/claimed everywhere: exhausted"); }
      /* 2026-09-07, run 10: a peer that could not be connected, handshaken
       * or lacked NODE_WITNESS kept ema 0 and so was offered as "untried"
       * again and again; a worker spent all 112 picks on such peers, 40
       * times over, and then abandoned every chunk it claimed. The worker
       * now marks such a peer 1.0 (tried, worthless), which the picker ranks
       * below any measured peer and never as untried. */
      { volatile int c3[4] = {1,0,0,0}, b3[4] = {0,0,0,0};
        volatile double e3[4] = {800.0, 300.0, 1.0, 0.0};
        ok(dlc_pick_peer(4, 0, e3, c3, b3, 400.0) == 3, "ema [800(claimed),300,1.0(dead mark),untried], bar 400: the untried one (3)");
        c3[3] = 1;
        ok(dlc_pick_peer(4, 0, e3, c3, b3, 400.0) == 1, "...untried gone: the 300 KB/s peer (1), NOT the dead-marked one -- it is measured, not untried");
        c3[1] = 1;
        ok(dlc_pick_peer(4, 0, e3, c3, b3, 400.0) == 2, "...and only the dead-marked one left: still returned rather than no peer (2)"); }
      /* 2026-09-09, run 19: a FRESH sync has no pool median yet (bar 0), and
       * with bar 0 the dead mark (1.0) outranked every untried peer, so two
       * workers went back to the same two peers that closed the socket on
       * every request -- 200 attempts each, the committer waiting on their
       * chunk, the whole run stalled at block 560. A peer whose only history
       * is failure never clears a bar, not even an unknown one. */
      { volatile int c4[4] = {0,0,0,0}, b4[4] = {0,0,0,0};
        volatile double e4[4] = {1.0, 0.5, 0.0, 0.0};
        ok(dlc_pick_peer(4, 0, e4, c4, b4, 0.0) == 2, "ema [1.0(dead mark),0.5(failed twice),untried,untried], bar 0 (fresh sync): the untried one (2)");
        c4[2] = 1; c4[3] = 1;
        ok(dlc_pick_peer(4, 0, e4, c4, b4, 0.0) == 0, "...nobody untried: the least-failed mark rather than no peer (0)");
        volatile double e5[4] = {1.0, 300.0, 0.0, 0.0}; volatile int c5[4] = {0,0,0,0};
        ok(dlc_pick_peer(4, 0, e5, c5, b4, 0.0) == 1, "ema [1.0(dead mark),300 measured,untried,untried], bar 0: the measured peer (1), as before"); }
      /* the far-behind trigger's height (2026-09-08): one liar cannot start
       * the parallel downloader; two agreeing peers can */
      { long one[1] = { 969817 }; long two[2] = { 969817, 966063 }; long many[5] = { 966063, 966063, 969817, 966062, 966063 };
        ok(dl_trigger_height(one, 1) == 969817, "a single peer: its own claim (a fresh node with one peer must still sync)");
        ok(dl_trigger_height(two, 2) == 966063, "two peers, one claiming 969,817: the second-highest, 966,063");
        ok(dl_trigger_height(many, 5) == 966063, "five peers with one liar: 966,063");
        ok(dl_trigger_height(many, 0) == 0, "no peers: 0"); }
      /* the download window and the retry ring ("write out monotonically,
       * like Core does"): a chunk is never claimed more than 1024 blocks
       * above the first hole, and an abandoned chunk is retried, never left. */
      { ok(dlc_window_allows(45160 + 4096, 45160, 4096), "a claim exactly 4096 above the first hole is inside the window (Core's 1024 scaled to our 640 in flight)");
        ok(!dlc_window_allows(45160 + 4097, 45160, 4096), "4097 above: outside -- the worker waits instead of running ahead");
        ok(dlc_window_allows(100, 45160, 4096), "a claim below the first hole (a retry) is always allowed");
        static volatile long ctl[DLC_CTL_RING + DLC_RETRY_MAX];
        for (long i = 0; i < DLC_CTL_RING + DLC_RETRY_MAX; i++) ctl[i] = i < DLC_CTL_RING ? 0 : -1;
        ok(dlc_retry_pop(ctl) == -1, "empty ring: nothing to retry");
        ok(dlc_retry_push(ctl, 45161) && dlc_retry_push(ctl, 0) && dlc_retry_push(ctl, 72001), "three abandoned chunks pushed (one of them chunk 0)");
        ok(dlc_retry_pop(ctl) == 45161 && dlc_retry_pop(ctl) == 0 && dlc_retry_pop(ctl) == 72001, "popped in order, chunk 0 included");
        ok(dlc_retry_pop(ctl) == -1, "and empty again");
        int full_ok = 1; for (long i = 0; i < DLC_RETRY_MAX; i++) if (!dlc_retry_push(ctl, i * 40)) full_ok = 0;
        ok(full_ok && !dlc_retry_push(ctl, 1), "a full ring refuses the next push (the pass's own hole scan picks it up) rather than overwriting");
        ok(dlc_retry_pop(ctl) == 0, "and drains from the oldest"); }
      /* run 14's two-minute stall: a failed fetch must cost the peer its
       * standing, cost the worker a pause, and a help must land on the
       * claim grid */
      /* 2026-09-09: tcp_connect_ip's connect() is blocking under a 10 s
       * SO_SNDTIMEO; its expiry surfaces as EINPROGRESS, which was rendered
       * "Operation now in progress" and read as an attempt still in flight */
      /* 2026-09-09: the fetch gate refuses a hash the store already holds (a sibling leg
       * landed it: production on snapshot n fetched and then refused six duplicates an
       * hour, each a strike) and claims a fresh one for this leg */
      { static unsigned char idxbuf[24 + HT_SLOTS*48]; idx_init(idxbuf, HT_SLOTS); unsigned char* saved = ht_idx; ht_idx = idxbuf;
        unsigned char known[32], fresh[32]; memset(known, 0x11, 32); memset(fresh, 0x22, 32); idx_put(ht_idx, known, 5);
        inflight_init(&g_inflight); g_sync_leg = 3;
        ok(block_fetch_gate(known) == 0, "a hash already in the store's index is not fetched");
        ok(block_fetch_gate(fresh) == 1, "a fresh hash is claimed for this leg");
        g_sync_leg = 4;
        ok(block_fetch_gate(fresh) == 0, "... and refused to another leg while the claim lives");
        inflight_release_leg(&g_inflight, 3);
        ok(block_fetch_gate(fresh) == 1, "... until the first leg's pass ends");
        ht_idx = saved; g_sync_leg = -1; inflight_init(&g_inflight); }
      /* 2026-09-09: we ping every leg every 2 min and close one silent for 20 min (Core's numbers) */
      { ok(leg_ping_due(1000, 0), "a fresh leg is pinged at once");
        ok(!leg_ping_due(1000 + 119, 1000), "... not again for 2 min");
        ok(leg_ping_due(1000 + 120, 1000), "... then again");
        ok(!leg_ping_timed_out(1000 + 1199, 1000, 0), "no pong for 19:59 is not a timeout");
        ok(leg_ping_timed_out(1000 + 1200, 1000, 0), "no pong for 20 min is");
        ok(!leg_ping_timed_out(1000 + 1200, 1000, 1001), "a pong after the ping clears it");
        ok(!leg_ping_timed_out(1000 + 9999, 0, 0), "a leg never pinged cannot time out");
        /* the pong callback matches the nonce to the slot */
        int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        mux_n_out = 1; mux_out_fd[0] = sp[0]; mux_out_ping_nonce[0] = 0x1122334455667788ULL; mux_out_pong_at[0] = 0; mux_out_ping_sent_ms[0] = dh_now_ms();
        unsigned char wrong[8] = {1,2,3,4,5,6,7,8}; leg_on_pong(sp[0], wrong);
        ok(mux_out_pong_at[0] == 0, "a pong with another nonce is ignored");
        unsigned char right[8]; unsigned long long nn = 0x1122334455667788ULL; memcpy(right, &nn, 8); leg_on_pong(sp[0], right);
        ok(mux_out_pong_at[0] != 0 && mux_out_ping_ms[0] >= 0, "the matching pong records the time and the round trip");
        mux_out_fd[0] = -1; mux_n_out = 0; close(sp[0]); close(sp[1]); }
      /* 2026-09-09, second leg batch: the peer's half-close is seen at once, and
       * a leg's socket ticks at 3 s after the handshake so the drains get their
       * designed patience (they counted 300 ms ticks: 2.4 s for headers) */
      { int sp[2]; ok(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0, "socketpair for the hang-up checks");
        short rv = 0;
        ok(leg_peer_hung_up(sp[0], &rv) == 0, "an open, quiet peer has not hung up");
        shutdown(sp[1], SHUT_WR);
        ok(leg_peer_hung_up(sp[0], &rv) == 1 && (rv & POLLRDHUP), "the peer's half-close (FIN) is a hang-up: POLLRDHUP");
        close(sp[1]);
        ok(leg_peer_hung_up(sp[0], &rv) == 1, "... and its full close still is");
        close(sp[0]);
        int sq[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sq);
        struct timeval before = {0, 300000}; setsockopt(sq[0], SOL_SOCKET, SO_RCVTIMEO, &before, sizeof before);
        leg_settle_socket(sq[0]);
        struct timeval after; socklen_t sl = sizeof after; getsockopt(sq[0], SOL_SOCKET, SO_RCVTIMEO, &after, &sl);
        ok(after.tv_sec == LEG_READ_TICK_S && after.tv_usec == 0, "a settled leg socket reads in 3 s ticks (was the dial's 300 ms)");
        close(sq[0]); close(sq[1]); }
      { dial_fail_errno("connect", -EINPROGRESS);
        ok(!strcmp(dial_fail_reason(), "connect timed out (10s)"), "EINPROGRESS from the bounded blocking connect reads as a timeout");
        dial_fail_errno("connect", -ECONNREFUSED);
        ok(!strcmp(dial_fail_reason(), "connect: Connection refused"), "a refused connect keeps strerror's text"); }
      { ok(dlc_ema_after_failure(800.0*1024) == 400.0*1024, "a failed fetch halves the peer's rate (800 -> 400 KB/s)");
        ok(dlc_ema_after_failure(0.0) == 1.0, "a never-measured peer that fails is marked tried (1.0), not left untried");
        ok(dlc_fail_backoff_ms(1) == 200 && dlc_fail_backoff_ms(5) == 1000 && dlc_fail_backoff_ms(10) == 2000 && dlc_fail_backoff_ms(400) == 2000,
           "backoff grows 200 ms per attempt and caps at 2 s (400 attempts take ~13 min, not 45 s)");
        ok(dlc_help_chunk_lo(82565, 1) == 82561, "first hole 82,565 on a pass starting at 1: the help chunk is [82561,82600], the owner's, not [82560,82599]");
        ok(dlc_help_chunk_lo(82565, 0) == 82560, "...and on a pass starting at 0 it is [82560,82599]");
        ok(dlc_help_chunk_lo(5, 40) == 40, "a hole below the span start: the span's first chunk"); }
      /* the in-order committer (2026-09-08): a worker STAGES a chunk, one
       * committer appends it from the first hole upward. The archive is
       * then written by a single process in height order -- the layout the
       * boot check, in-place pruning and physical truncation all want -- and
       * never has a hole. */
      { char cwd3[512] = ""; if (!getcwd(cwd3, sizeof cwd3)) cwd3[0] = 0;
        char td3[] = "/tmp/dlc_commit_XXXXXX";
        if (!mkdtemp(td3) || chdir(td3) != 0) ok(0, "scratch dir for the committer");
        else {
          ok(dlc_stage_wipe() == 0, "a fresh stage dir has nothing to discard");
          /* a chunk through the worker's sink: 40 records, then the rename that publishes it */
          char tmp[96]; int sfd = dlc_stage_open_tmp(tmp, sizeof tmp, 100);
          ok(sfd >= 0, "a staging tmp file opens exclusively");
          g_stage_fd = sfd; int sunk = 1;
          for (int i = 0; i < 40; i++){ long h = 100 + i; unsigned char hash[32], raw[100]; memset(hash, (int)(h & 0xff), 32); memset(raw, (int)(h & 0xff), 100);
              if (dlc_stage_sink(0, h, hash, raw, 100) != h) sunk = 0; }
          close(sfd); g_stage_fd = -1;
          ok(sunk, "the sink returns the height for each of 40 records");
          ok(!dlc_stage_exists(100), "...and the chunk is not visible until renamed");
          char fin[64]; dlc_stage_path(fin, sizeof fin, 100);
          ok(rename(tmp, fin) == 0 && dlc_stage_exists(100), "renamed: the chunk is staged");
          unsigned char* cb = mmap(0, DLC_STAGE_MAX_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
          g_rec_n = 0; g_rec_ok = 1; long cursor = 100;
          long n = dlc_commit_chunk(0, fin, &cursor, rec_append, 0, cb, DLC_STAGE_MAX_BYTES);
          ok(n == 40 && cursor == 140, "committed 40 blocks; the cursor is 140");
          ok(g_rec_n == 40 && g_rec_h[0] == 100 && g_rec_h[39] == 139 && g_rec_ok, "appended in height order, with the staged bytes and hashes");
          ok(!dlc_stage_exists(100), "the staged file is gone after the commit");
          /* a resumed datadir: the cursor sits mid-chunk, the heights below it are present */
          stage_chunk(140, 40); g_rec_n = 0; g_rec_ok = 1; cursor = 150; g_present_below = 150;
          char p140[64]; dlc_stage_path(p140, sizeof p140, 140);
          n = dlc_commit_chunk(0, p140, &cursor, rec_append, present_below, cb, DLC_STAGE_MAX_BYTES);
          ok(n == 30 && cursor == 180 && g_rec_h[0] == 150 && g_rec_ok, "heights already present are skipped: 30 appended from 150, cursor 180");
          /* a torn file (a worker killed mid-write can only leave a .tmp, but the committer checks anyway) */
          long sz = stage_chunk(180, 40); char p180[64]; dlc_stage_path(p180, sizeof p180, 180);
          ok(truncate(p180, sz - 10) == 0, "truncate the staged file by 10 bytes");
          g_rec_n = 0; cursor = 180;
          n = dlc_commit_chunk(0, p180, &cursor, rec_append, 0, cb, DLC_STAGE_MAX_BYTES);
          ok(n == -2 && g_rec_n == 0 && cursor == 180 && !dlc_stage_exists(180), "a torn staging file commits NOTHING and is discarded");
          /* a gap: the file's first height is above the cursor */
          stage_chunk(220, 40); char p220[64]; dlc_stage_path(p220, sizeof p220, 220);
          g_rec_n = 0; cursor = 180;
          n = dlc_commit_chunk(0, p220, &cursor, rec_append, 0, cb, DLC_STAGE_MAX_BYTES);
          ok(n == -2 && g_rec_n == 0 && cursor == 180 && !dlc_stage_exists(220), "a file starting above the cursor is discarded: a gap is never committed over");
          ok(dlc_commit_chunk(0, "stage/c9999.chunk", &cursor, rec_append, 0, cb, DLC_STAGE_MAX_BYTES) == -3, "a chunk not yet staged is -3 (wait)");
          /* the loop: chunks 100 and 140 staged, 180 missing, STOP set -> commits 80 in order, publishes 180, exits */
          static volatile long ctl2[DLC_CTL_RING + DLC_RETRY_MAX];
          for (long i = 0; i < DLC_CTL_RING + DLC_RETRY_MAX; i++) ctl2[i] = i < DLC_CTL_RING ? 0 : -1;
          ctl2[DLC_CTL_FIRST_HOLE] = 100; ctl2[DLC_CTL_STOP_COMMIT] = 1; ctl2[DLC_CTL_STAGED] = 2;
          stage_chunk(100, 40); stage_chunk(140, 40); g_rec_n = 0; g_rec_ok = 1; g_present_below = -1;
          g_synced_n = 0;
          int rc = dlc_committer_run(ctl2, 100, 999, 0, rec_append, 0, 5, 0, rec_synced);
          ok(rc == 0 && g_rec_n == 80 && g_rec_h[0] == 100 && g_rec_h[79] == 179 && g_rec_ok,
             "committer_run: two staged chunks appended in order (80 blocks)");
          ok(ctl2[DLC_CTL_FIRST_HOLE] == 180 && ctl2[DLC_CTL_COMMIT_TIP] == 179 && ctl2[DLC_CTL_N_COMMIT] == 2 && ctl2[DLC_CTL_STAGED] == 0,
             "...first hole 180 and committed tip 179 published, 2 commits counted, the gauge back to 0");
          ok(!dlc_stage_exists(100) && !dlc_stage_exists(140), "...and both files are gone; it exited at the missing chunk because STOP was set");
          /* the cursor-stall help (run 18 sat six minutes behind one trickling
           * peer while 85 chunks above were staged): a missing cursor chunk is
           * published after the help delay, a worker takes it, and the want
           * is cleared the moment the chunk commits */
          { volatile long* ctl3 = mmap(0, (DLC_CTL_RING + DLC_RETRY_MAX) * sizeof(long), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
            for (long i = 0; i < DLC_CTL_RING + DLC_RETRY_MAX; i++) ctl3[i] = i < DLC_CTL_RING ? 0 : -1;
            ctl3[DLC_CTL_FIRST_HOLE] = 300; ctl3[DLC_CTL_CURSOR_WANT] = -1;
            g_dlc_cursor_help_ms = 300;                   /* the seam: 300 ms instead of 10 s */
            pid_t cp = fork();
            if (cp == 0){ int rc = dlc_committer_run(ctl3, 300, 379, 0, rec_append, 0, 20, 0, 0); _exit(rc); }
            usleep(700000);
            ok(ctl3[DLC_CTL_CURSOR_WANT] == -1, "with nothing staged above it, a missing cursor chunk is NOT published (the pool has not moved on)");
            /* the pool has moved on: a third of the window staged ABOVE the cursor, as
             * real files -- the committer recounts the gauge from the directory */
            for (int k = 0; k <= DLC_CURSOR_HELP_MIN_STAGED; k++) stage_chunk(380 + 40L * k, 40);
            ctl3[DLC_CTL_STAGED] = DLC_CURSOR_HELP_MIN_STAGED + 1;
            long waited = 0; while (ctl3[DLC_CTL_CURSOR_WANT] != 300 && waited < 5000){ usleep(20000); waited += 20; }
            ok(ctl3[DLC_CTL_CURSOR_WANT] == 300, "with a third of the window staged above it, the missing cursor chunk (300) is published after the delay");
            stage_chunk(300, 40);                          /* the helper delivered it */
            waited = 0; while (ctl3[DLC_CTL_CURSOR_WANT] != -1 && waited < 5000){ usleep(20000); waited += 20; }
            ok(ctl3[DLC_CTL_CURSOR_WANT] == -1 && ctl3[DLC_CTL_COMMIT_TIP] == 339, "...the chunk commits and the want is cleared; committed tip 339");
            waited = 0; while (ctl3[DLC_CTL_CURSOR_WANT] != 340 && waited < 5000){ usleep(20000); waited += 20; }
            ok(ctl3[DLC_CTL_CURSOR_WANT] == 340, "...the next missing chunk (340) is published in its turn");
            ctl3[DLC_CTL_STOP_COMMIT] = 1; int st = 0; waitpid(cp, &st, 0);
            ok(WIFEXITED(st) && WEXITSTATUS(st) == 0 && ctl3[DLC_CTL_CURSOR_WANT] == -1, "STOP ends the run and clears the want");
            g_dlc_cursor_help_ms = DLC_CURSOR_HELP_SECS * 1000L;
            dlc_stage_wipe();
            munmap((void*)ctl3, (DLC_CTL_RING + DLC_RETRY_MAX) * sizeof(long)); }
          ok(g_synced_n == 2, "...and the store was synced once per committed chunk (2), not once per block (80)");
          /* stale staged files wholly below the cursor are swept and the gauge
           * becomes the directory's count (run 18 held six stale files that
           * inflated the gauge gating the cursor help) */
          { stage_chunk(20, 40); stage_chunk(60, 40); stage_chunk(180, 40); stage_chunk(220, 40);
            static volatile long ctl5[DLC_CTL_RING + DLC_RETRY_MAX]; ctl5[DLC_CTL_STAGED] = 99;
            long swept = dlc_stage_sweep(180, ctl5);
            ok(swept == 2 && !dlc_stage_exists(20) && !dlc_stage_exists(60), "chunks 20 and 60 (wholly below cursor 180) are swept");
            ok(dlc_stage_exists(180) && dlc_stage_exists(220) && ctl5[DLC_CTL_STAGED] == 2, "chunks 180 and 220 stay; the gauge is recounted from the directory (2, not 99)");
            ok(dlc_stage_wipe() == 2, "(cleanup)"); }
          /* Core's stall rule (2026-09-10): the parent evicts the worker holding
           * the window's tail -- the oldest missing chunk -- only while the
           * window is full, only if the chunk is not staged, only after the
           * adaptive timeout; the timeout doubles on an eviction and eases
           * when the tail moves. Time is the tick's parameter, so no waiting. */
          { volatile long* c = mmap(0, (DLC_CTL_RING + DLC_RETRY_MAX) * sizeof(long), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
            for (long i = 0; i < DLC_CTL_RING + DLC_RETRY_MAX; i++) c[i] = i < DLC_CTL_RING ? 0 : -1;
            static volatile dlc_stat_t sst[2]; memset((void*)sst, 0, sizeof sst);
            pid_t kids[2], opid[2];
            /* the tail's holder: a child that exits 7 on SIGUSR1 (the worker's abandon signal) */
            pid_t hp = fork();
            if (hp == 0){ for (;;){ sigset_t m; sigemptyset(&m); int s = 0; sigaddset(&m, SIGUSR1); sigprocmask(SIG_BLOCK, &m, 0); sigwait(&m, &s); if (s == SIGUSR1) _exit(7); } }
            kids[0] = opid[0] = hp; kids[1] = opid[1] = 0;
            sst[0].cur_lo = 100; sst[0].cur_hi = 139; strcpy((char*)sst[0].peer, "10.0.0.1:8333");
            c[DLC_CTL_FIRST_HOLE] = 100; c[DLC_CTL_SPAN_START] = 100; c[DLC_CTL_APPLIED] = -1;
            g_dlc_window = 4096; g_dlc_stall_timeout_s = 2;
            c[DLC_CTL_CLAIM] = 100 + 4000;                                   /* room left: not full */
            dlc_stall_tick(c, sst, kids, opid, 2, 100, 999999, 1000); dlc_stall_tick(c, sst, kids, opid, 2, 100, 999999, 60000);
            ok(c[DLC_CTL_N_STALL] == 0 && waitpid(hp, 0, WNOHANG) == 0, "window not full: the tail's holder is not a staller however long it holds");
            c[DLC_CTL_CLAIM] = 100 + 4097;                                   /* full */
            stage_chunk(100, 40);
            dlc_stall_tick(c, sst, kids, opid, 2, 100, 999999, 61000); dlc_stall_tick(c, sst, kids, opid, 2, 100, 999999, 120000);
            ok(c[DLC_CTL_N_STALL] == 0 && waitpid(hp, 0, WNOHANG) == 0, "window full but the tail chunk is STAGED: the committer has it, nobody is stalling");
            dlc_stage_wipe();
            dlc_stall_tick(c, sst, kids, opid, 2, 100, 999999, 121000);      /* the holder's clock starts */
            dlc_stall_tick(c, sst, kids, opid, 2, 100, 999999, 122900);      /* 1.9 s: not yet */
            ok(c[DLC_CTL_N_STALL] == 0 && waitpid(hp, 0, WNOHANG) == 0, "full, unstaged, held for 1.9 s of a 2 s timeout: not yet");
            dlc_stall_tick(c, sst, kids, opid, 2, 100, 999999, 123000);      /* 2.0 s: evicted */
            int st7 = 0; waitpid(hp, &st7, 0);
            ok(c[DLC_CTL_N_STALL] == 1 && WIFEXITED(st7) && WEXITSTATUS(st7) == 7 && sst[0].kill_reason == 1,
               "2 s at a full window: the holder is dropped (SIGUSR1, reason 'stalling the window'), the eviction counted");
            ok(g_dlc_stall_timeout_s == 4, "...and the timeout doubled to 4 s");
            kids[0] = 0;                                                    /* the worker is gone */
            c[DLC_CTL_FIRST_HOLE] = 140;                                     /* the tail moved on */
            dlc_stall_tick(c, sst, kids, opid, 2, 100, 999999, 124000);
            ok(g_dlc_stall_timeout_s == 3, "the tail moved: the timeout eases 15% (4 s -> 3 s)");
            dlc_stall_tick(c, sst, kids, opid, 2, 100, 999999, 200000);
            ok(c[DLC_CTL_N_STALL] == 1, "nobody holds the new tail (it is the retry ring's): no eviction");
            g_dlc_stall_timeout_s = DLC_STALL_TIMEOUT_MIN_S;
            munmap((void*)c, (DLC_CTL_RING + DLC_RETRY_MAX) * sizeof(long)); }
          /* a staged chunk is visible to the stall rule's guard, and the next run's wipe */
          stage_chunk(180, 40);
          ok(dlc_stage_exists(180), "a staged chunk is visible to the stall rule: its holder is not judged");
          ok(dlc_stage_wipe() == 1 && !dlc_stage_exists(180), "a new run discards what an earlier run left (its chunks are fetched again)");
          munmap(cb, DLC_STAGE_MAX_BYTES);
        }
        if (cwd3[0]) (void)!chdir(cwd3); }
      /* 2026-09-08: no tip announcements in IBD, Core's rule (tip older than maxtipage) */
      { long long now = 1800000000LL;
        ok(dl_announce_allowed((unsigned long)(now - 3600), now, 86400), "a tip an hour old: announce (not IBD)");
        ok(!dl_announce_allowed((unsigned long)(now - 90000), now, 86400), "a tip 25 hours old with maxtipage 24h: suppressed (IBD, as Core)");
        ok(dl_announce_allowed((unsigned long)(now + 100), now, 86400), "a tip slightly in the future: announce"); }
      /* slot rotation still breaks ties: 0 and 2 share the top ema, so from
       * slot 3 the walk reaches 0 by wrap in (slot+a) order */
      volatile double eq[4] = {9.0, 0.0, 9.0, 0.0};
      ok(dlc_pick_peer(4, 3, eq, cl, bn, 0.0) == 0, "tied top ema takes (slot+a) order first (slot 3 wraps to 0)");
      volatile double zero[4] = {0.0,0.0,0.0,0.0};
      ok(dlc_pick_peer(4, 2, zero, cl, bn, 0.0) == 2, "all-zero ema (fresh sync) falls back to rotation from the slot");
      bn[2] = 1;
      ok(dlc_pick_peer(4, 2, zero, cl, bn, 0.0) == 3, "...and the fallback skips banned exactly as the old loop did");
      bn[2] = 0;
      ok(dlc_pick_peer(4, 2, NULL, cl, bn, 0.0) == 2, "no ema pointer at all behaves as today"); }
    { char td3[] = "/tmp/bmc_goodpeers_XXXXXX"; if (!mkdtemp(td3)){ perror("mkdtemp"); return 1; }
      char cwd2[512]; if (!getcwd(cwd2, sizeof cwd2)) cwd2[0] = 0;
      if (chdir(td3) != 0){ perror("chdir"); return 1; }
      /* old format only: bare ips, junk ignored, no ema anywhere. NOTE the
       * bare-IPv4 rule (the same inet_pton gate as the pre-EMA loader): an
       * "ip:port" line is NOT a bare IPv4 and is skipped -- dlc_parse_peer,
       * not inet_pton, is what accepts ports on the dial path. */
      FILE* g = fopen("peers.good", "w");
      { const char* legacy = "1.1.1.1\nnot-an-ip\n2.2.2.2\n\n"; fwrite(legacy, 1, strlen(legacy), g); }
      fclose(g);
      static char gp[8][DL_POOL_SLOT]; static double ge[8];
      for (int i = 0; i < 8; i++) ge[i] = -1.0;
      for (int i = 0; i < 8; i++) gp[i][0]=0;
      int gn = dl_load_good_peers_ema(gp, ge, 8);
      ok(gn == 2 && !strcmp(gp[0],"1.1.1.1") && !strcmp(gp[1],"2.2.2.2"), "legacy bare-ip file parses (junk line skipped)");
      ok(ge[0] == 0.0 && ge[1] == 0.0, "...with ema 0 for every entry (no speed knowledge)");
      /* new format: ip<TAB>ema_kbps; the save side writes kilobits rounded,
       * the load side must hand back bytes/s (kbps/1000.0) */
      g = fopen("peers.good", "w");
      fputs("3.3.3.3\t1200\n4.4.4.4\t0\n5.5.5.5\t\n", g);
      fclose(g);
      for (int i = 0; i < 8; i++) ge[i] = -1.0;
      gn = dl_load_good_peers_ema(gp, ge, 8);
      ok(gn == 3 && !strcmp(gp[0],"3.3.3.3") && !strcmp(gp[1],"4.4.4.4") && !strcmp(gp[2],"5.5.5.5"), "ip-tab-number lines parse (0 and empty number allowed)");
      ok(ge[0] == 1.2 && ge[1] == 0.0 && ge[2] == 0.0, "ema_kbps/1000.0 == bytes/s (1200 kbps -> 1.2 B/s)");
      /* round-trip: save with an EMA vector, reload, compare */
      static char sp[3][DL_POOL_SLOT]; static double se[3];
      snprintf(sp[0], sizeof sp[0], "6.6.6.6"); snprintf(sp[1], sizeof sp[1], "7.7.7.7"); snprintf(sp[2], sizeof sp[2], "8.8.8.8");
      se[0] = 500.0; se[1] = 0.0; se[2] = 0.5;  /* 500000, bare (0), 500 -- all exact under *1000 round-trip */
      dl_save_good_peers_ema(sp, se, 3);
      for (int i = 0; i < 8; i++) ge[i] = -1.0;
      gn = dl_load_good_peers_ema(gp, ge, 8);
      ok(gn == 3 && !strcmp(gp[0],"6.6.6.6") && !strcmp(gp[1],"7.7.7.7") && !strcmp(gp[2],"8.8.8.8"), "save/load round-trips the peer list");
      ok(ge[0] == 500.0 && ge[1] == 0.0 && ge[2] == 0.5, "...and the speeds (stored as int value*1000, 0 stored bare)");
      { char buf[512]; FILE* rf = fopen("peers.good","r"); size_t rl = fread(buf,1,sizeof buf-1,rf); fclose(rf); buf[rl]=0;
        ok(strstr(buf,"6.6.6.6\t500000") != 0 && strstr(buf,"7.7.7.7\n") != 0 && strstr(buf,"8.8.8.8\t500") != 0,
           "on disk: ip<TAB>int-value*1000, zero written as a bare ip"); }
      /* a NULL ema pointer (callers with no speed array) reads the file as a
       * plain list -- the legacy behaviour */
      gn = dl_load_good_peers_ema(gp, NULL, 8);
      ok(gn == 3 && !strcmp(gp[2],"8.8.8.8"), "ema_out NULL reads any format as a plain list");
      if (cwd2[0]) (void)!chdir(cwd2); }

    kill(fp, SIGKILL); waitpid(fp, NULL, 0); close(l);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

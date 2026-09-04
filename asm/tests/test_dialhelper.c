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
    ok(dh_start("198.51.100.4:8333", 8333) == 0, "a third is refused (DH_MAX)");
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
      ok(dlc_dead_weight(2000.0, 0), "2 KB/s and no blocks this tick: dead weight");
      ok(dlc_dead_weight(2000.0, 9), "2 KB/s and 9 blocks: still dead weight (byte floor binds at any depth)");
      ok(dlc_dead_weight(2000.0, 50), "2 KB/s and 50 blocks: dead weight too (a block rate can launder bytes)");
      ok(!dlc_dead_weight(50000.0, 50), "50 KB/s and 50 blocks: pulling its weight, not banned");
      ok(!dlc_dead_weight(1500000.0, 1), "1.5 MB/s and one block: fine near the tip");
      ok(dlc_dead_weight(40000.0, 1), "40 KB/s and one block: marginal bytes AND stalled blocks");
      ok(!dlc_dead_weight(200000.0, 1), "200 KB/s and one block: big blocks, not stalled");
      ok(!dlc_dead_weight(-1.0, 0), "no rate sample yet: not judged");
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

    kill(fp, SIGKILL); waitpid(fp, NULL, 0); close(l);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

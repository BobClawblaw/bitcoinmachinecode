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

    kill(fp, SIGKILL); waitpid(fp, NULL, 0); close(l);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

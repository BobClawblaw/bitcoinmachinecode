/* tests/test_mux_dial_gate.c -- mux_next_peer refuses a dial the dial memory
 * or the manual-peer retry floor refuses (2026-09-24, from bmc_osx 5e71979a).
 *
 * The candidate loop marked a host `held` (under dial-memory backoff, already
 * a leg, anonymity net) and then dialled peers[p] anyway when no candidate
 * was free -- every pass, with a one-host pool. The osx deploy re-dialled a
 * wrong-port connect= peer 4.5 times a second for 33 minutes.
 *
 * The real mux_next_peer (main.c as a TU) against loopback hosts on a closed
 * port, so every helper dial fails fast:
 *   1  a one-host pool under backoff: no dial;
 *   2  two hosts, the first under backoff: the second is dialled;
 *   3  a connect= host under backoff IS dialled (manual peers are exempt),
 *      then not again inside Core's ~5.5 s -connect interval, then again;
 *   4  an addnode= host's floor is Core's 60 s.
 * A dial is observed as a helper in flight for the slot (dh_inflight_for). */
#include <stdio.h>
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main

static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c ? "ok  " : "FAIL", w); if(!c) fails++; }

/* wait out the slot's helper so the next call starts clean */
static void drain(void){
    dh_result_t r; int fd = -1; char h[128];
    for(int i = 0; i < 200 && dh_inflight_count() > 0; i++){
        if(dh_poll(&r, &fd, h, sizeof h) && fd >= 0){ close(fd); fd = -1; }
        else usleep(25000);
    }
}

int main(void){
    /* a loopback port nothing listens on: every dial is refused at once */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (struct sockaddr*)&sa, sizeof sa); socklen_t al = sizeof sa; getsockname(s, (struct sockaddr*)&sa, &al);
    int port = ntohs(sa.sin_port); close(s);

    char conf[] = "/tmp/test_mux_dial_gate.XXXXXX"; int cfd = mkstemp(conf);
    char body[256]; int bl = snprintf(body, sizeof body, "connect=127.0.0.3:%d\naddnode=127.0.0.4:%d\n", port, port);
    if(cfd < 0 || write(cfd, body, (size_t)bl) != bl){ perror("conf"); return 2; }
    close(cfd); node_config_load(conf); unlink(conf);

    for(int k = 0; k < MUX_MAX_OUT; k++) mux_out_fd[k] = -1;
    void* dm = malloc(dialmem_bytes(DIALMEM_CAP)); dialmem_init(dm, DIALMEM_CAP); g_dialmem = (dm_table_t*)dm;
    char a[64], b[64], c[64], d[64];
    snprintf(a, sizeof a, "127.0.0.1:%d", port); snprintf(b, sizeof b, "127.0.0.2:%d", port);
    snprintf(c, sizeof c, "127.0.0.3:%d", port); snprintf(d, sizeof d, "127.0.0.4:%d", port);
    long long now = dialmem_now();
    dialmem_note_failure(g_dialmem, a, DM_REFUSED, now);
    dialmem_note_failure(g_dialmem, c, DM_REFUSED, now);
    dialmem_note_failure(g_dialmem, d, DM_REFUSED, now);
    ok(!dialmem_allowed(g_dialmem, a, now) && !dialmem_allowed(g_dialmem, c, now), "fixture: the hosts are under backoff");

    printf("== 1. a one-host pool under backoff is not dialled ==\n");
    { const char* pool[] = { a }; mux_out_peer[0] = 0;
      mux_next_peer(0, pool, 1, port);
      ok(!dh_inflight_for(0), "no helper started for the slot"); drain(); }

    printf("== 2. the free host of two is dialled ==\n");
    { const char* pool[] = { a, b }; mux_out_peer[1] = 1;   /* rotation starts at index 0 (a) */
      mux_next_peer(1, pool, 2, port);
      ok(dh_inflight_for(1) && mux_out_peer[1] == 1, "the slot dials b, skipping a"); drain(); }

    printf("== 3. a connect= host: exempt from backoff, bounded by Core's -connect interval ==\n");
    { const char* pool[] = { c }; mux_out_peer[2] = 0;
      mux_next_peer(2, pool, 1, port);
      ok(dh_inflight_for(2), "dialled although under backoff (a manual peer)"); drain();
      mux_next_peer(2, pool, 1, port);
      ok(!dh_inflight_for(2), "not re-dialled at once"); drain();
      usleep((CONNECT_RETRY_FLOOR_MS + 300) * 1000);
      mux_next_peer(2, pool, 1, port);
      ok(dh_inflight_for(2), "re-dialled after ~5.5 s"); drain(); }

    printf("== 4. an addnode= host waits Core's 60 s ==\n");
    { const char* pool[] = { d }; mux_out_peer[3] = 0;
      long long t0 = dh_now_ms();
      mux_next_peer(3, pool, 1, port);
      ok(dh_inflight_for(3), "dialled although under backoff (a manual peer)"); drain();
      long long wait = g_leg_manual_next_dial[3] - t0;
      ok(wait >= 59000 && wait <= 61000, "the next dial is ~60 s out");
      mux_next_peer(3, pool, 1, port);
      ok(!dh_inflight_for(3), "not re-dialled at once"); drain(); }

    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

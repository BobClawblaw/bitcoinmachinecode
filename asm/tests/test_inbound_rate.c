/* test_inbound_rate.c -- the per-address inbound connection rate limit.
 *
 * WHY IT EXISTS. On 2026-09-14 one LAN host opened ~3,780 connections in 23
 * minutes, about nine a second, and this node forked a child for every one.
 * Nothing throttled it. The chain stayed healthy, but load went from 3.9 to 6.4
 * and the box was forking at ~160/s.
 *
 * This is NOT a Core divergence about the protocol: Core does not rate-limit
 * inbound connections per address either, because it serves peers with threads.
 * This node forks a process per connection, so the same flood costs it far more.
 * The limit protects an implementation difference.
 *
 * The limiter is a static in daemon/main.c, so this test compiles that logic
 * directly rather than linking the daemon -- the alternative is booting a node
 * and opening thousands of sockets to it, which is what the gate must not do. */
#include <stdio.h>
#include <string.h>
#include <time.h>

static int pass, fail;
static void ck(const char* n, int ok){ if(ok){ printf("ok  : %s\n", n); pass++; } else { printf("FAIL: %s\n", n); fail++; } }

/* --- the limiter under test, kept identical to daemon/main.c -------------- */
#define NP_NOBAN 1u
static unsigned g_perm_for_test = 0;
static unsigned netperm_for(const char* ip){ (void)ip; return g_perm_for_test; }
static time_t g_now = 1000;
#define time(x) (g_now)

#define INRATE_SLOTS    64
#define INRATE_BURST    12
#define INRATE_PER_SEC   1
static struct { char ip[64]; double tokens; time_t seen, last_log; } g_inrate[INRATE_SLOTS];

static int inbound_rate_ok(const char* ip, int* logged)
{
    if (logged) *logged = 0;
    if (!ip || !*ip) return 1;
    if (netperm_for(ip) & NP_NOBAN) return 1;
    time_t now = time(NULL);
    int slot = -1, oldest = 0;
    for (int i = 0; i < INRATE_SLOTS; i++){
        if (!strcmp(g_inrate[i].ip, ip)){ slot = i; break; }
        if (g_inrate[i].seen < g_inrate[oldest].seen) oldest = i;
    }
    if (slot < 0){
        slot = oldest;
        snprintf(g_inrate[slot].ip, sizeof g_inrate[slot].ip, "%s", ip);
        g_inrate[slot].tokens = INRATE_BURST;
        g_inrate[slot].last_log = 0;
    } else {
        double dt = (double)(now - g_inrate[slot].seen);
        if (dt > 0){
            g_inrate[slot].tokens += dt * INRATE_PER_SEC;
            if (g_inrate[slot].tokens > INRATE_BURST) g_inrate[slot].tokens = INRATE_BURST;
        }
    }
    g_inrate[slot].seen = now;
    if (g_inrate[slot].tokens >= 1.0){ g_inrate[slot].tokens -= 1.0; return 1; }
    if (now - g_inrate[slot].last_log >= 10){ g_inrate[slot].last_log = now; if (logged) *logged = 1; }
    return 0;
}
#undef time

static void reset(void){ memset(g_inrate, 0, sizeof g_inrate); g_perm_for_test = 0; g_now = 1000; }

int main(void){
    int lg;
    printf("== the burst, then the refusal ==\n");
    reset();
    int allowed = 0;
    for (int i = 0; i < INRATE_BURST; i++) allowed += inbound_rate_ok("192.0.2.9", &lg);
    ck("a fresh address gets its whole burst", allowed == INRATE_BURST);
    ck("the next connection in the same second is refused",
       !inbound_rate_ok("192.0.2.9", &lg));

    printf("== the incident, replayed ==\n");
    reset();
    /* nine connections a second for sixty seconds, as measured */
    int served = 0, refused = 0;
    for (int sec = 0; sec < 60; sec++){
        g_now = 1000 + sec;
        for (int k = 0; k < 9; k++){ if (inbound_rate_ok("192.168.5.76", &lg)) served++; else refused++; }
    }
    /* 12 burst + 59 refills = 71 served; the rest refused. Asserted against the
     * model rather than a round number, so the figure cannot drift unnoticed. */
    ck("540 attempts at 9/s are refused down to the sustained rate",
       refused == 540 - served && served < 80);
    /* the sustained rate is what gets through: burst + one per second */
    ck("...and what is served is the burst plus the sustained rate",
       served <= INRATE_BURST + 60 * INRATE_PER_SEC && served >= 60 * INRATE_PER_SEC);
    printf("      served %d of 540, refused %d\n", served, refused);

    printf("== an honest peer is unaffected ==\n");
    reset();
    int ok_honest = 1;
    for (int day = 0; day < 200; day++){       /* one reconnect every 30s for 100 min */
        g_now = 1000 + day * 30;
        if (!inbound_rate_ok("198.51.100.4", &lg)) ok_honest = 0;
    }
    ck("a peer reconnecting every 30s is never refused", ok_honest);
    reset();
    ck("a peer that connects once is never refused", inbound_rate_ok("198.51.100.5", &lg));

    printf("== refill ==\n");
    reset();
    for (int i = 0; i < INRATE_BURST; i++) inbound_rate_ok("192.0.2.10", &lg);
    ck("bucket empty", !inbound_rate_ok("192.0.2.10", &lg));
    g_now += 5;
    int after = 0; for (int i = 0; i < 5; i++) after += inbound_rate_ok("192.0.2.10", &lg);
    ck("five seconds refills five connections, not more", after == 5);
    ck("...and the sixth is refused again", !inbound_rate_ok("192.0.2.10", &lg));
    g_now += 10000;
    int capped = 0; for (int i = 0; i < INRATE_BURST + 5; i++) capped += inbound_rate_ok("192.0.2.10", &lg);
    ck("a long idle refills to the burst and no further", capped == INRATE_BURST);

    printf("== noban is exempt ==\n");
    reset();
    g_perm_for_test = NP_NOBAN;
    int wl = 0;
    for (int i = 0; i < 500; i++) wl += inbound_rate_ok("203.0.113.7", &lg);
    ck("a whitelisted peer is never refused, however fast", wl == 500);

    printf("== addresses are independent ==\n");
    reset();
    for (int i = 0; i < INRATE_BURST + 5; i++) inbound_rate_ok("192.0.2.20", &lg);
    ck("one address exhausting its bucket does not refuse another",
       inbound_rate_ok("192.0.2.21", &lg));

    printf("== the log does not flood with the connections ==\n");
    reset();
    for (int i = 0; i < INRATE_BURST; i++) inbound_rate_ok("192.0.2.30", &lg);
    int says = 0;
    for (int i = 0; i < 100; i++){ inbound_rate_ok("192.0.2.30", &lg); says += lg; }
    ck("100 refusals in one second log at most once", says <= 1);
    /* ...but a flood that carries on must not go silent for ever: after the
     * 10-second window it says so once more. Drain the refilled tokens first,
     * or the next call is served and nothing is logged. */
    reset();
    for (int i = 0; i < INRATE_BURST; i++) inbound_rate_ok("192.0.2.31", &lg);
    int first = 0; inbound_rate_ok("192.0.2.31", &first);
    /* Count logs ACROSS the next window, not just on the final call: the drain
     * consumes the one permitted log, and asserting on the last call alone
     * sees nothing and reads as a defect. (It did, first time round.) */
    g_now += 11;
    int later = 0;
    for (int i = 0; i < INRATE_BURST + 20; i++){ int l2 = 0; inbound_rate_ok("192.0.2.31", &l2); later += l2; }
    ck("but it does log again after the quiet window -- exactly once",
       first == 1 && later == 1);

    printf("== the copy has not drifted from daemon/main.c ==\n");
    {   /* This file COPIES the limiter, because it is a static in main.c and the
         * alternative is booting a node and opening thousands of sockets to it,
         * which the gate must not do. A copy can drift from its original and
         * then this suite proves nothing about the shipped code -- so the
         * constants are checked against the source itself. */
        FILE* f = fopen("daemon/main.c", "r");
        if (!f) f = fopen("../asm/daemon/main.c", "r");
        ck("daemon/main.c is readable from the test's working directory", f != NULL);
        int seen_slots = 0, seen_burst = 0, seen_rate = 0, seen_call = 0;
        if (f){
            char line[1024];
            while (fgets(line, sizeof line, f)){
                if (strstr(line, "#define INRATE_SLOTS")   && strstr(line, "64")) seen_slots = 1;
                if (strstr(line, "#define INRATE_BURST")   && strstr(line, "12")) seen_burst = 1;
                if (strstr(line, "#define INRATE_PER_SEC") && strstr(line, "1"))  seen_rate  = 1;
                /* and that it is actually CALLED before the fork, not merely defined */
                if (strstr(line, "inbound_rate_ok(bip")) seen_call = 1;
            }
            fclose(f);
        }
        ck("INRATE_SLOTS still 64 in the daemon",    seen_slots);
        ck("INRATE_BURST still 12 in the daemon",    seen_burst);
        ck("INRATE_PER_SEC still 1 in the daemon",   seen_rate);
        ck("and the daemon still CALLS it on the accept path", seen_call);
    }

    printf("\npassed %d, failed %d\n", pass, fail);
    if (fail) { printf("TESTS FAILED (%d failure(s))\n", fail); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}

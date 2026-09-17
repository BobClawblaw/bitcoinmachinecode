/* tests/test_leg_close_labels.c -- 2026-09-17: every outbound leg departure
 * names its owner.
 *
 * The defect this pins: a leg could leave a slot with NOTHING in the log.
 * mux_next_peer() closed a live fd on entry, setnetworkactive/disconnectnode/
 * setban closed one by hand, the serve_mux poll path printed "dropped" in a
 * shape that is neither ours nor theirs, and a worker restart took every leg
 * with it unannounced. Run 26's log (2026-09-16/17) showed 42 handshakes and
 * 3 logged closes, which reads as churn until the nine boots are counted --
 * and three legs whose sockets the kernel had already torn down were still
 * held as live, for up to 24 minutes, with no line at all.
 *
 * This is a STRUCTURAL test of daemon/main.c: the invariant is that the leg
 * fd is closed in exactly two places, leg_close_ours() and leg_close_theirs(),
 * which are the two functions that print a reason, a slot, an address and an
 * age. Anything else that clears mux_out_fd[i] is a departure with no owner.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c ? "ok  :" : "FAIL:", m); }

#define MAXL 40000
static char* line[MAXL]; static int nlines;

static void load(const char* path){
    FILE* f = fopen(path, "r");
    if(!f){ fprintf(stderr, "cannot open %s\n", path); exit(2); }
    static char buf[8192];
    while(nlines < MAXL && fgets(buf, sizeof buf, f)) line[nlines++] = strdup(buf);
    fclose(f);
}
/* [start,end) of the function whose definition line contains `sig` */
static int fn_range(const char* sig, int* start, int* end){
    for(int i = 0; i < nlines; i++){
        if(!strstr(line[i], sig)) continue;
        if(!strchr(line[i], '{')) continue;
        *start = i;
        for(int j = i + 1; j < nlines; j++)
            if(line[j][0] == '}'){ *end = j; return 1; }
        return 0;
    }
    return 0;
}
static int in_range(int i, int a, int b){ return i >= a && i < b; }
static int fn_contains(const char* sig, const char* needle){
    int a, b; if(!fn_range(sig, &a, &b)) return 0;
    for(int i = a; i < b; i++) if(strstr(line[i], needle)) return 1;
    return 0;
}
int main(int argc, char** argv){
    const char* path = argc > 1 ? argv[1] : "daemon/main.c";
    load(path);
    printf("== %s: %d lines ==\n", path, nlines);

    int ours_a = 0, ours_b = 0, theirs_a = 0, theirs_b = 0;
    ok(fn_range("static void leg_close_ours(",   &ours_a,   &ours_b),   "leg_close_ours() found");
    ok(fn_range("static void leg_close_theirs(", &theirs_a, &theirs_b), "leg_close_theirs() found");

    printf("== every close of a leg fd is inside one of the two labelled helpers ==\n");
    int strays = 0;
    for(int i = 0; i < nlines; i++){
        const char* l = line[i];
        /* a close of the leg socket: close(mux_out_fd[...]) or mux_out_fd[...] = -1 */
        int closes = 0;
        { const char* c = strstr(l, "close(mux_out_fd[");
          /* bmc_v2_close() ends the BIP324 session, not the socket: only a
           * bare close() is a departure */
          while(c){ if(c == l || !(c[-1] == '_' || (c[-1] >= 'a' && c[-1] <= 'z'))) closes = 1;
                    c = strstr(c + 1, "close(mux_out_fd["); } }
        int clears = 0;
        { const char* p = strstr(l, "mux_out_fd[");
          while(p){ const char* eq = strchr(p, ']');
                    if(eq){ const char* q = eq + 1; while(*q == ' ') q++;
                            if(q[0] == '=' && q[1] != '='){ const char* v = q + 1; while(*v == ' ') v++;
                                                            if(v[0] == '-' && v[1] == '1') clears = 1; } }
                    p = strstr(p + 1, "mux_out_fd["); } }
        if(!closes && !clears) continue;
        if(in_range(i, ours_a, ours_b) || in_range(i, theirs_a, theirs_b)) continue;
        strays++;
        printf("       unlabelled leg close at %s:%d: %s", path, i + 1, l);
    }
    ok(strays == 0, "no leg fd is closed outside leg_close_ours()/leg_close_theirs()");

    printf("== the paths that used to leave silently ==\n");
    ok(fn_contains("static void mux_next_peer(", "leg_close_ours"),
       "mux_next_peer() names the live leg it drops before rotating the slot");
    ok(fn_contains("static void legs_sweep_except(", "leg_check_gone"),
       "legs_sweep_except() checks leg liveness (the rotation is not the only place a hangup is seen)");
    ok(fn_contains("static int leg_check_gone(", "leg_close_theirs"),
       "leg_check_gone() reports a hung-up peer as theirs, with the revents and the unread bytes");

    printf("== the liveness rule is liveness, not throughput ==\n");
    { int a = 0, b = 0, bad = 0;
      if(fn_range("static int leg_check_gone(", &a, &b))
          for(int i = a; i < b; i++)
              if(strstr(line[i], "bps") || strstr(line[i], "KB/s") || strstr(line[i], "bytes_per")) bad++;
      ok(bad == 0, "leg_check_gone() carries no byte-rate rule (the 32 KB/s eviction floor stays dead)"); }

    printf("== a restart is a departure too ==\n");
    { int hit = 0;
      for(int i = 0; i < nlines; i++) if(strstr(line[i], "closed ours/shutdown after")) hit = 1;
      ok(hit, "the worker's shutdown names each live leg's departure with its age"); }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}

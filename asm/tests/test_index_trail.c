/* test_index_trail.c -- the trailing index supervisor (daemon/index_trail.h)
 * driven through its spawn seam: no real builder, no real archive. What is
 * asserted is the STATE MACHINE -- when it builds, over which range, that it
 * waits for the safety margin and the run size, that a committed run reaches
 * the caller's callback exactly once, that a failing child backs off without
 * an attempt cap, that merges take precedence once the runs pile up, and
 * that it keeps trailing after "IBD" (there is no such phase here at all).
 *
 * The child is a real fork that exits with the status the test chooses, so
 * the reap path is the real one. */
#include "../daemon/index_trail.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "test_tmpdir.h"
#ifdef __APPLE__
#define TRUE_BIN "/usr/bin/true"   /* macOS has no /bin/true */
#else
#define TRUE_BIN "/bin/true"
#endif


static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

static int  g_exit_code = 0;                 /* what the next child exits with */
static int  g_spawns, g_last_kind; static long g_last_from, g_last_to;
/* 2026-09-25: the stub child is HELD until the test releases it. It used to
 * _exit at once, so "a running child is left alone" raced the child's exit:
 * when the child won, the very next tick reaped it, reported the run and
 * spawned the next build, and every later "reported" count was off by one
 * (7 failures, 10 of 20 standalone runs on a loaded box). Now the child
 * blocks on a pipe; tick_until_reaped releases it (closes the write end). */
static int g_hold_fd = -1;                   /* write end holding the current child */
static void release_child(void){ if (g_hold_fd >= 0){ close(g_hold_fd); g_hold_fd = -1; } }
static pid_t stub_spawn(const itrail_t* t, int kind, long from, long to){
    (void)t; g_spawns++; g_last_kind = kind; g_last_from = from; g_last_to = to;
    int pp[2]; if (pipe(pp) != 0){ perror("pipe"); exit(2); }
    pid_t p = fork();
    if (p == 0){ close(pp[1]); char c; ssize_t r = read(pp[0], &c, 1); (void)r; _exit(g_exit_code); }
    close(pp[0]); release_child(); g_hold_fd = pp[1];
    return p;
}
static long g_runs_reported[16]; static int g_nreported;
static void on_run(long to, void* ctx){ (void)ctx; if (g_nreported < 16) g_runs_reported[g_nreported] = to; g_nreported++; }

static int tick_until_reaped(itrail_t* t, long covered, int nruns, long applied, long long* now){
    /* the child exits within 50 ms; tick until the SUPERVISOR has reaped it. The
     * test must not waitpid() itself: that would steal the exit status and
     * the supervisor would read the child as gone-without-status. (The first
     * draft did exactly that, and every failure case passed as a success.) */
    int st = t->state; pid_t was = t->pid;
    release_child();                         /* let the held child exit now */
    /* stop at the tick that reaped THIS child -- that tick may already have
     * spawned the next one, which is the supervisor's business, not ours */
    for (int i = 0; i < 2000 && t->pid == was; i++){ usleep(1000); *now += 1; st = it_tick(t, covered, nruns, applied, *now, on_run, 0); }
    return st;
}

int main(void){
    tt_isolate();
    it_spawn_hook = stub_spawn;
    itrail_t t; long long now = 1000;
    it_configure(&t, "txindex", TRUE_BIN, TRUE_BIN, ".", "main", 100 /* run_blocks */, 10 /* safety */, 3 /* merge_at */, 1);
    /* The tick that reaps a child may spawn the next one at once -- that is
     * the supervisor doing its job. To inspect one step at a time, every reap
     * below is ticked with an applied height ONE SHORT of the next run
     * (covered + safety + run_blocks - 1), so nothing new starts until the
     * test asks for it with a larger applied height. */
#define ONE_SHORT(covered) ((covered) + 10 + 99)

    /* nothing ready: applied 50, safety 10 -> 41 heights, below a run */
    int st = it_tick(&t, -1, 0, 50, now, on_run, 0);
    ck("below a run's worth of ready heights: no spawn", st == IT_CURRENT && g_spawns == 0);
    ck("...and says how many more it needs", strstr(it_status(&t), "59 more") != NULL);

    /* exactly a run's worth: [0, 99] needs applied - 10 >= 99 -> applied 109 */
    st = it_tick(&t, -1, 0, 108, ++now, on_run, 0);
    ck("one short of a run: still waiting", st == IT_CURRENT && g_spawns == 0);
    st = it_tick(&t, -1, 0, 109, ++now, on_run, 0);
    ck("a run's worth ready: builds", st == IT_BUILDING && g_spawns == 1);
    ck("...the first run starts at genesis", g_last_kind == 1 && g_last_from == 0 && g_last_to == 99);
    st = it_tick(&t, -1, 0, 500, ++now, on_run, 0);
    ck("a running child is left alone (no second spawn)", st == IT_BUILDING && g_spawns == 1);
    st = tick_until_reaped(&t, 99, 1, ONE_SHORT(99), &now);
    ck("the run is reported to the caller once, with its to height", g_nreported == 1 && g_runs_reported[0] == 99);
    ck("...and the supervisor is current (nothing more ready)", st == IT_CURRENT && t.pid < 0);

    /* far behind (applied 500, covered 99): runs of exactly run_blocks, never everything at once */
    st = it_tick(&t, 99, 1, 500, ++now, on_run, 0);
    ck("the next run is [100,199], not everything at once", st == IT_BUILDING && g_last_from == 100 && g_last_to == 199);
    st = tick_until_reaped(&t, 199, 2, ONE_SHORT(199), &now);
    ck("second run reported", g_nreported == 2 && g_runs_reported[1] == 199);
    st = it_tick(&t, 199, 2, 500, ++now, on_run, 0);
    st = tick_until_reaped(&t, 299, 3, ONE_SHORT(299), &now);
    ck("third run reported", g_nreported == 3 && g_runs_reported[2] == 299);

    /* three runs: merge takes precedence over the next build, even with a run's worth ready */
    ck("...but with merge_at runs the reap tick started the MERGER, not a build", st == IT_MERGING && g_last_kind == 2 && t.pid > 0);
    st = tick_until_reaped(&t, 299, 1, ONE_SHORT(299), &now);
    ck("a merge is not reported as a run", g_nreported == 3 && st == IT_CURRENT);

    /* a failing child backs off, is retried after the backoff, and there is no attempt cap */
    g_exit_code = 3;
    st = it_tick(&t, 299, 1, 500, ++now, on_run, 0);
    ck("builder spawned for [300,399]", st == IT_BUILDING && g_last_from == 300 && g_last_to == 399);
    st = tick_until_reaped(&t, 299, 1, 500, &now);
    ck("a non-zero exit -> backoff, run NOT reported", st == IT_BACKOFF && g_nreported == 3);
    int spawns_before = g_spawns;
    st = it_tick(&t, 299, 1, 500, now + 5, on_run, 0);
    ck("inside the backoff: no spawn", st == IT_BACKOFF && g_spawns == spawns_before);
    now += IT_BACKOFF_S + 1;
    for (int i = 0; i < 5; i++){
        st = it_tick(&t, 299, 1, 500, ++now, on_run, 0);
        ck(i == 0 ? "after the backoff: retried" : "retried again (no attempt cap)", st == IT_BUILDING);
        st = tick_until_reaped(&t, 299, 1, 500, &now);
        now += IT_BACKOFF_S + 1;
    }
    ck("six failures in a row and still willing", t.failures == 6 && st == IT_BACKOFF);
    g_exit_code = 0;
    st = it_tick(&t, 299, 1, 500, ++now, on_run, 0);
    st = tick_until_reaped(&t, 399, 2, ONE_SHORT(399), &now);
    ck("a success after failures resets the streak and reports the run", t.failures == 0 && g_nreported == 4 && g_runs_reported[3] == 399);

    /* the safety margin: with applied 505 and covered 399, [400,495] is ready -- 96 heights, under a run */
    st = it_tick(&t, 399, 2, 505, ++now, on_run, 0);
    ck("a run's worth must be ready BELOW the safety margin, not merely applied", st == IT_CURRENT);
    /* applied 509: [400,499] is exactly a run, and 499 == applied - safety */
    st = it_tick(&t, 399, 2, 509, ++now, on_run, 0);
    ck("a run never reaches into the safety margin", st == IT_BUILDING && g_last_from == 400 && g_last_to == 499 && g_last_to == 509 - 10);
    st = tick_until_reaped(&t, 499, 3, 509, &now);

    /* disabled: nothing, ever */
    itrail_t d; it_configure(&d, "txospender", TRUE_BIN, "", ".", "main", 100, 10, 0, 0);
    spawns_before = g_spawns;
    st = it_tick(&d, -1, 0, 100000, ++now, on_run, 0);
    ck("a disabled index never spawns", st == IT_DISABLED && g_spawns == spawns_before);

    /* no applied height yet (engine not up): nothing */
    itrail_t e; it_configure(&e, "txindex", TRUE_BIN, "", ".", "main", 100, 10, 0, 1);
    st = it_tick(&e, -1, 0, -1, ++now, on_run, 0);
    ck("without an applied height nothing is built", st == IT_IDLE && g_spawns == spawns_before);

    printf(fails ? "\nFAILURES: %d\n" : "\nall good\n", fails);
    return fails ? 1 : 0;
}

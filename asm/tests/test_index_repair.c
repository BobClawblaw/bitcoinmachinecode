/* tests/test_index_repair.c -- the index repair supervisor (daemon/index_repair.c,
 * 2026-09-10, CORE_DIVERGENCES row 2): spawns when an index needs a build and
 * the node is out of IBD, never while a build runs, reaps and adopts, backs off
 * and gives up after three failures, and stays quiet when nothing is needed. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../daemon/index_repair.h"
static int fails; static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static int spawned; static long spawned_to; static int child_rc;
static pid_t stub_spawn(const ir_t* r, long to){ (void)r; spawned++; spawned_to = to; pid_t p = fork(); if (p == 0) _exit(child_rc); return p; }
int main(void){
    ir_spawn_hook = stub_spawn;
    ir_t r; ir_configure(&r, "bfilter", "/bin/true", ".", "main", "", 1);
    ck("nothing needed: OK, no spawn", ir_tick(&r, 0, 1000, 0, 100) == IR_OK && spawned == 0);
    ck("needed but in IBD: waits, no spawn", ir_tick(&r, 1, 1000, 1, 101) == IR_IBD && spawned == 0);
    ck("needed, out of IBD: the builder is spawned to the target", ir_tick(&r, 1, 1000, 0, 102) == IR_RUNNING && spawned == 1 && spawned_to == 1000);
    ck("while it runs: no second spawn", ir_tick(&r, 1, 1001, 0, 103) == IR_RUNNING && spawned == 1);
    usleep(50000);
    ck("the builder exits and the index is current: OK", ir_tick(&r, 0, 1001, 0, 104) == IR_OK);
    ck("...status names the adoption", strstr(ir_status(&r), "adopted") != 0);
    /* a builder that leaves the index still needing a build: backoff, then give up */
    ir_t b; ir_configure(&b, "addrhist", "/bin/true", ".", "main", "", 1);
    spawned = 0;
    ck("attempt 1 spawns", ir_tick(&b, 1, 500, 0, 200) == IR_RUNNING); usleep(50000);
    ck("still needed after it ended: BACKOFF (6 h)", ir_tick(&b, 1, 500, 0, 201) == IR_BACKOFF && b.next_allowed == 201 + IR_BACKOFF_S);
    ck("inside the backoff: no spawn", ir_tick(&b, 1, 500, 0, 300) == IR_BACKOFF && spawned == 1);
    ck("after the backoff: attempt 2", ir_tick(&b, 1, 500, 0, 201 + IR_BACKOFF_S + 1) == IR_RUNNING && spawned == 2); usleep(50000);
    ir_tick(&b, 1, 500, 0, 201 + IR_BACKOFF_S + 2);
    ck("attempt 3 after the next backoff", ir_tick(&b, 1, 500, 0, 201 + 2 * IR_BACKOFF_S + 3) == IR_RUNNING && spawned == 3); usleep(50000);
    ck("three failures: GAVE UP for this boot", ir_tick(&b, 1, 500, 0, 201 + 2 * IR_BACKOFF_S + 4) == IR_GAVE_UP);
    ck("...and no fourth spawn however long", ir_tick(&b, 1, 500, 0, 201 + 9 * IR_BACKOFF_S) == IR_GAVE_UP && spawned == 3);
    ir_t d; ir_configure(&d, "bfilter", "/bin/true", ".", "main", "", 0);
    ck("repair disabled in the config: DISABLED, no spawn", ir_tick(&d, 1, 10, 0, 1) == IR_DISABLED && spawned == 3);
    ir_t m; ir_configure(&m, "bfilter", "/nonexistent/builder", ".", "main", "", 1); ir_spawn_hook = 0;
    ck("no builder beside the daemon: NO_BUILDER", ir_tick(&m, 1, 10, 0, 1) == IR_NO_BUILDER);
    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

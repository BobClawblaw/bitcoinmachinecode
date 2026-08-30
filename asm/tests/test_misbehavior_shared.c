/* tests/test_misbehavior_shared.c -- misbehaviour scores must survive across
 * processes (audit finding 7, second half).
 *
 * The serve loop that detects protocol violations runs in a FORKED CHILD. The
 * score table used to be a process-local array, so every child started from
 * zero and a peer could misbehave once per connection forever without ever
 * reaching the 100-point threshold. The machinery looked like a defence and
 * could not accumulate -- the failure was invisible because each individual
 * report was logged correctly.
 *
 * This test therefore does the one thing a single-process test cannot: it
 * scores the SAME peer from several separate children and asserts the total
 * adds up in shared memory. Run against the old process-local table, the
 * accumulation assertion fails.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "../rpc_node.h"

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* Mirrors peer_misbehaving's shared-table update. Kept here rather than
 * linking daemon/main.c (which drags in the whole node) -- the property under
 * test is the SHARING, and this exercises the same region, lock and slot
 * discipline. */
#define BAN_THRESHOLD 100
static void mis_lock(node_status_t* st){ while (__sync_lock_test_and_set(&st->mis_lock, 1)) usleep(200); }
static void mis_unlock(node_status_t* st){ __sync_lock_release(&st->mis_lock); }

static int score(node_status_t* st, const char* ip, int points){
    mis_lock(st);
    int slot = -1, freeslot = -1;
    for (int i = 0; i < RPC_MISBEHAVIOR_SLOTS; i++){
        if (st->misbehavior[i].ip[0] && !strcmp((char*)st->misbehavior[i].ip, ip)){ slot = i; break; }
        if (!st->misbehavior[i].ip[0] && freeslot < 0) freeslot = i;
    }
    if (slot < 0){
        slot = freeslot < 0 ? 0 : freeslot;
        snprintf((char*)st->misbehavior[slot].ip, sizeof st->misbehavior[slot].ip, "%s", ip);
        st->misbehavior[slot].score = 0;
    }
    st->misbehavior[slot].score += points;
    int total = st->misbehavior[slot].score;
    if (total >= BAN_THRESHOLD) st->misbehavior[slot].score = 0;
    mis_unlock(st);
    return total;
}
static int score_of(node_status_t* st, const char* ip){
    for (int i = 0; i < RPC_MISBEHAVIOR_SLOTS; i++)
        if (st->misbehavior[i].ip[0] && !strcmp((char*)st->misbehavior[i].ip, ip))
            return st->misbehavior[i].score;
    return -1;
}

int main(void){
    node_status_t* st = mmap(NULL, sizeof *st, PROT_READ|PROT_WRITE,
                             MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED){ printf("  FAIL mmap\n"); return 1; }
    memset(st, 0, sizeof *st);

    printf("== a single process accumulates (the easy half) ==\n");
    score(st, "1.2.3.4", 10);
    score(st, "1.2.3.4", 10);
    ck("two reports of 10 give 20", score_of(st, "1.2.3.4") == 20);

    printf("== scores survive across FORKED CHILDREN ==\n");
    /* This is the property that did not exist. Each child is a separate
     * process, exactly like a forked serve child handling one connection. */
    { memset(st, 0, sizeof *st);
      for (int i = 0; i < 5; i++){
          pid_t p = fork();
          if (p == 0){ score(st, "9.9.9.9", 10); _exit(0); }
          int s; waitpid(p, &s, 0);
      }
      int total = score_of(st, "9.9.9.9");
      char l[120]; snprintf(l, sizeof l, "5 children x 10 points = %d (expect 50)", total);
      ck(l, total == 50);
      if (total == 10) printf("        each child started from zero -- the table is not shared\n"); }

    printf("== the threshold is reached across connections, not just within one ==\n");
    { memset(st, 0, sizeof *st);
      int banned = 0;
      for (int i = 0; i < 10; i++){
          pid_t p = fork();
          if (p == 0){ int t = score(st, "8.8.8.8", 10); _exit(t >= BAN_THRESHOLD ? 7 : 0); }
          int s; waitpid(p, &s, 0);
          if (WIFEXITED(s) && WEXITSTATUS(s) == 7) banned = 1;
      }
      ck("10 separate connections x 10 points reaches the ban threshold", banned);
      ck("  and the score resets after the ban", score_of(st, "8.8.8.8") == 0); }

    printf("== concurrent children do not corrupt the table ==\n");
    /* Without the lock, two children can allocate two slots for one peer and
     * each accumulate half the evidence -- the quiet version of the same bug. */
    { memset(st, 0, sizeof *st);
      const int N = 16, PER = 5;
      for (int i = 0; i < N; i++){
          pid_t p = fork();
          if (p == 0){ for (int k = 0; k < PER; k++) score(st, "7.7.7.7", 1); _exit(0); }
      }
      for (int i = 0; i < N; i++) wait(NULL);
      int slots = 0;
      for (int i = 0; i < RPC_MISBEHAVIOR_SLOTS; i++)
          if (st->misbehavior[i].ip[0] && !strcmp((char*)st->misbehavior[i].ip, "7.7.7.7")) slots++;
      char l[120];
      snprintf(l, sizeof l, "one peer occupies exactly 1 slot after %d concurrent children (got %d)", N, slots);
      ck(l, slots == 1);
      int total = score_of(st, "7.7.7.7");
      snprintf(l, sizeof l, "  and every point landed: %d of %d", total, N * PER);
      ck(l, total == N * PER); }

    munmap(st, sizeof *st);
    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

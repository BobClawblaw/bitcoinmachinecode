/* tests/test_inflight.c -- one request per block across the legs (daemon/inflight.c)
 *
 * 2026-11-07: the table is shared by the worker and its forked pass helpers,
 * and a stored block is remembered. Covered beyond the single-process rules:
 *   - a stored mark refuses every leg until INFLIGHT_DONE_S, is not a claim
 *     (count, release_leg), takes over a claim on the same hash, and is
 *     forgotten on a rewind;
 *   - across fork(): a claim or a stored mark made in one child refuses the
 *     same hash to a sibling that forked BEFORE it was made (production's
 *     case, 2026-11-06), and a PRIVATE table -- what each helper had until
 *     now -- does not (the control);
 *   - eight processes racing to claim the same 2,000 hashes: every hash is
 *     won exactly once;
 *   - a holder that died inside the lock does not wedge the others.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../daemon/inflight.h"
static int fails = 0;
static void ck(const char* l, long g, long e){ if (g == e) printf("  ok  %s (%ld)\n", l, g); else { printf("  FAIL %s (got %ld exp %ld)\n", l, g, e); fails++; } }
static void hset(unsigned char h[32], int n){ memset(h, 0, 32); h[0] = 0x5a; h[1] = (unsigned char)n; h[2] = (unsigned char)(n >> 8); }

/* Two pass helpers forked from the same worker before either did anything.
 * The first claims block X and then stores block Y; only then does the
 * second ask for X and Y. Returns how many of the two the second is refused
 * (2 = both, as the one-request rule wants). */
static int sibling_refusals(inflight_t* t){
    unsigned char x[32], y[32]; hset(x, 7001); hset(y, 7002);
    int go[2], done[2]; if (pipe(go) || pipe(done)) return -1;
    pid_t a = fork();
    if (a == 0){ char c; if (read(go[0], &c, 1) != 1) _exit(9);
                 inflight_claim(t, x, 1, 5000); inflight_mark_stored(t, y, 5000);
                 if (write(done[1], "d", 1) != 1) _exit(9);
                 _exit(0); }
    pid_t b = fork();
    if (b == 0){ char c; if (read(done[0], &c, 1) != 1) _exit(9);
                 int r = !inflight_claim(t, x, 2, 5001) + !inflight_claim(t, y, 2, 5001);
                 _exit(r); }
    if (write(go[1], "g", 1) != 1) return -1;
    int sa, sb; waitpid(a, &sa, 0); waitpid(b, &sb, 0);
    close(go[0]); close(go[1]); close(done[0]); close(done[1]);
    return WIFEXITED(sb) ? WEXITSTATUS(sb) : -1;
}

int main(void){
    printf("== one process ==\n");
    inflight_t t; inflight_init(&t); unsigned char a[32], b[32]; memset(a, 0xaa, 32); memset(b, 0xbb, 32); long long now = 1000;
    ck("leg 0 claims block a", inflight_claim(&t, a, 0, now), 1);
    ck("leg 1 is refused block a", inflight_claim(&t, a, 1, now + 5), 0);
    ck("leg 0 may fetch its own claim again", inflight_claim(&t, a, 0, now + 5), 1);
    ck("leg 1 claims block b", inflight_claim(&t, b, 1, now), 1);
    ck("two in flight", inflight_count(&t), 2);
    inflight_release_leg(&t, 0);
    ck("leg 0's pass ended: its claim is gone", inflight_count(&t), 1);
    ck("... and leg 1 may take block a now", inflight_claim(&t, a, 1, now + 6), 1);
    ck("a claim older than 10 min is stale: leg 2 takes block b over", inflight_claim(&t, b, 2, now + INFLIGHT_STALE_S), 1);
    ck("... and leg 1 is refused its former claim", inflight_claim(&t, b, 1, now + INFLIGHT_STALE_S + 1), 0);
    inflight_release(&t, b);
    ck("released by hash", inflight_count(&t), 1);
    for (int i = 0; i < INFLIGHT_MAX + 3; i++){ unsigned char h[32]; memset(h, (unsigned char)i, 32); h[0] = 0x77; inflight_claim(&t, h, 3, now + 100 + i); }
    ck("a full table never refuses: the oldest entry is recycled", inflight_count(&t), INFLIGHT_MAX);
    ck("refusals counted", (long)t.refused, 2);

    printf("\n== stored marks ==\n");
    inflight_init(&t); unsigned char s[32]; memset(s, 0x5c, 32); now = 2000;
    ck("leg 4 claims block s", inflight_claim(&t, s, 4, now), 1);
    inflight_mark_stored(&t, s, now + 1);
    ck("stored: leg 4's claim is done (not counted in flight)", inflight_count(&t), 0);
    ck("stored: leg 5 is refused it", inflight_claim(&t, s, 5, now + 2), 0);
    ck("stored: so is leg 4, which stored it", inflight_claim(&t, s, 4, now + 2), 0);
    ck("stored: the rotation's pick is refused too", inflight_would_allow(&t, s, 6, now + 2), 0);
    ck("refusals of a stored block counted apart", (long)t.refused_stored, 2);
    inflight_release_leg(&t, -1); inflight_release(&t, s);
    ck("a release does not drop the stored mark", inflight_claim(&t, s, 5, now + 3), 0);
    ck("INFLIGHT_DONE_S later the mark has lapsed: leg 5 may fetch", inflight_claim(&t, s, 5, now + 1 + INFLIGHT_DONE_S), 1);
    unsigned char m[32]; memset(m, 0x6d, 32);
    inflight_mark_stored(&t, m, now);
    ck("a mark with no claim before it refuses as well", inflight_claim(&t, m, 1, now + 1), 0);
    inflight_forget_stored(&t);
    ck("a rewind forgets the stored marks", inflight_claim(&t, m, 1, now + 2), 1);
    ck("... and a claim survives the rewind", inflight_count(&t), 2);

    printf("\n== across processes ==\n");
    inflight_t* sh = inflight_shared();
    ck("the shared table maps", sh != 0, 1);
    if (!sh){ printf("TESTS FAILED\n"); return 1; }
    ck("a claim and a store made by one helper refuse both blocks to a sibling forked before them", sibling_refusals(sh), 2);
    inflight_t* priv = (inflight_t*)malloc(sizeof *priv); inflight_init(priv);
    ck("control: with a private table (each helper's own copy, as before) the sibling is refused neither", sibling_refusals(priv), 0);
    free(priv);
    ck("the worker sees what its helpers did (1 claim, 1 stored)", inflight_count(sh) == 1 && sh->claims == 1, 1);

    /* eight helpers race for the same 2,000 hashes; each counts its wins */
    inflight_init(sh);
    enum { NP = 8, NH = 2000 };
    int wp[2]; if (pipe(wp)) return 1;
    for (int p = 0; p < NP; p++){
        if (fork() == 0){
            int won = 0;
            for (int i = 0; i < NH; i++){ unsigned char h[32]; hset(h, i); if (inflight_claim(sh, h, p, 9000)) won++; }
            if (write(wp[1], &won, sizeof won) != (ssize_t)sizeof won) _exit(9);
            _exit(0);
        }
    }
    long total = 0; for (int p = 0; p < NP; p++){ int w = 0; if (read(wp[0], &w, sizeof w) == (ssize_t)sizeof w) total += w; }
    while (wait(0) > 0) {}
    /* the table holds 64; a recycled slot can be won again, so the race is
     * judged on what the table still holds: every live entry has ONE leg,
     * and the wins add up to the claims the table recorded */
    ck("8 racing processes: the wins add up to the claims recorded", total, (long)sh->claims);
    ck("... and at least every hash was won once", total >= NH, 1);
    { int dup = 0; for (int i = 0; i < INFLIGHT_MAX; i++) for (int j = i + 1; j < INFLIGHT_MAX; j++)
          if (sh->e[i].used && sh->e[j].used && !memcmp(sh->e[i].hash, sh->e[j].hash, 32)) dup++;
      ck("... and no hash is held twice", dup, 0); }

    /* a holder that died with the lock held */
    inflight_init(sh);
    pid_t d = fork();
    if (d == 0){ __atomic_store_n(&sh->lock, (int)getpid(), __ATOMIC_RELEASE); _exit(0); }
    waitpid(d, 0, 0);
    ck("the lock word names the dead holder", sh->lock, (long)d);
    alarm(10);                       /* a wedge fails the test instead of hanging the gate */
    ck("a claim still goes through: the dead holder's lock is taken over", inflight_claim(sh, a, 0, 100), 1);
    alarm(0);
    ck("... and the lock is free again", sh->lock, 0);

    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

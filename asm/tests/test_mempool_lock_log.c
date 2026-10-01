/* test_mempool_lock_log.c -- the mempool lock's wait/hold log (2026-09-30).
 *
 * daemon/mempool_lock.h says why it exists: the RPC surface's multi-second
 * holds were handlers WAITING on this lock, held by the download worker in
 * another process, and nothing named the site. This pins what the log says:
 *
 *   A. a hold of the threshold or longer is one line naming the site, the
 *      pid, the hold, and each step the holder named (mp_lock_phase) with
 *      its time; a waiter's line names its own site, its wait, and the
 *      holder it waited for -- site, step at release, pid, hold;
 *   B. across PROCESSES: the parent waits on a child's hold and names the
 *      child's site and pid (the holder record lives in the shared page);
 *   C. a hold and a wait under the threshold write nothing; 0 switches the
 *      log off; the hook (mp_lock, no site) names the RPC label when the
 *      server provides one and "(unnamed)" otherwise;
 *   D. a step named when this thread does not hold the lock is a no-op;
 *   E. a CONVOY -- a wait made of many short holds, none of them over the
 *      threshold -- is told apart from one long holder: the waiter's line
 *      counts the takes that went by and names the longest of them (x86's
 *      first production lines were this shape, and the last releaser alone
 *      could not say so).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include "../daemon/node_config.h"
#include "../daemon/mempool_lock.h"

extern int  mempool_configure(void);
extern void* mp_ext_area;

static int fails=0, checks=0;
static void ck(const char* what, int cond){ checks++; if(cond) printf("ok  : %s\n",what); else { printf("FAIL: %s\n",what); fails++; } }

/* link stub: bitcoin_mempool_policy.c references the UTXO resolver; never reached */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char* t, unsigned long i,
                                    unsigned long long* v, const unsigned char** sp,
                                    unsigned long* sl){
    (void)u;(void)t;(void)i;(void)v;(void)sp;(void)sl; return 0;
}
/* the RPC server's label, as the daemon provides it (weak in mempool_cfg.c) */
static const char* g_label = 0;
void rpc_exec_current_label(char* out, size_t cap){ snprintf(out, cap, "%s", g_label ? g_label : ""); }

static long ms_in(const char* line, const char* key){
    const char* p = strstr(line, key); if (!p) return -1;
    return atol(p + strlen(key));
}

/* E: six convoy threads -- take, hold 3 ms, release, take again at once */
static volatile int g_convoy_stop;
static void* convoy_thread(void* a){
    (void)a;
    while (!g_convoy_stop){ mp_lock_at("convoy_site"); usleep(3000); mp_unlock(); }
    return NULL;
}
/* A: the holder -- three named steps, ~120 ms each */
static void* holder_thread(void* a){
    int wfd = *(int*)a;
    mp_lock_at("holder_site");
    if (write(wfd, "L", 1) != 1) {}
    mp_lock_phase("step_one");   usleep(120000);
    mp_lock_phase("step_two");   usleep(120000);
    mp_lock_phase("step_three"); usleep(120000);
    mp_unlock();
    return NULL;
}

int main(void){
    g_cfg.maxmempool_mb = 8;
    ck("mempool_configure(8MB)", mempool_configure() == 1);
    ck("shared pool published", mp_ext_area != NULL);
    ck("the default threshold is 1000 ms", mp_lock_log_ms() == 1000);
    mp_lock_set_log_ms(100);
    ck("threshold set to 100 ms for the test", mp_lock_log_ms() == 100);

    /* ---- A: one thread holds ~360 ms in three steps; this thread waits ---- */
    int pfd[2]; if (pipe(pfd) != 0) return 1;
    pthread_t th; pthread_create(&th, NULL, holder_thread, &pfd[1]);
    char c; if (read(pfd[0], &c, 1) != 1) return 1;       /* the holder has the lock */
    usleep(20000);                                        /* into step_one */
    long ev0 = mp_lock_slow_events();
    mp_lock_at("waiter_site");
    long ev1 = mp_lock_slow_events();
    mp_unlock();
    pthread_join(th, NULL);
    char log[2048]; mp_lock_slow_log(log, sizeof log);
    printf("--- the log ---\n%s---\n", log);
    ck("A: the wait wrote its line at the take (the holder's own line races it: 1 or 2 by then)", ev1 == ev0 + 1 || ev1 == ev0 + 2);
    ck("A: two lines in all: the wait and the hold", mp_lock_slow_events() == ev0 + 2);
    const char* wl = strstr(log, "[mempool] pool lock: waiter_site (pid ");
    const char* hl = strstr(log, "[mempool] pool lock: holder_site (pid ");
    ck("A: the waiter's line names its site", wl != NULL);
    ck("A: the holder's line names its site", hl != NULL);
    if (wl && hl){
        long waited = ms_in(wl, ") waited ");
        ck("A: the waiter waited about 340 ms (300..900)", waited >= 300 && waited <= 900);
        ck("A: the waiter names the holder's site and the step it released in",
           strstr(wl, "the holder was holder_site/step_three (pid ") != NULL);
        char pidbuf[32]; snprintf(pidbuf, sizeof pidbuf, "(pid %d)", (int)getpid());
        ck("A: the waiter's pid is this process", strstr(wl, pidbuf) != NULL);
        long hheld = ms_in(wl, ", held ");
        ck("A: the waiter reports the holder's hold (>= 350 ms)", hheld >= 350);
        ck("A: nobody else waiting", strstr(wl, "; 0 still waiting") != NULL);
        long held = ms_in(hl, ") held ");
        ck("A: the holder held about 360 ms (350..900)", held >= 350 && held <= 900);
        ck("A: the holder waited 0 ms", strstr(hl, "(waited 0 ms)") != NULL);
        long s1 = ms_in(hl, "step_one "), s2 = ms_in(hl, "step_two "), s3 = ms_in(hl, "step_three ");
        ck("A: each step is timed (~120 ms: 100..400)",
           s1 >= 100 && s1 <= 400 && s2 >= 100 && s2 <= 400 && s3 >= 100 && s3 <= 400);
        ck("A: the steps are listed in order", strstr(hl, "step_one") < strstr(hl, "step_two") && strstr(hl, "step_two") < strstr(hl, "step_three"));
        ck("A: the holder saw one waiter behind it", strstr(hl, "; 1 waiting behind it") != NULL);
    }

    /* ---- B: across processes: a child holds, the parent waits ---- */
    if (pipe(pfd) != 0) return 1;
    long before_fork = mp_lock_slow_events();             /* the child inherits the count */
    pid_t pid = fork();
    if (pid == 0){
        mp_lock_at("child_site");
        if (write(pfd[1], "L", 1) != 1) {}
        mp_lock_phase("child_step");
        usleep(250000);
        mp_unlock();
        _exit(mp_lock_slow_events() == before_fork + 1 ? 0 : 1);   /* the child's own hold line, in the child */
    }
    if (read(pfd[0], &c, 1) != 1) return 1;
    usleep(20000);
    ev0 = mp_lock_slow_events();
    mp_lock_at("parent_site");
    mp_unlock();
    int st = -1; waitpid(pid, &st, 0);
    ck("B: the child wrote its own hold line", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    ck("B: the parent wrote one wait line", mp_lock_slow_events() == ev0 + 1);
    mp_lock_slow_log(log, sizeof log);
    const char* pl = strstr(log, "[mempool] pool lock: parent_site (pid ");
    ck("B: the parent's line is in the ring", pl != NULL);
    if (pl){
        char want[96]; snprintf(want, sizeof want, "the holder was child_site/child_step (pid %d, held ", (int)pid);
        ck("B: it names the child's site, step and PID from the shared page", strstr(pl, want) != NULL);
        long waited = ms_in(pl, ") waited ");
        ck("B: the parent waited about 230 ms (200..900)", waited >= 200 && waited <= 900);
    }

    /* ---- C: quiet takes write nothing; 0 is off; the hook's label ---- */
    ev0 = mp_lock_slow_events();
    mp_lock_at("quick"); mp_unlock();
    ck("C: a take under the threshold writes nothing", mp_lock_slow_events() == ev0);
    mp_lock_set_log_ms(0);
    mp_lock_at("silent"); usleep(150000); mp_unlock();
    ck("C: 0 switches the log off (a 150 ms hold, no line)", mp_lock_slow_events() == ev0);
    mp_lock_set_log_ms(100);
    g_label = "getrawtransaction";
    mp_lock(); usleep(150000); mp_unlock();              /* the hooks' pointer: no site */
    mp_lock_slow_log(log, sizeof log);
    ck("C: the hook names the RPC label", strstr(log, "[mempool] pool lock: getrawtransaction (pid ") != NULL);
    g_label = 0;
    mp_lock(); usleep(150000); mp_unlock();
    mp_lock_slow_log(log, sizeof log);
    ck("C: no label -> (unnamed)", strstr(log, "[mempool] pool lock: (unnamed) (pid ") != NULL);
    ck("C: those were two more lines", mp_lock_slow_events() == ev0 + 2);

    /* ---- D: a step named outside a hold is a no-op ---- */
    mp_lock_phase("nowhere");
    mp_lock_at("after_stray_phase"); usleep(150000); mp_unlock();
    mp_lock_slow_log(log, sizeof log);
    const char* dl = strstr(log, "[mempool] pool lock: after_stray_phase (pid ");
    ck("D: a stray step does not leak into the next hold's line", dl && !strstr(dl, "nowhere"));
    ck("D: a hold with no steps ends at the wait count", dl && strstr(dl, " ms); 0 waiting behind it"));

    /* ---- E: a convoy of 3 ms holds; this thread waits behind it ---- */
    { const char* cl = NULL; long waited = -1;
      for (int attempt = 0; attempt < 8 && !cl; attempt++){   /* a fair handoff can let the waiter in early; under a loaded suite that happened 3 times running once */
          g_convoy_stop = 0;
          pthread_t ct[6];
          for (int i = 0; i < 6; i++) pthread_create(&ct[i], NULL, convoy_thread, NULL);
          usleep(30000);                                     /* the convoy is running */
          ev0 = mp_lock_slow_events();
          mp_lock_at("behind_the_convoy");
          /* read the ring while HOLDING the lock: the convoy threads are
           * blocked on it, so no line of theirs (under load they wait on
           * each other long enough to log) can follow ours into the 4-slot
           * ring before we look -- a full-suite run lost the line that way */
          mp_lock_slow_log(log, sizeof log);
          mp_unlock();
          g_convoy_stop = 1;
          for (int i = 0; i < 6; i++) pthread_join(ct[i], NULL);
          cl = strstr(log, "[mempool] pool lock: behind_the_convoy (pid ");
          if (cl && mp_lock_slow_events() == ev0) cl = NULL;   /* a stale ring entry */
          if (cl) waited = ms_in(cl, ") waited ");
          if (!cl) printf("      (attempt %d: the waiter got in under the threshold; retrying)\n", attempt + 1);
      }
      ck("E: the waiter sat through a convoy for >= 100 ms (a wait line)", cl != NULL);
      if (cl){
          long went_by = ms_in(cl, "held ") >= 0 ? atol(strstr(cl, "ms); ") + 5) : -1;
          long longest = ms_in(cl, "the longest of them held ");
          printf("      %s\n", cl);
          ck("E: the line counts the takes that went by (>= 10 in >= 100 ms of 3 ms holds)", went_by >= 10);
          ck("E: the longest of them is a short hold (< 100 ms), named", longest >= 0 && longest < 100 && strstr(cl, "ms (convoy_site)") != NULL);
          ck("E: the last release was short too (< 100 ms)", ms_in(cl, ", held ") >= 0 && ms_in(cl, ", held ") < 100);
          ck("E: the wait is longer than any single hold: a convoy, said so by the line", waited > longest && waited >= 100);
          ck("E: no hold line was written by anyone (no hold reached the threshold)", strstr(log, "convoy_site (pid ") == NULL || strstr(strstr(log, "convoy_site (pid "), ") held ") == NULL);
      }
    }
    /* the convoy's reset: with nobody waiting, the next quiet take reports no convoy */
    mp_lock_at("quiet_after"); mp_unlock();

    printf("\n%d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}

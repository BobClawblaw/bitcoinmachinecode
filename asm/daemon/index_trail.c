/* daemon/index_trail.c -- see index_trail.h */
#include "index_trail.h"
#include "index_runs.h"
#include <stdio.h>
#include "log_ts.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/resource.h>

pid_t (*it_spawn_hook)(const itrail_t* t, int kind, long from, long to) = 0;

void it_configure(itrail_t* t, const char* name, const char* builder, const char* merger,
                  const char* chaindir, const char* chain, long run_blocks, long safety, int merge_at, int enabled){
    memset(t, 0, sizeof *t);
    snprintf(t->name, sizeof t->name, "%s", name ? name : "index");
    snprintf(t->builder, sizeof t->builder, "%s", builder ? builder : "");
    snprintf(t->merger, sizeof t->merger, "%s", merger ? merger : "");
    snprintf(t->chaindir, sizeof t->chaindir, "%s", chaindir ? chaindir : ".");
    snprintf(t->chain, sizeof t->chain, "%s", chain ? chain : "main");
    t->run_blocks = run_blocks > 0 ? run_blocks : 1;
    t->safety = safety < 0 ? 0 : safety;
    t->merge_at = merge_at;
    t->enabled = enabled; t->configured = 1; t->pid = -1; t->state = IT_IDLE;
}

/* 1 gone (status filled), 0 still running */
static int reap(pid_t pid, int* status){
    int st = 0; pid_t w = waitpid(pid, &st, WNOHANG);
    if (w == pid){ *status = st; return 1; }
    if (w < 0 && errno == ECHILD){ *status = 0; return kill(pid, 0) != 0 && errno == ESRCH; }
    return 0;
}

static pid_t spawn_real(const itrail_t* t, int kind, long from, long to){
    char from_s[32], to_s[32], run[320];
    snprintf(from_s, sizeof from_s, "%ld", from);
    snprintf(to_s, sizeof to_s, "%ld", to);
    irs_run_name(t->name, from, to, run, sizeof run);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0){
        setpriority(PRIO_PROCESS, 0, 10);
        setenv("BMC_CHAIN", t->chain, 1);
        if (kind == 1){
            const char* base = strrchr(t->builder, '/'); base = base ? base + 1 : t->builder;
            execl(t->builder, base, t->chaindir, from_s, to_s, run, (char*)0);
        } else {
            const char* base = strrchr(t->merger, '/'); base = base ? base + 1 : t->merger;
            execl(t->merger, base, t->chaindir, t->name, (char*)0);
        }
        _exit(127);
    }
    return pid;
}

int it_tick(itrail_t* t, long covered, int nruns, long applied, long long now,
            void (*on_run)(long to, void* ctx), void* ctx){
    if (!t->configured) return IT_IDLE;
    if (!t->enabled){ t->state = IT_DISABLED; snprintf(t->why, sizeof t->why, "the %s index is off in the config", t->name); return t->state; }
    if (t->pid > 0){
        int st = 0;
        if (!reap(t->pid, &st)) return t->state;
        long long secs = now - t->started; pid_t was = t->pid; t->pid = -1;
        int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
        if (ok){
            t->failures = 0;
            if (t->kind == 1){
                t->runs_built++;
                fprintf(stderr, "[%s] run [%ld,%ld] built by pid %d in %llds (%ld runs so far)\n", t->name, t->from, t->to, (int)was, secs, t->runs_built);
                if (on_run) on_run(t->to, ctx);
            } else {
                t->merges++;
                fprintf(stderr, "[%s] runs merged by pid %d in %llds (%ld merges so far)\n", t->name, (int)was, secs, t->merges);
            }
            t->state = IT_IDLE;
        } else {
            t->failures++;
            t->next_allowed = now + IT_BACKOFF_S;
            t->state = IT_BACKOFF;
            snprintf(t->why, sizeof t->why, "the %s %s (pid %d) failed after %llds (%s %d); retrying in %ld s (failure %d in a row)",
                     t->name, t->kind == 1 ? "builder" : "merger", (int)was, secs,
                     WIFEXITED(st) ? "exit" : "signal", WIFEXITED(st) ? WEXITSTATUS(st) : (WIFSIGNALED(st) ? WTERMSIG(st) : -1),
                     IT_BACKOFF_S, t->failures);
            fprintf(stderr, "[%s] trail: %s\n", t->name, t->why);
            return t->state;
        }
    }
    if (t->state == IT_BACKOFF){ if (now < t->next_allowed) return t->state; t->state = IT_IDLE; }
    if (applied < 0) return t->state;
    /* merge first: a pile of runs makes every lookup slower */
    if (t->merge_at > 0 && nruns >= t->merge_at && t->merger[0]){
        if (access(t->merger, X_OK) != 0){
            if (t->state != IT_NO_BUILDER) fprintf(stderr, "[%s] trail: merger %s not executable\n", t->name, t->merger);
            t->state = IT_NO_BUILDER; snprintf(t->why, sizeof t->why, "%d runs need merging and the merger is missing beside the daemon", nruns); return t->state;
        }
        pid_t pid = it_spawn_hook ? it_spawn_hook(t, 2, -1, -1) : spawn_real(t, 2, -1, -1);
        if (pid < 0){ fprintf(stderr, "[%s] trail: merge spawn failed (%s)\n", t->name, strerror(errno)); return t->state; }
        t->pid = pid; t->kind = 2; t->started = now; t->state = IT_MERGING;
        snprintf(t->why, sizeof t->why, "merging %d runs (pid %d)", nruns, (int)pid);
        fprintf(stderr, "[%s] trail: merging %d runs with %s (pid %d)\n", t->name, nruns, t->merger, (int)pid);
        return t->state;
    }
    long ready_to = applied - t->safety;
    long from = covered + 1;
    if (ready_to - from + 1 < t->run_blocks){
        t->state = IT_CURRENT;
        snprintf(t->why, sizeof t->why, "runs reach %ld; the next run starts once %ld more heights are ready", covered, t->run_blocks - (ready_to - from + 1));
        return t->state;
    }
    if (!t->builder[0] || access(t->builder, X_OK) != 0){
        if (t->state != IT_NO_BUILDER) fprintf(stderr, "[%s] trail: builder %s not executable -- the index cannot be built\n", t->name, t->builder);
        t->state = IT_NO_BUILDER; snprintf(t->why, sizeof t->why, "the %s index needs a run and its builder is missing beside the daemon", t->name); return t->state;
    }
    long to = from + t->run_blocks - 1;
    if (to > ready_to) to = ready_to;
    pid_t pid = it_spawn_hook ? it_spawn_hook(t, 1, from, to) : spawn_real(t, 1, from, to);
    if (pid < 0){ fprintf(stderr, "[%s] trail: spawn failed (%s)\n", t->name, strerror(errno)); return t->state; }
    t->pid = pid; t->kind = 1; t->from = from; t->to = to; t->started = now; t->state = IT_BUILDING;
    snprintf(t->why, sizeof t->why, "building run [%ld,%ld] (pid %d)", from, to, (int)pid);
    fprintf(stderr, "[%s] trail: building run [%ld,%ld] with %s (pid %d)\n", t->name, from, to, t->builder, (int)pid);
    return t->state;
}

const char* it_status(const itrail_t* t){
    switch (t->state){
    case IT_CURRENT: case IT_BUILDING: case IT_MERGING: case IT_BACKOFF: case IT_DISABLED: case IT_NO_BUILDER: return t->why;
    default: return "not checked yet";
    }
}

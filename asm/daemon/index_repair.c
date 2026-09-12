/* daemon/index_repair.c -- see index_repair.h */
#include "index_repair.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/resource.h>
#include "log_ts.h"
pid_t (*ir_spawn_hook)(const ir_t* r, long to) = 0;
void ir_configure(ir_t* r, const char* name, const char* builder, const char* chaindir, const char* chain, const char* lockpath, int enabled){
    memset(r, 0, sizeof *r);
    snprintf(r->name, sizeof r->name, "%s", name ? name : "index");
    snprintf(r->builder, sizeof r->builder, "%s", builder ? builder : "");
    snprintf(r->chaindir, sizeof r->chaindir, "%s", chaindir ? chaindir : ".");
    snprintf(r->chain, sizeof r->chain, "%s", chain ? chain : "main");
    snprintf(r->lockpath, sizeof r->lockpath, "%s", lockpath ? lockpath : "");
    r->enabled = enabled; r->configured = 1; r->pid = -1; r->state = IR_IDLE;
}
static int lock_held(const ir_t* r){
    if (!r->lockpath[0]) return 0;
    int fd = open(r->lockpath, O_RDONLY); if (fd < 0) return 0;
    int held = flock(fd, LOCK_EX | LOCK_NB) != 0; if (!held) flock(fd, LOCK_UN);
    close(fd); return held;
}
static int child_gone(pid_t pid){
    int st = 0; pid_t w = waitpid(pid, &st, WNOHANG);
    if (w == pid) return 1;
    if (w < 0 && errno == ECHILD) return kill(pid, 0) != 0 && errno == ESRCH;
    return 0;
}
static pid_t spawn_real(const ir_t* r, long to){
    char to_s[32]; snprintf(to_s, sizeof to_s, "%ld", to);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0){
        setpriority(PRIO_PROCESS, 0, 10);
        setenv("BMC_CHAIN", r->chain, 1);
        const char* base = strrchr(r->builder, '/'); base = base ? base + 1 : r->builder;
        execl(r->builder, base, r->chaindir, to_s, (char*)0);
        _exit(127);
    }
    return pid;
}
int ir_tick(ir_t* r, int needed, long target, int in_ibd, long long now){
    if (!r->configured) return IR_IDLE;
    if (r->state == IR_RUNNING){
        if (!child_gone(r->pid)) return IR_RUNNING;
        long long secs = now - r->started; pid_t was = r->pid; r->pid = -1;
        if (!needed){
            r->state = IR_OK;
            snprintf(r->why, sizeof r->why, "the %s builder (pid %d) finished in %llds; the index is adopted", r->name, (int)was, secs);
            fprintf(stderr, "[%s] repair: %s\n", r->name, r->why);
            return r->state;
        }
        r->next_allowed = now + IR_BACKOFF_S;
        r->state = r->attempts >= IR_MAX_ATTEMPTS ? IR_GAVE_UP : IR_BACKOFF;
        snprintf(r->why, sizeof r->why, "the %s builder (pid %d) ended after %llds and the index still needs a build; %s", r->name, (int)was, secs,
                 r->state == IR_GAVE_UP ? "no more attempts this boot" : "next attempt in 6 h");
        fprintf(stderr, "[%s] repair: %s\n", r->name, r->why);
        return r->state;
    }
    if (!needed){ if (r->state != IR_OK){ r->state = IR_OK; snprintf(r->why, sizeof r->why, "the %s index is current", r->name); } return r->state; }
    if (!r->enabled){ r->state = IR_DISABLED; snprintf(r->why, sizeof r->why, "the %s index needs a build; its repair is off in the config", r->name); return r->state; }
    if (r->attempts >= IR_MAX_ATTEMPTS){ r->state = IR_GAVE_UP; return r->state; }
    if (now < r->next_allowed){ r->state = IR_BACKOFF; return r->state; }
    if (in_ibd){ r->state = IR_IBD; snprintf(r->why, sizeof r->why, "the %s index needs a build; it waits for initial block download to finish", r->name); return r->state; }
    if (lock_held(r)){ if (r->state != IR_WAIT_LOCK) fprintf(stderr, "[%s] repair: another builder holds %s -- waiting for it\n", r->name, r->lockpath); r->state = IR_WAIT_LOCK; return r->state; }
    if (!r->builder[0] || access(r->builder, X_OK) != 0){
        if (r->state != IR_NO_BUILDER) fprintf(stderr, "[%s] repair: builder %s not executable -- cannot build the index\n", r->name, r->builder);
        r->state = IR_NO_BUILDER; snprintf(r->why, sizeof r->why, "the %s index needs a build and its builder is missing beside the daemon", r->name); return r->state;
    }
    if (target < 0){ r->state = IR_IDLE; return r->state; }
    pid_t pid = ir_spawn_hook ? ir_spawn_hook(r, target) : spawn_real(r, target);
    if (pid < 0){ fprintf(stderr, "[%s] repair: spawn failed (%s)\n", r->name, strerror(errno)); return r->state; }
    r->pid = pid; r->started = now; r->to = target; r->attempts++; r->state = IR_RUNNING;
    snprintf(r->why, sizeof r->why, "the %s index is being built to %ld (builder pid %d, attempt %d of %d)", r->name, target, (int)pid, r->attempts, IR_MAX_ATTEMPTS);
    fprintf(stderr, "[%s] repair: building the index to %ld with %s (pid %d, attempt %d of %d)\n", r->name, target, r->builder, (int)pid, r->attempts, IR_MAX_ATTEMPTS);
    return r->state;
}
const char* ir_status(const ir_t* r){
    switch (r->state){
    case IR_RUNNING: case IR_OK: case IR_DISABLED: case IR_IBD: case IR_NO_BUILDER: return r->why;
    case IR_BACKOFF: return r->why[0] ? r->why : "waiting to retry the build";
    case IR_GAVE_UP: return r->why[0] ? r->why : "the builds failed; restart to retry";
    case IR_WAIT_LOCK: return "another builder is running outside this process; its result is adopted when it finishes";
    default: return "not checked yet";
    }
}

/* rpc_signer.c -- the external signer interface (Core's -signer / HWI).
 *
 * Core's model: the operator names a signing program with -signer=<cmd>
 * (in practice HWI), and the node shells out to it -- `<cmd> enumerate` to
 * list hardware signers, `<cmd> --fingerprint <fp> displayaddress --desc
 * <descriptor>` to show an address on the device. The program's stdout is
 * JSON. This module does exactly that and nothing more: the OPERATOR chose
 * the command in bitcoin.conf, the node never invents one, and with no
 * signer configured the methods answer with Core's exact error text.
 *
 * ARGUMENT QUOTING is the one sharp edge. The descriptor reaches a shell,
 * and descriptors legitimately contain (), ', # and *. Every argument is
 * therefore single-quoted with embedded single quotes rewritten as '\''
 * (the POSIX idiom), so no descriptor byte is ever interpreted by the
 * shell. The command string itself is the operator's own configuration and
 * is deliberately NOT quoted -- like Core, `signer=hwi --testnet` is a
 * command line, not a path. */

#define _GNU_SOURCE 1   /* pipe2, __WCLONE */
#include "rpc_signer.h"
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char** environ;

/* ---- the signer child (HST-1, HST-3; audit 2026-10-23) ------------------
 * This used popen/pclose, and two things went wrong with that inside the
 * daemon:
 *   - HST-1: the serve parent reaps with waitpid(-1) in its SIGCHLD handler
 *     (main.c reap_children). That handler could reap popen's child before
 *     pclose did, pclose then failed with ECHILD, and a signer that ran
 *     fine was reported as "could not run the signer" -- while the handler
 *     also counted the reap as an inbound peer leaving.
 *   - HST-3: popen's child inherited every descriptor the daemon had open:
 *     the RPC listener, client sockets, peer sockets, the datadir .lock.
 *     The signer is an operator-chosen program (HWI); it has no business
 *     holding any of them, and holding .lock delayed the next start.
 * The child is now made with clone() and NO exit signal: a child that
 * delivers no SIGCHLD is a "clone child", which waitpid(-1, ..) without
 * __WCLONE never reaps, so only this file's waitpid(pid, .., __WCLONE) can.
 * An exec resets the exit signal to SIGCHLD, so that child does not exec:
 * it is a small keeper that forks the shell, waits for it, and leaves with
 * the shell's own wait status (exit code, or the same signal re-raised).
 * The shell keeps fds 0-2 (stdout = the pipe) and closes everything else,
 * as notify.c's hooks do. Everything both children touch is prepared before
 * the clone, and they make raw system calls only: the daemon is threaded,
 * and a lock another thread held at the clone (malloc's, glibc's fork
 * handlers) stays held in the copy. */
static void signer_close_from3(long maxfd){
    if (syscall(SYS_close_range, 3U, ~0U, 0U) != 0)
        for (long fd = 3; fd < maxfd; fd++) close((int)fd);
}
static pid_t signer_spawn(const char* cmd, int* rfd){
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC) != 0) return -1;
    char* argv[] = { (char*)"sh", (char*)"-c", (char*)cmd, NULL };
    sigset_t none; sigemptyset(&none);
    struct sigaction dfl; memset(&dfl, 0, sizeof dfl); dfl.sa_handler = SIG_DFL; sigemptyset(&dfl.sa_mask);
    struct rlimit nocore = { 0, 0 };
    long maxfd = sysconf(_SC_OPEN_MAX); if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
    long r = syscall(SYS_clone, 0UL /* no CLONE_* flags, exit signal 0 */, NULL, NULL, NULL, NULL);
    if (r < 0){ close(pfd[0]); close(pfd[1]); return -1; }
    if (r == 0){
        /* the keeper: the daemon's SIGCHLD handler must not run here */
        sigaction(SIGCHLD, &dfl, NULL);
        sigaction(SIGPIPE, &dfl, NULL);
        sigprocmask(SIG_SETMASK, &none, NULL);
        long g = syscall(SYS_fork);
        if (g == 0){
            if (dup2(pfd[1], 1) < 0) _exit(127);
            signer_close_from3(maxfd);
            execve("/bin/sh", argv, environ);
            _exit(127);
        }
        signer_close_from3(maxfd);           /* the pipe too: EOF is the shell's to give */
        if (g < 0) _exit(127);
        int st = 0;
        for (;;){
            long w = syscall(SYS_wait4, g, &st, 0, NULL);
            if (w == g) break;
            if (w < 0 && errno == EINTR) continue;
            _exit(127);
        }
        if (WIFSIGNALED(st)){
            int sig = WTERMSIG(st);
            setrlimit(RLIMIT_CORE, &nocore);  /* the shell's death, not a dump of this copy */
            sigaction(sig, &dfl, NULL);
            syscall(SYS_kill, syscall(SYS_getpid), sig);
            _exit(128 + sig);
        }
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 127);
    }
    close(pfd[1]);
    *rfd = pfd[0];
    return (pid_t)r;
}
static int signer_wait(pid_t pid){
    int st = 0;
    for (;;){
        pid_t w = waitpid(pid, &st, __WCLONE);
        if (w == pid) return st;
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
}

static char g_signer_cmd[512];

void rpc_signer_set_cmd(const char* cmd){
    if (!cmd || !cmd[0]){ g_signer_cmd[0] = 0; return; }
    snprintf(g_signer_cmd, sizeof g_signer_cmd, "%s", cmd);
}
int rpc_signer_configured(void){ return g_signer_cmd[0] != 0; }

/* single-quote `in` for a POSIX shell into out; 0 if it does not fit */
static int sq(const char* in, char* out, unsigned long cap){
    unsigned long o = 0;
    if (o + 1 >= cap) return 0;
    out[o++] = '\'';
    for (const char* p = in; *p; p++){
        if (*p == '\''){
            if (o + 4 >= cap) return 0;
            out[o++]='\''; out[o++]='\\'; out[o++]='\''; out[o++]='\'';
        } else {
            if (o + 1 >= cap) return 0;
            out[o++] = *p;
        }
    }
    if (o + 2 >= cap) return 0;
    out[o++] = '\''; out[o] = 0;
    return 1;
}

/* Run the signer with `args` appended, capture stdout (bounded), parse as
 * JSON. Returns the parsed value (caller rj_free), or NULL with *em set.
 * stderr is left attached to the daemon's own stderr so a signer's
 * diagnostics land in the log rather than vanishing. */
static rj_val* signer_run(const char* args, long* ec, const char** em){
    static char errbuf[256];
    if (!g_signer_cmd[0]){
        *ec = -1; *em = "Error: restart bitcoind with -signer=<cmd>";
        return NULL;
    }
    char cmd[2048];
    if (snprintf(cmd, sizeof cmd, "%s %s", g_signer_cmd, args) >= (int)sizeof cmd){
        *ec = -1; *em = "signer command too long"; return NULL; }
    int rfd = -1;
    pid_t pid = signer_spawn(cmd, &rfd);
    if (pid < 0){ *ec = -1; *em = "could not run the configured signer"; return NULL; }
    static char out[65536];
    size_t n = 0;
    while (n < sizeof out - 1){
        ssize_t k = read(rfd, out + n, sizeof out - 1 - n);
        if (k > 0){ n += (size_t)k; continue; }
        if (k < 0 && errno == EINTR) continue;
        break;
    }
    out[n] = 0;
    close(rfd);                     /* a signer still writing past the cap gets SIGPIPE */
    int rc = signer_wait(pid);
    if (rc != 0){
        /* RPC-17 (audit 2026-09-03): pclose (waitpid since HST-1) returns a WAIT STATUS, not an
         * exit code. Printing it raw told the operator "the signer exited
         * with status 256" when HWI had exited 1, and said nothing at all
         * about a signal -- so a signer killed by SIGPIPE or SIGSEGV was
         * reported as a mystery number. Decoded here into what actually
         * happened, because this string is the ONLY thing the operator sees:
         * the child's stderr goes to the daemon's, not into the RPC reply. */
        if (rc < 0){
            snprintf(errbuf, sizeof errbuf,
                     "could not wait for the signer: %s%s%.120s", strerror(errno),
                     n ? "; output: " : "", n ? out : "");
        } else if (WIFSIGNALED(rc)){
            snprintf(errbuf, sizeof errbuf,
                     "the signer was killed by signal %d (%s)%s%.120s",
                     WTERMSIG(rc), strsignal(WTERMSIG(rc)),
                     n ? "; output: " : "", n ? out : "");
        } else if (WIFEXITED(rc)){
            snprintf(errbuf, sizeof errbuf,
                     "the signer exited %d%s%.120s", WEXITSTATUS(rc),
                     n ? "; output: " : "", n ? out : "");
        } else {
            snprintf(errbuf, sizeof errbuf,
                     "the signer ended abnormally (wait status 0x%x)%s%.120s", rc,
                     n ? "; output: " : "", n ? out : "");
        }
        *ec = -1; *em = errbuf;
        return NULL;
    }
    rj_val* v = rj_parse(out, n);
    if (!v){
        snprintf(errbuf, sizeof errbuf,
                 "the signer's output is not JSON: %.180s", out);
        *ec = -1; *em = errbuf;
        return NULL;
    }
    return v;
}

/* enumeratesigners -> {"signers":[{"fingerprint","name"}]}
 * HWI's enumerate emits [{"fingerprint": "...", "model": "...", ...}]. */
int rpc_signer_enumerate(rj_val** res, long* ec, const char** em){
    rj_val* v = signer_run("enumerate", ec, em);
    if (!v) return 0;
    if (v->typ != RJ_ARR){
        rj_free(v);
        *ec = -1; *em = "the signer's enumerate output is not a JSON array";
        return 0;
    }
    rj_val* arr = rj_arr();
    for (size_t i = 0; i < v->nitems; i++){
        rj_val* e = v->items[i];
        if (e->typ != RJ_OBJ) continue;
        rj_val* fp = rj_obj_get(e, "fingerprint");
        if (!fp || fp->typ != RJ_STR) continue;    /* Core requires it too */
        rj_val* o = rj_obj();
        rj_obj_set(o, "fingerprint", rj_str(fp->str));
        rj_val* model = rj_obj_get(e, "model");
        rj_obj_set(o, "name", rj_str(model && model->typ == RJ_STR ? model->str : ""));
        rj_arr_push(arr, o);
    }
    rj_free(v);
    rj_val* o = rj_obj();
    rj_obj_set(o, "signers", arr);
    *res = o;
    return 1;
}

/* walletdisplayaddress: ask the signer to display `desc`; echo the address
 * the SIGNER confirmed, not the one we asked about -- if the device shows a
 * different address than expected the caller must see that. */
int rpc_signer_display(const char* fingerprint, const char* desc,
                       rj_val** res, long* ec, const char** em){
    char qd[1024], qf[136], args[1400];
    if (!sq(desc, qd, sizeof qd)){ *ec = -8; *em = "descriptor too long"; return 0; }
    if (fingerprint && fingerprint[0]){
        if (!sq(fingerprint, qf, sizeof qf)){ *ec = -8; *em = "fingerprint too long"; return 0; }
        snprintf(args, sizeof args, "--fingerprint %s displayaddress --desc %s", qf, qd);
    } else {
        snprintf(args, sizeof args, "displayaddress --desc %s", qd);
    }
    rj_val* v = signer_run(args, ec, em);
    if (!v) return 0;
    rj_val* addr = (v->typ == RJ_OBJ) ? rj_obj_get(v, "address") : NULL;
    if (!addr || addr->typ != RJ_STR){
        rj_free(v);
        *ec = -1; *em = "the signer did not return an address";
        return 0;
    }
    rj_val* o = rj_obj();
    rj_obj_set(o, "address", rj_str(addr->str));
    rj_free(v);
    *res = o;
    return 1;
}

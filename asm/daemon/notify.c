/* daemon/notify.c -- Core's -*notify hooks: run an operator-supplied shell
 * command when something happens (a block connects, the node starts or stops,
 * a wallet transaction appears, an alert fires).
 *
 * WHY THE SUBSTITUTION IS SANITISED. Core's contract is that "%s" in the
 * command is replaced by a value -- a block hash, a txid, an alert message.
 * The result is handed to a shell. For a hash that is harmless because a hash
 * is hex; for an ALERT MESSAGE it is not, and Core has carried warnings about
 * exactly this shape for years (an attacker who can influence the substituted
 * text can influence the command line). This node refuses the risk rather
 * than documenting it: the substituted value is filtered to
 * [A-Za-z0-9._:/-] and truncated, so no quote, backtick, dollar, semicolon,
 * newline or pipe can reach the shell no matter what produced the value.
 * A hash or txid passes through unchanged; a hostile message loses its teeth.
 *
 * WHY DOUBLE-FORK. The hook must not block the caller (a block connect is on
 * the hot path) and must not leave a zombie. The intermediate child exits
 * immediately, so the grandchild is reparented to init and reaped by it --
 * the daemon's own SIGCHLD reaper counts inbound serve children to enforce
 * MAX_INBOUND, and a notify process must not be mistaken for one.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "notify.h"
#include "log_ts.h"

#define NOTIFY_MAX_SUBST 256
#define NOTIFY_MAX_CMD   2048

/* keep only characters that cannot change a shell's parse */
static void notify_sanitise(const char* in, char* out, unsigned long cap){
    unsigned long o = 0;
    if (!in){ if (cap) out[0] = 0; return; }
    for (unsigned long i = 0; in[i] && o + 1 < cap && o < NOTIFY_MAX_SUBST; i++){
        char c = in[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') ||
                 c == '.' || c == '_' || c == ':' || c == '/' || c == '-';
        if (ok) out[o++] = c;
    }
    out[o] = 0;
}

/* Expand every "%s" in `tmpl` with `safe`. Returns 0 if it would not fit --
 * a truncated shell command is worse than none, because the truncation point
 * is arbitrary and could leave a different, still-valid command. */
static int notify_expand(const char* tmpl, const char* safe, char* out, unsigned long cap){
    unsigned long o = 0, sl = strlen(safe);
    for (unsigned long i = 0; tmpl[i]; i++){
        if (tmpl[i] == '%' && tmpl[i+1] == 's'){
            if (o + sl + 1 > cap) return 0;
            memcpy(out + o, safe, sl); o += sl; i++;
        } else {
            if (o + 2 > cap) return 0;
            out[o++] = tmpl[i];
        }
    }
    out[o] = 0;
    return 1;
}

void notify_run(const char* cmd_template, const char* value, const char* what){
    if (!cmd_template || !cmd_template[0]) return;
    char safe[NOTIFY_MAX_SUBST + 1];
    notify_sanitise(value, safe, sizeof safe);
    char cmd[NOTIFY_MAX_CMD];
    if (!notify_expand(cmd_template, safe, cmd, sizeof cmd)){
        fprintf(stderr, "[notify] %s command too long after substitution -- not run\n",
                what ? what : "hook");
        return;
    }
    pid_t p = fork();
    if (p < 0){ fprintf(stderr, "[notify] %s fork failed\n", what ? what : "hook"); return; }
    if (p == 0){
        /* intermediate child: fork again so the grandchild is init's problem,
         * not ours, and this one exits before the parent's waitpid returns */
        pid_t q = fork();
        if (q == 0){
            /* the daemon ignores SIGPIPE and counts SIGCHLD; a hook must
             * start from a clean slate or it inherits both */
            signal(SIGPIPE, SIG_DFL);
            signal(SIGCHLD, SIG_DFL);
            execl("/bin/sh", "sh", "-c", cmd, (char*)NULL);
            _exit(127);
        }
        _exit(0);
    }
    /* reap the intermediate immediately: it exits at once, so this does not
     * block, and it keeps the hook out of the inbound-child accounting */
    int st = 0;
    waitpid(p, &st, 0);
}

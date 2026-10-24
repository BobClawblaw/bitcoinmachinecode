/* test_rpc_signer.c -- the external signer interface, against a FAKE signer.
 *
 * The fake is a shell script written by this test that speaks HWI's shapes:
 * `enumerate` emits a device list, `displayaddress --desc <d>` echoes the
 * descriptor it was handed inside an {"address": ...} reply. That echo is
 * the sharp assertion: the descriptor travels through a SHELL, and
 * descriptors legitimately contain (), ', and #. If the quoting in
 * rpc_signer.c were wrong, the descriptor would come back mangled (or the
 * shell would have executed part of it) and the echo comparison fails.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>      /* open: the killed fixture parks stderr on /dev/null */
#include <unistd.h>     /* dup, dup2 */
#include "test_tmpdir.h"
#include "../rpc_signer.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }
static const char* S(const rj_val* o, const char* k){
    rj_val* v = o ? rj_obj_get((rj_val*)o, k) : NULL; return v ? v->str : NULL;
}

#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
/* the serve parent's reaper (main.c reap_children): every child, any pid */
static void greedy_reaper(int sig){
    (void)sig; int e = errno, st; while (waitpid(-1, &st, WNOHANG) > 0) {} errno = e;
}
static void write_script(const char* path, const char* body){
    FILE* f = fopen(path, "w");
    fprintf(f, "#!/bin/sh\n%s", body);
    fclose(f);
    chmod(path, 0755);
}

int main(void){
    tt_isolate();
    long ec; const char* em; rj_val* r;

    /* ---- no signer configured: Core's exact error ---- */
    rpc_signer_set_cmd(NULL);
    ck("unconfigured is reported", rpc_signer_configured() == 0);
    r = NULL; ec = 0;
    ck("enumerate without a signer refuses with Core's exact text",
       rpc_signer_enumerate(&r, &ec, &em) == 0 && ec == -1 &&
       em && !strcmp(em, "Error: restart bitcoind with -signer=<cmd>"));
    rj_free(r);

    /* ---- a fake HWI ---- */
    write_script("fakehwi",
        "case \"$1\" in\n"
        "enumerate)\n"
        "  echo '[{\"fingerprint\":\"d34db33f\",\"model\":\"faux_ledger\",\"path\":\"/dev/x\"},"
        "{\"model\":\"no_fingerprint_device\"},"
        "{\"fingerprint\":\"cafe0000\",\"model\":\"faux_trezor\"}]'\n"
        "  ;;\n"
        "displayaddress)\n"
        "  shift; shift\n"                     /* drop 'displayaddress' '--desc' */
        "  printf '{\"address\":\"ECHO:%s\"}\\n' \"$1\"\n"
        "  ;;\n"
        "--fingerprint)\n"
        "  FP=\"$2\"; shift; shift; shift; shift\n"  /* --fingerprint <fp> displayaddress --desc */
        "  printf '{\"address\":\"FP:%s:%s\"}\\n' \"$FP\" \"$1\"\n"
        "  ;;\n"
        "*) echo 'bad args' >&2; exit 9 ;;\n"
        "esac\n");
    { char cmd[1100]; snprintf(cmd, sizeof cmd, "%s/fakehwi", tt_workdir());
      rpc_signer_set_cmd(cmd); }
    ck("configured is reported", rpc_signer_configured() == 1);

    /* ---- enumerate ---- */
    r = NULL;
    ck("enumerate dispatches", rpc_signer_enumerate(&r, &ec, &em) == 1 && r);
    { rj_val* sg = r ? rj_obj_get(r, "signers") : NULL;
      ck("two signers listed (the fingerprint-less device is dropped, as Core drops it)",
         sg && sg->typ == RJ_ARR && sg->nitems == 2);
      rj_val* s0 = (sg && sg->nitems) ? sg->items[0] : NULL;
      ck("fingerprint and name carried through",
         s0 && S(s0,"fingerprint") && !strcmp(S(s0,"fingerprint"), "d34db33f") &&
         S(s0,"name") && !strcmp(S(s0,"name"), "faux_ledger")); }
    rj_free(r);

    /* ---- displayaddress: the descriptor must survive the shell ---- */
    { const char* DESC = "wpkh([d34db33f/84h/0h/0h]xpub6CUGRUo/0/*)#ay43hs9x";
      r = NULL;
      ck("displayaddress dispatches",
         rpc_signer_display(NULL, DESC, &r, &ec, &em) == 1 && r);
      char want[300]; snprintf(want, sizeof want, "ECHO:%s", DESC);
      ck("the descriptor survived the shell BYTE-FOR-BYTE (quoting is right)",
         r && S(r,"address") && !strcmp(S(r,"address"), want));
      rj_free(r); }

    { /* a descriptor carrying a single quote -- the quoting idiom's own
       * worst case -- and shell metacharacters that must NOT execute */
      const char* EVIL = "addr(bc1q');echo pwned;'x)";
      r = NULL;
      int rc = rpc_signer_display(NULL, EVIL, &r, &ec, &em);
      char want[300]; snprintf(want, sizeof want, "ECHO:%s", EVIL);
      ck("a descriptor with quotes and ; survives unexecuted",
         rc == 1 && r && S(r,"address") && !strcmp(S(r,"address"), want));
      rj_free(r); }

    { /* the fingerprint form */
      r = NULL;
      ck("the --fingerprint form is passed through",
         rpc_signer_display("d34db33f", "addr(x)", &r, &ec, &em) == 1 &&
         r && S(r,"address") && !strcmp(S(r,"address"), "FP:d34db33f:addr(x)"));
      rj_free(r); }

    /* ---- failure shapes ---- */
    { write_script("badexit", "echo 'device wedged' >&2\nexit 3\n");
      char cmd[1100]; snprintf(cmd, sizeof cmd, "%s/badexit", tt_workdir());
      rpc_signer_set_cmd(cmd);
      r = NULL; ec = 0;
      /* RPC-17 (2026-09-05): this used to assert the message contains the word
       * "status", which it did -- by printing pclose's raw WAIT STATUS. For a
       * script exiting 3 that read "the signer exited with status 768". The
       * assertion is now the EXIT CODE itself, which is what an operator can
       * act on and what HWI documents. */
      ck("a signer that exits nonzero -> error naming the real exit code",
         rpc_signer_enumerate(&r, &ec, &em) == 0 && ec == -1 &&
         em && strstr(em, "exited 3"));
      if (em && !strstr(em, "exited 3")) printf("      got: %s\n", em);
      rj_free(r); }
    /* RPC-17: a signer killed by a signal.
     *
     * popen() runs the command through a SHELL, so when the script is killed
     * the shell survives and exits 128+signal -- WIFSIGNALED describes the
     * shell, not the signer, and is therefore false here. 139 = 128 + SIGSEGV
     * is the honest report, and the point of the fix is that it now reads
     * "exited 139" instead of the raw wait status 35584. (WIFSIGNALED is
     * still handled in rpc_signer.c for the case where the SHELL itself is
     * killed -- rarer, and previously indistinguishable from anything else.) */
    { write_script("killed", "kill -SEGV $$\n");
      char cmd[1100]; snprintf(cmd, sizeof cmd, "%s/killed", tt_workdir());
      rpc_signer_set_cmd(cmd);
      r = NULL; ec = 0;
      /* 2026-09-30: the shell popen() runs reports its child's death on OUR
       * stderr -- "Segmentation fault (core dumped)" -- and that is the gate
       * auditor's crash marker verbatim. Every gate on the 29th and 30th
       * failed gate-log-check on this one line while every test passed
       * (gate-execlock.log, gate-attest.log, gate-dlinfo.log, gate-prefix.log),
       * and a rule that ignored a segfault line would blunt the auditor for
       * the real thing. The fixture dies on purpose; stderr is parked on
       * /dev/null for exactly this call and restored after. The test's own
       * verdicts are on stdout, untouched. */
      int saved_err = dup(2); int devnull = open("/dev/null", O_WRONLY);
      if (devnull >= 0){ fflush(stderr); dup2(devnull, 2); close(devnull); }
      int rc2 = rpc_signer_enumerate(&r, &ec, &em);
      if (saved_err >= 0){ fflush(stderr); dup2(saved_err, 2); close(saved_err); }
      ck("RPC-17: a signer killed by a signal is refused",
         rc2 == 0 && ec == -1);
      /* Which one depends on /bin/sh: dash forks the script and exits 139;
       * bash (macOS's /bin/sh) execs a lone -c command, so the signer IS
       * popen's child and WIFSIGNALED reports the signal itself. Either is an
       * honest report; the raw wait status is not. */
      int honest = em && (strstr(em, "exited 139") || strstr(em, "killed by signal 11"));
      ck("RPC-17: ...reported as 128+signal (or the signal), not a raw wait status",
         honest && !strstr(em, "35584"));
      if (em && !honest) printf("      got: %s\n", em);
      rj_free(r); }
    { write_script("notjson", "echo 'i am not json'\n");
      char cmd[1100]; snprintf(cmd, sizeof cmd, "%s/notjson", tt_workdir());
      rpc_signer_set_cmd(cmd);
      r = NULL; ec = 0;
      ck("non-JSON output -> error quoting what came back",
         rpc_signer_enumerate(&r, &ec, &em) == 0 && ec == -1 &&
         em && strstr(em, "not JSON"));
      rj_free(r); }

    /* ---- HST-1 / HST-3 (audit 2026-10-23): inside the daemon ----
     * The serve parent reaps every child with waitpid(-1) from its SIGCHLD
     * handler (main.c reap_children). Under popen that handler could take
     * the signer's child before pclose did, and a signer that exited 3 was
     * reported as "could not run the signer: No child processes". And the
     * child inherited every descriptor the daemon had open. Both reproduced
     * here with the daemon's own reaper shape and a marker descriptor. */
    {
      int marker = open("/dev/null", O_RDONLY);            /* no O_CLOEXEC, like the datadir .lock */
      if (marker >= 0 && marker != 77){ dup2(marker, 77); close(marker); }
      write_script("fdlist",
          "printf '[{\"fingerprint\":\" %s\",\"model\":\"fds\"}]' \"$(ls /proc/$$/fd | tr '\\n' ' ')\"\n");
      char cmd[1100]; snprintf(cmd, sizeof cmd, "%s/fdlist", tt_workdir());
      rpc_signer_set_cmd(cmd);
      r = NULL;
      int rc = rpc_signer_enumerate(&r, &ec, &em);
      rj_val* sg = r ? rj_obj_get(r, "signers") : NULL;
      const char* fds = (sg && sg->typ == RJ_ARR && sg->nitems) ? S(sg->items[0], "fingerprint") : NULL;
      ck("HST-3: the signer runs and reports its descriptors", rc == 1 && fds);
      ck("HST-3: ...and the daemon's descriptor 77 is not among them", fds && !strstr(fds, " 77 "));
      if (fds) printf("      signer fds:%s\n", fds);
      rj_free(r);
      close(77); }
    { struct sigaction sc; memset(&sc, 0, sizeof sc); sc.sa_handler = greedy_reaper;
      sigemptyset(&sc.sa_mask); sc.sa_flags = SA_RESTART | SA_NOCLDSTOP;
      sigaction(SIGCHLD, &sc, NULL);
      write_script("badexit2", "sleep 0.2\nexit 3\n");
      char cmd[1100]; snprintf(cmd, sizeof cmd, "%s/badexit2", tt_workdir());
      rpc_signer_set_cmd(cmd);
      int saw3 = 1;
      for (int i = 0; i < 5; i++){
          r = NULL; ec = 0; em = NULL;
          int rc = rpc_signer_enumerate(&r, &ec, &em);
          if (!(rc == 0 && em && strstr(em, "exited 3"))){ saw3 = 0; if (em) printf("      got: %s\n", em); }
          rj_free(r);
      }
      ck("HST-1: under the daemon's waitpid(-1) reaper the signer's exit code still arrives (5 of 5)", saw3);
      signal(SIGCHLD, SIG_DFL); }

    rpc_signer_set_cmd(NULL);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}

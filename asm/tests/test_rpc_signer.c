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
#include "test_tmpdir.h"
#include "../rpc_signer.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }
static const char* S(const rj_val* o, const char* k){
    rj_val* v = o ? rj_obj_get((rj_val*)o, k) : NULL; return v ? v->str : NULL;
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
      int rc2 = rpc_signer_enumerate(&r, &ec, &em);
      ck("RPC-17: a signer killed by a signal is refused",
         rc2 == 0 && ec == -1);
      ck("RPC-17: ...reported as 128+signal, not a raw wait status",
         em && strstr(em, "exited 139") && !strstr(em, "35584"));
      if (em && !strstr(em, "exited 139")) printf("      got: %s\n", em);
      rj_free(r); }
    { write_script("notjson", "echo 'i am not json'\n");
      char cmd[1100]; snprintf(cmd, sizeof cmd, "%s/notjson", tt_workdir());
      rpc_signer_set_cmd(cmd);
      r = NULL; ec = 0;
      ck("non-JSON output -> error quoting what came back",
         rpc_signer_enumerate(&r, &ec, &em) == 0 && ec == -1 &&
         em && strstr(em, "not JSON"));
      rj_free(r); }

    rpc_signer_set_cmd(NULL);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}

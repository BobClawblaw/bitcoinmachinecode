/* test_multisig_opcount.c -- OP_CHECKMULTISIG's key count is charged to the
 * opcode budget. The regression for a false accept found 2026-08-26.
 *
 * THE BUG. Core's OP_CHECKMULTISIG arm does `nOpCount += nKeysCount` and then
 * re-checks MAX_OPS_PER_SCRIPT (201). Our interpreter validated the key count
 * against MAX_PUBKEYS_PER_MULTISIG (20) but never charged it to the budget --
 * so a script whose KEYS push it past 201, while its opcodes alone do not,
 * verified here and was rejected by Core with SCRIPT_ERR_OP_COUNT.
 *
 * Ten 0-of-20 multisigs are 10 opcodes but 200 keys: 210 total, over the
 * limit. Nine are 189, under it. Those two scripts are the vectors, and the
 * boundary between them is the whole point -- a fix that simply rejected all
 * multisig-heavy scripts would fail the nine-multisig case.
 *
 * Direction: we ACCEPTED what Core REJECTS, so a block carrying such a spend
 * would have split us from the network. 0-of-N checks no signatures, so no
 * key material is needed to construct one.
 *
 * Driven through tests/verify_p2sh_shim, the same binary the differential
 * uses, so this exercises the production verifier.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "multisig_opcount_vec.h"
#include "test_tmpdir.h"

static int fails = 0;
static void ck(const char* w, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", w); if (!c) fails++; }

static int shim_verify(FILE* in, FILE* out, const char* spk){
    fprintf(in, "VERIFY %08x 0 %s - %s\n", (unsigned)MSOC_FLAGS, MSOC_TX, spk);
    fflush(in);
    char line[256];
    if (!fgets(line, sizeof line, out)) return -1;
    int ok = -1, err = 0;
    if (sscanf(line, "OK %d %d", &ok, &err) != 2) return -1;
    return ok;
}

int main(void){
    const char* shim = tt_src("tests/verify_p2sh_shim");
    int pin[2], pout[2];
    if (pipe(pin) || pipe(pout)){ printf("FAIL: pipe\n"); return 1; }
    pid_t pid = fork();
    if (pid == 0){
        dup2(pin[0], 0); dup2(pout[1], 1);
        close(pin[1]); close(pout[0]);
        execl(shim, shim, (char*)NULL);
        _exit(127);
    }
    close(pin[0]); close(pout[1]);
    FILE* in = fdopen(pin[1], "w"); FILE* out = fdopen(pout[0], "r");
    if (!in || !out){ printf("FAIL: fdopen\n"); return 1; }

    int a = shim_verify(in, out, MSOC_OK);
    int b = shim_verify(in, out, MSOC_BAD);
    printf("  9 x 0-of-20 (189 ops) -> %d ; 10 x 0-of-20 (210 ops) -> %d\n", a, b);
    ck("9 multisigs stay within the 201-opcode budget and VERIFY", a == 1);
    ck("10 multisigs exceed it via the KEY COUNT and are REJECTED "
       "(Core: SCRIPT_ERR_OP_COUNT)", b == 0);

    fprintf(in, "QUIT\n"); fflush(in);
    fclose(in); fclose(out);
    int st; waitpid(pid, &st, 0);
    printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}

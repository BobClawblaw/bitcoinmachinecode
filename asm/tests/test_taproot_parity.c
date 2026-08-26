/* test_taproot_parity.c -- BIP341 control-block PARITY, the regression.
 *
 * THE BUG (found 2026-08-26 by validation/synth_corpus_diff.py, fixed the
 * same day): the script-path commitment check compared only the tweaked
 * output key's X coordinate against the scriptPubKey and ignored the control
 * block's low bit -- which BIP341 defines as the tweaked key's Y PARITY, and
 * which Core verifies inside CheckTapTweak (secp256k1_xonly_pubkey_
 * tweak_add_check takes parity as an INPUT, not an output).
 *
 * For a given internal key and merkle root, Q = P + tG is ONE point: its x
 * AND its y-parity are both determined. Checking only x leaves the parity bit
 * unconstrained, so an attacker could flip it on any otherwise-valid
 * script-path spend and this node ACCEPTED what Core REJECTED
 * (WITNESS_PROGRAM_MISMATCH) -- a false-accept in the chain-split direction,
 * reachable by flipping one bit of witness data, with no key material and no
 * grinding.
 *
 * The vectors are a real Schnorr-signed script-path spend (valid) and the
 * same spend with ONLY the control byte's low bit flipped (invalid). Both
 * verdicts were confirmed against Bitcoin Core's own VerifyScript before
 * being frozen here.
 *
 * The spend is driven through tests/verify_p2sh_shim -- the same binary the
 * differential harness uses -- so this test exercises the production entry
 * point with the production serialization contract (witness-stripped tx plus
 * packed prevout arrays) rather than a second, drifting copy of it.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "taproot_parity_vec.h"
#include "test_tmpdir.h"

static int fails = 0;
static void ck(const char* w, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", w); if (!c) fails++; }

/* Ask the shim: TAPVERIFY <idx> <tx> <nprev> <amt> <spk>. -> 1 accept / 0 reject */
static int shim_verify(FILE* in, FILE* out, const char* txhex){
    fprintf(in, "TAPVERIFY 0 %s 1 %llu %s\n", txhex, (unsigned long long)TP_AMT, TP_SPK);
    fflush(in);
    char line[256];
    if (!fgets(line, sizeof line, out)) return -1;
    int ok = -1, err = 0;
    if (sscanf(line, "OK %d %d", &ok, &err) != 2) return -1;
    return ok;
}

int main(void){
    const char* shim = tt_src("tests/verify_p2sh_shim");
    char cmd[1024];
    snprintf(cmd, sizeof cmd, "%s", shim);
    FILE* out = NULL; FILE* in = NULL;
    int pin[2], pout[2];
    if (pipe(pin) || pipe(pout)) { printf("FAIL: pipe\n"); return 1; }
    pid_t pid = fork();
    if (pid == 0){
        dup2(pin[0], 0); dup2(pout[1], 1);
        close(pin[1]); close(pout[0]);
        execl(shim, shim, (char*)NULL);
        _exit(127);
    }
    close(pin[0]); close(pout[1]);
    in = fdopen(pin[1], "w"); out = fdopen(pout[0], "r");
    if (!in || !out){ printf("FAIL: fdopen\n"); return 1; }

    int ok  = shim_verify(in, out, TP_TX_OK);
    int bad = shim_verify(in, out, TP_TX_BAD);
    printf("  valid spend -> %d ; parity-flipped -> %d\n", ok, bad);
    ck("a valid taproot script-path spend VERIFIES", ok == 1);
    ck("the SAME spend with control[0]&1 flipped is REJECTED "
       "(Core rejects it too, WITNESS_PROGRAM_MISMATCH)", bad == 0);

    fprintf(in, "QUIT\n"); fflush(in);
    fclose(in); fclose(out);
    int st; waitpid(pid, &st, 0);
    printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}

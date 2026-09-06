/* tests/test_wallet_pass.c -- where the daemon gets the wallet passphrase
 * (audit 2026-08-29 finding 2).
 *
 * The old boot path read <store>.pass from the datadir: ciphertext and key in
 * one directory, under a guessable name, and therefore in the same backup.
 * The replacement takes an absolute path outside the datadir and REFUSES a
 * file that is world-accessible, group-writable, or inside the datadir.
 *
 * Refusals are the interesting half. A permission check that never rejects
 * anything looks identical to one that works, so each rejection is exercised
 * explicitly -- and each is paired with the mode that must still be accepted,
 * so a check that simply refuses everything cannot pass either.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../daemon/wallet_pass.h"

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static char DIR[256];
static char PF[512];

static void write_pass(const char* path, const char* secret, mode_t mode){
    FILE* f = fopen(path, "w");
    if (f){ fputs(secret, f); fclose(f); }
    chmod(path, mode);
}

/* returns 1 if a secret was loaded, and copies it out */
static int try_load(char* out, size_t cap){
    out[0] = 0;
    return wallet_pass_load(out, (int)cap, 0);
}

int main(void){
    snprintf(DIR, sizeof DIR, "/tmp/bmc_wp_%d", (int)getpid());
    mkdir(DIR, 0700);
    snprintf(PF, sizeof PF, "%s/wallet.pass", DIR);
    char got[256];

    unsetenv("BMC_WALLET_PASS");
    wallet_pass_set_file(0);

    printf("== no source configured ==\n");
    ck("nothing configured yields no passphrase", try_load(got, sizeof got) == 0);

    printf("== the environment variable still works ==\n");
    setenv("BMC_WALLET_PASS", "from-env", 1);
    ck("BMC_WALLET_PASS is used", try_load(got, sizeof got) == 1 && !strcmp(got, "from-env"));
    unsetenv("BMC_WALLET_PASS");

    printf("== a properly protected file is accepted ==\n");
    write_pass(PF, "s3cret-from-file\n", 0640);
    wallet_pass_set_file(PF);
    ck("mode 0640 is accepted", try_load(got, sizeof got) == 1);
    ck("  and the trailing newline is stripped", !strcmp(got, "s3cret-from-file"));
    write_pass(PF, "tight\n", 0600);
    ck("mode 0600 is accepted too", try_load(got, sizeof got) == 1 && !strcmp(got, "tight"));

    printf("== the environment wins over the file ==\n");
    setenv("BMC_WALLET_PASS", "env-priority", 1);
    ck("env takes precedence", try_load(got, sizeof got) == 1 && !strcmp(got, "env-priority"));
    unsetenv("BMC_WALLET_PASS");

    printf("== unsafe modes are refused ==\n");
    write_pass(PF, "leaky\n", 0644);
    ck("world-readable (0644) is refused", try_load(got, sizeof got) == 0);
    write_pass(PF, "leaky\n", 0604);
    ck("other-readable (0604) is refused", try_load(got, sizeof got) == 0);
    write_pass(PF, "leaky\n", 0660);
    ck("group-writable (0660) is refused", try_load(got, sizeof got) == 0);
    write_pass(PF, "leaky\n", 0666);
    ck("world-writable (0666) is refused", try_load(got, sizeof got) == 0);
    /* and the accepted mode still is, so the check is not simply refusing all */
    write_pass(PF, "fine\n", 0640);
    ck("  0640 still accepted after all those refusals", try_load(got, sizeof got) == 1);

    printf("== a relative path is refused ==\n");
    wallet_pass_set_file("wallet.pass");
    ck("relative walletpassfile is refused", try_load(got, sizeof got) == 0);

    printf("== a file inside the datadir is refused ==\n");
    /* the daemon chdir's into the datadir, so cwd IS the datadir */
    { char cwd[4096]; if (!getcwd(cwd, sizeof cwd)) return 1;
      char inside[4600];
      snprintf(inside, sizeof inside, "%s/wp_inside.pass", cwd);
      write_pass(inside, "colocated\n", 0600);
      wallet_pass_set_file(inside);
      ck("a 0600 file inside the datadir is still refused", try_load(got, sizeof got) == 0);
      printf("        (correct modes are not enough -- a datadir backup carries it)\n");
      unlink(inside); }

    printf("== an empty or missing file yields nothing ==\n");
    write_pass(PF, "", 0600);
    wallet_pass_set_file(PF);
    ck("an empty file is not a passphrase", try_load(got, sizeof got) == 0);
    unlink(PF);
    ck("a missing file is not a passphrase", try_load(got, sizeof got) == 0);

    /* ---- DMN-13 (audit 2026-09-03): refuse an over-long passphrase, never
     * truncate it.
     *
     * read_secret_file used fgets(out, cap, f), which SILENTLY TRUNCATES at
     * cap -- 256 for every caller. That was invisible while the KDF truncated
     * at 96 anyway, and WAL-7 removed that truncation, so the two paths now
     * DISAGREE: a long passphrase file seals with its full contents through
     * one path and unlocks with 255 bytes through this one, and the wallet
     * will not open. The operator is told "wrong passphrase" for a correct
     * passphrase. Fixing WAL-7 is what made this reachable.
     *
     * The control's other half is the ordinary case, which must keep loading:
     * a refusal applied too eagerly would lock every wallet out. */
    { char big[600]; memset(big, 'p', sizeof big - 1); big[sizeof big - 1] = 0;
      write_pass(PF, big, 0600);
      wallet_pass_set_file(PF);
      char out[256];
      ck("DMN-13 a passphrase longer than the buffer is REFUSED, not truncated",
         try_load(out, sizeof out) == 0);

      /* and a passphrase that FITS still loads, byte for byte */
      write_pass(PF, "correct horse battery staple", 0600);
      ck("DMN-13 an ordinary passphrase still loads", try_load(out, sizeof out) == 1);
      ck("DMN-13   ...with its exact bytes", strcmp(out, "correct horse battery staple") == 0);

      /* exactly at the limit: 254 bytes plus the NUL must still fit */
      { char edge[256]; memset(edge, 'q', 254); edge[254] = 0;
        write_pass(PF, edge, 0600);
        ck("DMN-13 a passphrase exactly at the limit still loads",
           try_load(out, sizeof out) == 1 && strlen(out) == 254); }

      wallet_pass_set_file(0);
      unlink(PF); }

    rmdir(DIR);
    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

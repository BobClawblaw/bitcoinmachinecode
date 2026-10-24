/* tests/test_cli_prompt.c -- 2026-09-02: manual wallet decryption without a
 * passphrase on disk. wallet_cli asks for the passphrase when nothing supplied
 * it and the wallet is encrypted: echo OFF on a terminal (proved here with a
 * pty: the typed passphrase must not come back in the output), one line from
 * a pipe otherwise. bmc_cli gains Core's -stdinwalletpassphrase / -stdin,
 * so `walletpassphrase` never carries the secret in argv. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <sys/wait.h>
#include <sys/stat.h>
extern int wallet_store_create(const char* path, const char* mnemonic, const char* pass);
static int fails = 0;
static void ck(const char* l, int c){ printf("  %s %s\n", c ? "ok  " : "FAIL", l); if (!c) fails++; }
static char WCLI[1200], BCLI[1200], DIR[600];
static int run_sh(const char* cmd, char* out, int cap){
    FILE* f = popen(cmd, "r"); if (!f) return -1; size_t n = fread(out, 1, (size_t)cap - 1, f); out[n] = 0; return pclose(f);
}
/* run wallet_cli in a pty (a real terminal), answer the prompt, collect everything it printed */
static int run_pty(const char* answer, char* out, int cap, int* saw_prompt){
    int mfd; pid_t pid = forkpty(&mfd, NULL, NULL, NULL);
    if (pid < 0) return -1;
    if (pid == 0){ if (chdir(DIR)) _exit(9); unsetenv("BMC_WALLET_PASS"); execl(WCLI, "wallet_cli", "getaddress", (char*)0); _exit(9); }
    int n = 0; *saw_prompt = 0; int answered = 0;
    for (int spins = 0; spins < 400; spins++){
        struct pollfd p = { mfd, POLLIN, 0 };
        int r = poll(&p, 1, 50);
        if (r > 0){ ssize_t k = read(mfd, out + n, (size_t)(cap - 1 - n)); if (k <= 0) break; n += (int)k; out[n] = 0; }
        if (!answered && strstr(out, "Passphrase")){ *saw_prompt = 1; ssize_t w = write(mfd, answer, strlen(answer)); (void)w; w = write(mfd, "\n", 1); (void)w; answered = 1; }
    }
    int st = 0; waitpid(pid, &st, 0); close(mfd);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -2;
}
int main(void){
    const char* MN = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    char cwd[512]; if (!getcwd(cwd, sizeof cwd)) return 1;
    snprintf(WCLI, sizeof WCLI, "%s/daemon/bmc_wallet_cli", cwd); snprintf(BCLI, sizeof BCLI, "%s/daemon/bmc_cli", cwd);
    char tmpl[] = "/tmp/cliprompt.XXXXXX"; char* d = mkdtemp(tmpl); if (!d) return 1; snprintf(DIR, sizeof DIR, "%s", d);
    char path[1400]; snprintf(path, sizeof path, "%s/data", DIR); mkdir(path, 0700);
    snprintf(path, sizeof path, "%s/data/bmcwallet.dat", DIR);
    unsetenv("BMC_WALLET_PASS");
    ck("an encrypted wallet exists for the test", wallet_store_create(path, MN, "hunter2") == 0);
    char out[16384], cmd[4096];
    printf("== wallet_cli: passphrase from a pipe (not a terminal) ==\n");
    snprintf(cmd, sizeof cmd, "cd %s && printf 'hunter2\\n' | %s getaddress 2>&1", DIR, WCLI);
    int rc = run_sh(cmd, out, sizeof out);
    ck("piped passphrase decrypts the wallet (exit 0)", rc == 0);
    ck("...and prints the address", strstr(out, "bc1q") != NULL);
    snprintf(cmd, sizeof cmd, "cd %s && printf 'wrong\\n' | %s getaddress 2>&1", DIR, WCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("a wrong piped passphrase fails (exit 1)", rc != 0 && strstr(out, "wrong passphrase") != NULL && !strstr(out, "bc1q"));
    snprintf(cmd, sizeof cmd, "cd %s && %s getaddress </dev/null 2>&1", DIR, WCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("no passphrase at all fails with the four ways to supply one", rc != 0 && strstr(out, "at the prompt") != NULL);
    printf("== wallet_cli: interactive prompt on a terminal, echo off ==\n");
    int saw = 0; rc = run_pty("hunter2", out, sizeof out, &saw);
    ck("the CLI prompted for the passphrase", saw == 1);
    ck("the typed passphrase was NOT echoed back", strstr(out, "hunter2") == NULL);
    ck("the wallet decrypted and the address was printed", rc == 0 && strstr(out, "bc1q") != NULL);
    rc = run_pty("nope", out, sizeof out, &saw);
    ck("a wrong typed passphrase is refused", saw == 1 && rc != 0 && strstr(out, "wrong passphrase") != NULL);
    printf("== wallet_cli: env/.pass still work and do NOT prompt ==\n");
    snprintf(cmd, sizeof cmd, "cd %s && BMC_WALLET_PASS=hunter2 %s getaddress </dev/null 2>&1", DIR, WCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("BMC_WALLET_PASS decrypts without any prompt", rc == 0 && strstr(out, "bc1q") && !strstr(out, "Passphrase"));
    printf("== wallet_cli init on a terminal: asks twice, stores no .pass file ==\n");
    { char d2[900]; snprintf(d2, sizeof d2, "%s/init", DIR); mkdir(d2, 0700); snprintf(path, sizeof path, "%s/data", d2); mkdir(path, 0700);
      int mfd; pid_t pid = forkpty(&mfd, NULL, NULL, NULL);
      if (pid == 0){ if (chdir(d2)) _exit(9); unsetenv("BMC_WALLET_PASS"); execl(WCLI, "wallet_cli", "init", (char*)0); _exit(9); }
      int n = 0, answers = 0; out[0] = 0;
      for (int spins = 0; spins < 400 && pid > 0; spins++){
          struct pollfd p = { mfd, POLLIN, 0 }; int r = poll(&p, 1, 50);
          if (r > 0){ ssize_t k = read(mfd, out + n, (size_t)(sizeof out - 1 - n)); if (k <= 0) break; n += (int)k; out[n] = 0; }
          int prompts = 0; for (char* q = out; (q = strstr(q, "Passphrase for")); q++) prompts++;
          if (prompts > answers){ ssize_t w = write(mfd, "s3cret\n", 7); (void)w; answers++; }
      }
      int st = 0; if (pid > 0){ waitpid(pid, &st, 0); close(mfd); }
      ck("init prompted twice", answers == 2);
      ck("the typed passphrase was not echoed", strstr(out, "s3cret") == NULL);
      ck("init succeeded", pid > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0 && strstr(out, "mnemonic:") != NULL);
      snprintf(path, sizeof path, "%s/data/bmcwallet.dat", d2);
      snprintf(cmd, sizeof cmd, "head -c 9 %s", path); run_sh(cmd, out, sizeof out);
      ck("the wallet was written encrypted (BMCWAL v3)", !strncmp(out, "BMCWAL v3", 9));
      snprintf(path, sizeof path, "%s/data/bmcwallet.dat.pass", d2);
      ck("and NO .pass file was left beside it", access(path, F_OK) != 0);
      snprintf(cmd, sizeof cmd, "cd %s && printf 's3cret\\n' | %s getaddress 2>&1", d2, WCLI);
      rc = run_sh(cmd, out, sizeof out);
      ck("it opens with the typed passphrase", rc == 0 && strstr(out, "bc1q") != NULL); }
    printf("== CRY-7: init's flags are not positional arguments ==\n");
    { char d3[900]; snprintf(d3, sizeof d3, "%s/force", DIR); mkdir(d3, 0700); snprintf(path, sizeof path, "%s/data", d3); mkdir(path, 0700);
      snprintf(cmd, sizeof cmd, "cd %s && %s init --force </dev/null 2>&1", d3, WCLI);
      rc = run_sh(cmd, out, sizeof out);
      ck("`init --force` (no passphrase, no terminal) succeeds", rc == 0 && strstr(out, "mnemonic:") != NULL);
      snprintf(path, sizeof path, "%s/data/bmcwallet.dat", d3);
      snprintf(cmd, sizeof cmd, "head -c 9 %s", path); run_sh(cmd, out, sizeof out);
      ck("...and writes a PLAINTEXT wallet, not one encrypted under \"--force\"", !strncmp(out, "BMCWAL v1", 9));
      snprintf(path, sizeof path, "%s/data/bmcwallet.dat.pass", d3);
      ck("...with no .pass file holding \"--force\"", access(path, F_OK) != 0);
      snprintf(cmd, sizeof cmd, "cd %s && %s init pw7 --force </dev/null 2>&1", d3, WCLI);
      rc = run_sh(cmd, out, sizeof out);
      snprintf(path, sizeof path, "%s/--force", d3);
      ck("`init <pass> --force` does not write a wallet named \"--force\"", rc == 0 && access(path, F_OK) != 0);
      snprintf(path, sizeof path, "%s/data/bmcwallet.dat", d3);
      snprintf(cmd, sizeof cmd, "head -c 9 %s", path); run_sh(cmd, out, sizeof out);
      ck("...it replaced the default wallet, encrypted", !strncmp(out, "BMCWAL v3", 9));
      snprintf(cmd, sizeof cmd, "cd %s && printf 'pw7\\n' | BMC_WALLET_PASS= %s getaddress 2>&1", d3, WCLI);
      rc = run_sh(cmd, out, sizeof out);
      ck("...under the passphrase given, \"pw7\"", rc == 0 && strstr(out, "bc1q") != NULL);
      /* CRY-6: the .pass file is 0600 and a symlink at its name is refused */
      snprintf(path, sizeof path, "%s/data/bmcwallet.dat.pass", d3);
      struct stat psb;
      ck("CRY-6 the .pass file is mode 0600", stat(path, &psb) == 0 && (psb.st_mode & 0777) == 0600);
      char d4[900]; snprintf(d4, sizeof d4, "%s/link", DIR); mkdir(d4, 0700); snprintf(path, sizeof path, "%s/data", d4); mkdir(path, 0700);
      char victim[1000]; snprintf(victim, sizeof victim, "%s/victim.txt", d4);
      FILE* vf = fopen(victim, "w"); if (vf){ fputs("untouched\n", vf); fclose(vf); }
      chmod(victim, 0644);
      snprintf(path, sizeof path, "%s/data/bmcwallet.dat.pass", d4);
      ck("CRY-6 (setup) a symlink planted at the .pass name", symlink(victim, path) == 0);
      snprintf(cmd, sizeof cmd, "cd %s && %s init pw-cry6-secret </dev/null 2>&1", d4, WCLI);
      rc = run_sh(cmd, out, sizeof out);
      ck("CRY-6 init still creates the wallet", rc == 0 && strstr(out, "mnemonic:") != NULL);
      ck("CRY-6 ...and says the .pass file was not written", strstr(out, "could not write") != NULL);
      snprintf(cmd, sizeof cmd, "cat %s", victim); run_sh(cmd, out, sizeof out);
      ck("CRY-6 the symlink's target did NOT receive the passphrase", strstr(out, "pw-cry6-secret") == NULL && strstr(out, "untouched") != NULL); }
    printf("== bmc_cli: -stdinwalletpassphrase / -stdin (Core semantics) ==\n");
    snprintf(cmd, sizeof cmd, "printf 'hunter2\\n' | BMC_CLI_DRYRUN=1 %s -stdinwalletpassphrase -rpcport=1 -rpcuser=u -rpcpassword=p walletpassphrase 60 2>&1", BCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("the passphrase from stdin is the FIRST param, the timeout a number", rc == 0 && strstr(out, "\"params\":[\"hunter2\",60]") != NULL);
    snprintf(cmd, sizeof cmd, "printf 'hunter2\\n60\\n' | BMC_CLI_DRYRUN=1 %s -stdinwalletpassphrase -stdin -rpcport=1 -rpcuser=u -rpcpassword=p walletpassphrase 2>&1", BCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("with -stdin the remaining params come one per line", rc == 0 && strstr(out, "\"params\":[\"hunter2\",60]") != NULL);
    snprintf(cmd, sizeof cmd, "BMC_CLI_DRYRUN=1 %s -rpcport=1 -rpcuser=u -rpcpassword=p getblockcount 2>&1", BCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("without the flags nothing is read from stdin", rc == 0 && strstr(out, "\"params\":[]") != NULL);
    printf("== bmc_cli: parameter conversion (bitcoin-cli's RPCConvertValues, by shape) ==\n");
    snprintf(cmd, sizeof cmd, "BMC_CLI_DRYRUN=1 %s -rpcport=1 -rpcuser=u -rpcpassword=p getrawmempool true 2>&1", BCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("getrawmempool true sends a JSON boolean, not the string \"true\"", rc == 0 && strstr(out, "\"params\":[true]") != NULL);
    snprintf(cmd, sizeof cmd, "BMC_CLI_DRYRUN=1 %s -rpcport=1 -rpcuser=u -rpcpassword=p createrawtransaction '[{\"txid\":\"ab\",\"vout\":0}]' '{\"bc1qx\":0.1}' 2>&1", BCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("an argument that parses as a JSON array or object is sent as one", rc == 0 && strstr(out, "\"params\":[[{\"txid\":\"ab\",\"vout\":0}],{\"bc1qx\":0.1}]") != NULL);
    snprintf(cmd, sizeof cmd, "BMC_CLI_DRYRUN=1 %s -rpcport=1 -rpcuser=u -rpcpassword=p getblock 00aa 2 2>&1", BCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("a hash stays a string and a verbosity stays a number", rc == 0 && strstr(out, "\"params\":[\"00aa\",2]") != NULL);
    /* A 64-character hash made only of DIGITS looked numeric and was sent as a
     * JSON number: `waitforblock 000...0 1` came back -32700 "Parse error" and
     * `111...1` came back "expected string parameter", while a mixed-case hash
     * worked. The SERVER was right in both cases -- checked on the wire, it
     * answers exactly as Core does. The CLI was mangling the request.
     * Found 2026-09-15 by the RPC shape differential. */
    snprintf(cmd, sizeof cmd, "BMC_CLI_DRYRUN=1 %s -rpcport=1 -rpcuser=u -rpcpassword=p waitforblock "
             "0000000000000000000000000000000000000000000000000000000000000000 1 2>&1", BCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("an all-zero 64-char hash stays a STRING, not a number",
       rc == 0 && strstr(out, "\"params\":[\"0000000000000000000000000000000000000000000000000000000000000000\",1]") != NULL);
    snprintf(cmd, sizeof cmd, "BMC_CLI_DRYRUN=1 %s -rpcport=1 -rpcuser=u -rpcpassword=p waitforblock "
             "1111111111111111111111111111111111111111111111111111111111111111 1 2>&1", BCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("an all-digit 64-char hash stays a STRING too",
       rc == 0 && strstr(out, "\"params\":[\"1111111111111111111111111111111111111111111111111111111111111111\",1]") != NULL);
    /* and a real number of any other length is still a number -- the guard is
     * narrow, not a blanket "digits are strings" */
    snprintf(cmd, sizeof cmd, "BMC_CLI_DRYRUN=1 %s -rpcport=1 -rpcuser=u -rpcpassword=p getblockhash 966000 2>&1", BCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("a height is still sent as a number", rc == 0 && strstr(out, "\"params\":[966000]") != NULL);

    snprintf(cmd, sizeof cmd, "BMC_CLI_DRYRUN=1 %s -rpcport=1 -rpcuser=u -rpcpassword=p setlabel bc1qx '[not json' false null 2>&1", BCLI);
    rc = run_sh(cmd, out, sizeof out);
    ck("false and null convert; a bracket that is not JSON stays a string", rc == 0 && strstr(out, "\"params\":[\"bc1qx\",\"[not json\",false,null]") != NULL);
    printf("== bmc_cli: a request past 32 KB goes out whole (RPC-25) ==\n");
    { /* the body used to live in a 32 KB stack buffer and was sent with
       * rj_write's FULL length, so bytes past the buffer went out */
      enum { ARGLEN = 40000 };
      char* arg = malloc(ARGLEN + 1); char* big = malloc(ARGLEN + 4096); char* got = malloc(256 * 1024);
      for (int i = 0; i < ARGLEN; i++) arg[i] = "0123456789abcdef"[i & 15];
      arg[ARGLEN] = 0;
      snprintf(big, ARGLEN + 4096, "BMC_CLI_DRYRUN=1 %s -rpcport=1 -rpcuser=u -rpcpassword=p sendrawtransaction %s 2>&1", BCLI, arg);
      rc = run_sh(big, got, 256 * 1024);
      char want[256]; snprintf(want, sizeof want, "\"params\":[\"");
      char* at = strstr(got, want);
      size_t glen = strlen(got);
      ck("the 40,000-byte argument is in the request intact",
         rc == 0 && at && !strncmp(at + strlen(want), arg, ARGLEN) && !strncmp(at + strlen(want) + ARGLEN, "\"]", 2));
      ck("and nothing past the request is printed (ends with }\\n)", glen >= 2 && !strcmp(got + glen - 2, "}\n"));
      if (fails) printf("    got %zu bytes, rc=%d\n", glen, rc);
      free(arg); free(big); free(got); }
    printf("%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL PASS", fails);
    return fails ? 1 : 0;
}

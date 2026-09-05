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
    snprintf(WCLI, sizeof WCLI, "%s/daemon/wallet_cli", cwd); snprintf(BCLI, sizeof BCLI, "%s/daemon/bmc_cli", cwd);
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
    printf("%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL PASS", fails);
    return fails ? 1 : 0;
}

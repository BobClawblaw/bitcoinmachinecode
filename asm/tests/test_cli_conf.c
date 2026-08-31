/* tests/test_cli_conf.c -- where bitcoin_cli finds its port and credentials.
 *
 * The bug this pins: the CLI hardcoded port 8332 and "bitcoin"/"bitcoin", so
 * against this node's own shipped config (RPC 8331, P2P 8332, cookie auth) a
 * bare command dialled the P2P LISTENER and reported "malformed HTTP reply".
 * That reads as a dead server. It was wrong for every non-mainnet chain too,
 * since the port did not depend on the chain at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../daemon/cli_conf.h"

static int fails = 0;
static void ok(int c, const char* w){
    printf("  %s %s\n", c ? "ok " : "FAIL", w); if (!c) fails++;
}
static char DIR[256];
static void wr(const char* rel, const char* body){
    char p[512]; snprintf(p, sizeof p, "%s/%s", DIR, rel);
    FILE* f = fopen(p, "w"); if (!f){ perror(p); exit(2); }
    fputs(body, f); fclose(f);
}
static void mk(const char* rel){
    char p[512]; snprintf(p, sizeof p, "%s/%s", DIR, rel); mkdir(p, 0755);
}

int main(void){
    snprintf(DIR, sizeof DIR, "/tmp/bmc_cliconf_%d", (int)getpid());
    mkdir(DIR, 0755);
    cli_conf_t c; const char* err = 0;

    printf("== chain defaults match Core ==\n");
    ok(cli_conf_default_rpcport("main")     == 8332,  "main     8332");
    ok(cli_conf_default_rpcport("signet")   == 38332, "signet   38332");
    ok(cli_conf_default_rpcport("testnet4") == 48332, "testnet4 48332");
    ok(cli_conf_default_rpcport("regtest")  == 18443, "regtest  18443");
    ok(cli_conf_default_rpcport("florin")   == 0,     "an unknown chain has none");

    printf("== THE BUG: rpcport from the config, not a hardcoded 8332 ==\n");
    wr("bitcoin.conf", "rpcport=8331\nport=8332\nchain=main\n");
    mk("main"); wr("main/.cookie", "__cookie__:secret\n");   /* main lives in its own subdir now */
    ok(cli_conf_resolve(DIR, 0, &c, &err) == 1, "resolves");
    ok(c.port == 8331, "port is the configured 8331, NOT the P2P port 8332");
    ok(c.from_cookie && !strcmp(c.user, "__cookie__") && !strcmp(c.pass, "secret"),
       "credentials come from the cookie the daemon wrote");

    printf("== per-chain datadir layout, as chainparams_datadir lays it out ==\n");
    wr("bitcoin.conf", "chain=signet\n");
    mk("signet");
    wr("signet/.cookie", "__cookie__:sig\n");
    ok(cli_conf_resolve(DIR, 0, &c, &err) == 1, "signet resolves");
    ok(c.port == 38332, "port defaults to signet's 38332 with no rpcport set");
    ok(!strcmp(c.pass, "sig"), "and the cookie comes from <datadir>/signet/");
    ok(cli_conf_resolve(DIR, "regtest", &c, &err) == 0,
       "an override to a chain with no cookie there fails rather than guesses");
    ok(strstr(c.cookie_path, "/regtest/") != 0,
       "and it reports WHERE it looked, so the message is actionable");

    printf("== an explicit rpcuser/rpcpassword wins over the cookie ==\n");
    wr("bitcoin.conf", "rpcport=9999\nrpcuser=alice\nrpcpassword=pw\n");
    ok(cli_conf_resolve(DIR, 0, &c, &err) == 1, "resolves");
    ok(!c.from_cookie && !strcmp(c.user, "alice") && !strcmp(c.pass, "pw"),
       "configured credentials are used, cookie untouched");
    ok(c.port == 9999, "and the configured port");

    printf("== rpccookiefile is honoured ==\n");
    wr("elsewhere.cookie", "__cookie__:moved\n");
    { char p[512]; snprintf(p, sizeof p, "rpcport=8331\nrpccookiefile=%s/elsewhere.cookie\n", DIR);
      wr("bitcoin.conf", p); }
    ok(cli_conf_resolve(DIR, 0, &c, &err) == 1 && !strcmp(c.pass, "moved"),
       "the cookie is read from rpccookiefile");

    printf("== the config in ../config/, which the daemon also reads ==\n");
    { char sub[512]; snprintf(sub, sizeof sub, "%s/data", DIR); mkdir(sub, 0755);
      snprintf(sub, sizeof sub, "%s/config", DIR); mkdir(sub, 0755); }
    wr("config/bitcoin.conf", "rpcport=7777\n");
    mk("data/main"); wr("data/main/.cookie", "__cookie__:d\n");   /* main subdir layout */
    { char dd[512]; snprintf(dd, sizeof dd, "%s/data", DIR);
      ok(cli_conf_resolve(dd, 0, &c, &err) == 1 && c.port == 7777,
         "<datadir>/../config/bitcoin.conf is consulted"); }

    printf("== failures say what to do, rather than sending bitcoin/bitcoin ==\n");
    ok(cli_conf_resolve(0, 0, &c, &err) == 0 && err && strstr(err, "-datadir"),
       "no datadir: refuses and names the flag to pass");
    { char empty[512]; snprintf(empty, sizeof empty, "%s/empty", DIR); mkdir(empty, 0755);
      ok(cli_conf_resolve(empty, 0, &c, &err) == 0 && err && strstr(err, "cookie"),
         "a datadir with no config and no cookie: refuses, saying so"); }
    ok(cli_conf_resolve(DIR, "florin", &c, &err) == 0 && err && strstr(err, "chain"),
       "an unknown chain is refused for having no default port");

    printf("\n%s (%d failure%s)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}

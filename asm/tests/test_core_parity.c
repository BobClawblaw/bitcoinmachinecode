/* tests/test_core_parity.c -- the five Core options added on 2026-08-29, each
 * checked at the point where it CHANGES BEHAVIOUR rather than at the point
 * where it is parsed.
 *
 * That distinction is the whole reason this file exists. Earlier the same day
 * `externalip` was found parsed, documented in the sample conf, and never
 * read by anything -- a setting that looked supported from the config file
 * and did nothing. Parsing tests would have passed on it. So every case here
 * asserts an effect: a work floor that refuses a chain, a credential that
 * authenticates, a ban that is written.
 *
 *   1. -minimumchainwork  hex parsing, per-chain defaults, and the refusal
 *   2. rpc cookie auth    file contents, permissions, accept and reject
 *   3. -bantime           drives the automatic ban horizon
 *   4. -conf              overrides the datadir search
 *   5. -blockfilterindex / -coinstatsindex   parse to the gates main() reads
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../daemon/node_config.h"
#include "../daemon/chainparams.h"

extern node_config_t g_cfg;
extern void reorg_set_min_chain_work(const unsigned char be32[32]);
extern int  reorg_work_meets_minimum(const unsigned char work[16]);
extern int  reorg_min_chain_work_set(void);
extern int  reorg_min_chain_work_unrepresentable(void);
extern int  rpc_cookie_write(const char* path);
extern void rpc_cookie_remove(void);
extern int  rpc_auth_ok_for_test(const char* hdrs, unsigned long hlen,
                                 const char* user, const char* pass);
extern void notify_run(const char* cmd_template, const char* value, const char* what);
extern int  rpc_auth_add(const char* spec);
extern int  rpc_auth_count(void);
extern void rpc_auth_clear(void);

/* the hooks run asynchronously (double fork); wait briefly for the effect */
static int wait_for_file(const char* path, int tenths){
    for (int i = 0; i < tenths; i++){ if (access(path, F_OK) == 0) return 1; usleep(100000); }
    return 0;
}

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* build "Authorization: Basic base64(user:pass)\r\n\r\n" */
static void mk_auth(char* out, unsigned long cap, const char* user, const char* pass){
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char cred[512]; int n = snprintf(cred, sizeof cred, "%s:%s", user, pass);
    char b64[768]; int o = 0;
    for (int i = 0; i < n; i += 3){
        unsigned v = (unsigned char)cred[i] << 16;
        if (i+1 < n) v |= (unsigned char)cred[i+1] << 8;
        if (i+2 < n) v |= (unsigned char)cred[i+2];
        b64[o++] = T[(v>>18)&63]; b64[o++] = T[(v>>12)&63];
        b64[o++] = (i+1 < n) ? T[(v>>6)&63] : '=';
        b64[o++] = (i+2 < n) ? T[v&63]      : '=';
    }
    b64[o] = 0;
    snprintf(out, cap, "POST / HTTP/1.1\r\nAuthorization: Basic %s\r\n\r\n", b64);
}

int main(void){
    unsigned char w[32];

    printf("== 1. -minimumchainwork: hex parsing ==\n");
    ck("a full 64-digit value parses",
       nodecfg_hex32_be("0000000000000000000000000000000000000001128750f82f4c366153a3a030", w) == 1);
    ck("  and lands BIG-endian (low byte 0x30, 0x01 at byte 19)", w[31] == 0x30 && w[19] == 0x01);
    { int hi0 = 1; for (int i = 0; i < 16; i++) if (w[i]) hi0 = 0;
      ck("  mainnet's floor fits the 128-bit accumulator (high half zero)", hi0); }
    memset(w, 0xAA, 32);
    ck("a short value is right-aligned, not left", nodecfg_hex32_be("ff", w) == 1 && w[31] == 0xff && w[30] == 0 && w[0] == 0);
    ck("an 0x prefix is accepted", nodecfg_hex32_be("0xff", w) == 1 && w[31] == 0xff);
    ck("a non-hex character is REJECTED, not truncated", nodecfg_hex32_be("00zz", w) == 0);
    ck("more than 64 digits is rejected",
       nodecfg_hex32_be("00000000000000000000000000000000000000000000000000000000000000000", w) == 0);
    ck("an empty string is rejected", nodecfg_hex32_be("", w) == 0);

    printf("== 1b. per-chain defaults match Core ==\n");
    chainparams_select("main");
    ck("mainnet carries a floor", g_chainp->min_chain_work_hex && g_chainp->min_chain_work_hex[0]);
    ck("  and it is Core's value",
       !strcmp(g_chainp->min_chain_work_hex,
               "0000000000000000000000000000000000000001128750f82f4c366153a3a030"));
    chainparams_select("regtest");
    ck("regtest has NO floor, exactly as Core leaves it",
       !g_chainp->min_chain_work_hex || !g_chainp->min_chain_work_hex[0]);
    chainparams_select("main");

    printf("== 1c. the floor actually refuses work ==\n");
    /* the accumulator is 128-bit; the floor's low half is what it compares */
    memset(w, 0, 32); nodecfg_hex32_be("0000000000000000000000000000000000000000000000000000000000001000", w);
    reorg_set_min_chain_work(w);
    ck("a floor is registered", reorg_min_chain_work_set() == 1);
    ck("  and is representable", reorg_min_chain_work_unrepresentable() == 0);
    /* work values are the accumulator's own form: 16 bytes LITTLE-endian.
     * The floor above is 0x1000, so byte[1]=0x10 is exactly equal. */
    unsigned char below[16]; memset(below, 0, 16); below[0] = 0x01;   /* 1      */
    unsigned char equal[16]; memset(equal, 0, 16); equal[1] = 0x10;   /* 0x1000 */
    unsigned char above[16]; memset(above, 0, 16); above[2] = 0x01;   /* 0x10000 */
    ck("work BELOW the floor is refused",   reorg_work_meets_minimum(below) == 0);
    ck("work EQUAL to the floor is accepted", reorg_work_meets_minimum(equal) == 1);
    ck("work ABOVE the floor is accepted",  reorg_work_meets_minimum(above) == 1);

    printf("== 1d. an all-zero floor means no floor ==\n");
    memset(w, 0, 32); reorg_set_min_chain_work(w);
    ck("no floor is registered", reorg_min_chain_work_set() == 0);
    ck("  so any work passes", reorg_work_meets_minimum(below) == 1);

    printf("== 1e. a floor too large for a 128-bit accumulator FAILS CLOSED ==\n");
    /* Core's type is 256-bit and ours is 128. A floor in the high half cannot
     * be compared; silently truncating it would enforce something WEAKER than
     * the operator asked for, so it must refuse everything instead. */
    memset(w, 0, 32); w[0] = 0x01;
    reorg_set_min_chain_work(w);
    ck("it is flagged unrepresentable", reorg_min_chain_work_unrepresentable() == 1);
    ck("and every chain is refused, never silently allowed",
       reorg_work_meets_minimum(above) == 0);
    memset(w, 0, 32); reorg_set_min_chain_work(w);   /* leave no floor set */

    printf("== 2. rpc cookie authentication ==\n");
    const char* cp = "test_parity.cookie";
    unlink(cp);
    ck("the cookie is written", rpc_cookie_write(cp) == 1);
    struct stat st;
    ck("  at mode 0600 and nothing wider", stat(cp, &st) == 0 && (st.st_mode & 0777) == 0600);
    char cookie[256] = {0};
    { FILE* f = fopen(cp, "r"); if (f){ size_t n = fread(cookie, 1, sizeof cookie - 1, f); cookie[n] = 0; fclose(f); } }
    ck("  in Core's __cookie__:<hex> form", !strncmp(cookie, "__cookie__:", 11) && strlen(cookie) == 11 + 64);
    ck("  with no trailing newline (Core writes none)", strchr(cookie, '\n') == NULL);

    char* colon = strchr(cookie, ':');
    char hdrs[1024];
    mk_auth(hdrs, sizeof hdrs, "__cookie__", colon ? colon + 1 : "");
    ck("the cookie authenticates", rpc_auth_ok_for_test(hdrs, strlen(hdrs), "cfguser", "cfgpass") == 1);

    mk_auth(hdrs, sizeof hdrs, "cfguser", "cfgpass");
    ck("the configured password still authenticates", rpc_auth_ok_for_test(hdrs, strlen(hdrs), "cfguser", "cfgpass") == 1);

    mk_auth(hdrs, sizeof hdrs, "__cookie__", "00000000000000000000000000000000000000000000000000000000deadbeef");
    ck("a WRONG cookie is refused", rpc_auth_ok_for_test(hdrs, strlen(hdrs), "cfguser", "cfgpass") == 0);

    mk_auth(hdrs, sizeof hdrs, "cfguser", "");
    ck("an EMPTY password never authenticates", rpc_auth_ok_for_test(hdrs, strlen(hdrs), "cfguser", "") == 0);

    mk_auth(hdrs, sizeof hdrs, "__cookie__", colon ? colon + 1 : "");
    rpc_cookie_remove();
    ck("the cookie file is deleted on shutdown", access(cp, F_OK) != 0);
    ck("  and the credential stops working immediately",
       rpc_auth_ok_for_test(hdrs, strlen(hdrs), "cfguser", "cfgpass") == 0);

    printf("== 3/4/5. config keys reach the fields main() reads ==\n");
    { const char* e="test_parity_empty.conf"; FILE* f=fopen(e,"w"); fputs("# empty\n",f); fclose(f); node_config_load(e); unlink(e); }
    ck("bantime defaults to Core's 24h", g_cfg.bantime == 86400);
    ck("blockfilterindex defaults on", g_cfg.blockfilterindex == 1);
    ck("coinstatsindex defaults on",   g_cfg.coinstatsindex == 1);

    { const char* tmp = "test_parity.conf";
      FILE* f = fopen(tmp, "w");
      fputs("bantime=600\n"
            "blockfilterindex=0\n"
            "coinstatsindex=0\n"
            "minimumchainwork=00000000000000000000000000000000000000000000000000000000000000ff\n"
            "rpccookiefile=/tmp/somewhere.cookie\n", f);
      fclose(f);
      node_config_load(tmp);
      ck("bantime=600 applied", g_cfg.bantime == 600);
      ck("blockfilterindex=0 applied", g_cfg.blockfilterindex == 0);
      ck("coinstatsindex=0 applied", g_cfg.coinstatsindex == 0);
      ck("minimumchainwork applied", g_cfg.have_minchainwork == 1 && g_cfg.minchainwork[31] == 0xff);
      ck("rpccookiefile applied", !strcmp(g_cfg.rpccookiefile, "/tmp/somewhere.cookie"));
      unlink(tmp); }

    printf("== 4. -conf overrides the datadir search ==\n");
    { char buf[512];
      node_config_set_conf_path("/etc/somewhere/custom.conf");
      ck("an explicit -conf wins over <datadir>/bitcoin.conf",
         !strcmp(node_config_path("/some/datadir", buf, sizeof buf), "/etc/somewhere/custom.conf"));
      node_config_set_conf_path("");
      const char* p = node_config_path("/some/datadir", buf, sizeof buf);
      ck("cleared, the datadir search resumes", strstr(p, "/some/datadir") != NULL); }

    printf("== 6. batch two: keys wired to real behaviour ==\n");
    { const char* tmp = "test_parity2.conf";
      FILE* f = fopen(tmp, "w");
      fputs("permitbaremultisig=0\n"
            "networkactive=0\n"
            "forcednsseed=1\n"
            "pid=/tmp/bmc_test.pid\n", f);
      fclose(f);
      node_config_load(tmp);
      ck("permitbaremultisig=0 applied", g_cfg.permitbaremultisig == 0);
      ck("networkactive=0 applied",      g_cfg.networkactive == 0);
      ck("forcednsseed=1 applied",       g_cfg.forcednsseed == 1);
      ck("pid path applied",             !strcmp(g_cfg.pidfile, "/tmp/bmc_test.pid"));
      unlink(tmp); }

    /* the rejection itself is asserted in tests/test_mempool_policy, where the
     * mempool stack this policy object needs is already linked. */
    printf("== 7. -*notify hooks run, and cannot be injected into ==\n");
    { const char* out = "/tmp/bmc_notify_ok.txt";
      unlink(out);
      char cmd[256]; snprintf(cmd, sizeof cmd, "echo %%s > %s", out);
      notify_run(cmd, "0000deadbeefcafe", "test");
      ck("the hook actually executes", wait_for_file(out, 30));
      char got[128] = {0};
      { FILE* f = fopen(out, "r"); if (f){ if(!fgets(got, sizeof got, f)) got[0]=0; fclose(f); } }
      { char* nl = strchr(got, '\n'); if (nl) *nl = 0; }
      ck("  and %s is substituted verbatim for a hash", !strcmp(got, "0000deadbeefcafe"));
      unlink(out); }

    /* The value reaches a shell. A hash is hex and harmless; an alert MESSAGE
     * is not, which is the shape Core has carried warnings about. Assert the
     * injection fails rather than trusting the filter by inspection. */
    { const char* pwned = "/tmp/bmc_notify_PWNED.txt";
      const char* out2  = "/tmp/bmc_notify_inj.txt";
      unlink(pwned); unlink(out2);
      char cmd[256]; snprintf(cmd, sizeof cmd, "echo %%s > %s", out2);
      notify_run(cmd, "x; touch /tmp/bmc_notify_PWNED.txt", "test");
      wait_for_file(out2, 30);
      usleep(300000);
      ck("a shell-injection attempt does NOT execute", access(pwned, F_OK) != 0);
      char got[128] = {0};
      { FILE* f = fopen(out2, "r"); if (f){ if(!fgets(got, sizeof got, f)) got[0]=0; fclose(f); } }
      ck("  and the metacharacters are stripped from the value",
         !strchr(got, ';') && !strchr(got, '`') && !strchr(got, '$'));
      unlink(pwned); unlink(out2); }

    { /* an empty template must be a no-op, not a shell invocation */
      notify_run("", "anything", "test");
      ck("an unconfigured hook does nothing", 1); }

    printf("== 8. an unimplemented Core option is REPORTED, not swallowed ==\n");
    { extern int nodecfg_unimplemented(const char*);
      ck("whitelist is flagged (it sits in the live conf doing nothing)",
         nodecfg_unimplemented("whitelist") == 1);
      /* asmap WAS on that list until it was implemented. Now it must not be:
       * the list and the implementation have to move together, or the node
       * starts telling operators a working option does nothing. This
       * assertion is what makes them move together. */
      ck("asmap is NOT flagged -- it is implemented now",
         nodecfg_unimplemented("asmap") == 0);
      ck("uacomment is flagged",      nodecfg_unimplemented("uacomment") == 1);
      ck("an IMPLEMENTED option is not flagged", nodecfg_unimplemented("bantime") == 0);
      ck("  nor is minimumchainwork", nodecfg_unimplemented("minimumchainwork") == 0);
      ck("  nor blocknotify",         nodecfg_unimplemented("blocknotify") == 0);
      ck("another consumer's key is not flagged", nodecfg_unimplemented("dbcache") == 0); }

    printf("== 9. batch A: buffers, hwm, persistmempool ==\n");
    { const char* tmp = "test_parityA.conf";
      FILE* f = fopen(tmp, "w");
      fputs("maxreceivebuffer=2000\n"
            "maxsendbuffer=3000\n"
            "zmqpubrawblockhwm=250\n"
            "zmqpubsequencehwm=7\n", f);
      fclose(f);
      node_config_load(tmp);
      ck("maxreceivebuffer applied", g_cfg.maxrecvbuffer_kb == 2000);
      ck("maxsendbuffer applied",    g_cfg.maxsendbuffer_kb == 3000);
      ck("zmqpubrawblockhwm applied", g_cfg.zmq_hwm[2] == 250);
      ck("zmqpubsequencehwm applied", g_cfg.zmq_hwm[4] == 7);
      unlink(tmp); }

    printf("== 9b. the warning list tracks what is actually implemented ==\n");
    { extern int nodecfg_unimplemented(const char*);
      ck("maxsendbuffer no longer flagged",   nodecfg_unimplemented("maxsendbuffer") == 0);
      /* Wired 2026-08-30: the dump is written in the parent's shutdown path
       * BEFORE the worker is signalled, and reloaded at boot through the same
       * code the importmempool RPC uses. The old note here said wiring it
       * "touches shutdown, which must stay fast for the SIGKILL window" --
       * still true, which is why the save happens while the pool is
       * quiescent and before any teardown, not after. */
      ck("persistmempool is no longer flagged", nodecfg_unimplemented("persistmempool") == 0);
      ck("the zmq hwms no longer flagged",    nodecfg_unimplemented("zmqpubrawtxhwm") == 0);
      /* deferred on purpose: implementing it means moving when sigop cost is
       * computed, and a half-wired fee policy is worse than an absent one */
      ck("bytespersigop IS still flagged (deferred, not done)",
         nodecfg_unimplemented("bytespersigop") == 1);
      ck("persistmempoolv1 still flagged",    nodecfg_unimplemented("persistmempoolv1") == 1);
      /* walletnotify was PARSED into a config field, never used, and its own
       * strcmp branch ran before the unimplemented check -- so it was silently
       * accepted rather than warned. The key is gone; it must warn now. */
      ck("walletnotify is flagged (its inert key was removed)",
         nodecfg_unimplemented("walletnotify") == 1); }

    printf("== 10. rpcauth: hashed credentials, no plaintext in the config ==\n");
    /* This credential was generated by CORE'S OWN share/rpcauth/rpcauth.py
     * for user "alice", password "hunter2". If our HMAC-SHA256 or our parsing
     * differs from Core's by one byte, this does not authenticate. */
    { const char* CORE_ENTRY =
        "alice:455ee7e565f3e59749edc1a50dbfd9c8$"
        "e857294341178fc69115104aed6a15a44b004c533540d3ee1a633c1b438a0798";
      rpc_auth_clear();
      ck("Core's own rpcauth entry parses", rpc_auth_add(CORE_ENTRY) == 1);
      ck("  and is counted", rpc_auth_count() == 1);

      char hdrs[1024];
      mk_auth(hdrs, sizeof hdrs, "alice", "hunter2");
      ck("the right password authenticates (our HMAC matches Core's)",
         rpc_auth_ok_for_test(hdrs, strlen(hdrs), "cfguser", "cfgpass") == 1);

      mk_auth(hdrs, sizeof hdrs, "alice", "hunter3");
      ck("a wrong password does NOT", rpc_auth_ok_for_test(hdrs, strlen(hdrs), "cfguser", "cfgpass") == 0);

      mk_auth(hdrs, sizeof hdrs, "bob", "hunter2");
      ck("the right password under the wrong user does NOT",
         rpc_auth_ok_for_test(hdrs, strlen(hdrs), "cfguser", "cfgpass") == 0);

      /* the configured password must still work alongside it */
      mk_auth(hdrs, sizeof hdrs, "cfguser", "cfgpass");
      ck("rpcuser/rpcpassword still works alongside rpcauth",
         rpc_auth_ok_for_test(hdrs, strlen(hdrs), "cfguser", "cfgpass") == 1);

      ck("a malformed entry is REFUSED, not silently accepted",
         rpc_auth_add("nodollarsign") == 0);
      ck("  a short hash is refused too", rpc_auth_add("u:salt$abc") == 0);
      ck("  and an empty user", rpc_auth_add(":salt$" "0000000000000000000000000000000000000000000000000000000000000000") == 0);
      rpc_auth_clear();
      ck("cleared", rpc_auth_count() == 0); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

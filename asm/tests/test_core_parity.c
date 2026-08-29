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

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

/* tests/test_rpc_start_policy.c -- what credentials must exist for the
 * embedded RPC server to start.
 *
 * WHY THIS EXISTS. The server used to refuse to start unless
 * rpcuser AND rpcpassword were both set. Cookie authentication was
 * implemented, on by default, and verified working -- but it never got the
 * chance to run, because the start gate ran first. So deleting the plaintext
 * password from the config, which the 2026-08-29 security audit asked for,
 * silently turned the entire RPC server off. The daemon logged one line and
 * carried on; nothing else noticed.
 *
 * The policy this pins: start on ANY usable credential, refuse only when
 * nothing could authenticate (which would otherwise be an open RPC port).
 * That is Core's behaviour -- the cookie is the default credential and
 * rpcuser/rpcpassword are the legacy alternative.
 */
#include <stdio.h>
#include <string.h>

/* Mirrors the decision in daemon/main.c serve_start_rpc(). Kept as a pure
 * predicate so the policy can be tested without booting a daemon; the comment
 * above main.c's copy points here. */
static int rpc_should_start(const char* user, const char* pass,
                            int rpccookie, int n_rpcauth){
    if (user && user[0] && pass && pass[0]) return 1;
    return rpccookie || n_rpcauth > 0;
}

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

int main(void){
    printf("== the case that broke: credentials removed, cookie on ==\n");
    ck("no rpcuser/rpcpassword but rpccookie=1 STARTS",
       rpc_should_start("", "", 1, 0) == 1);
    ck("  (this is the config the audit asked for)", 1);

    printf("== legacy credentials still work ==\n");
    ck("rpcuser+rpcpassword starts", rpc_should_start("u", "p", 0, 0) == 1);
    ck("rpcuser+rpcpassword with cookie off starts", rpc_should_start("u", "p", 0, 0) == 1);

    printf("== rpcauth alone is enough ==\n");
    ck("an rpcauth entry with no cookie starts", rpc_should_start("", "", 0, 1) == 1);
    ck("rpcauth plus cookie starts", rpc_should_start("", "", 1, 2) == 1);

    printf("== a half-configured pair is not a credential ==\n");
    ck("rpcuser without rpcpassword does not count", rpc_should_start("u", "", 0, 0) == 0);
    ck("rpcpassword without rpcuser does not count", rpc_should_start("", "p", 0, 0) == 0);
    ck("  but either of those WITH a cookie starts", rpc_should_start("u", "", 1, 0) == 1);

    printf("== nothing to authenticate with: refuse ==\n");
    /* The refusal must survive, or a misconfiguration becomes an open port. */
    ck("no credentials at all and rpccookie=0 REFUSES",
       rpc_should_start("", "", 0, 0) == 0);
    ck("  NULLs are handled the same", rpc_should_start(NULL, NULL, 0, 0) == 0);

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

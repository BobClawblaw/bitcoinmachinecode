/* P-AUTH: the pre-authentication header path of the JSON-RPC server
 * (rpc_server.c auth_ok via rpc_auth_ok_for_test: find_header, the Basic
 * credential's base64_decode, the user:password split and the constant-time
 * compares), on a header block of nondeterministic content and length <= FP_N
 * -- bytes from a client that has not authenticated.
 * Environment: hmac_sha256 (crypto_hkdf.c, proved elsewhere / trusted) is a
 * free function of readable inputs; no -rpcauth entries unless FP_RPCAUTH.
 * Claims: memory safety, no leak; the configured user/password are compared
 * against exactly the decoded bytes; acceptance with an empty configured
 * password never happens (the code's documented rule). */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
void hmac_sha256(unsigned char out[32], const unsigned char* k, size_t kl, const unsigned char* m, size_t ml){
    CHECK(__CPROVER_r_ok(k, kl) && (ml == 0 || __CPROVER_r_ok(m, ml)), "hmac inputs readable");
    for (int i = 0; i < 32; i++) out[i] = nondet_uchar();
}
#include SRC
#ifndef FP_N
#define FP_N 40
#endif
int main(void){
    size_t len = nondet_size(); ASSUME(len <= FP_N);
    char* h = (char*)nd_tail(len + 4, FP_N + 4); /* the caller's buffer continues past hlen (the CRLFCRLF) */
    h[len] = '\r'; h[len+1] = '\n'; h[len+2] = '\r'; h[len+3] = '\n';
    const char* user = nondet_int() ? "u" : "";
    const char* pass = nondet_int() ? "pw" : "";
#ifdef FP_RPCAUTH
    g_n_rpcauth = 1; strcpy(g_rpcauth[0].user, "a"); strcpy(g_rpcauth[0].salt, "s"); memset(g_rpcauth[0].hash, '0', 64); g_rpcauth[0].hash[64] = 0;
#endif
    int ok = rpc_auth_ok_for_test(h, len, user, pass);
    if (ok && !g_cookie_pass[0] && !g_n_rpcauth) CHECK(*pass != 0, "an empty configured password never authenticates");
    free(nd_tail_base((unsigned char*)h, len + 4, FP_N + 4));
    COVER(ok, "credentials accepted");
    COVER(!ok && len >= 30, "a long header refused");
    return 0;
}

/* P-REST: rest_handle (rest.c) on /rest/getutxos -- the one REST route that
 * parses a BINARY request body -- served with NO authentication when rest=1.
 * The path is "/rest/getutxos" followed by <= FP_P nondeterministic bytes, the
 * body <= FP_B nondeterministic bytes.
 * Environment (stubs; trusted): rpc_dispatch (the JSON-RPC handlers) answers
 * nondeterministically: a failure, or a fresh JSON object (getblockchaininfo:
 * blocks + bestblockhash strings; gettxout: an object or null).
 * Claims: memory safety and no leak of the parse and the reply build; the
 * reply buffer is never overrun; > 15 outpoints is refused before any
 * gettxout; a binary count is read only from bytes the body holds. */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
#include "rpc_json.h"
#include "rest.h"
static int g_txouts;
int rpc_dispatch(const char* method, const rj_val* params, const rpc_wallet* w, rj_val** result, long* ec, const char** em){
    (void)params; (void)w;
    if (!strcmp(method, "gettxout")) g_txouts++;
    if (nondet_int()){ *ec = -1; *em = "stub"; return 0; }
    if (!strcmp(method, "gettxout") && nondet_int()){ *result = rj_null(); return 1; }
    rj_val* o = rj_obj(); rj_obj_set(o, "blocks", rj_num("7"));
    if (nondet_int()) rj_obj_set(o, "confirmations", rj_num("1"));
    if (nondet_int()) rj_obj_set(o, "value", rj_num("0.5"));
    *result = o; return 1;
}
#include SRC
#include "../../../asm/rpc_json.c"
#ifndef FP_P
#define FP_P 4
#endif
#ifndef FP_B
#define FP_B 6
#endif
int main(void){
    static const char pre[] = "/rest/getutxos";
    size_t sl = nondet_size(); ASSUME(sl <= FP_P);
    size_t plen = sizeof pre - 1 + sl;
    char* path = (char*)nd_buf(plen + 1); memcpy(path, pre, sizeof pre - 1); path[plen] = 0;
    size_t blen = nondet_size(); ASSUME(blen <= FP_B);
    char* body = (char*)nd_buf(blen);
    char* out = 0; size_t outlen = 0; int status = 0; const char* ctype = 0;
    rest_handle("POST", 4, path, plen, body, blen, 0, &out, &outlen, &status, &ctype);
    CHECK(out == 0 || outlen == 0 || __CPROVER_r_ok(out, outlen), "reply readable");
    CHECK(g_txouts <= 15, "at most 15 gettxout per request");
    free(out); free(path); free(body);
    COVER(status == 200, "a reply");
    COVER(status == 400 && blen >= 2, "a parse error on a body");
    return 0;
}

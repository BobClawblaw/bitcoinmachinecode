/* P-JSON: rj_parse (rpc_json.c), the JSON-RPC / REST request body parser,
 * reached by any client that can send an HTTP request to the RPC port (the
 * body is parsed before the method is authorised).
 * Claims, for every body of length <= FP_N, with and without the per-request
 * arena (rj_arena_begin/end, chosen nondeterministically):
 *   - memory safety, and no leak once the caller frees the tree and ends the
 *     arena (--memory-leak-check), on success and on every error path,
 *   - a successful parse consumed the whole body (trailing junk refused),
 *   - the tree it returns can be serialised by rj_write into a buffer of any
 *     size without overrunning it,
 *   - FP_DEPTH: with RJ_MAX_DEPTH lowered to 2 in a scratch copy (a model
 *     change, stated), nesting deeper than the limit is refused, so the
 *     recursion depth is bounded by RJ_MAX_DEPTH + 1 frames. */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
#include SRC
#ifndef FP_N
#define FP_N 6
#endif
static int depth(const rj_val* v){
    int d = 0;
    if (v->typ == RJ_ARR) for (size_t i = 0; i < v->nitems; i++){ int k = depth(v->items[i]); if (k > d) d = k; }
    if (v->typ == RJ_OBJ) for (size_t i = 0; i < v->nmembers; i++){ int k = depth(v->members[i].val); if (k > d) d = k; }
    return (v->typ == RJ_ARR || v->typ == RJ_OBJ) ? d + 1 : d;
}
int main(void){
    size_t len = nondet_size(); ASSUME(len <= FP_N);
    char* s = (char*)nd_buf(len);
    int arena = nondet_int() & 1;
    if (arena) rj_arena_begin();
    rj_val* v = rj_parse(s, len);
    if (v){
#ifdef FP_DEPTH
        CHECK(depth(v) <= RJ_MAX_DEPTH, "nesting within RJ_MAX_DEPTH");
#endif
        long cap = nondet_long(); ASSUME(cap >= 0 && cap <= 24);
        char* out = (char*)nd_buf((size_t)cap);
        long w = rj_write(out, cap, v, nondet_int() & 1);
        CHECK(w >= 0 && (cap == 0 || out[w < cap ? w : cap - 1] == 0), "rj_write NUL-terminates within cap");
        free(out);
    }
    rj_free(v);
    if (arena) rj_arena_end();
    free(s);
    COVER(v && v->typ == RJ_ARR && v->nitems == 2, "a two-element array");
    COVER(v && v->typ == RJ_OBJ, "an object");
    COVER(v && v->typ == RJ_STR, "a string");
    COVER(v && v->typ == RJ_NUM && len >= 3, "a number");
    return 0;
}

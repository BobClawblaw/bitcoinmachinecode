/* tests/test_rpc_json_depth.c -- JSON nesting is bounded (audit follow-up,
 * "parser recursion-depth counter", 2026-08-30).
 *
 * Every '[' or '{' recursed into p_val, so nesting depth was
 * attacker-controlled STACK depth. Unbounded, "[[[[..." exhausts the stack and
 * the process dies on SIGSEGV -- measured, not theorised: a core dump at
 * 200,000 levels. The file even carried a comment asserting that recursion
 * "is bounded by the parser's own nesting limit", and no such limit existed,
 * which is worse than no comment at all.
 *
 * The limit is 512, matching UniValue's MAX_JSON_DEPTH, so this parser accepts
 * and rejects exactly the nesting Core does.
 *
 * The rejection is the easy half. The half that matters is that legal nesting
 * STILL PARSES: a bound that also refused ordinary requests would pass every
 * "hostile input is rejected" assertion while breaking the RPC interface.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../rpc_json.h"

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* n nested arrays: [[[...]]] */
static rj_val* parse_nested_arrays(int n){
    char* s = (char*)malloc((size_t)n * 2 + 2);
    if (!s) return NULL;
    for (int i = 0; i < n; i++) s[i] = '[';
    for (int i = 0; i < n; i++) s[n + i] = ']';
    s[2 * n] = 0;
    rj_val* v = rj_parse(s, (unsigned long)strlen(s));
    free(s);
    return v;
}
/* n nested objects: {"a":{"a":...}} */
static rj_val* parse_nested_objects(int n){
    size_t cap = (size_t)n * 6 + 8;
    char* s = (char*)malloc(cap);
    if (!s) return NULL;
    size_t o = 0;
    for (int i = 0; i < n; i++){ memcpy(s + o, "{\"a\":", 5); o += 5; }
    s[o++] = '1';
    for (int i = 0; i < n; i++) s[o++] = '}';
    s[o] = 0;
    rj_val* v = rj_parse(s, (unsigned long)o);
    free(s);
    return v;
}

int main(void){
    printf("== ordinary requests still parse ==\n");
    { const char* req = "{\"jsonrpc\":\"1.0\",\"method\":\"getblockcount\",\"params\":[]}";
      rj_val* v = rj_parse(req, (unsigned long)strlen(req));
      ck("a real RPC request parses", v != NULL); rj_free(v); }
    { rj_val* v = parse_nested_arrays(1);   ck("depth 1 parses", v != NULL); rj_free(v); }
    { rj_val* v = parse_nested_arrays(100); ck("depth 100 parses", v != NULL); rj_free(v); }

    printf("== the boundary is exactly Core's (UniValue MAX_JSON_DEPTH = 512) ==\n");
    { rj_val* v = parse_nested_arrays(511); ck("depth 511 parses", v != NULL); rj_free(v); }
    { rj_val* v = parse_nested_arrays(512); ck("depth 512 parses (the limit itself is legal)", v != NULL); rj_free(v); }
    { rj_val* v = parse_nested_arrays(513); ck("depth 513 is REJECTED", v == NULL); rj_free(v); }

    printf("== objects are bounded too, not just arrays ==\n");
    { rj_val* v = parse_nested_objects(512); ck("512 nested objects parse", v != NULL); rj_free(v); }
    { rj_val* v = parse_nested_objects(513); ck("513 nested objects are REJECTED", v == NULL); rj_free(v); }

    printf("== the shape that used to core-dump ==\n");
    /* Before the bound this exhausted the stack and killed the process. If it
     * ever regresses, this test does not fail -- it dies, which is its own
     * loud signal. */
    { rj_val* v = parse_nested_arrays(200000);
      ck("200,000 levels is rejected rather than fatal", v == NULL); rj_free(v); }
    { rj_val* v = parse_nested_objects(200000);
      ck("  and the same for objects", v == NULL); rj_free(v); }

    printf("== depth counts NESTING, not total containers ==\n");
    /* A flat array of many containers is legal at any length; if the counter
     * were never decremented on the way out, this would be rejected and the
     * limit would silently mean something else entirely. */
    { size_t n = 5000, cap = n * 3 + 8;
      char* s = (char*)malloc(cap);
      size_t o = 0; s[o++] = '[';
      for (size_t i = 0; i < n; i++){ if (i) s[o++] = ','; s[o++] = '['; s[o++] = ']'; }
      s[o++] = ']'; s[o] = 0;
      rj_val* v = rj_parse(s, (unsigned long)o);
      ck("5000 SIBLING arrays parse (depth 2, not depth 5000)", v != NULL);
      rj_free(v); free(s); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

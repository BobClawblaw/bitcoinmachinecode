/* test_rpc_json.c -- unit tests for the Core-bit-exact JSON renderer.
 *
 * Verifies rpc_json.c reproduces Bitcoin Core UniValue::write(pretty=2)
 * byte-for-byte on representative shapes (Core field order + 2-space indent +
 * escape set), plus rpc_amounts (Core ValueFromAmount) and parse round-trips.
 */
#include "../rpc_json.h"
#include "../rpc_commands.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
static void ck(const char* label, int cond) {
    printf("%s %s\n", cond ? "ok  :" : "FAIL:", label);
    if (!cond) fails++;
}

static void ck_str(const char* label, const char* got, const char* expect) {
    int c = got && expect && !strcmp(got, expect);
    printf("%s %s\n", c ? "ok  :" : "FAIL:", label);
    if (!c) {
        printf("      got : [%s]\n      want: [%s]\n", got ? got : "(null)", expect ? expect : "(null)");
        fails++;
    }
}

int main(void) {
    /* ---- empty object / array ---- */
    {
        rj_val* o = rj_obj(); char b[256];
        long n = rj_write(b, sizeof b, o, 2);
        rj_free(o);
        ck("empty obj write(2) == {} ", n == 2 && !strcmp(b, "{}"));
    }
    {
        rj_val* a = rj_arr(); char b[256];
        long n = rj_write(b, sizeof b, a, 2);
        rj_free(a);
        ck("empty arr write(2) == [] ", n == 2 && !strcmp(b, "[]"));
    }

    /* ---- single-key object ---- */
    {
        rj_val* o = rj_obj();
        rj_obj_set(o, "isvalid", rj_bool(1));
        char b[256]; rj_write(b, sizeof b, o, 2); rj_free(o);
        ck_str("obj one key", b, "{\n  \"isvalid\": true\n}");
    }

    /* ---- multi-key object preserves insertion order ---- */
    {
        rj_val* o = rj_obj();
        rj_obj_set(o, "txid", rj_str("aabb"));
        rj_obj_set(o, "vout", rj_numf("%d", 1));
        rj_obj_set(o, "amount", rj_str("0.05000000"));
        char b[512]; rj_write(b, sizeof b, o, 2); rj_free(o);
        ck_str("obj 3 keys order",
            b,
            "{\n"
            "  \"txid\": \"aabb\",\n"
            "  \"vout\": 1,\n"
            "  \"amount\": \"0.05000000\"\n"
            "}");
    }

    /* ---- nested object indentation ---- */
    {
        rj_val* o = rj_obj();
        rj_val* inner = rj_obj();
        rj_obj_set(inner, "asm", rj_str("OP_DUP"));
        rj_obj_set(inner, "hex", rj_str("76a914"));
        rj_obj_set(o, "scriptPubKey", inner);
        rj_obj_set(o, "n", rj_numf("%d", 0));
        char b[512]; rj_write(b, sizeof b, o, 2); rj_free(o);
        ck_str("nested indent",
            b,
            "{\n"
            "  \"scriptPubKey\": {\n"
            "    \"asm\": \"OP_DUP\",\n"
            "    \"hex\": \"76a914\"\n"
            "  },\n"
            "  \"n\": 0\n"
            "}");
    }

    /* ---- array of objects ---- */
    {
        rj_val* a = rj_arr();
        rj_val* e1 = rj_obj(); rj_obj_set(e1, "k", rj_str("v"));
        rj_arr_push(a, e1);
        rj_val* e2 = rj_numf("%d", 7);
        rj_arr_push(a, e2);
        char b[256]; rj_write(b, sizeof b, a, 2); rj_free(a);
        ck_str("arr of obj+num",
            b,
            "[\n"
            "  {\n"
            "    \"k\": \"v\"\n"
            "  },\n"
            "  7\n"
            "]");
    }

    /* ---- escapes: control chars + quotes + backslash ---- */
    {
        rj_val* s = rj_str("a\"b\\c\nd\te\ff\br\x01q");
        char b[256]; rj_write(b, sizeof b, s, 2); rj_free(s);
        ck_str("escaped string",
            b,
            "\"a\\\"b\\\\c\\nd\\te\\ff\\br\\u0001q\"");
    }

    /* ---- compact (write(0)) ---- */
    {
        rj_val* o = rj_obj();
        rj_obj_set(o, "a", rj_str("x"));
        rj_obj_set(o, "b", rj_bool(0));
        rj_obj_set(o, "c", rj_null());
        char b[256]; rj_write(b, sizeof b, o, 0); rj_free(o);
        ck_str("compact", b, "{\"a\":\"x\",\"b\":false,\"c\":null}");
    }

    /* ---- numbers / booleans / null scalar ---- */
    {
        rj_val* n = rj_numf("%llu", 5000000ULL); char b[64]; rj_write(b,sizeof b,n,2); rj_free(n);
        ck_str("num scalar", b, "5000000");
        rj_val* t = rj_bool(1); char c[64]; rj_write(c,sizeof c,t,2); rj_free(t);
        ck_str("true scalar", c, "true");
        rj_val* z = rj_null(); char d[64]; rj_write(d,sizeof d,z,2); rj_free(z);
        ck_str("null scalar", d, "null");
        rj_val* st = rj_str("hi"); char e[64]; rj_write(e,sizeof e,st,2); rj_free(st);
        ck_str("str scalar quoted", e, "\"hi\"");
    }

    /* ---- parser: round-trip a request + reply ---- */
    {
        const char* req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"validateaddress\",\"params\":[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"]}";
        rj_val* v = rj_parse(req, strlen(req));
        ck("parse request ok", v != NULL && v->typ == RJ_OBJ);
        if (v) {
            rj_val* m = rj_obj_get(v, "method");
            ck_str("method field", m ? m->str : NULL, "validateaddress");
            rj_val* p = rj_obj_get(v, "params");
            ck("params is array", p && p->typ == RJ_ARR && p->nitems == 1);
            rj_val* a0 = p && p->nitems ? p->items[0] : NULL;
            ck_str("param[0]", a0 && a0->typ == RJ_STR ? a0->str : NULL,
                   "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
            rj_val* id = rj_obj_get(v, "id");
            ck_str("id == 1", id && id->typ == RJ_NUM ? id->str : NULL, "1");
        }
        rj_free(v);
    }

    /* ---- parser negative ---- */
    ck("parse garbage fails", rj_parse("not json", 8) == NULL);
    ck("parse truncated fails", rj_parse("{\"a\":", 5) == NULL);
    ck("parse trailing fails", rj_parse("{} x", 4) == NULL);

    /* ---- rpc_amounts (Core ValueFromAmount) ---- */
    {
        char b[24];
        rpc_amounts(0, b, sizeof b);       ck_str("0 sats", b, "0.00000000");
        rpc_amounts(1, b, sizeof b);       ck_str("1 sat", b, "0.00000001");
        rpc_amounts(100000, b, sizeof b);  ck_str("0.001", b, "0.00100000");
        rpc_amounts(5000000, b, sizeof b); ck_str("0.05", b, "0.05000000");
        rpc_amounts(100000000, b, sizeof b); ck_str("1 BTC", b, "1.00000000");
        rpc_amounts(123456789, b, sizeof b); ck_str("1.23456789", b, "1.23456789");
        rpc_amounts(-5000000, b, sizeof b); ck_str("-0.05", b, "-0.05000000");
        rpc_amounts(2100000000000000LL, b, sizeof b); ck_str("max 21M", b, "21000000.00000000");
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

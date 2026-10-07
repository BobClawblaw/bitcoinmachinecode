/* test_rpc_json.c -- unit tests for the Core-bit-exact JSON renderer.
 *
 * Verifies rpc_json.c reproduces Bitcoin Core UniValue::write(pretty=2)
 * byte-for-byte on representative shapes (Core field order + 2-space indent +
 * escape set), plus rpc_amounts (Core ValueFromAmount) and parse round-trips.
 */
#include "../rpc_json.h"
#include "../rpc_commands.h"
#include <stdio.h>
#include <stdlib.h>
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

/* a sink for rj_write_to: collects what it is handed, counts the calls, and
 * fails from the fail_at'th call on (0 = never) */
typedef struct { char* b; size_t n, cap; long calls, fail_at; } sink_t;
static int sink_put(void* ctx, const char* p, size_t n){
    sink_t* k = (sink_t*)ctx;
    k->calls++;
    if (k->fail_at && k->calls >= k->fail_at) return -1;
    if (k->n + n + 1 > k->cap){ k->cap = (k->n + n + 1) * 2; k->b = realloc(k->b, k->cap); }
    memcpy(k->b + k->n, p, n); k->n += n; k->b[k->n] = 0;
    return 0;
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

    /* ---- rj_clone: a DEEP copy, independently freeable ----------------
     * Added for signrawtransactionwithwallet, which forwards a params array
     * it does not own into one it does. A shallow copy there would free the
     * caller's request nodes -- a use-after-free the caller could not see. */
    {
        const char* src = "{\"a\":[1,\"two\",{\"b\":true},null],\"c\":{\"d\":-3.5}}";
        rj_val* o = rj_parse(src, strlen(src));
        rj_val* c = rj_clone(o);
        char b1[512], b2[512];
        rj_write(b1, sizeof b1, o, 0);
        rj_write(b2, sizeof b2, c, 0);
        ck_str("rj_clone round-trips a nested value byte-for-byte", b2, b1);
        /* free the SOURCE first, then read the clone: if the copy were
         * shallow this is exactly where it would read freed memory. */
        rj_free(o);
        rj_write(b2, sizeof b2, c, 0);
        ck_str("the clone survives its source being freed", b2, b1);
        ck("cloned object keeps its members", rj_obj_get(c, "a") != NULL);
        ck("cloned array keeps its length", rj_obj_get(c, "a")->nitems == 4);
        rj_free(c);
        ck("rj_clone(NULL) is NULL, not a crash", rj_clone(NULL) == NULL);
    }

    /* ---- RPC-11 (audit 2026-09-03): DEL is escaped ----
     * rj_append_escaped handled the named escapes and bytes < 0x20 but
     * emitted 0x7f raw. UniValue's generated table has
     * escapes['\x7f'] = "\\u007f", so Core escapes it. Reachable through
     * operator-supplied strings such as labels and comments.
     *
     * The control is the pair: 0x7e must stay RAW. An implementation that
     * escaped everything >= 0x7e would pass a DEL-only test while mangling
     * ordinary printable output. */
    {
        rj_val* o = rj_obj();
        rj_obj_set(o, "label", rj_str("a\x7f" "b"));
        char b[256]; rj_write(b, sizeof b, o, 2); rj_free(o);
        ck_str("RPC-11 DEL is escaped as \\u007f", b, "{\n  \"label\": \"a\\u007fb\"\n}");
    }
    {
        rj_val* o = rj_obj();
        rj_obj_set(o, "label", rj_str("a\x7e" "b"));
        char b[256]; rj_write(b, sizeof b, o, 2); rj_free(o);
        ck_str("RPC-11 0x7e (~) stays raw", b, "{\n  \"label\": \"a~b\"\n}");
    }

    /* ---- RPC-7 (audit 2026-09-03): the parser was laxer than UniValue ----
     * Bodies Core rejects with -32700 were dispatched here and produced
     * method-level errors instead, so error-code fidelity diverged on exactly
     * the inputs a client uses to detect malformed JSON.
     *
     * (a) a raw byte below 0x20 inside a string -- UniValue's getJsonToken
     *     returns JTOK_ERR; this passed it straight through.
     * (d) the number grammar: `-` alone passed (the sign consume alone made
     *     p != start), and so did `01`, `1.` and `1e`.
     *
     * Every case is paired with its legal twin, so a parser that simply got
     * stricter fails too: the ESCAPED control characters must still parse, and
     * 0, -0, 1.0 and 1e5 are all valid JSON. */
    {
        { const char* j = "[\"a\x01" "b\"]";
          ck("RPC-7 a raw control byte in a string is refused", rj_parse(j, strlen(j)) == NULL); }
        { const char* j = "[\"a\x1f" "b\"]";
          ck("RPC-7 a raw NUL-adjacent byte (0x1f) is refused", rj_parse(j, strlen(j)) == NULL); }
        { const char* j = "[\"a\\nb\"]"; rj_val* v = rj_parse(j, strlen(j));
          ck("RPC-7   ...but the ESCAPED form still parses", v != NULL);
          rj_free(v); }
        { const char* j = "[\"a\\u0009b\"]"; rj_val* v = rj_parse(j, strlen(j));
          ck("RPC-7   ...and so does \\u0009", v != NULL);
          rj_free(v); }

        ck("RPC-7 a bare minus is not a number", rj_parse("[-]", 3) == NULL);
        ck("RPC-7 a leading zero is refused (01)", rj_parse("[01]", 4) == NULL);
        ck("RPC-7 a trailing decimal point is refused (1.)", rj_parse("[1.]", 4) == NULL);
        ck("RPC-7 an empty exponent is refused (1e)", rj_parse("[1e]", 4) == NULL);
        ck("RPC-7 an empty signed exponent is refused (1e+)", rj_parse("[1e+]", 5) == NULL);

        { const char* j = "[0,-0,1.0,1e5,-1.5e-3,10]"; rj_val* v = rj_parse(j, strlen(j));
          ck("RPC-7   ...but every legal number still parses",
             v != NULL && v->typ == RJ_ARR && v->nitems == 6);
          rj_free(v); }
    }

    /* ---- 2026-10-06 (plan A5): the span escaper, the hand formatter, rj_hex,
     * the member operations and the request arena. Each pinned against a
     * reference written here from the previous byte-at-a-time code. ---- */
    {
        /* the escaper: every byte value, alone and inside a run, renders as
         * the reference escapeStringBN did */
        int all = 1; char bad = 0;
        for (int b = 1; b < 256 && all; b++){
            char s[8] = { 'x', (char)b, 'y', (char)b, 0 };
            rj_val* v = rj_str(s); char got[64]; long n = rj_write(got, sizeof got, v, 0); rj_free(v);
            char want[64]; size_t wl = 0; want[wl++] = '"';
            for (int k = 0; k < 2; k++){
                want[wl++] = k ? 'y' : 'x';
                const char* e = b == '"' ? "\\\"" : b == '\\' ? "\\\\" : b == '\b' ? "\\b" : b == '\f' ? "\\f" : b == '\n' ? "\\n" : b == '\r' ? "\\r" : b == '\t' ? "\\t" : NULL;
                if (e){ memcpy(want + wl, e, strlen(e)); wl += strlen(e); }
                else if (b < 0x20 || b == 0x7f){ wl += (size_t)sprintf(want + wl, "\\u%04x", b); }
                else want[wl++] = (char)b;
            }
            want[wl++] = '"'; want[wl] = 0;
            if (n != (long)wl || memcmp(got, want, wl) != 0){ all = 0; bad = (char)b; }
        }
        ck("A5 the span escaper renders every byte value as the reference did", all);
        if (!all) printf("      first differing byte: 0x%02x\n", (unsigned char)bad);
        { char big[4000]; for (int i = 0; i < 3999; i++) big[i] = (char)('a' + i % 26); big[3999] = 0; big[1000] = '"'; big[2000] = '\n'; big[3000] = 0x7f;
          rj_val* v = rj_str(big); long len = 0; char* out = rj_write_alloc(v, 0, &len); rj_free(v);
          char want[4100]; size_t wl = 0; want[wl++] = '"';
          for (int i = 0; i < 3999; i++){ unsigned char c = (unsigned char)big[i];
              if (c == '"'){ want[wl++] = '\\'; want[wl++] = '"'; } else if (c == '\n'){ want[wl++] = '\\'; want[wl++] = 'n'; }
              else if (c == 0x7f){ wl += (size_t)sprintf(want + wl, "\\u%04x", c); } else want[wl++] = (char)c; }
          want[wl++] = '"'; want[wl] = 0;
          ck("A5 ...and a 4,000-byte string with escapes inside long spans (the buffer grows across spans)", len == (long)wl && memcmp(out, want, wl) == 0);
          free(out); }

        /* the hand formatter: the seven formats against printf */
        { int ok = 1; char want[64];
          long long sv[] = { 0, 1, -1, 7, -7, 9, 10, -10, 123456789, -123456789, 2147483647LL, -2147483647LL - 1, 9223372036854775807LL, -9223372036854775807LL - 1 };
          for (size_t i = 0; i < sizeof sv / sizeof sv[0] && ok; i++){
              rj_val* a = rj_numf("%lld", sv[i]); snprintf(want, sizeof want, "%lld", sv[i]); if (strcmp(a->str, want)) ok = 0; rj_free(a);
              rj_val* b = rj_numf("%ld", (long)sv[i]); snprintf(want, sizeof want, "%ld", (long)sv[i]); if (strcmp(b->str, want)) ok = 0; rj_free(b);
              rj_val* c = rj_numf("%d", (int)sv[i]); snprintf(want, sizeof want, "%d", (int)sv[i]); if (strcmp(c->str, want)) ok = 0; rj_free(c);
          }
          unsigned long long uv[] = { 0, 1, 9, 10, 4294967295ULL, 4294967296ULL, 18446744073709551615ULL };
          for (size_t i = 0; i < sizeof uv / sizeof uv[0] && ok; i++){
              rj_val* a = rj_numf("%llu", uv[i]); snprintf(want, sizeof want, "%llu", uv[i]); if (strcmp(a->str, want)) ok = 0; rj_free(a);
              rj_val* b = rj_numf("%lu", (unsigned long)uv[i]); snprintf(want, sizeof want, "%lu", (unsigned long)uv[i]); if (strcmp(b->str, want)) ok = 0; rj_free(b);
              rj_val* c = rj_numf("%zu", (size_t)uv[i]); snprintf(want, sizeof want, "%zu", (size_t)uv[i]); if (strcmp(c->str, want)) ok = 0; rj_free(c);
              rj_val* d = rj_numf("%u", (unsigned)uv[i]); snprintf(want, sizeof want, "%u", (unsigned)uv[i]); if (strcmp(d->str, want)) ok = 0; rj_free(d);
          }
          ck("A5 rj_numf's hand formatter prints %lld/%ld/%d/%llu/%lu/%zu/%u as printf does (zero, signs, both limits)", ok);
          rj_val* f = rj_numf("%.8f", 1.5); ck("A5 ...and any other format still goes through printf", !strcmp(f->str, "1.50000000")); rj_free(f);
          rj_val* g = rj_numf("%llu.%08llu", 3ULL, 5ULL); ck("A5 ...including the amount shape", !strcmp(g->str, "3.00000005")); rj_free(g); }

        /* rj_hex */
        { unsigned char b[256]; for (int i = 0; i < 256; i++) b[i] = (unsigned char)i;
          rj_val* v = rj_hex(b, 256); int ok = v->typ == RJ_STR && strlen(v->str) == 512;
          for (int i = 0; i < 256 && ok; i++){ char w[3]; snprintf(w, 3, "%02x", i); if (memcmp(v->str + 2 * i, w, 2)) ok = 0; }
          ck("A5 rj_hex encodes every byte as two lowercase digits in place", ok); rj_free(v);
          rj_val* e = rj_hex(b, 0); ck("A5 ...and zero bytes is the empty string", e->typ == RJ_STR && e->str[0] == 0); rj_free(e); }

        /* rj_obj_del / rj_obj_splice */
        { rj_val* o = rj_obj(); rj_obj_set(o, "a", rj_num("1")); rj_obj_set(o, "hex", rj_str("ff")); rj_obj_set(o, "b", rj_num("2"));
          char buf[128]; rj_write(buf, sizeof buf, o, 0);
          ck("A5 rj_obj_del removes the member and keeps the order", rj_obj_del(o, "hex") == 1 && (rj_write(buf, sizeof buf, o, 0), !strcmp(buf, "{\"a\":1,\"b\":2}")));
          ck("A5 ...and answers 0 for a key that is not there", rj_obj_del(o, "hex") == 0 && o->nmembers == 2);
          rj_val* t = rj_obj(); rj_obj_set(t, "c", rj_num("3")); rj_obj_set(t, "d", rj_str("x"));
          rj_obj_splice(o, t);
          rj_write(buf, sizeof buf, o, 0);
          ck("A5 rj_obj_splice appends the source's members in order and consumes it", !strcmp(buf, "{\"a\":1,\"b\":2,\"c\":3,\"d\":\"x\"}"));
          rj_free(o); }

        /* the request arena */
        ck("A5 no arena before begin", !rj_arena_active() && rj_arena_bytes() == -1);
        rj_val* foreign = rj_arr(); for (int i = 0; i < 3; i++) rj_arr_push(foreign, rj_numf("%d", i));
        rj_arena_begin();
        ck("A5 begin: the arena is active and empty", rj_arena_active() && rj_arena_bytes() == 0);
        rj_val* o = rj_obj(); rj_obj_set(o, "k", rj_str("v")); rj_obj_set(o, "n", rj_numf("%d", 42));
        ck("A5 a value built under the arena is the arena's (the value, its string, its members)",
           rj_arena_owns(o) && rj_arena_owns(o->members) && rj_arena_owns(o->members[0].key) && rj_arena_owns(o->members[0].val) && rj_arena_owns(o->members[0].val->str));
        ck("A5 ...and the foreign value built before begin is not", !rj_arena_owns(foreign) && !rj_arena_owns(foreign->items));
        { char buf[128]; rj_write(buf, sizeof buf, o, 0); ck("A5 ...it renders the same", !strcmp(buf, "{\"k\":\"v\",\"n\":42}")); }
        long before = rj_arena_bytes(); rj_free(o);
        ck("A5 rj_free of an arena value is a no-op (the arena's size is unchanged)", rj_arena_bytes() == before && rj_arena_owns(o));
        { rj_val* a = rj_arr(); for (int i = 0; i < 5000; i++) rj_arr_push(a, rj_numf("%d", i));
          int ok = a->nitems == 5000; for (int i = 0; i < 5000 && ok; i++){ char w[16]; snprintf(w, 16, "%d", i); if (strcmp(a->items[i]->str, w)) ok = 0; }
          ck("A5 an array grown to 5,000 items under the arena (in-place extends and copies) keeps every item", ok && rj_arena_owns(a->items)); }
        { for (int i = 3; i < 40; i++) rj_arr_push(foreign, rj_numf("%d", i));
          int ok = foreign->nitems == 40; for (int i = 0; i < 40 && ok; i++){ char w[16]; snprintf(w, 16, "%d", i); if (strcmp(foreign->items[i]->str, w)) ok = 0; }
          ck("A5 a foreign array grown under the arena is copied in and keeps its items", ok && rj_arena_owns(foreign->items)); }
        { const char* j = "{\"method\":\"getblock\",\"params\":[\"ab\",2]}"; rj_val* v = rj_parse(j, strlen(j));
          ck("A5 the parser's output lives in the arena too", v && rj_arena_owns(v) && rj_arena_owns(rj_obj_get(v, "method")->str)); rj_free(v); }
        rj_arena_begin(); rj_arena_end();
        ck("A5 a nested begin/end pair does not release the outer arena", rj_arena_active() && rj_arena_bytes() > before);
        { rj_val* big = rj_arr(); for (int i = 0; i < 20000; i++) rj_arr_push(big, rj_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
          ck("A5 a 20,000-string array spans several chunks and every string is owned", rj_arena_bytes() > (1L << 20) && rj_arena_owns(big->items[19999]->str)); }
        /* a foreign value freed UNDER the arena frees its own parts and
         * skips the arena's (its item array and the items pushed under the
         * arena are the arena's now); nothing built under an arena may be
         * touched after the end, so this happens before it */
        rj_free(foreign);
        rj_arena_end();
        ck("A5 end: the arena is gone", !rj_arena_active() && rj_arena_bytes() == -1);
        { rj_val* after = rj_obj(); ck("A5 after the end values are malloc'd again (not owned by any arena)", !rj_arena_owns(after)); rj_free(after); }
    }

    /* ---- frozen values (rj_freeze / RJ_RAW, 2026-10-06): verbose
     * getrawmempool keeps each entry's text, not its tree ---- */
    {
        const char* ej = "{\"vsize\":141,\"fees\":{\"base\":0.00000282,\"ancestor\":0.00000282},"
                         "\"depends\":[\"aa\"],\"spentby\":[],\"bip125-replaceable\":false,\"s\":\"q\\\"\\n\"}";
        for (int arena = 0; arena < 2; arena++){
            const char* tag = arena ? "under the arena" : "without an arena";
            char what[160];
            if (arena) rj_arena_begin();
            rj_val* parent = rj_obj();
            rj_obj_set(parent, "first", rj_num("1"));
            rj_val* ref = rj_parse(ej, strlen(ej));
            char want_c[512], want_p[1024]; rj_write(want_c, sizeof want_c, ref, 0); rj_write(want_p, sizeof want_p, ref, 2);
            long b0 = rj_arena_bytes();
            rj_mark mk = rj_arena_mark();
            rj_val* tree = rj_parse(ej, strlen(ej));       /* stands in for an entry built after the mark */
            rj_val* fz = rj_freeze(tree, mk);
            snprintf(what, sizeof what, "freeze %s: an RJ_RAW holding the compact text", tag);
            ck(what, fz && fz->typ == RJ_RAW && !strcmp(fz->str, want_c));
            if (arena){
                ck("freeze under the arena: the tree's bytes are given back (only the text and its shell remain)",
                   rj_arena_bytes() - b0 < (long)strlen(want_c) + 128);
            }
            rj_obj_set(parent, "e", fz);
            rj_obj_set(parent, "last", rj_num("2"));
            char got[1024], wantall[1024];
            snprintf(wantall, sizeof wantall, "{\"first\":1,\"e\":%s,\"last\":2}", want_c);
            rj_write(got, sizeof got, parent, 0);
            snprintf(what, sizeof what, "freeze %s: the parent renders byte-identical (compact)", tag);
            ck(what, !strcmp(got, wantall));
            { rj_val* pref = rj_obj(); rj_obj_set(pref, "first", rj_num("1")); rj_obj_set(pref, "e", rj_clone(ref)); rj_obj_set(pref, "last", rj_num("2"));
              char wp[2048], gp[2048]; rj_write(wp, sizeof wp, pref, 2); rj_write(gp, sizeof gp, parent, 2);
              snprintf(what, sizeof what, "freeze %s: ...and pretty, re-rendered at its depth", tag);
              ck(what, !strcmp(wp, gp)); rj_free(pref); }
            { rj_val* cl = rj_clone(fz); char c1[512]; rj_write(c1, sizeof c1, cl, 0);
              snprintf(what, sizeof what, "freeze %s: a clone stays frozen and renders the same", tag);
              ck(what, cl && cl->typ == RJ_RAW && !strcmp(c1, want_c)); rj_free(cl); }
            ck("rj_type_name of a frozen object is \"object\"", !strcmp(rj_type_name(fz), "object"));
            { rj_val* vs = rj_obj_get(fz, "vsize"); rj_val* fees = rj_obj_get(fz, "fees");
              rj_val* base = fees ? rj_obj_get(fees, "base") : NULL;
              snprintf(what, sizeof what, "freeze %s: rj_obj_get expands it in place and finds the members", tag);
              ck(what, fz->typ == RJ_OBJ && vs && !strcmp(vs->str, "141") && base && !strcmp(base->str, "0.00000282")); }
            rj_write(got, sizeof got, parent, 0);
            snprintf(what, sizeof what, "freeze %s: ...and the expanded value still renders the same", tag);
            ck(what, !strcmp(got, wantall));
            rj_free(ref); rj_free(parent);
            if (arena) rj_arena_end();
        }
        /* a rewind across a chunk boundary: the chunks the tree opened are freed */
        rj_arena_begin();
        { rj_val* keep = rj_arr(); rj_arr_push(keep, rj_str("kept"));
          long b0 = rj_arena_bytes(); rj_mark mk = rj_arena_mark();
          rj_val* big = rj_arr(); for (int i = 0; i < 20000; i++) rj_arr_push(big, rj_str("0123456789abcdef0123456789abcdef"));
          int spanned = rj_arena_bytes() - b0 > (1L << 20);
          rj_val* fz = rj_freeze(big, mk);
          ck("freeze: a tree spanning several arena chunks is rewound to the mark", spanned && fz && fz->typ == RJ_RAW
             && rj_arena_bytes() - b0 < (long)strlen(fz->str) + 128);
          rj_arr_push(keep, fz); rj_arr_push(keep, rj_str("after"));
          ck("freeze: what was built before the mark survives, and the arena keeps working after",
             keep->nitems == 3 && !strcmp(keep->items[0]->str, "kept") && !strcmp(keep->items[2]->str, "after")
             && strlen(fz->str) > 20000u * 34); }
        rj_arena_end();
    }

    /* ---- streaming (rj_measure / rj_write_to, 2026-10-07): the server
     * measures a reply for Content-Length, then streams it to the socket
     * piece by piece. Both must agree with rj_write_alloc byte for byte, in
     * both layouts, through every kind of value: named and \\u00XX escapes
     * and DEL, empty containers, numbers, bools, null, a frozen entry, and a
     * string longer than any buffer. */
    {
        size_t bn = 300000; char* big = malloc(bn + 1);
        for (size_t i = 0; i < bn; i++) big[i] = (char)('a' + i % 26);
        big[bn] = 0; big[1000] = '"'; big[200000] = '\n';
        for (int arena = 0; arena < 2; arena++){
            if (arena) rj_arena_begin();
            rj_val* v = rj_obj();
            rj_obj_set(v, "esc", rj_str("q\"b\\s\b\f\n\r\tc\x01d\x7f"));
            rj_obj_set(v, "k\"ey", rj_num("-42"));
            rj_obj_set(v, "e1", rj_obj()); rj_obj_set(v, "e2", rj_arr());
            rj_val* a = rj_arr(); rj_arr_push(a, rj_bool(1)); rj_arr_push(a, rj_bool(0)); rj_arr_push(a, rj_null());
            rj_arr_push(a, rj_num("7")); rj_obj_set(v, "arr", a);
            { rj_mark mk = rj_arena_mark(); rj_val* t = rj_obj(); rj_obj_set(t, "fee", rj_num("1000"));
              rj_obj_set(t, "depends", rj_arr()); rj_obj_set(v, "frozen", rj_freeze(t, mk)); }
            rj_obj_set(v, "big", rj_str(big));
            for (int pretty = 0; pretty < 2; pretty++){
                char lab[160];
                long wl = 0; char* w = rj_write_alloc(v, pretty, &wl);
                snprintf(lab, sizeof lab, "stream: rj_measure is rj_write_alloc's length (%s, %s arena)", pretty ? "pretty" : "compact", arena ? "in an" : "no");
                ck(lab, rj_measure(v, pretty) == wl);
                sink_t k = {0};
                int rc = rj_write_to(v, pretty, sink_put, &k);
                snprintf(lab, sizeof lab, "stream: rj_write_to hands over rj_write_alloc's bytes (%s, %s arena)", pretty ? "pretty" : "compact", arena ? "in an" : "no");
                ck(lab, rc == 0 && (long)k.n == wl && memcmp(k.b, w, (size_t)wl) == 0 && k.calls > 10);
                free(k.b); free(w);
            }
            /* a failing sink: the call reports it and nothing more is handed over */
            { sink_t k = { .fail_at = 5 };
              int rc = rj_write_to(v, 0, sink_put, &k);
              ck(arena ? "stream: a failing sink is reported, and not called again (in an arena)"
                       : "stream: a failing sink is reported, and not called again",
                 rc == -1 && k.calls == 5 && k.n < 64);
              free(k.b); }
            if (arena) rj_arena_end(); else rj_free(v);
        }
        free(big);
        /* the bare kinds, compact: what a reply's top level can be */
        rj_val* kinds[] = { rj_null(), rj_bool(1), rj_num("0"), rj_str(""), rj_arr(), rj_obj() };
        int ok = 1;
        for (unsigned i = 0; i < sizeof kinds / sizeof kinds[0]; i++){
            long wl = 0; char* w = rj_write_alloc(kinds[i], 0, &wl); sink_t k = {0};
            ok &= rj_measure(kinds[i], 0) == wl && rj_write_to(kinds[i], 0, sink_put, &k) == 0 && (long)k.n == wl
                  && (wl == 0 || memcmp(k.b, w, (size_t)wl) == 0);
            free(w); free(k.b); rj_free(kinds[i]);
        }
        ck("stream: null, bool, number, empty string, [] and {} measure and stream like rj_write_alloc", ok);
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

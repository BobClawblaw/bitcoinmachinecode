/* rpc_json.c -- Core-bit-exact JSON serializer + strict parser.
 *
 * Serializer mirrors Bitcoin Core src/univalue/univalue.cpp UniValue::write()
 * and escapeStringBN() byte-for-byte. Parser is a small recursive-descent JSON
 * reader sufficient for JSON-RPC request/reply bodies (no floats needed; the
 * project avoids floating point for amounts).
 */
#include "rpc_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

/* ---------------- allocation helpers ---------------- */
static void* xmalloc(size_t n) { void* p = malloc(n ? n : 1); if (!p) abort(); return p; }
static char* xstrdup(const char* s) { size_t n = strlen(s) + 1; char* p = xmalloc(n); memcpy(p, s, n); return p; }
static char* xstrndup(const char* s, size_t n) { char* p = xmalloc(n + 1); memcpy(p, s, n); p[n] = 0; return p; }

rj_val* rj_null(void) { rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_NULL; return v; }
rj_val* rj_bool(int b) { rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_BOOL; v->str = xstrdup(b ? "1" : "0"); return v; }
rj_val* rj_num(const char* s) { rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_NUM; v->str = xstrdup(s); return v; }
rj_val* rj_numf(const char* fmt, ...) {
    char buf[64]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    return rj_num(buf);
}
rj_val* rj_str(const char* s) { rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_STR; v->str = xstrdup(s ? s : ""); return v; }
rj_val* rj_strf(const char* fmt, ...) {
    char buf[512]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    return rj_str(buf);
}

static void rj_arr_reserve(rj_val* a, size_t n) {
    if (a->cap_items >= n) return;
    size_t nc = a->cap_items ? a->cap_items : 8;
    while (nc < n) nc *= 2;
    a->items = realloc(a->items, nc * sizeof(rj_val*));
    if (!a->items) abort();
    a->cap_items = nc;
}
rj_val* rj_arr(void) { rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_ARR; return v; }
void rj_arr_push(rj_val* a, rj_val* v) {
    rj_arr_reserve(a, a->nitems + 1);
    a->items[a->nitems++] = v;
}

static void rj_obj_reserve(rj_val* o, size_t n) {
    if (o->cap_members >= n) return;
    size_t nc = o->cap_members ? o->cap_members : 8;
    while (nc < n) nc *= 2;
    o->members = realloc(o->members, nc * sizeof(rj_member));
    if (!o->members) abort();
    o->cap_members = nc;
}
rj_val* rj_obj(void) { rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_OBJ; return v; }
void rj_obj_set(rj_val* o, const char* key, rj_val* v) {
    rj_obj_reserve(o, o->nmembers + 1);
    o->members[o->nmembers].key = xstrdup(key);
    o->members[o->nmembers].val = v;
    o->nmembers++;
}
/* Deep copy; see rpc_json.h. Bounded because the tree it walks came from
 * p_val, which now refuses to build anything deeper than RJ_MAX_DEPTH -- so a
 * hostile request cannot drive this past that. (This comment previously
 * asserted the same conclusion from a limit that did not exist.) */
rj_val* rj_clone(const rj_val* v){
    if (!v) return NULL;
    rj_val* c = NULL;
    switch (v->typ){
        case RJ_NULL: c = rj_null(); break;
        case RJ_BOOL: c = rj_bool(v->str && v->str[0] == '1'); break;
        case RJ_NUM:  c = rj_num(v->str ? v->str : "0"); break;
        case RJ_STR:  c = rj_str(v->str ? v->str : ""); break;
        case RJ_ARR:
            c = rj_arr();
            if (!c) return NULL;
            for (size_t i = 0; i < v->nitems; i++){
                rj_val* e = rj_clone(v->items[i]);
                if (!e){ rj_free(c); return NULL; }
                rj_arr_push(c, e);
            }
            break;
        case RJ_OBJ:
            c = rj_obj();
            if (!c) return NULL;
            for (size_t i = 0; i < v->nmembers; i++){
                rj_val* e = rj_clone(v->members[i].val);
                if (!e){ rj_free(c); return NULL; }
                rj_obj_set(c, v->members[i].key, e);
            }
            break;
    }
    return c;
}

rj_val* rj_obj_get(const rj_val* o, const char* key) {
    for (size_t i = 0; i < o->nmembers; i++)
        if (!strcmp(o->members[i].key, key)) return o->members[i].val;
    return NULL;
}

/* ---------------- escapeStringBN (Core-exact) ---------------- */
static void rj_append_escaped(char** out, size_t* cap, size_t* len, const char* in) {
    for (const unsigned char* p = (const unsigned char*)in; *p; p++) {
        char c = (char)*p;
        const char* esc = NULL;
        switch (c) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\b': esc = "\\b";  break;
            case '\f': esc = "\\f";  break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            default:
                /* RPC-11 (audit 2026-09-03): 0x7f (DEL) too. UniValue's
                 * generated escape table has escapes['\x7f'] = "\\u007f",
                 * so Core emits it escaped and this writer emitted it raw.
                 * Reachable through operator-supplied strings (labels,
                 * comments); peer user agents are sanitised at ingest. */
                if (*p < 0x20 || *p == 0x7f) {
                    /* \uXXXX with lowercase hex, 4 digits */
                    char buf[8];
                    snprintf(buf, sizeof buf, "\\u%04x", (unsigned)*p);
                    size_t bl = strlen(buf);
                    if (*len + bl + 1 >= *cap) { *cap = (*cap ? *cap * 2 : 64); *out = realloc(*out, *cap); if (!*out) abort(); }
                    memcpy(*out + *len, buf, bl); *len += bl;
                    break;
                }
                if (*len + 2 >= *cap) { *cap = (*cap ? *cap * 2 : 64); *out = realloc(*out, *cap); if (!*out) abort(); }
                (*out)[(*len)++] = c;
        }
        if (esc) {
            size_t el = strlen(esc);
            if (*len + el + 1 >= *cap) { *cap = (*cap ? *cap * 2 : 64); *out = realloc(*out, *cap); if (!*out) abort(); }
            memcpy(*out + *len, esc, el); *len += el;
        }
    }
}

/* ---------------- serializer ---------------- */
typedef struct { char* buf; size_t len; size_t cap; } sbuf;
static void sb_push(sbuf* s, const char* txt, size_t n) {
    if (s->len + n + 1 >= s->cap) {
        while (s->cap < s->len + n + 1) s->cap = s->cap ? s->cap * 2 : 128;
        s->buf = realloc(s->buf, s->cap); if (!s->buf) abort();
    }
    memcpy(s->buf + s->len, txt, n); s->len += n;
    s->buf[s->len] = 0;
}
static void sb_pushs(sbuf* s, const char* txt) { sb_push(s, txt, strlen(txt)); }
static void sb_repeat(sbuf* s, char c, size_t k) {
    char block[128]; memset(block, c, sizeof block);
    while (k) { size_t take = k > sizeof block ? sizeof block : k; sb_push(s, block, take); k -= take; }
}

static void rj_w(sbuf* s, const rj_val* v, int pretty, unsigned indent) {
    if (!v) { sb_pushs(s, "null"); return; }
    switch (v->typ) {
        case RJ_OBJ: {
            if (pretty) {
                sb_pushs(s, "{");
                if (v->nmembers) {
                    sb_pushs(s, "\n");
                    for (size_t i = 0; i < v->nmembers; i++) {
                        if (i) sb_pushs(s, ",\n");
                        sb_repeat(s, ' ', 2 * (indent + 1));
                        sb_pushs(s, "\"");
                        rj_append_escaped(&s->buf, &s->cap, &s->len, v->members[i].key);
                        sb_pushs(s, "\": ");
                        rj_w(s, v->members[i].val, pretty, indent + 1);
                    }
                    sb_pushs(s, "\n");
                    sb_repeat(s, ' ', 2 * indent);
                }
                sb_pushs(s, "}");
            } else {
                sb_pushs(s, "{");
                for (size_t i = 0; i < v->nmembers; i++) {
                    if (i) sb_pushs(s, ",");
                    sb_pushs(s, "\"");
                    rj_append_escaped(&s->buf, &s->cap, &s->len, v->members[i].key);
                    sb_pushs(s, "\":");
                    rj_w(s, v->members[i].val, pretty, indent);
                }
                sb_pushs(s, "}");
            }
            break;
        }
        case RJ_ARR: {
            if (pretty) {
                sb_pushs(s, "[");
                if (v->nitems) {
                    sb_pushs(s, "\n");
                    for (size_t i = 0; i < v->nitems; i++) {
                        if (i) sb_pushs(s, ",\n");
                        sb_repeat(s, ' ', 2 * (indent + 1));
                        rj_w(s, v->items[i], pretty, indent + 1);
                    }
                    sb_pushs(s, "\n");
                    sb_repeat(s, ' ', 2 * indent);
                }
                sb_pushs(s, "]");
            } else {
                sb_pushs(s, "[");
                for (size_t i = 0; i < v->nitems; i++) {
                    if (i) sb_pushs(s, ",");
                    rj_w(s, v->items[i], pretty, indent);
                }
                sb_pushs(s, "]");
            }
            break;
        }
        case RJ_STR:
            sb_pushs(s, "\"");
            rj_append_escaped(&s->buf, &s->cap, &s->len, v->str);
            sb_pushs(s, "\"");
            break;
        case RJ_NUM:
            sb_pushs(s, v->str ? v->str : "0");
            break;
        case RJ_BOOL:
            sb_pushs(s, (v->str && !strcmp(v->str, "1")) ? "true" : "false");
            break;
        case RJ_NULL:
        default:
            sb_pushs(s, "null");
            break;
    }
}

long rj_write(char* out, long cap, const rj_val* v, int pretty) {
    sbuf s = {0, 0, 0};
    unsigned indent = 0;
    rj_w(&s, v, pretty, indent);
    if (cap > 0) {
        long n = (long)s.len;
        if (n > cap - 1) n = cap - 1;          /* leave room for NUL (was: out[cap] OOB) */
        if (n > 0) memcpy(out, s.buf, (size_t)n);
        out[n] = 0;
    }
    long len = (long)s.len;
    free(s.buf);
    return len;
}

/* Serialize into a freshly malloc'd, NUL-terminated buffer sized exactly to the
 * value (no truncation). Returns the buffer (caller frees) and, via *len_out,
 * its length excluding the NUL. Use this for responses of unbounded size --
 * a fixed stack buffer + rj_write's returned length is an out-of-bounds read
 * waiting to happen. Returns NULL only on allocation failure. */
char* rj_write_alloc(const rj_val* v, int pretty, long* len_out) {
    sbuf s = {0, 0, 0};
    rj_w(&s, v, pretty, 0);
    if (!s.buf) { s.buf = malloc(1); if (s.buf) s.buf[0] = 0; }
    else s.buf[s.len] = 0;                      /* sb_push keeps cap >= len+1 */
    if (len_out) *len_out = (long)s.len;
    return s.buf;
}

void rj_free(rj_val* v) {
    if (!v) return;
    if (v->typ == RJ_ARR) for (size_t i = 0; i < v->nitems; i++) rj_free(v->items[i]);
    if (v->typ == RJ_OBJ) for (size_t i = 0; i < v->nmembers; i++) { free(v->members[i].key); rj_free(v->members[i].val); }
    free(v->items);
    free(v->members);
    free(v->str);
    free(v);
}

/* ---------------- parser ---------------- */
/* MAX_JSON_DEPTH matches UniValue's (univalue_read.cpp), so this parser
 * accepts and rejects exactly the nesting Core does. */
#define RJ_MAX_DEPTH 512
typedef struct { const char* p; const char* end; int err; int depth; } pctx;

static void p_ws(pctx* c) { while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r')) c->p++; }
static rj_val* p_val(pctx* c);

static rj_val* p_string_core(pctx* c, char** out) {
    /* c->p points at the opening quote */
    c->p++;
    sbuf s = {0, 0, 0};
    while (1) {
        if (c->p >= c->end) { c->err = 1; break; }
        char ch = *c->p;
        if (ch == '"') { c->p++; break; }
        if (ch == '\\') {
            c->p++;
            if (c->p >= c->end) { c->err = 1; break; }
            char e = *c->p;
            switch (e) {
                case '"': sb_push(&s, "\"", 1); break;
                case '\\': sb_push(&s, "\\", 1); break;
                case '/': sb_push(&s, "/", 1); break;
                case 'b': sb_push(&s, "\b", 1); break;
                case 'f': sb_push(&s, "\f", 1); break;
                case 'n': sb_push(&s, "\n", 1); break;
                case 'r': sb_push(&s, "\r", 1); break;
                case 't': sb_push(&s, "\t", 1); break;
                case 'u': {
                    if (c->end - c->p < 5) { c->err = 1; break; }
                    unsigned cp = 0;
                    for (int i = 0; i < 4; i++) {
                        char h = c->p[1 + i];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                        else { c->err = 1; break; }
                    }
                    if (c->err) break;
                    c->p += 4;
                    /* Encode as UTF-8, BMP only. RPC-7 (audit 2026-09-03):
                     * the previous note claimed surrogate pairs were
                     * "validated below via re-parse in callers if needed" --
                     * NO CALLER RE-PARSES, so that was simply false and is
                     * removed rather than left to mislead. A surrogate half is
                     * still encoded as-is (CESU-8) where UniValue combines a
                     * pair into one 4-byte code point and rejects a lone half;
                     * that remains open, and is the (b) part of RPC-7. */
                    char utf[4]; int ul = 0;
                    if (cp < 0x80) { utf[ul++] = (char)cp; }
                    else if (cp < 0x800) { utf[ul++] = (char)(0xC0 | (cp >> 6)); utf[ul++] = (char)(0x80 | (cp & 0x3F)); }
                    else { utf[ul++] = (char)(0xE0 | (cp >> 12)); utf[ul++] = (char)(0x80 | ((cp >> 6) & 0x3F)); utf[ul++] = (char)(0x80 | (cp & 0x3F)); }
                    sb_push(&s, utf, (size_t)ul);
                    break;
                }
                default: c->err = 1; break;
            }
            if (c->err) break;
            c->p++;
            continue;
        }
        /* RPC-7 (audit 2026-09-03): a raw byte below 0x20 is not legal inside a
         * JSON string. UniValue's getJsonToken returns JTOK_ERR for it; this
         * accepted it and passed it through, so a body Core rejects with
         * -32700 was dispatched here and produced a method-level error
         * instead. Note the ESCAPED forms are unaffected -- \n, \t and
         * \u0009 are handled above; this is only the literal byte. */
        if ((unsigned char)ch < 0x20) { c->err = 1; break; }
        sb_push(&s, &ch, 1);
        c->p++;
    }
    if (c->err) { free(s.buf); return NULL; }
    if (out) *out = s.buf ? s.buf : xstrdup("");
    else if (s.buf) free(s.buf);
    return NULL;
}

static rj_val* p_string(pctx* c) {
    char* s = NULL;
    if (p_string_core(c, &s)) return NULL;
    rj_val* v = rj_str(s);
    free(s);
    return v;
}

/* RPC-7 (audit 2026-09-03): the JSON number grammar, which this used to
 * approximate. `-` alone passed (the sign consume alone made p != start), and
 * so did `01`, `1.` and `1e` -- every one of which UniValue rejects. Each
 * component now requires at least one digit, and a leading zero may not be
 * followed by another digit (RFC 8259: int = zero / digit1-9 *DIGIT). */
static rj_val* p_number(pctx* c) {
    const char* start = c->p;
    if (c->p < c->end && *c->p == '-') c->p++;
    /* integer part: at least one digit, and no leading zero followed by more */
    { const char* ds = c->p;
      while (c->p < c->end && (*c->p >= '0' && *c->p <= '9')) c->p++;
      if (c->p == ds) { c->err = 1; return NULL; }
      if (c->p - ds > 1 && ds[0] == '0') { c->err = 1; return NULL; } }
    if (c->p < c->end && *c->p == '.') {
        c->p++;
        const char* fs = c->p;
        while (c->p < c->end && (*c->p >= '0' && *c->p <= '9')) c->p++;
        if (c->p == fs) { c->err = 1; return NULL; }        /* "1." */
    }
    if (c->p < c->end && (*c->p == 'e' || *c->p == 'E')) {
        c->p++;
        if (c->p < c->end && (*c->p == '+' || *c->p == '-')) c->p++;
        const char* es = c->p;
        while (c->p < c->end && (*c->p >= '0' && *c->p <= '9')) c->p++;
        if (c->p == es) { c->err = 1; return NULL; }        /* "1e", "1e+" */
    }
    if (c->p == start) { c->err = 1; return NULL; }
    rj_val* v = rj_num(xstrndup(start, (size_t)(c->p - start)));
    return v;
}

static rj_val* p_val(pctx* c) {
    p_ws(c);
    if (c->p >= c->end) { c->err = 1; return NULL; }
    char ch = *c->p;
    /* SECURITY: every '[' or '{' recurses into p_val, so nesting depth is
     * attacker-controlled stack depth. Unbounded, "[[[[..." simply exhausts
     * the stack and the process dies on SIGSEGV -- confirmed by core dump at
     * 200,000 levels before this bound existed. The file previously carried a
     * comment asserting "recursion depth is bounded by the parser's own
     * nesting limit"; there was no such limit, which is worse than having no
     * comment. Container depth is counted here, before recursing. */
    if ((ch == '{' || ch == '[') && ++c->depth > RJ_MAX_DEPTH) { c->err = 1; return NULL; }
    if (ch == '"') return p_string(c);
    if (ch == '{') {
        c->p++; rj_val* o = rj_obj();
        p_ws(c);
        if (c->p < c->end && *c->p == '}') { c->p++; c->depth--; return o; }
        while (1) {
            p_ws(c);
            if (c->p >= c->end || *c->p != '"') { c->err = 1; rj_free(o); return NULL; }
            char* key = NULL; p_string_core(c, &key);
            if (c->err) { free(key); rj_free(o); return NULL; }
            p_ws(c);
            if (c->p >= c->end || *c->p != ':') { free(key); c->err = 1; rj_free(o); return NULL; }
            c->p++;
            rj_val* v = p_val(c);
            if (c->err) { free(key); rj_free(o); return NULL; }
            rj_obj_set(o, key, v);
            free(key);
            p_ws(c);
            if (c->p >= c->end) { c->err = 1; rj_free(o); return NULL; }
            if (*c->p == ',') { c->p++; continue; }
            if (*c->p == '}') { c->p++; c->depth--; return o; }
            c->err = 1; rj_free(o); return NULL;
        }
    }
    if (ch == '[') {
        c->p++; rj_val* a = rj_arr();
        p_ws(c);
        if (c->p < c->end && *c->p == ']') { c->p++; c->depth--; return a; }
        while (1) {
            rj_val* v = p_val(c);
            if (c->err) { rj_free(a); return NULL; }
            rj_arr_push(a, v);
            p_ws(c);
            if (c->p >= c->end) { c->err = 1; rj_free(a); return NULL; }
            if (*c->p == ',') { c->p++; continue; }
            if (*c->p == ']') { c->p++; c->depth--; return a; }
            c->err = 1; rj_free(a); return NULL;
        }
    }
    if (c->p + 4 <= c->end && !strncmp(c->p, "true", 4)) { c->p += 4; return rj_bool(1); }
    if (c->p + 5 <= c->end && !strncmp(c->p, "false", 5)) { c->p += 5; return rj_bool(0); }
    if (c->p + 4 <= c->end && !strncmp(c->p, "null", 4)) { c->p += 4; return rj_null(); }
    if (ch == '-' || (ch >= '0' && ch <= '9')) return p_number(c);
    c->err = 1;
    return NULL;
}

rj_val* rj_parse(const char* s, size_t len) {
    pctx c = { s, s + len, 0, 0 };
    rj_val* v = p_val(&c);
    if (c.err) { if (v) rj_free(v); return NULL; }
    p_ws(&c);
    if (c.p != c.end) { rj_free(v); return NULL; }
    return v;
}

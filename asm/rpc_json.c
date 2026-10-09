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
#include "bmc_thread.h"   /* BMC_TLS_GROW */

/* ---------------- the request arena (2026-10-06, plan A5) ----------------
 *
 * getblock verbosity 2 on a full mainnet block builds ~400,000 values --
 * 3,573 transactions, every field its own rj_val plus its own string --
 * and a third of the render time was malloc/free (perf on block 969,000:
 * malloc_consolidate 14%, unlink_chunk 7%, _int_malloc/_int_free 9%, 36 ms
 * build+write+free of which ~13 ms allocator). Core's UniValue pays the
 * same shape in C++ allocations; the fix here is the classic one: every
 * value a request builds lives in a per-thread bump arena and is released
 * in one step when the response has been written.
 *
 * Contract: rj_arena_begin() on a thread routes every rj_* allocation
 * (values, strings, keys, item/member arrays, the parser's output) to that
 * thread's arena until the matching rj_arena_end(), which frees the arena
 * whole. rj_free of an arena-owned value is a no-op (the walk still runs,
 * so a foreign child -- built before the arena began -- is freed as
 * before). Nested begin/end pairs share one arena (released at the
 * outermost end). Nothing built under an arena may outlive its end: the
 * server begins one per request on its execution thread and ends it after
 * the body is written (render_request), and no RPC handler keeps rj_val
 * trees across requests (grep'd 2026-10-06: none). Code that never calls
 * rj_arena_begin -- the REST facade's own threads, the tests, the CLI --
 * sees malloc exactly as before. */
typedef struct rj_chunk { struct rj_chunk* next; size_t cap, used; unsigned char* base; } rj_chunk;
typedef struct { rj_chunk* head; rj_chunk* cur; size_t total; size_t chunks; int depth; } rj_arena;
static __thread rj_arena* t_arena;
#define RJ_ARENA_CHUNK (256u << 10)
#define RJ_ARENA_ALIGN 16u
static size_t arena_round(size_t n){ return (n + (RJ_ARENA_ALIGN - 1)) & ~(size_t)(RJ_ARENA_ALIGN - 1); }
static rj_chunk* arena_chunk_new(size_t cap){
    rj_chunk* c = malloc(sizeof *c + cap);
    if (!c) abort();
    c->next = NULL; c->cap = cap; c->used = 0; c->base = (unsigned char*)(c + 1);
    return c;
}
static void* arena_alloc(size_t n){
    rj_arena* a = t_arena;
    n = arena_round(n ? n : 1);
    rj_chunk* c = a->cur;
    if (!c || c->used + n > c->cap){
        size_t cap = c ? c->cap * 2 : RJ_ARENA_CHUNK;
        if (cap > (64u << 20)) cap = 64u << 20;
        if (cap < n) cap = n;
        rj_chunk* nc = arena_chunk_new(cap);
        if (c) c->next = nc; else a->head = nc;
        a->cur = c = nc; a->chunks++;
    }
    void* p = c->base + c->used; c->used += n; a->total += n;
    return p;
}
static int arena_owns(const void* p){
    if (!t_arena) return 0;
    const unsigned char* q = p;
    for (rj_chunk* c = t_arena->head; c; c = c->next) if (q >= c->base && q < c->base + c->cap) return 1;
    return 0;
}
void rj_arena_begin(void){
    if (t_arena){ t_arena->depth++; return; }
    rj_arena* a = malloc(sizeof *a); if (!a) abort();
    memset(a, 0, sizeof *a); a->depth = 1; t_arena = a;
}
void rj_arena_end(void){
    rj_arena* a = t_arena;
    if (!a) return;
    if (--a->depth > 0) return;
    for (rj_chunk* c = a->head; c;){ rj_chunk* n = c->next; free(c); c = n; }
    free(a); t_arena = NULL;
}
int  rj_arena_active(void){ return t_arena != NULL; }
/* where the arena is now: rj_freeze rewinds to it */
rj_mark rj_arena_mark(void){
    rj_mark m = { 0, 0, 0 };
    if (t_arena){ m.chunk = t_arena->cur; m.used = t_arena->cur ? t_arena->cur->used : 0; m.total = t_arena->total; }
    return m;
}
/* back to m: chunks opened since are freed, the marked chunk is cut back */
static void arena_rewind(rj_mark m){
    rj_arena* a = t_arena;
    rj_chunk* keep = (rj_chunk*)m.chunk;
    rj_chunk* c = keep ? keep->next : a->head;
    while (c){ rj_chunk* n = c->next; free(c); a->chunks--; c = n; }
    if (keep){ keep->next = NULL; keep->used = m.used; }
    else a->head = NULL;
    a->cur = keep; a->total = m.total;
}
long rj_arena_bytes(void){ return t_arena ? (long)t_arena->total : -1; }
int  rj_arena_owns(const void* p){ return arena_owns(p); }

/* ---------------- allocation helpers ---------------- */
static void* xmalloc(size_t n) { if (t_arena) return arena_alloc(n); void* p = malloc(n ? n : 1); if (!p) abort(); return p; }
/* xfree: a pointer the arena owns is released with the arena, not here */
static void xfree(void* p) { if (!p) return; if (t_arena && arena_owns(p)) return; free(p); }
/* xrealloc: the caller knows the old size (the containers keep their
 * capacity), so an arena block grows in place when it is the arena's last
 * allocation and is copied otherwise; a foreign block (malloc'd before the
 * arena began) is copied in and freed. */
static void* xrealloc(void* p, size_t old_bytes, size_t new_bytes) {
    if (!t_arena){ void* q = realloc(p, new_bytes); if (!q) abort(); return q; }
    if (p && arena_owns(p)){
        rj_chunk* c = t_arena->cur;
        size_t ro = arena_round(old_bytes), rn = arena_round(new_bytes);
        if (c && (unsigned char*)p + ro == c->base + c->used && c->used - ro + rn <= c->cap){
            c->used += rn - ro; t_arena->total += rn - ro; return p;   /* the last allocation: extend in place */
        }
        void* q = arena_alloc(new_bytes);
        memcpy(q, p, old_bytes < new_bytes ? old_bytes : new_bytes);
        return q;
    }
    void* q = arena_alloc(new_bytes);
    if (p){ memcpy(q, p, old_bytes < new_bytes ? old_bytes : new_bytes); free(p); }
    return q;
}
static char* xstrdup(const char* s) { size_t n = strlen(s) + 1; char* p = xmalloc(n); memcpy(p, s, n); return p; }
static char* xstrndup(const char* s, size_t n) { char* p = xmalloc(n + 1); memcpy(p, s, n); p[n] = 0; return p; }

rj_val* rj_null(void) { rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_NULL; return v; }
rj_val* rj_bool(int b) { rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_BOOL; v->str = xstrdup(b ? "1" : "0"); return v; }
rj_val* rj_num(const char* s) { rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_NUM; v->str = xstrdup(s); return v; }
/* the integer formats rj_numf is called with (grep 2026-10-06: %lld %ld %d
 * %u %llu %lu %zu are 340 of 400 call sites) are formatted by hand; anything
 * else goes through vsnprintf as before. Same digits, same sign, no
 * padding, so the text is what printf would print. */
static char* fmt_u64(char* end, unsigned long long v){ *--end = 0; do { *--end = (char)('0' + v % 10); v /= 10; } while (v); return end; }
static char* fmt_i64(char* end, long long v){
    unsigned long long u = v < 0 ? 0ULL - (unsigned long long)v : (unsigned long long)v;
    char* s = fmt_u64(end, u); if (v < 0) *--s = '-'; return s;
}
rj_val* rj_numf(const char* fmt, ...) {
    char buf[64]; va_list ap; va_start(ap, fmt);
    const char* s = NULL;
    if (fmt[0] == '%'){
        const char* f = fmt + 1;
        if      (!strcmp(f, "lld")) s = fmt_i64(buf + sizeof buf, va_arg(ap, long long));
        else if (!strcmp(f, "ld"))  s = fmt_i64(buf + sizeof buf, va_arg(ap, long));
        else if (!strcmp(f, "d"))   s = fmt_i64(buf + sizeof buf, va_arg(ap, int));
        else if (!strcmp(f, "u"))   s = fmt_u64(buf + sizeof buf, va_arg(ap, unsigned));
        else if (!strcmp(f, "llu")) s = fmt_u64(buf + sizeof buf, va_arg(ap, unsigned long long));
        else if (!strcmp(f, "lu"))  s = fmt_u64(buf + sizeof buf, va_arg(ap, unsigned long));
        else if (!strcmp(f, "zu"))  s = fmt_u64(buf + sizeof buf, va_arg(ap, size_t));
    }
    if (!s){ vsnprintf(buf, sizeof buf, fmt, ap); s = buf; }
    va_end(ap);
    return rj_num(s);
}
rj_val* rj_str(const char* s) { rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_STR; v->str = xstrdup(s ? s : ""); return v; }
/* a lowercase-hex string value written straight into the value (2026-10-06:
 * the callers hex-encoded into a malloc'd buffer, rj_str copied it, the
 * buffer was freed -- three passes and two allocations per script,
 * witness item and transaction of a getblock v2 render) */
static const char RJ_HEX2[512] =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
rj_val* rj_hex(const unsigned char* b, size_t n) {
    rj_val* v = xmalloc(sizeof(*v)); memset(v, 0, sizeof(*v)); v->typ = RJ_STR;
    char* h = xmalloc(n * 2 + 1);
    for (size_t i = 0; i < n; i++) memcpy(h + i * 2, RJ_HEX2 + b[i] * 2, 2);
    h[n * 2] = 0; v->str = h;
    return v;
}
rj_val* rj_strf(const char* fmt, ...) {
    char buf[512]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    return rj_str(buf);
}

static void rj_arr_reserve(rj_val* a, size_t n) {
    if (a->cap_items >= n) return;
    size_t nc = a->cap_items ? a->cap_items : 8;
    while (nc < n) nc *= 2;
    a->items = xrealloc(a->items, a->cap_items * sizeof(rj_val*), nc * sizeof(rj_val*));
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
    o->members = xrealloc(o->members, o->cap_members * sizeof(rj_member), nc * sizeof(rj_member));
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
        case RJ_RAW:
            c = rj_null(); if (!c) return NULL;
            c->typ = RJ_RAW; c->str = xstrdup(v->str ? v->str : "null"); break;
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
    if (o->typ == RJ_RAW) rj_expand((rj_val*)o);   /* logically const: same value, unfolded */
    for (size_t i = 0; i < o->nmembers; i++)
        if (!strcmp(o->members[i].key, key)) return o->members[i].val;
    return NULL;
}
/* 2026-10-06: the two member operations callers used to do by hand with
 * free() on the key and the member array -- under the request arena those
 * frees abort (the memory is the arena's), so they live here, arena-aware. */
int rj_obj_del(rj_val* o, const char* key) {
    if (!o || o->typ != RJ_OBJ) return 0;
    for (size_t i = 0; i < o->nmembers; i++) if (!strcmp(o->members[i].key, key)) {
        xfree(o->members[i].key); rj_free(o->members[i].val);
        memmove(&o->members[i], &o->members[i + 1], (o->nmembers - i - 1) * sizeof o->members[0]);
        o->nmembers--;
        return 1;
    }
    return 0;
}
void rj_obj_splice(rj_val* dst, rj_val* src) {
    if (!src) return;
    if (src->typ == RJ_OBJ) {
        for (size_t k = 0; k < src->nmembers; k++) { rj_obj_set(dst, src->members[k].key, src->members[k].val); src->members[k].val = NULL; }
    }
    rj_free(src);   /* the keys and the member array; the values are NULL now */
}

/* ---------------- output buffer ---------------- */
/* Three modes. GROW (sink NULL, count_only 0): append to buf, doubling it.
 * COUNT (count_only 1): add up the length, write nothing -- rj_measure.
 * SINK (sink set): hand every piece to the sink as it is made, keep nothing
 * -- rj_write_to; once the sink fails, the rest is dropped. (2026-10-07: the
 * server wrote a reply into one buffer and then wrote that buffer out; a
 * 39 MB verbose getrawmempool doubled its way to 64 MB first.) */
typedef struct {
    char* buf; size_t len; size_t cap;
    int count_only;
    int (*sink)(void* ctx, const char* p, size_t n); void* ctx; int failed;
} sbuf;
static void sb_push(sbuf* s, const char* txt, size_t n) {
    if (s->count_only) { s->len += n; return; }
    if (s->sink) {
        if (!s->failed && n && s->sink(s->ctx, txt, n) != 0) s->failed = 1;
        s->len += n;
        return;
    }
    if (s->len + n + 1 >= s->cap) {
        while (s->cap < s->len + n + 1) s->cap = s->cap ? s->cap * 2 : 128;
        s->buf = realloc(s->buf, s->cap); if (!s->buf) abort();
    }
    memcpy(s->buf + s->len, txt, n); s->len += n;
    s->buf[s->len] = 0;
}

/* ---------------- escapeStringBN (Core-exact) ---------------- */
/* the bytes the escaper rewrites: the seven named escapes, every control
 * byte and 0x7f. Everything else is copied through in spans (2026-10-06:
 * the byte-at-a-time loop with a capacity check per byte was 11% of a
 * getblock v2 render -- 10 MB of hex and base58 that never needs escaping). */
static const unsigned char rj_esc_needed[256] = {
    [0]=1,[1]=1,[2]=1,[3]=1,[4]=1,[5]=1,[6]=1,[7]=1,[8]=1,[9]=1,[10]=1,[11]=1,[12]=1,[13]=1,[14]=1,[15]=1,
    [16]=1,[17]=1,[18]=1,[19]=1,[20]=1,[21]=1,[22]=1,[23]=1,[24]=1,[25]=1,[26]=1,[27]=1,[28]=1,[29]=1,[30]=1,[31]=1,
    ['"']=1, ['\\']=1, [0x7f]=1 };
static void rj_append_escaped(sbuf* s, const char* in) {
    for (const unsigned char* p = (const unsigned char*)in; *p; p++) {
        if (!rj_esc_needed[*p]) {
            const unsigned char* q = p + 1;
            while (*q && !rj_esc_needed[*q]) q++;
            sb_push(s, (const char*)p, (size_t)(q - p));
            p = q - 1;   /* the loop's p++ lands on q */
            continue;
        }
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
                    sb_push(s, buf, strlen(buf));
                    break;
                }
                sb_push(s, &c, 1);
        }
        if (esc) sb_push(s, esc, strlen(esc));
    }
}

/* ---------------- serializer ---------------- */
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
                        rj_append_escaped(s, v->members[i].key);
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
                    rj_append_escaped(s, v->members[i].key);
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
            rj_append_escaped(s, v->str);
            sb_pushs(s, "\"");
            break;
        case RJ_NUM:
            sb_pushs(s, v->str ? v->str : "0");
            break;
        case RJ_RAW:
            if (!pretty) { sb_pushs(s, v->str ? v->str : "null"); break; }
            {   /* pretty: the text is compact, so render it again (rare --
                 * the server writes compact) */
                rj_val* t = v->str ? rj_parse(v->str, strlen(v->str)) : NULL;
                rj_w(s, t, pretty, indent);
                rj_free(t);
            }
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
    sbuf s = {0};
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
    sbuf s = {0};
    rj_w(&s, v, pretty, 0);
    if (!s.buf) { s.buf = malloc(1); if (s.buf) s.buf[0] = 0; }
    else s.buf[s.len] = 0;                      /* sb_push keeps cap >= len+1 */
    if (len_out) *len_out = (long)s.len;
    return s.buf;
}

/* the length rj_write_alloc would return, without writing anything */
long rj_measure(const rj_val* v, int pretty) {
    sbuf s = { .count_only = 1 };
    rj_w(&s, v, pretty, 0);
    return (long)s.len;
}

/* Serialize to a sink, piece by piece: nothing is kept. 0, or -1 once the
 * sink has failed (the rest of the value is not handed to it). */
int rj_write_to(const rj_val* v, int pretty, int (*sink)(void* ctx, const char* p, size_t n), void* ctx) {
    sbuf s = { .sink = sink, .ctx = ctx };
    rj_w(&s, v, pretty, 0);
    return s.failed ? -1 : 0;
}

void rj_free(rj_val* v) {
    if (!v) return;
    /* an arena value's children are arena values (everything a request
     * builds is built after its arena began; no handler keeps a tree across
     * requests), so there is nothing to walk: the arena's end releases it */
    if (t_arena && arena_owns(v)) return;
    if (v->typ == RJ_ARR) for (size_t i = 0; i < v->nitems; i++) rj_free(v->items[i]);
    if (v->typ == RJ_OBJ) for (size_t i = 0; i < v->nmembers; i++) { xfree(v->members[i].key); rj_free(v->members[i].val); }
    xfree(v->items);
    xfree(v->members);
    xfree(v->str);
    xfree(v);
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
    xfree(s);
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
    /* BLD-7 (2026-09-05): this was
     *     rj_val* v = rj_num(xstrndup(start, len));
     * and it LEAKED the xstrndup result on every number parsed. rj_num does
     * `v->str = xstrdup(s)` -- it makes its OWN copy -- so the argument was a
     * second allocation nothing ever owned or freed.
     *
     * rpc_json parses untrusted JSON-RPC bodies on a long-lived server, so
     * this is a few bytes per NUMBER per REQUEST, forever: a slow
     * memory-exhaustion vector rather than untidiness. Every params array
     * with a number in it -- which is most of them -- hit it.
     *
     * Found by the SAN=1 build this commit adds, on the first harness run:
     * parsing the single character "1" leaks 2 bytes. */
    char* txt = xstrndup(start, (size_t)(c->p - start));
    rj_val* v = rj_num(txt);
    xfree(txt);
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
            if (c->err) { xfree(key); rj_free(o); return NULL; }
            p_ws(c);
            if (c->p >= c->end || *c->p != ':') { xfree(key); c->err = 1; rj_free(o); return NULL; }
            c->p++;
            rj_val* v = p_val(c);
            if (c->err) { xfree(key); rj_free(o); return NULL; }
            rj_obj_set(o, key, v);
            xfree(key);
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

const char* rj_type_name(const rj_val* v) {
    if (!v) return "null";
    if (v->typ == RJ_RAW) return (v->str && v->str[0] == '[') ? "array" : (v->str && v->str[0] == '{') ? "object" : "null";
    switch (v->typ) {
        case RJ_NULL: return "null";  case RJ_BOOL: return "bool";
        case RJ_NUM:  return "number"; case RJ_STR: return "string";
        case RJ_ARR:  return "array";  case RJ_OBJ: return "object";
        default:      return "null";
    }
}

const char* rj_wrong_type_msg(char* buf, size_t cap, int position, const char* name,
                              const rj_val* got, const char* expected) {
    snprintf(buf, cap,
             "Wrong type passed:\n{\n    \"Position %d (%s)\": \"JSON value of type %s "
             "is not of expected type %s\"\n}",
             position, name, rj_type_name(got), expected);
    return buf;
}

const char* rj_wrong_field_type_msg(char* buf, size_t cap, const char* field,
                                    const rj_val* got, const char* expected) {
    if (!got || got->typ == RJ_NULL)                 /* Core names no field for a null */
        snprintf(buf, cap, "JSON value of type null is not of expected type %s", expected);
    else
        snprintf(buf, cap, "JSON value of type %s for field %s is not of expected type %s",
                 rj_type_name(got), field, expected);
    return buf;
}

const char* rj_wrong_type_msg_bare(char* buf, size_t cap, const rj_val* got, const char* expected) {
    snprintf(buf, cap, "JSON value of type %s is not of expected type %s",
             rj_type_name(got), expected);
    return buf;
}

void rj_typeerr_init(rj_typeerrs* t) { t->buf[0] = 0; t->n = 0; }

void rj_typeerr_add(rj_typeerrs* t, int position, const char* name,
                    const rj_val* got, const char* expected) {
    size_t at = strlen(t->buf);
    if (at + 200 >= sizeof t->buf) return;              /* keep what fits */
    snprintf(t->buf + at, sizeof t->buf - at,
             "%s    \"Position %d (%s)\": \"JSON value of type %s is not of expected type %s\"",
             t->n ? ",\n" : "", position, name, rj_type_name(got), expected);
    t->n++;
}

int rj_typeerr_fail(rj_typeerrs* t, long* ec, const char** em) {
    static __thread char out[2048 + 32];   /* per thread: lane methods run concurrently */
    if (!t->n) return 0;
    snprintf(out, sizeof out, "Wrong type passed:\n{\n%s\n}", t->buf);
    *ec = -3; *em = out; return 1;
}

/* ---------------- frozen values (2026-10-06) ---------------- */
/* verbose getrawmempool built ~68,000 entry trees and kept them all until the
 * reply was written: ~200 MB of arena at a 68k pool for ~39 MB of text. Each
 * entry is now written as soon as it is built and only its text is kept.
 * The scratch is freed at thread exit (bmc_thread.h, 2026-10-09). */
static __thread bmc_tls_grow* t_frz;
rj_val* rj_freeze(rj_val* v, rj_mark m){
    if (!v) return NULL;
    BMC_TLS_GROW(t_frz);
    sbuf sb = { .buf = t_frz->buf, .cap = t_frz->cap };   /* one scratch buffer per thread, reused */
    rj_w(&sb, v, 0, 0);
    t_frz->buf = sb.buf; t_frz->cap = sb.cap;
    if (t_arena) arena_rewind(m); else rj_free(v);
    rj_val* r = xmalloc(sizeof *r); memset(r, 0, sizeof *r);
    r->typ = RJ_RAW;
    r->str = xstrndup(sb.buf ? sb.buf : "null", sb.buf ? sb.len : 4);
    return r;
}
int rj_expand(rj_val* v){
    if (!v || v->typ != RJ_RAW) return 0;
    rj_val* t = v->str ? rj_parse(v->str, strlen(v->str)) : NULL;
    if (!t) return -1;
    xfree(v->str);
    *v = *t;                     /* take the parsed value's fields */
    xfree(t);                    /* its shell only */
    return 0;
}

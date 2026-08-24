/* rpc_json.h -- minimal JSON value model + Core-bit-exact serializer/parser.
 *
 * This is the "bit-identical response rendering" engine for the bitcoin-cli
 * network layer. It reproduces Bitcoin Core's UniValue rendering rules exactly
 * (src/univalue/univalue.cpp write()/read()):
 *
 *   - write(prettyIndent) with prettyIndent>0 emits Core's pretty JSON:
 *       2-space indentation at depth, keys/values on their own line, inserts
 *       non-escaped printable bytes, escapes strings with Core's escape set
 *       (\" \\ \b \f \n \r \t and \uXXXX for control chars < 0x20).
 *   - Keys preserve insertion order (Core does not sort object keys).
 *   - Numbers print verbatim; booleans true/false; null prints "null".
 *   - Empty object {} and empty array [].
 *
 * Values are owned strings (the serializer is used to build responses, so the
 * simple heap-string model is sufficient and fast).
 */
#ifndef RPC_JSON_H
#define RPC_JSON_H

#include <stddef.h>

enum rj_type { RJ_NULL, RJ_BOOL, RJ_NUM, RJ_STR, RJ_ARR, RJ_OBJ };

typedef struct rj_val rj_val;

/* A JSON object member: key + value. */
typedef struct {
    char* key;
    rj_val* val;
} rj_member;

struct rj_val {
    enum rj_type typ;
    char* str;        /* for RJ_STR (UTF-8), RJ_NUM (verbatim), RJ_BOOL: "1"/"0" */
    rj_val** items;   /* for RJ_ARR: element pointers */
    size_t nitems;
    size_t cap_items;
    rj_member* members; /* for RJ_OBJ */
    size_t nmembers;
    size_t cap_members;
};

/* Constructors --- all return heap-allocated values that must be rj_free()d. */
rj_val* rj_null(void);
rj_val* rj_bool(int b);
rj_val* rj_num(const char* s);        /* verbatim number text */
rj_val* rj_numf(const char* fmt, ...);/* printf'd number (e.g. "%llu") */
rj_val* rj_str(const char* s);        /* JSON string (raw bytes, no quotes) */
rj_val* rj_strf(const char* fmt, ...);
rj_val* rj_arr(void);
rj_val* rj_obj(void);

/* Array helpers. */
void rj_arr_push(rj_val* a, rj_val* v);
/* Object helpers. */
void rj_obj_set(rj_val* o, const char* key, rj_val* v);
rj_val* rj_obj_get(const rj_val* o, const char* key);

/* Serialize v into out using Core's write() semantics.
 * pretty>0: Core pretty format (indent = pretty spaces/depth).
 * pretty==0: compact (no whitespace), still Core-exact.
 * Appends NUL, truncating to cap-1 bytes if the value is larger. Returns the
 * value's FULL length excl. NUL (may exceed cap -- never use it as a length
 * into `out`; a return >= cap means the output was truncated). */
long rj_write(char* out, long cap, const rj_val* v, int pretty);

/* Serialize into a malloc'd, NUL-terminated buffer sized to the value (no
 * truncation). Returns the buffer (caller frees); *len_out gets its length
 * excl. NUL. For responses of unbounded size. NULL only on OOM. */
char* rj_write_alloc(const rj_val* v, int pretty, long* len_out);

/* Deep-free a value tree. */
void rj_free(rj_val* v);

/* -------- Parser (Core UniValue::read semantics) --------
 * Parse a complete JSON document from `s` (len bytes). Returns a heap value on
 * success, or NULL on any parse error. Accepts the JSON Core produces, incl.
 * strings/numbers/bools/null/arrays/objects nested arbitrarily, with or without
 * whitespace. Numbers are kept as verbatim text. */
rj_val* rj_parse(const char* s, size_t len);

#endif /* RPC_JSON_H */

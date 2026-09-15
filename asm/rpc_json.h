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

/* Deep copy. The result owns everything and is rj_free()d independently of
 * the source -- needed whenever a value parsed from a request has to be
 * placed into a structure that will itself be freed. Returns NULL only for
 * a NULL input or on OOM. */
rj_val* rj_clone(const rj_val* v);

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

/* Core reports EVERY positional argument whose type is wrong, in one object,
 * in position order -- not just the first:
 *
 *   Wrong type passed:
 *   {
 *       "Position 1 (inputs)": "JSON value of type string is not of expected type array",
 *       "Position 5 (version)": "JSON value of type string is not of expected type number"
 *   }
 *
 * Measured against v31.1 on 2026-09-15 for createrawtransaction, createpsbt,
 * getblockheader, gettxoutsetinfo, gettxspendingprevout, estimaterawfee and
 * prioritisetransaction. A UNION-typed position (createrawtransaction's
 * outputs, gettxoutsetinfo's hash_or_height) never appears in this object at
 * all -- RPCHelpMan does not type it, so the body reports it later with the
 * bare sentence. Check those AFTER rj_typeerr_fail, never inside the collection.
 *
 * Collect with rj_typeerr_add, then rj_typeerr_fail: it returns 1 and sets
 * *ec/-3 and *em when anything was collected, 0 when nothing was. */
typedef struct { char buf[2048]; int n; } rj_typeerrs;
void rj_typeerr_init(rj_typeerrs* t);
void rj_typeerr_add(rj_typeerrs* t, int position, const char* name,
                    const rj_val* got, const char* expected);
int  rj_typeerr_fail(rj_typeerrs* t, long* ec, const char** em);

/* Core's argument-check vocabulary (univalue checkType via RPCHelpMan::Arg).
 * Measured against Core v31.1 on 2026-09-15: a method answers
 *   missing required argument -> -1  + the method's full help text
 *   wrong JSON type           -> -3  + rj_wrong_type_msg() below
 *   right type, bad value     -> -8  + a method-specific message
 * and for a wallet method the wallet is resolved BETWEEN the type check and
 * the value check, so a bad-but-well-typed argument yields the wallet's -18.
 *
 * rj_type_name is the name Core prints for a value's actual type. */
const char* rj_type_name(const rj_val* v);
/* Formats Core's exact -3 body into buf and returns it:
 *   Wrong type passed:
 *   {
 *       "Position 1 (txid)": "JSON value of type null is not of expected type string"
 *   }
 * Give buf at least 256 bytes. */
const char* rj_wrong_type_msg(char* buf, size_t cap, int position, const char* name,
                              const rj_val* got, const char* expected);

/* The same check for a named field INSIDE an options object has a DIFFERENT
 * shape in Core -- no wrapper, no position, the field named inline:
 *   JSON value of type string for field mempool_only is not of expected type bool
 * and a NULL drops the "for field" clause entirely (Core's checkType throws
 * before the named-field wrapper is applied):
 *   JSON value of type null is not of expected type bool
 * Both measured against v31.1 on 2026-09-15. Give buf at least 256 bytes. */
const char* rj_wrong_field_type_msg(char* buf, size_t cap, const char* field,
                                    const rj_val* got, const char* expected);

/* Core's THIRD shape: a UNION-typed argument (createrawtransaction's outputs,
 * gettxoutsetinfo's hash_or_height) and a nested value inside a container get
 * the bare sentence -- no wrapper, no position, no field:
 *   JSON value of type number is not of expected type array
 * Measured against v31.1 on 2026-09-15. Give buf at least 96 bytes. */
const char* rj_wrong_type_msg_bare(char* buf, size_t cap, const rj_val* got, const char* expected);

/* Deep-free a value tree. */
void rj_free(rj_val* v);

/* -------- Parser (Core UniValue::read semantics) --------
 * Parse a complete JSON document from `s` (len bytes). Returns a heap value on
 * success, or NULL on any parse error. Accepts the JSON Core produces, incl.
 * strings/numbers/bools/null/arrays/objects nested arbitrarily, with or without
 * whitespace. Numbers are kept as verbatim text. */
rj_val* rj_parse(const char* s, size_t len);

#endif /* RPC_JSON_H */

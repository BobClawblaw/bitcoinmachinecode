/* miniscript.h -- Miniscript, Core's script/miniscript.h in C.
 *
 * A miniscript is a tree of fragments over keys, hashes and timelocks that
 * maps to exactly one Bitcoin Script (P2WSH witnessScript or tapscript leaf)
 * and back. This engine gives, for either context:
 *   - parsing from the textual form (wrappers, sugar: pk/pkh/t:/l:/u:/and_n),
 *   - Core's type system (B/V/K/W, z/o/n/d/u, e/f/s/m, x, g/h/i/j/k) and the
 *     resource analysis behind sanity: script size, static ops + the worst
 *     CHECKMULTISIG contribution, stack size (P2WSH witness items / tapscript
 *     execution depth), witness size,
 *   - compilation to script bytes and decoding of script bytes back to a
 *     tree (for inference: the witnessScript a PSBT carries),
 *   - the satisfier: given which keys can sign, which preimages are known
 *     and which timelocks are met, the witness stack -- choosing the
 *     non-malleable satisfaction the way Core does (InputStack algebra).
 *
 * Nodes live in a flat pool in construction order, so every child index is
 * smaller than its parent's: bottom-up passes are plain loops and the
 * top-down ones (script/string emission) use an explicit stack. Nothing
 * here recurses -- the daemon's threads have ~150 KB of stack (see
 * docs/ENGINEERING.md, TLS) and a valid tapscript miniscript can be
 * thousands of nodes deep.
 *
 * Keys are integers the caller interprets through an ms_ctx_t: the
 * descriptor engine uses its key-expression indices, the vector test uses
 * raw pubkeys. Nothing in this file allocates a key. */
#ifndef BMC_MINISCRIPT_H
#define BMC_MINISCRIPT_H
#include <stdint.h>
#include <stddef.h>

enum { MS_JUST_0 = 0, MS_JUST_1, MS_PK_K, MS_PK_H, MS_OLDER, MS_AFTER,
       MS_SHA256, MS_HASH256, MS_RIPEMD160, MS_HASH160,
       MS_WRAP_A, MS_WRAP_S, MS_WRAP_C, MS_WRAP_D, MS_WRAP_V, MS_WRAP_J, MS_WRAP_N,
       MS_AND_V, MS_AND_B, MS_OR_B, MS_OR_C, MS_OR_D, MS_OR_I, MS_ANDOR,
       MS_THRESH, MS_MULTI, MS_MULTI_A, MS_NFRAG };

/* type property bits (the letters of Core's ""_mst literals) */
#define MST_B (1u<<0)
#define MST_V (1u<<1)
#define MST_K (1u<<2)
#define MST_W (1u<<3)
#define MST_z (1u<<4)
#define MST_o (1u<<5)
#define MST_n (1u<<6)
#define MST_d (1u<<7)
#define MST_u (1u<<8)
#define MST_e (1u<<9)
#define MST_f (1u<<10)
#define MST_s (1u<<11)
#define MST_m (1u<<12)
#define MST_x (1u<<13)
#define MST_g (1u<<14)
#define MST_h (1u<<15)
#define MST_i (1u<<16)
#define MST_j (1u<<17)
#define MST_k (1u<<18)

enum { MS_AVAIL_NO = 0, MS_AVAIL_YES = 1, MS_AVAIL_MAYBE = 2 };

typedef struct {
    uint8_t  frag;
    uint8_t  nsubs;              /* 0..3, or the thresh arity when > 3 lives in subs_off */
    uint8_t  datalen;            /* 20 or 32 for the hash fragments */
    uint8_t  dup;                /* duplicate-key state: 0 unknown, 1 none, 2 duplicates */
    uint32_t k;                  /* older/after value, multi/thresh threshold */
    int32_t  nkeys, keys_off;    /* key ids: tree->keys[keys_off .. +nkeys) */
    int32_t  subs_off;           /* child node indices: tree->subs[subs_off .. +nsubs) */
    uint8_t  data[32];
    uint32_t typ;                /* the sanitized type; 0 = invalid */
    uint32_t scriptlen;
    uint32_t ops_count; int32_t ops_sat, ops_dsat;                 /* -1 = no valid (dis)satisfaction */
    int32_t  ss_sat_valid, ss_sat_net, ss_sat_exec;                /* SatInfo of the satisfaction traces */
    int32_t  ss_dsat_valid, ss_dsat_net, ss_dsat_exec;
    int32_t  ws_sat, ws_dsat;                                       /* -1 = none */
} ms_node_t;

/* The pools a forest of miniscript trees is built in. Either the caller
 * points these at fixed arrays (growable = 0; construction fails with
 * "too complex" when full) or at malloc'd ones the engine may realloc. */
typedef struct {
    ms_node_t* nodes; int32_t nn, ncap;
    int32_t*   subs;  int32_t ns, scap;
    int32_t*   keys;  int32_t nk, kcap;
    int growable;
    int tapscript;               /* the script context of every tree in the pool */
} ms_tree_t;

/* The caller's view of keys. Return 1 on success, 0 on failure. */
typedef struct {
    void* user;
    /* the text of a key expression (what stands between "pk(" and ")") -> key id;
     * a 0 must leave the reason in err (the descriptor reports it verbatim) */
    int (*key_from_str)(void* user, const char* s, size_t n, int* key, char* err, size_t errcap);
    /* a 33-byte (P2WSH) or 32-byte x-only (tapscript) key pushed by a script -> key id */
    int (*key_from_bytes)(void* user, const uint8_t* b, size_t n, int* key);
    /* a hash160 pushed by pk_h -> key id (only keys the caller knows) */
    int (*key_from_hash)(void* user, const uint8_t h[20], int* key);
    /* the bytes a pk_k pushes: 33 bytes, or 32 x-only under tapscript */
    int (*key_bytes)(void* user, int key, uint8_t out[33], int* n);
    /* hash160 of those bytes */
    int (*key_hash)(void* user, int key, uint8_t out[20]);
    /* the textual form of a key (public form unless the caller chose otherwise) */
    int (*key_to_str)(void* user, int key, char* out, size_t cap);
    /* total order on keys for the duplicate check: <0, 0 (equal), >0 */
    int (*key_cmp)(void* user, int a, int b);
} ms_ctx_t;

/* What the satisfier may use. Each returns an MS_AVAIL_* value. */
typedef struct {
    void* user;
    int (*sign)(void* user, int key, uint8_t* sig, size_t* siglen, size_t cap);   /* DER+hashtype or 64/65-byte BIP340 */
    int (*check_older)(void* user, uint32_t k);                                    /* 1 satisfied / 0 */
    int (*check_after)(void* user, uint32_t k);
    int (*preimage)(void* user, int frag, const uint8_t* hash, uint8_t out[32]);   /* frag = MS_SHA256..MS_HASH160 */
} ms_sat_ctx_t;

/* witness stack: elements bottom-first, each varint-length-prefixed in buf */
typedef struct {
    uint8_t* buf; size_t cap, len;
    int nelems;
} ms_witness_t;

void   ms_tree_init(ms_tree_t* t, int tapscript);              /* growable, empty (malloc'd on demand) */
void   ms_tree_free(ms_tree_t* t);                             /* only for growable trees */
void   ms_tree_reset(ms_tree_t* t);                            /* drop every tree, keep the storage */

/* parse the text s[0..n) in the pool's context; returns the root index or
 * -1 (reason in err, empty when the text is simply not miniscript) */
int    ms_parse(ms_tree_t* t, const ms_ctx_t* ctx, const char* s, size_t n, char* err, size_t errcap);
/* decode script bytes; root index or -1 */
int    ms_decode(ms_tree_t* t, const ms_ctx_t* ctx, const uint8_t* script, size_t n);
/* script bytes of the tree at root; length or -1 (cap too small / key error) */
int    ms_to_script(const ms_tree_t* t, const ms_ctx_t* ctx, int root, uint8_t* out, size_t cap);
/* the textual form; 1 ok / 0 (cap too small / key error) */
int    ms_to_string(const ms_tree_t* t, const ms_ctx_t* ctx, int root, char* out, size_t cap);
/* the witness for the tree at root; MS_AVAIL_*; w->buf is malloc'd/grown by
 * the engine and freed by ms_witness_free. nonmalleable=1 refuses malleable
 * or signature-less satisfactions, as Core's Satisfy does. */
int    ms_satisfy(const ms_tree_t* t, const ms_ctx_t* ctx, const ms_sat_ctx_t* sat, int root, int nonmalleable, ms_witness_t* w);
void   ms_witness_free(ms_witness_t* w);

/* properties of the tree at root (Core's Node accessors) */
uint32_t ms_type(const ms_tree_t* t, int root);
void   ms_type_string(uint32_t typ, char out[24]);
size_t ms_script_size(const ms_tree_t* t, int root);
int    ms_is_valid(const ms_tree_t* t, int root);
int    ms_is_valid_top(const ms_tree_t* t, int root);
int    ms_is_nonmalleable(const ms_tree_t* t, int root);
int    ms_needs_signature(const ms_tree_t* t, int root);
int    ms_check_timelocks_mix(const ms_tree_t* t, int root);
int    ms_check_duplicate_key(const ms_tree_t* t, int root);
int    ms_check_ops_limit(const ms_tree_t* t, int root);
int    ms_check_stack_size(const ms_tree_t* t, int root);
int    ms_valid_satisfactions(const ms_tree_t* t, int root);
int    ms_is_sane_subexpression(const ms_tree_t* t, int root);
int    ms_is_sane(const ms_tree_t* t, int root);
int    ms_is_not_satisfiable(const ms_tree_t* t, int root);
int    ms_find_insane_sub(const ms_tree_t* t, int root);      /* node index or -1 */
int    ms_get_ops(const ms_tree_t* t, int root, uint32_t* out);            /* 1 if defined */
int    ms_get_stack_size(const ms_tree_t* t, int root, uint32_t* out);
int    ms_get_exec_stack_size(const ms_tree_t* t, int root, uint32_t* out);
int    ms_get_witness_size(const ms_tree_t* t, int root, uint32_t* out);
/* the older() nodes whose value exceeds what BIP68 can express (Core warns) */
int    ms_unsafe_older(const ms_tree_t* t, int root, uint32_t* raw_out, int* time_based);
/* duplicate-key check, needed after ms_decode/ms_parse when key_cmp changed */
void   ms_duplicate_key_check(ms_tree_t* t, const ms_ctx_t* ctx, int root);
size_t ms_max_script_size(int tapscript);
#endif

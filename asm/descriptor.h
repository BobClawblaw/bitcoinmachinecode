/* descriptor.h -- output script descriptors (Core doc/descriptors.md).
 *
 * A descriptor is parsed into a small tree: script nodes (pk, pkh, wpkh,
 * combo, multi, sortedmulti, multi_a, sortedmulti_a, sh, wsh, tr, rawtr,
 * addr, raw, and the {a,b} branches of a taproot tree) over key
 * expressions (hex pubkeys, x-only keys, WIF private keys, xpub/xprv with
 * a derivation path, an optional key origin, and an optional range).
 * Expansion at an index yields the scriptPubKey(s) -- combo yields up to
 * four -- byte-identical to Core's Expand(). Private-key material is kept
 * so a descriptor that carries its own keys can sign. */
#ifndef BMC_DESCRIPTOR_H
#define BMC_DESCRIPTOR_H
#include "miniscript.h"
#define DESCR_MAX_NODES 96
#define DESCR_MAX_KEYS  64
#define DESCR_MAX_PATH  32
#define DESCR_NODE_KEYS 32
#define DESCR_MAX_SPK   520

enum { DK_HEX = 0, DK_WIF = 1, DK_XPUB = 2, DK_XPRV = 3, DK_MUSIG = 4 };
#define DESCR_MUSIG_MAX 32
#define DESCR_MP_MAX    8     /* items in one multipath specifier <a;b;...> (BIP389) */
typedef struct {
    int kind;
    int has_priv;                 /* WIF or xprv: descr_key_priv_at works */
    int compressed;               /* serialized pubkey form (WIF/hex) */
    int xonly;                    /* given as 32-byte x-only hex */
    int testnet;                  /* WIF 0xef / tpub / tprv */
    int tr_ctx;                   /* appears inside tr(): printed x-only */
    unsigned char priv[32];       /* WIF */
    unsigned char pub[65]; int publen;   /* hex key, or the extended key's compressed pubkey (xpub) */
    unsigned char ver[4], depth, parentfp[4]; unsigned child;   /* extended key header */
    unsigned char cc[32], xkey[32];                              /* chain code; xprv private key */
    unsigned path[DESCR_MAX_PATH]; int pathlen;
    int ranged, range_hard;       /* trailing range marker, hardened or not */
    int apostrophe;               /* hardened marker style: 1 = ', 0 = h */
    int has_origin; unsigned char origin_fp[4]; unsigned origin[DESCR_MAX_PATH]; int origin_len;
    /* DK_MUSIG (BIP390): the participants (indices into descr_t.keys, in the
     * written order; aggregation sorts them as Core does), and whether any of
     * them is ranged. The musig()'s own derivation lives in path/ranged above
     * (a synthetic xpub over the aggregate, unhardened steps only). */
    int musig_n; int musig_parts[DESCR_MUSIG_MAX]; int musig_parts_ranged;
    /* BIP389 multipath: path[mp_pos] is a placeholder holding mp_vals[d->mp_sel]
     * (descr_multipath_select rewrites it); mp_n = 0 when the key has none */
    int mp_pos, mp_n; unsigned mp_vals[DESCR_MP_MAX];
} descr_key_t;

enum { DN_PK = 1, DN_PKH, DN_WPKH, DN_COMBO, DN_MULTI, DN_SORTEDMULTI, DN_MULTI_A, DN_SORTEDMULTI_A,
       DN_SH, DN_WSH, DN_TR, DN_ADDR, DN_RAW, DN_RAWTR, DN_BRANCH, DN_MINISCRIPT };
typedef struct {
    int type;
    int k;                        /* multi threshold */
    int nkeys; int keys[DESCR_NODE_KEYS];   /* indices into descr_t.keys; tr: keys[0] = internal key */
    int child[2];                 /* sh/wsh: child[0]; tr: child[0] = tree root or -1; branch: both */
    int ms_root;                  /* DN_MINISCRIPT: root index in the descriptor's miniscript pool */
} descr_node_t;

/* A descriptor's miniscript pool (wsh(<miniscript>) and every tr() leaf that
 * is a miniscript share it; keys are descr_t.keys indices). Bounded: a
 * P2WSH miniscript is at most 3600 script bytes; a tapscript one is
 * accepted up to these pools ("Descriptor too complex" beyond). */
#define MS_DESC_NODES 4096
#define MS_DESC_SUBS  4096
#define MS_DESC_KEYS  4096

typedef struct {
    descr_node_t nodes[DESCR_MAX_NODES]; int nn;
    descr_key_t  keys[DESCR_MAX_KEYS];   int nk;
    int root;
    int ranged, has_priv, has_hardened_range;
    int mp_n, mp_sel;             /* multipath expansions (0/1 = none) and the one selected into the key paths */
    unsigned char raw[DESCR_MAX_SPK]; int rawlen;   /* addr()/raw() script */
    char checksum[9];             /* computed over the text (without #...) */
    int had_checksum;             /* the input carried one (and it matched) */
    char text[1400];              /* the input without its checksum */
    int ms_tapscript;             /* the pool's context: 1 under tr() */
    int32_t msnn, msns, msnk;
    ms_node_t msnodes[MS_DESC_NODES];
    int32_t   mssubs[MS_DESC_SUBS];
    int32_t   mskeys[MS_DESC_KEYS];
} descr_t;

typedef struct { unsigned char spk[DESCR_MAX_SPK]; int len; } descr_spk_t;

/* checksum of a descriptor body (no '#'); 0 if it contains a character
 * outside the descriptor charset */
int  descr_checksum(const char* span, char out[9]);
/* parse; a "#checksum" suffix is verified when present. 1 ok / 0 with err */
int  descr_parse(const char* text, descr_t* d, char* err, unsigned long errcap);
/* scriptPubKeys at range index idx (ignored when !ranged). Returns the
 * count (1, or 2/4 for combo), or -1 with the reason in descr_last_error() */
int  descr_expand(const descr_t* d, long idx, descr_spk_t* out, int cap);
const char* descr_last_error(void);
/* the descriptor text with private keys shown (with_priv) or replaced by
 * their public forms; no checksum. 1 ok / 0 if it does not fit */
int  descr_to_string(const descr_t* d, int with_priv, char* out, unsigned long cap);
/* key material at an index: pubkey (33/65, or 32 when x-only was given), or
 * the private key when the descriptor carries it */
int  descr_key_pub_at(const descr_t* d, int key, long idx, unsigned char pub[65], int* publen);
int  descr_key_priv_at(const descr_t* d, int key, long idx, unsigned char priv[32], int* compressed);
/* the redeemScript (sh) / witnessScript (wsh) at an index for the script
 * under the outermost wrapper, when there is one: 0 = none */
int  descr_inner_script_at(const descr_t* d, long idx, unsigned char* out, int cap, int* which /* 1 sh, 2 wsh, 3 sh(wsh) */);
/* 1 if the top-level expansion has a single address (Core ExtractDestination) */
int  descr_has_address(const descr_t* d);
/* BIP389 multipath (2026-09-01): a descriptor with /<a;b;...> derivation steps
 * parses as ONE descr_t whose key paths hold expansion `mp_sel` (0 after
 * parse); descr_multipath_n is the expansion count (1 when there is none)
 * and descr_multipath_select rewrites every key path to expansion `sel`
 * (-1 = none; 1 ok / 0 out of range). Every derivation/expansion/printing
 * function then sees that single-path descriptor. descr_to_string_multipath
 * prints the original multipath form. */
/* tr() tree leaves for the PSBT Updater (BIP371 fields) */
typedef struct { int depth, leaf_ver, slen, npath, ctrl_len; unsigned char script[1400]; unsigned char leaf_hash[32];
                 unsigned char path[128][32]; unsigned char ctrl[33 + 32 * 128]; } descr_leaf_t;
int  descr_tr_leaves(const descr_t* d, long idx, descr_leaf_t* out, int cap, unsigned char internal32[32], unsigned char root32[32], int* has_root, int* odd);
int  descr_multipath_n(const descr_t* d);
int  descr_multipath_select(descr_t* d, int sel);
int  descr_to_string_multipath(const descr_t* d, int with_priv, char* out, unsigned long cap);

/* ---- miniscript access (the PSBT signer) ----
 * The miniscript view of a descriptor's pool, and the key context that
 * derives/prints its keys at range index idx (tr = x-only keys). Both point
 * INTO d; keep d alive while using them. */
typedef struct { const descr_t* d; long idx; int tr; int with_priv; char* err; unsigned long errcap; int key_err; } descr_msuser_t;
void descr_ms_tree(const descr_t* d, ms_tree_t* out);
void descr_ms_ctx(const descr_t* d, long idx, int with_priv, descr_msuser_t* u, ms_ctx_t* ctx);
/* the miniscript root of the top-level wsh(), or of the single tr() leaf
 * whose script equals leaf[0..leaflen) at idx; -1 if none */
int  descr_ms_root(const descr_t* d, long idx, const unsigned char* leaf, int leaflen);

/* ---- musig() (BIP390) ----
 * For key `key` (must be DK_MUSIG) at range index idx: the untweaked,
 * underived aggregate (33 bytes), the participants sorted as Core sorts them
 * (what PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS carries), the derived key the
 * script uses (33 bytes; equal to the aggregate without derivation) and the
 * derivation path applied to the synthetic xpub (the range index appended
 * when the musig() is ranged). 1 ok / 0 not a musig key or derivation failed. */
int  descr_musig_info(const descr_t* d, int key, long idx, unsigned char agg33[33],
                      unsigned char (*parts)[33], int* nparts, unsigned char derived33[33], unsigned* path, int* plen);
/* the key index of a top-level tr()/rawtr() internal key, -1 otherwise */
int  descr_top_key(const descr_t* d);
#endif

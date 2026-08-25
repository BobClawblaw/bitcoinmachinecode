/* rpc_chain.c -- blockchain-query / node-status JSON-RPC methods over the
 * on-disk archive. See rpc_chain.h for why this is a separate, read-only
 * module (bitcoin_rpcd is a standalone process with no in-memory chain).
 *
 * Implemented (Core v31 shapes, src/rpc/blockchain.cpp + rawtransaction.cpp
 * + core_io.cpp):
 *   getblockcount, getbestblockhash, getblockhash, getblockheader, getblock,
 *   getblockchaininfo, getdifficulty, getrawtransaction (block-hash form),
 *   gettxoutproof / verifytxoutproof (BIP37 partial merkle tree; proofs are
 *   byte-identical to Core's), decodescript (util; identical to Core modulo
 *   the omitted descriptor), createmultisig (util; identical modulo the
 *   omitted descriptor), uptime, stop.
 *
 * How chain state reaches this process: bitcoin_store.asm's store_init +
 * store_reload on -datadir's index.dat (positional 48-byte records:
 * [0..32) hash, [32..36) file_no, [36..44) data_pos, [44..48) data_size),
 * bitcoin_store_fast.asm's pread-based read path for block bytes, a
 * bitcoin_idx.asm hash->height table that THIS module fills from the raw
 * record bytes (built at open, extended incrementally as the live daemon
 * appends), chainwork.dat
 * (positional 16-byte LE cumulative work; recomputed from headers when the
 * file is absent/short), headers.dat (112-byte records) for the "headers"
 * count. store_reload is called on every request so the answers track the
 * live daemon's appends without a restart.
 *
 * Byte order, verified against the production archive rather than trusted
 * from comments: index.dat stores the hash in WIRE (raw sha256d) order.
 * bitcoin_idx.asm's idx_build_from_file comment claims DISPLAY order and
 * byte-reverses every record before idx_put; that is inconsistent with what
 * the writers actually persist, so this module deliberately does not use it
 * -- it keys the table on the raw record bytes and reverses only the RPC
 * parameter (display order) at lookup time, which is self-consistent
 * whichever way the archive was written. RPC output reverses record bytes
 * into display order.
 *
 * Known, deliberate divergences from Core (each a fabrication we refuse to
 * make rather than a bug):
 *   - scriptPubKey "desc": Core emits an inferred output descriptor with
 *     checksum; we have no descriptor engine, so the key is OMITTED.
 *   - "address" for witness_unknown / anchor outputs is omitted (no bech32m
 *     encoder for unknown versions in wallet_script_to_address).
 *   - getblockchaininfo "verificationprogress" is blocks/headers, not Core's
 *     tx-count-weighted GuessVerificationProgress. "initialblockdownload" is
 *     "tip older than 24h" (Core also requires min chainwork).
 *   - getblock verbosity 3 behaves like 2 (no undo data => no prevout/fee);
 *     this matches Core's own output when undo data is unavailable.
 *   - uptime/stop apply to THIS RPC process (bitcoin_rpcd), which is not the
 *     block-relaying node; stop's reply names this project, not Core.
 */
#include "rpc_chain.h"
#include "rpc_node.h"     /* rpc_mempool_hooks: getblocktemplate reads the shared pool */
#include "mempool_entry.h"
#include "rpc_commands.h"
#include "version_gen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>

typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;

/* ---- asm primitives ---- */
extern int  store_init(void* st);
extern int  store_reload(void* st);
extern int  store_get_at(void* st, u64 height, u64 out_meta[3]);
extern void store_rd_init(void* st);
extern int  store_rd_fd(void* st, unsigned file_no);
extern long store_read_at(void* st, unsigned long height, void* buf, unsigned long cap);
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const u8 hash[32], long height);
extern int  idx_get(void* idx, const u8 hash[32], long* height);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);
extern void sha256d(u8 out[32], const void* data, unsigned long len);
extern void block_work(u8 work[16], unsigned bits);
extern void chainwork_add(u8 out[16], const u8 a[16], const u8 b[16]);
extern int  wallet_script_to_address(char* out, long cap, const u8* script, long slen);
extern int  wallet_validate_address(const char* str, int* type_, unsigned char* version,
                                    unsigned char h160[20], unsigned char prog32[32]);
extern void hash160(u8 out[20], const void* in, long long len);
extern void sha256_full(u8 out[32], const void* msg, long long len);

/* ---- module state ---- */
#define ST_SIZE 4096
static u8   g_st[ST_SIZE];
static int  g_open = 0;
static void* g_idx = NULL;
static unsigned long g_idx_slots = 0;
static long g_idx_tip = -1;          /* highest height folded into g_idx */
static int  g_cw_fd = -1;            /* chainwork.dat, read-only, or -1 */
static u8 (*g_cw_cache)[16] = NULL;  /* computed cumulative work fallback */
static long g_cw_cache_n = 0;        /* entries valid in g_cw_cache */
static long g_cw_cache_cap = 0;
static long g_prune_mib = 0;
static time_t g_start = 0;
static u8*  g_blockbuf = NULL;
#define BLOCKBUF_CAP (8u<<20)

static void default_stop(void){ kill(getpid(), SIGTERM); }
static void (*g_stop_fn)(void) = default_stop;
void rpc_chain_set_stop_handler(void (*fn)(void)){ g_stop_fn = fn ? fn : default_stop; }
void rpc_chain_set_prune_mib(long mib){ g_prune_mib = mib; }

#define ST_IDX_FD(st)     (*(long*)((u8*)(st)+8))
#define ST_TIP(st)        (*(int*)((u8*)(st)+24))
#define ST_PRUNE_H(st)    (*(int*)((u8*)(st)+48))

/* ---- small helpers ---- */
static const char HEXD[] = "0123456789abcdef";
static void hex_of(char* out, const u8* b, size_t n){
    for (size_t i = 0; i < n; i++){ out[i*2] = HEXD[b[i]>>4]; out[i*2+1] = HEXD[b[i]&15]; }
    out[n*2] = 0;
}
static void hex_rev(char* out, const u8* b, size_t n){ /* display order of a wire hash */
    for (size_t i = 0; i < n; i++){ u8 c = b[n-1-i]; out[i*2] = HEXD[c>>4]; out[i*2+1] = HEXD[c&15]; }
    out[n*2] = 0;
}
static int hexv(char c){
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int is_hex_str(const char* s){ for (; *s; s++) if (hexv(*s) < 0) return 0; return 1; }
static u32 rd32(const u8* p){ return (u32)p[0] | ((u32)p[1]<<8) | ((u32)p[2]<<16) | ((u32)p[3]<<24); }
static u64 rd64(const u8* p){ u64 v = 0; for (int i = 7; i >= 0; i--) v = (v<<8) | p[i]; return v; }
static u64 read_varint(const u8* p, const u8* end, u64* consumed){
    if (p >= end){ *consumed = 0; return 0; }
    u8 c = p[0];
    if (c < 0xfd){ *consumed = 1; return c; }
    if (c == 0xfd){ if (p+3 > end){ *consumed = 0; return 0; } *consumed = 3; return (u64)p[1] | ((u64)p[2]<<8); }
    if (c == 0xfe){ if (p+5 > end){ *consumed = 0; return 0; } *consumed = 5; return rd32(p+1); }
    if (p+9 > end){ *consumed = 0; return 0; }
    *consumed = 9; return rd64(p+1);
}
static size_t varint_size(u64 n){ return n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffffULL ? 5 : 9; }

/* Core ParseHashV: "parameter N must be of length 64 (not M, for 'x')" /
 * "parameter N must be hexadecimal string (not 'x')". Writes the 32-byte
 * DISPLAY-order bytes to out. */
static char g_hasherr[256];
static int parse_hash_param(const char* s, int pnum, u8 out[32], long* ec, const char** em){
    size_t n = strlen(s);
    if (n != 64){
        snprintf(g_hasherr, sizeof g_hasherr, "parameter %d must be of length 64 (not %zu, for '%s')", pnum, n, s);
        *ec = -8; *em = g_hasherr; return 0;
    }
    if (!is_hex_str(s)){
        snprintf(g_hasherr, sizeof g_hasherr, "parameter %d must be hexadecimal string (not '%s')", pnum, s);
        *ec = -8; *em = g_hasherr; return 0;
    }
    for (int i = 0; i < 32; i++) out[i] = (u8)((hexv(s[i*2])<<4) | hexv(s[i*2+1]));
    return 1;
}

/* ---- archive access ---- */
static int read_idx_rec(long h, u8 rec[48]){
    long fd = ST_IDX_FD(g_st);
    if (fd < 0) return 0;
    if (pread(fd, rec, 48, (off_t)h * 48) != 48) return 0;
    return 1;
}
static int rec_present(const u8 rec[48]){ return rd32(rec) != 0; }

/* Load index.dat records [from, to] into the table, keyed by the RAW record
 * hash bytes (wire order). Returns 0 ok / 2 table full. */
static int idx_load_range(void* idx, long from, long to){
    long fd = ST_IDX_FD(g_st);
    enum { CHUNK = 4096 };
    static u8 buf[CHUNK * 48];
    for (long h = from; h <= to; h += CHUNK){
        long n = to - h + 1; if (n > CHUNK) n = CHUNK;
        ssize_t got = pread(fd, buf, (size_t)n * 48, (off_t)h * 48);
        if (got < 0) return 0;
        long have = got / 48;
        for (long i = 0; i < have; i++){
            const u8* rec = buf + i * 48;
            if (!rec_present(rec)) continue;
            if (idx_put(idx, rec, h + i) == 2) return 2;
        }
    }
    return 0;
}
static int idx_alloc(unsigned long slots){
    void* n = malloc(24 + (size_t)slots*48 + 64);
    if (!n) return 0;
    idx_init(n, slots);
    free(g_idx); g_idx = n; g_idx_slots = slots; g_idx_tip = -1;
    return 1;
}
/* Fold every height in (g_idx_tip, tip] into the hash index, rebuilding
 * bigger if it fills. */
static void idx_sync(long tip){
    if (!g_idx) return;
    int r = idx_load_range(g_idx, g_idx_tip + 1, tip);
    if (r == 2){
        if (!idx_alloc(g_idx_slots * 2)) return;
        if (idx_load_range(g_idx, 0, tip) != 0) return;
    }
    g_idx_tip = tip;
}

/* Re-sync with the live daemon's appends. Returns current tip (-1 empty). */
static long refresh(void){
    store_reload(g_st);
    long tip = ST_TIP(g_st);
    if (tip > g_idx_tip) idx_sync(tip);
    return tip;
}

int rpc_chain_open(const char* dir){
    if (dir && chdir(dir) != 0) return 0;
    if (g_start == 0) g_start = time(NULL);
    memset(g_st, 0, sizeof g_st);
    struct stat sb;
    if (stat("index.dat", &sb) != 0) return 0;  /* store_init would create an empty one; don't */
    if (store_init(g_st) != 1) return 0;
    store_reload(g_st);
    store_rd_init(g_st);
    long tip = ST_TIP(g_st);
    unsigned long slots = 1u << 16;
    while (slots < (unsigned long)(tip + 1) * 4) slots <<= 1;
    if (!idx_alloc(slots)) return 0;
    idx_sync(tip);
    g_cw_fd = open("chainwork.dat", O_RDONLY);
    if (!g_blockbuf) g_blockbuf = malloc(BLOCKBUF_CAP);
    g_open = g_blockbuf != NULL;
    return g_open;
}

/* Records are keyed by their raw (wire-order) bytes; an RPC hash string is
 * display order, so reverse it to look up. */
static int height_by_hash(const u8 display[32], long* h){
    u8 wire[32]; for (int i = 0; i < 32; i++) wire[i] = display[31-i];
    return idx_get(g_idx, wire, h) == 1;
}

/* First `n` bytes of block at `h` (header + tx-count prefix). 1 ok / -3 pruned
 * or hole / -1 error. */
static int read_block_prefix(long h, u8* out, size_t n){
    u64 meta[3];
    int r = store_get_at(g_st, (u64)h, meta);
    if (r != 1) return r == -3 ? -3 : -1;
    if (meta[1] == 0) return -3;                       /* hole record */
    if (n > meta[1]) n = (size_t)meta[1];
    int fd = store_rd_fd(g_st, (unsigned)meta[2]);
    if (fd < 0) return -1;
    if (pread(fd, out, n, (off_t)(meta[0] + 8)) != (ssize_t)n) return -1;
    return 1;
}
/* Whole block into g_blockbuf. Returns size, or -3 unavailable / -1 error. */
static long read_block(long h){
    long r = store_read_at(g_st, (unsigned long)h, g_blockbuf, BLOCKBUF_CAP);
    if (r == -3 || r == -2) return -3;
    if (r < 0) return -1;
    if (r < 81) return -3; /* hole / short */
    return r;
}

/* ---- chainwork ---- */
static int chainwork_at(long h, u8 out[16]){
    if (g_cw_fd >= 0 && pread(g_cw_fd, out, 16, (off_t)h * 16) == 16) return 1;
    /* fallback: accumulate from headers, cached */
    if (h >= g_cw_cache_n){
        if (h >= g_cw_cache_cap){
            long cap = g_cw_cache_cap ? g_cw_cache_cap : 4096;
            while (cap <= h) cap *= 2;
            void* n = realloc(g_cw_cache, (size_t)cap * 16);
            if (!n) return 0;
            g_cw_cache = n; g_cw_cache_cap = cap;
        }
        for (long i = g_cw_cache_n; i <= h; i++){
            u8 hdr[80];
            if (read_block_prefix(i, hdr, 80) != 1) return 0;
            u8 w[16]; block_work(w, rd32(hdr + 72));
            if (i == 0) memcpy(g_cw_cache[0], w, 16);
            else chainwork_add(g_cw_cache[i], g_cw_cache[i-1], w);
            g_cw_cache_n = i + 1;
        }
    }
    memcpy(out, g_cw_cache[h], 16);
    return 1;
}
static void chainwork_hex(const u8 w[16], char out[65]){
    memset(out, '0', 32);
    hex_rev(out + 32, w, 16);
}

/* ---- header math (Core GetDifficulty / DeriveTarget / GetMedianTimePast) ---- */
static double difficulty_of(u32 bits){
    int shift = (bits >> 24) & 0xff;
    double d = (double)0x0000ffff / (double)(bits & 0x00ffffff);
    while (shift < 29){ d *= 256.0; shift++; }
    while (shift > 29){ d /= 256.0; shift--; }
    return d;
}
static void target_bytes(u32 bits, u8 t[32]){ /* arith_uint256::SetCompact, big-endian */
    memset(t, 0, 32);
    int size = bits >> 24;
    u32 word = bits & 0x007fffff;
    if (size <= 3){
        word >>= 8 * (3 - size);
        t[31] = (u8)word; t[30] = (u8)(word>>8); t[29] = (u8)(word>>16);
    } else {
        int shift = size - 3; /* bytes */
        /* word occupies 3 bytes, placed so its LSB lands `shift` bytes from the end */
        for (int i = 0; i < 3; i++){
            int pos = 31 - shift - i;
            if (pos >= 0 && pos < 32) t[pos] = (u8)(word >> (8*i));
        }
    }
}
static void target_hex(u32 bits, char out[65]){
    u8 t[32]; target_bytes(bits, t); hex_of(out, t, 32);
}
static int cmp_u32(const void* a, const void* b){ u32 x = *(const u32*)a, y = *(const u32*)b; return x < y ? -1 : x > y; }
static long median_time_past(long h){
    u32 t[11]; int n = 0;
    for (long i = h; i >= 0 && n < 11; i--){
        u8 hdr[80];
        if (read_block_prefix(i, hdr, 80) != 1) break;
        t[n++] = rd32(hdr + 68);
    }
    if (n == 0) return 0;
    qsort(t, (size_t)n, sizeof t[0], cmp_u32);
    return (long)t[n/2];
}
/* UniValue::setFloat: ostringstream << setprecision(16) */
static rj_val* rj_double(double v){ return rj_numf("%.16g", v); }

/* ---- transaction walker (witness-aware) ---- */
#define TX_MAX_IN  65536
typedef struct {
    u32 version, locktime;
    int segwit;
    size_t len, stripped;           /* full serialized size; size without marker/flag/witness */
    u64 n_in, n_out;
    const u8* vin;                  /* start of input count varint */
    const u8* vout;                 /* start of output count varint */
    const u8* wit;                  /* start of witness section (segwit only) */
} txw_t;

/* Walks one tx at p; returns 1 and fills w, or 0 if malformed/truncated. */
static int tx_walk(const u8* p, const u8* end, txw_t* w){
    const u8* s = p;
    u64 c;
    if (p + 4 > end) return 0;
    w->version = rd32(p); p += 4;
    w->segwit = 0;
    if (p + 2 <= end && p[0] == 0x00 && p[1] != 0x00){ w->segwit = 1; p += 2; }
    w->vin = p;
    w->n_in = read_varint(p, end, &c); if (!c) return 0; p += c;
    if (w->n_in > TX_MAX_IN) return 0;
    for (u64 i = 0; i < w->n_in; i++){
        if (p + 36 > end) return 0; p += 36;
        u64 sl = read_varint(p, end, &c); if (!c) return 0; p += c;
        { u64 avail=(u64)(end - p); if (avail < sl || avail - sl < 4) return 0; } p += sl + 4;  /* split bound (incident #38) */
    }
    w->vout = p;
    w->n_out = read_varint(p, end, &c); if (!c) return 0; p += c;
    for (u64 i = 0; i < w->n_out; i++){
        if (p + 8 > end) return 0; p += 8;
        u64 sl = read_varint(p, end, &c); if (!c) return 0; p += c;
        if ((u64)(end - p) < sl) return 0; p += sl;
    }
    size_t witbytes = 0;
    w->wit = NULL;
    if (w->segwit){
        w->wit = p;
        for (u64 i = 0; i < w->n_in; i++){
            u64 ni = read_varint(p, end, &c); if (!c) return 0; p += c;
            for (u64 j = 0; j < ni; j++){
                u64 il = read_varint(p, end, &c); if (!c) return 0; p += c;
                if ((u64)(end - p) < il) return 0; p += il;
            }
        }
        witbytes = (size_t)(p - w->wit);
    }
    if (p + 4 > end) return 0;
    w->locktime = rd32(p); p += 4;
    w->len = (size_t)(p - s);
    w->stripped = w->segwit ? w->len - 2 - witbytes : w->len;
    return 1;
}

/* ---- script rendering (Core ScriptToAsmStr / Solver / GetTxnOutputType) ---- */
static const char* opname(u8 op){
    static const char* names[256] = {0};
    static int init = 0;
    if (!init){
        init = 1;
        for (int i = 0; i < 256; i++) names[i] = NULL;
        names[0x00]="0"; names[0x4c]="OP_PUSHDATA1"; names[0x4d]="OP_PUSHDATA2"; names[0x4e]="OP_PUSHDATA4";
        names[0x4f]="-1"; names[0x50]="OP_RESERVED";
        static const char* small[16] = {"1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16"};
        for (int i = 0; i < 16; i++) names[0x51+i] = small[i];
        names[0x61]="OP_NOP"; names[0x62]="OP_VER"; names[0x63]="OP_IF"; names[0x64]="OP_NOTIF"; names[0x65]="OP_VERIF";
        names[0x66]="OP_VERNOTIF"; names[0x67]="OP_ELSE"; names[0x68]="OP_ENDIF"; names[0x69]="OP_VERIFY"; names[0x6a]="OP_RETURN";
        names[0x6b]="OP_TOALTSTACK"; names[0x6c]="OP_FROMALTSTACK"; names[0x6d]="OP_2DROP"; names[0x6e]="OP_2DUP"; names[0x6f]="OP_3DUP";
        names[0x70]="OP_2OVER"; names[0x71]="OP_2ROT"; names[0x72]="OP_2SWAP"; names[0x73]="OP_IFDUP"; names[0x74]="OP_DEPTH";
        names[0x75]="OP_DROP"; names[0x76]="OP_DUP"; names[0x77]="OP_NIP"; names[0x78]="OP_OVER"; names[0x79]="OP_PICK";
        names[0x7a]="OP_ROLL"; names[0x7b]="OP_ROT"; names[0x7c]="OP_SWAP"; names[0x7d]="OP_TUCK"; names[0x7e]="OP_CAT";
        names[0x7f]="OP_SUBSTR"; names[0x80]="OP_LEFT"; names[0x81]="OP_RIGHT"; names[0x82]="OP_SIZE"; names[0x83]="OP_INVERT";
        names[0x84]="OP_AND"; names[0x85]="OP_OR"; names[0x86]="OP_XOR"; names[0x87]="OP_EQUAL"; names[0x88]="OP_EQUALVERIFY";
        names[0x89]="OP_RESERVED1"; names[0x8a]="OP_RESERVED2"; names[0x8b]="OP_1ADD"; names[0x8c]="OP_1SUB"; names[0x8d]="OP_2MUL";
        names[0x8e]="OP_2DIV"; names[0x8f]="OP_NEGATE"; names[0x90]="OP_ABS"; names[0x91]="OP_NOT"; names[0x92]="OP_0NOTEQUAL";
        names[0x93]="OP_ADD"; names[0x94]="OP_SUB"; names[0x95]="OP_MUL"; names[0x96]="OP_DIV"; names[0x97]="OP_MOD";
        names[0x98]="OP_LSHIFT"; names[0x99]="OP_RSHIFT"; names[0x9a]="OP_BOOLAND"; names[0x9b]="OP_BOOLOR"; names[0x9c]="OP_NUMEQUAL";
        names[0x9d]="OP_NUMEQUALVERIFY"; names[0x9e]="OP_NUMNOTEQUAL"; names[0x9f]="OP_LESSTHAN"; names[0xa0]="OP_GREATERTHAN";
        names[0xa1]="OP_LESSTHANOREQUAL"; names[0xa2]="OP_GREATERTHANOREQUAL"; names[0xa3]="OP_MIN"; names[0xa4]="OP_MAX"; names[0xa5]="OP_WITHIN";
        names[0xa6]="OP_RIPEMD160"; names[0xa7]="OP_SHA1"; names[0xa8]="OP_SHA256"; names[0xa9]="OP_HASH160"; names[0xaa]="OP_HASH256";
        names[0xab]="OP_CODESEPARATOR"; names[0xac]="OP_CHECKSIG"; names[0xad]="OP_CHECKSIGVERIFY"; names[0xae]="OP_CHECKMULTISIG";
        names[0xaf]="OP_CHECKMULTISIGVERIFY"; names[0xb0]="OP_NOP1"; names[0xb1]="OP_CHECKLOCKTIMEVERIFY"; names[0xb2]="OP_CHECKSEQUENCEVERIFY";
        names[0xb3]="OP_NOP4"; names[0xb4]="OP_NOP5"; names[0xb5]="OP_NOP6"; names[0xb6]="OP_NOP7"; names[0xb7]="OP_NOP8";
        names[0xb8]="OP_NOP9"; names[0xb9]="OP_NOP10"; names[0xba]="OP_CHECKSIGADD"; names[0xff]="OP_INVALIDOPCODE";
    }
    return names[op] ? names[op] : "OP_UNKNOWN";
}
/* CScript::GetOp. Returns 1 ok (opcode, push data span), 0 error. */
static int script_getop(const u8** pc, const u8* end, u8* op, const u8** data, size_t* dlen){
    if (*pc >= end) return 0;
    u8 o = *(*pc)++;
    *op = o; *data = NULL; *dlen = 0;
    if (o <= 0x4e){
        size_t n;
        if (o < 0x4c) n = o;
        else if (o == 0x4c){ if (end - *pc < 1) return 0; n = **pc; *pc += 1; }
        else if (o == 0x4d){ if (end - *pc < 2) return 0; n = (*pc)[0] | ((*pc)[1]<<8); *pc += 2; }
        else { if (end - *pc < 4) return 0; n = rd32(*pc); *pc += 4; }
        if ((size_t)(end - *pc) < n) return 0;
        *data = *pc; *dlen = n; *pc += n;
    }
    return 1;
}
/* CScriptNum(vch, false).getint() for |vch| <= 4 */
static long scriptnum_int(const u8* d, size_t n){
    if (n == 0) return 0;
    long long v = 0;
    for (size_t i = 0; i < n; i++) v |= (long long)d[i] << (8*i);
    if (d[n-1] & 0x80) v = -(v & ~(0x80LL << (8*(n-1))));
    if (v > INT_MAX) return INT_MAX;
    if (v < INT_MIN) return INT_MIN;
    return (long)v;
}
/* IsValidSignatureEncoding (strict DER, Core interpreter.cpp) */
static int der_sig_ok(const u8* s, size_t n){
    if (n < 9 || n > 73) return 0;
    if (s[0] != 0x30 || s[1] != n - 3) return 0;
    size_t lr = s[3]; if (5 + lr >= n) return 0;
    size_t ls = s[5 + lr]; if (lr + ls + 7 != n) return 0;
    if (s[2] != 0x02 || lr == 0 || (s[4] & 0x80)) return 0;
    if (lr > 1 && s[4] == 0 && !(s[5] & 0x80)) return 0;
    if (s[lr+4] != 0x02 || ls == 0 || (s[lr+6] & 0x80)) return 0;
    if (ls > 1 && s[lr+6] == 0 && !(s[lr+7] & 0x80)) return 0;
    return 1;
}
static const char* sighash_name(u8 t){
    switch (t){
        case 0x01: return "ALL"; case 0x02: return "NONE"; case 0x03: return "SINGLE";
        case 0x81: return "ALL|ANYONECANPAY"; case 0x82: return "NONE|ANYONECANPAY"; case 0x83: return "SINGLE|ANYONECANPAY";
        default: return NULL;
    }
}
static int script_unspendable(const u8* s, size_t n){ return (n > 0 && s[0] == 0x6a) || n > 10000; }

static char* script_asm(const u8* s, size_t n, int sighash_decode){
    size_t cap = n * 3 + 64;
    char* out = malloc(cap); if (!out) return NULL;
    size_t len = 0; out[0] = 0;
    const u8* pc = s; const u8* end = s + n;
    int unspendable = script_unspendable(s, n);
    while (pc < end){
        if (len){ out[len++] = ' '; out[len] = 0; }
        u8 op; const u8* d; size_t dl;
        if (!script_getop(&pc, end, &op, &d, &dl)){ len += (size_t)snprintf(out+len, cap-len, "[error]"); return out; }
        if (op <= 0x4e){
            if (dl <= 4){ len += (size_t)snprintf(out+len, cap-len, "%ld", scriptnum_int(d, dl)); }
            else {
                size_t hl = dl; const char* tag = NULL;
                if (sighash_decode && !unspendable && der_sig_ok(d, dl) && (tag = sighash_name(d[dl-1])) != NULL) hl = dl - 1;
                if (len + hl*2 + 32 >= cap){ cap = len + hl*2 + 64; char* n2 = realloc(out, cap); if (!n2){ free(out); return NULL; } out = n2; }
                hex_of(out+len, d, hl); len += hl*2;
                if (tag){ len += (size_t)snprintf(out+len, cap-len, "[%s]", tag); }
            }
        } else {
            len += (size_t)snprintf(out+len, cap-len, "%s", opname(op));
        }
    }
    return out;
}
static int pubkey_size_ok(const u8* p, size_t n){
    return (n == 33 && (p[0] == 0x02 || p[0] == 0x03)) || (n == 65 && p[0] == 0x04);
}
static int small_int(u8 op, int* v){
    if (op == 0x00){ *v = 0; return 1; }
    if (op >= 0x51 && op <= 0x60){ *v = op - 0x50; return 1; }
    return 0;
}
static const char* script_type(const u8* s, size_t n){
    if (n == 25 && s[0]==0x76 && s[1]==0xa9 && s[2]==0x14 && s[23]==0x88 && s[24]==0xac) return "pubkeyhash";
    if (n == 23 && s[0]==0xa9 && s[1]==0x14 && s[22]==0x87) return "scripthash";
    if (n == 4 && s[0]==0x51 && s[1]==0x02 && s[2]==0x4e && s[3]==0x73) return "anchor";
    if (n >= 4 && n <= 42 && (s[0] == 0x00 || (s[0] >= 0x51 && s[0] <= 0x60)) && s[1] >= 2 && s[1] <= 40 && (size_t)s[1] + 2 == n){
        int ver = s[0] == 0 ? 0 : s[0] - 0x50;
        if (ver == 0 && s[1] == 20) return "witness_v0_keyhash";
        if (ver == 0 && s[1] == 32) return "witness_v0_scripthash";
        if (ver == 1 && s[1] == 32) return "witness_v1_taproot";
        if (ver != 0) return "witness_unknown";
    }
    if ((n == 35 && s[0]==33 && s[34]==0xac && pubkey_size_ok(s+1, 33)) || (n == 67 && s[0]==65 && s[66]==0xac && pubkey_size_ok(s+1, 65))) return "pubkey";
    if (n >= 1 && s[0] == 0x6a){
        const u8* pc = s + 1; u8 op; const u8* d; size_t dl; int ok = 1;
        while (pc < s + n){ if (!script_getop(&pc, s+n, &op, &d, &dl) || op > 0x60){ ok = 0; break; } }
        if (ok) return "nulldata";
    }
    if (n >= 3 && s[n-1] == 0xae){
        int k, m; const u8* pc = s; u8 op; const u8* d; size_t dl;
        if (small_int(s[0], &k) && small_int(s[n-2], &m)){
            pc = s + 1; int keys = 0, ok = 1;
            while (pc < s + n - 2){
                if (!script_getop(&pc, s+n-2, &op, &d, &dl) || op > 0x4e || !pubkey_size_ok(d, dl)){ ok = 0; break; }
                keys++;
            }
            if (ok && keys == m && k >= 1 && k <= m) return "multisig";
        }
    }
    return "nonstandard";
}
static char* desc_inner_of(const u8* s, size_t n);        /* InferDescriptor, defined below */
static char* desc_with_checksum(const char* inner);

/* ScriptToUniv(include_hex=true, include_address=true). want_desc adds the
 * inferred "desc" (after asm) as Core does for tx outputs; decodescript's
 * segwit passes 0 because it supplies its own provider-aware desc. */
static rj_val* script_pubkey_json_x(const u8* s, size_t n, int want_desc){
    rj_val* o = rj_obj();
    char* a = script_asm(s, n, 0);
    rj_obj_set(o, "asm", rj_str(a ? a : "")); free(a);
    if (want_desc){ char* di = desc_inner_of(s, n); char* dc = desc_with_checksum(di);
                    if (dc){ rj_obj_set(o, "desc", rj_str(dc)); free(dc); } free(di); }
    char* h = malloc(n*2 + 1); if (h){ hex_of(h, s, n); rj_obj_set(o, "hex", rj_str(h)); free(h); }
    const char* type = script_type(s, n);
    if (strcmp(type, "pubkey") != 0){
        char addr[128]; addr[0] = 0;
        if (wallet_script_to_address(addr, sizeof addr, s, (long)n) > 0 && addr[0]) rj_obj_set(o, "address", rj_str(addr));
    }
    rj_obj_set(o, "type", rj_str(type));
    return o;
}

/* ---- TxToUniv (core_io.cpp), include_hex=true, no undo data ---- */
static rj_val* amount_json(u64 sats){ return rj_numf("%llu.%08llu", sats / 100000000ULL, sats % 100000000ULL); }

/* Read the per-input prevout VALUES from undo_<h>.dat, in block order (all
 * non-coinbase inputs, tx-by-tx). Lets getblock v2 report per-tx fees without
 * a UTXO lookup. Record layout (daemon/undo_log.c): txid[32] index(4)
 * value(8) height(4) is_coinbase(1) script_len(2) script[len] -- 51-byte
 * header + script. Returns count, or -1 if the file is absent/pruned (Core
 * always has undo; we keep only a window, so fees are recent-blocks-only). */
static long undo_block_values(long h, u64* out, long cap){
    char path[64]; snprintf(path, sizeof path, "undo_%ld.dat", h);
    int fd = open(path, O_RDONLY); if (fd < 0) return -1;
    struct stat sb; if (fstat(fd, &sb) != 0 || sb.st_size <= 0){ close(fd); return -1; }
    u8* buf = malloc((size_t)sb.st_size); if (!buf){ close(fd); return -1; }
    long got = 0, off = 0; ssize_t rd;
    while (got < sb.st_size && (rd = pread(fd, buf+got, (size_t)(sb.st_size-got), got)) > 0) got += rd;
    close(fd);
    if (got != sb.st_size){ free(buf); return -1; }
    long n = 0;
    while (off + 51 <= sb.st_size && n < cap){
        out[n++] = rd64(buf + off + 36);            /* value at offset 36 */
        u32 slen = (u32)buf[off+49] | ((u32)buf[off+50] << 8);
        off += 51 + (long)slen;
    }
    free(buf);
    return (off == sb.st_size) ? n : -1;            /* trailing garbage -> unusable */
}

/* Like undo_block_values but also returns each spent prevout's script length
 * (for getblockstats' utxo_size_inc). Fills vals[] and slens[] in block order;
 * returns count or -1 (absent/pruned/garbage). */
static long undo_block_prevouts(long h, u64* vals, u32* slens, long cap){
    char path[64]; snprintf(path, sizeof path, "undo_%ld.dat", h);
    int fd = open(path, O_RDONLY); if (fd < 0) return -1;
    struct stat sb; if (fstat(fd, &sb) != 0 || sb.st_size <= 0){ close(fd); return -1; }
    u8* buf = malloc((size_t)sb.st_size); if (!buf){ close(fd); return -1; }
    long got = 0, off = 0; ssize_t rd;
    while (got < sb.st_size && (rd = pread(fd, buf+got, (size_t)(sb.st_size-got), got)) > 0) got += rd;
    close(fd);
    if (got != sb.st_size){ free(buf); return -1; }
    long n = 0;
    while (off + 51 <= sb.st_size && n < cap){
        u32 slen = (u32)buf[off+49] | ((u32)buf[off+50] << 8);
        vals[n] = rd64(buf + off + 36);
        slens[n] = slen;
        n++;
        off += 51 + (long)slen;
    }
    free(buf);
    return (off == sb.st_size) ? n : -1;
}

static rj_val* tx_to_json(const u8* tx, const txw_t* w, long long in_total){
    rj_val* o = rj_obj();
    u8 txid[32], wtxid[32]; char hx[65];
    u8* scratch = malloc(w->len ? w->len : 1);
    if (scratch){ tx_txid(txid, tx, w->len, scratch, w->len); free(scratch); } else memset(txid, 0, 32);
    if (w->segwit) sha256d(wtxid, tx, w->len); else memcpy(wtxid, txid, 32);
    hex_rev(hx, txid, 32);  rj_obj_set(o, "txid", rj_str(hx));
    hex_rev(hx, wtxid, 32); rj_obj_set(o, "hash", rj_str(hx));
    rj_obj_set(o, "version", rj_numf("%u", w->version));
    size_t weight = w->stripped * 3 + w->len;
    rj_obj_set(o, "size", rj_numf("%zu", w->len));
    rj_obj_set(o, "vsize", rj_numf("%zu", (weight + 3) / 4));
    rj_obj_set(o, "weight", rj_numf("%zu", weight));
    rj_obj_set(o, "locktime", rj_numf("%u", w->locktime));

    int coinbase = 0;
    const u8* p = w->vin; u64 c; read_varint(p, tx + w->len, &c); p += c;
    const u8* wp = w->wit;
    rj_val* vin = rj_arr();
    for (u64 i = 0; i < w->n_in; i++){
        rj_val* in = rj_obj();
        const u8* prev = p; u32 vout = rd32(p + 32); p += 36;
        u64 sl = read_varint(p, tx + w->len, &c); p += c;
        const u8* ss = p; p += sl;
        u32 seq = rd32(p); p += 4;
        static const u8 zero32[32] = {0};
        if (i == 0 && vout == 0xffffffffu && memcmp(prev, zero32, 32) == 0) coinbase = 1;
        if (coinbase){
            char* h = malloc(sl*2 + 1); if (h){ hex_of(h, ss, sl); rj_obj_set(in, "coinbase", rj_str(h)); free(h); }
        } else {
            hex_rev(hx, prev, 32); rj_obj_set(in, "txid", rj_str(hx));
            rj_obj_set(in, "vout", rj_numf("%u", vout));
            rj_val* sso = rj_obj();
            char* a = script_asm(ss, sl, 1); rj_obj_set(sso, "asm", rj_str(a ? a : "")); free(a);
            char* h = malloc(sl*2 + 1); if (h){ hex_of(h, ss, sl); rj_obj_set(sso, "hex", rj_str(h)); free(h); }
            rj_obj_set(in, "scriptSig", sso);
        }
        if (wp){
            u64 ni = read_varint(wp, tx + w->len, &c); wp += c;
            if (ni > 0){
                rj_val* arr = rj_arr();
                for (u64 j = 0; j < ni; j++){
                    u64 il = read_varint(wp, tx + w->len, &c); wp += c;
                    char* h = malloc(il*2 + 1); if (h){ hex_of(h, wp, il); rj_arr_push(arr, rj_str(h)); free(h); }
                    wp += il;
                }
                rj_obj_set(in, "txinwitness", arr);
            }
        }
        rj_obj_set(in, "sequence", rj_numf("%u", seq));
        rj_arr_push(vin, in);
    }
    rj_obj_set(o, "vin", vin);

    p = w->vout; read_varint(p, tx + w->len, &c); p += c;
    rj_val* vout = rj_arr();
    u64 out_total = 0;
    for (u64 i = 0; i < w->n_out; i++){
        u64 val = rd64(p); p += 8; out_total += val;
        u64 sl = read_varint(p, tx + w->len, &c); p += c;
        rj_val* out = rj_obj();
        rj_obj_set(out, "value", amount_json(val));
        rj_obj_set(out, "n", rj_numf("%llu", i));
        rj_obj_set(out, "scriptPubKey", script_pubkey_json_x(p, sl, 1));
        p += sl;
        rj_arr_push(vout, out);
    }
    rj_obj_set(o, "vout", vout);
    /* fee = sum(prevout values) - sum(output values), when the caller supplied
     * the input total from the block's undo data (getblock v2). in_total < 0
     * means "not available" (coinbase, or undo file pruned/absent). */
    if (in_total >= 0 && (u64)in_total >= out_total)
        rj_obj_set(o, "fee", amount_json((u64)in_total - out_total));
    char* h = malloc(w->len*2 + 1); if (h){ hex_of(h, tx, w->len); rj_obj_set(o, "hex", rj_str(h)); free(h); }
    return o;
}

/* ---- blockheaderToJSON ---- */
static int header_json(long h, long tip, rj_val** out, long* ec, const char** em){
    u8 pre[89 + 9];
    int r = read_block_prefix(h, pre, sizeof pre);
    if (r != 1){ *ec = -1; *em = "Block not available"; return 0; }
    u8 rec[48]; if (!read_idx_rec(h, rec)){ *ec = -1; *em = "Block not available"; return 0; }
    char hx[65];
    rj_val* o = rj_obj();
    hex_rev(hx, rec, 32); rj_obj_set(o, "hash", rj_str(hx));
    rj_obj_set(o, "confirmations", rj_numf("%ld", tip - h + 1));
    rj_obj_set(o, "height", rj_numf("%ld", h));
    u32 ver = rd32(pre);
    rj_obj_set(o, "version", rj_numf("%d", (int)ver));
    rj_obj_set(o, "versionHex", rj_strf("%08x", ver));
    hex_rev(hx, pre + 36, 32); rj_obj_set(o, "merkleroot", rj_str(hx));
    rj_obj_set(o, "time", rj_numf("%u", rd32(pre + 68)));
    rj_obj_set(o, "mediantime", rj_numf("%ld", median_time_past(h)));
    rj_obj_set(o, "nonce", rj_numf("%u", rd32(pre + 76)));
    u32 bits = rd32(pre + 72);
    rj_obj_set(o, "bits", rj_strf("%08x", bits));
    target_hex(bits, hx); rj_obj_set(o, "target", rj_str(hx));
    rj_obj_set(o, "difficulty", rj_double(difficulty_of(bits)));
    u8 cw[16]; if (chainwork_at(h, cw)){ chainwork_hex(cw, hx); rj_obj_set(o, "chainwork", rj_str(hx)); }
    u64 c; u64 ntx = read_varint(pre + 80, pre + sizeof pre, &c);
    rj_obj_set(o, "nTx", rj_numf("%llu", ntx));
    if (h > 0){ hex_rev(hx, pre + 4, 32); rj_obj_set(o, "previousblockhash", rj_str(hx)); }
    if (h < tip){ u8 nrec[48]; if (read_idx_rec(h + 1, nrec) && rec_present(nrec)){ hex_rev(hx, nrec, 32); rj_obj_set(o, "nextblockhash", rj_str(hx)); } }
    *out = o;
    return 1;
}

/* ---- param helpers ---- */
static int param_present(const rj_val* params, size_t i){
    return params && params->typ == RJ_ARR && i < params->nitems && params->items[i]->typ != RJ_NULL;
}
/* Core ParseVerbosity(allow_bool) */
static int param_verbosity(const rj_val* params, size_t i, int dflt, long* ec, const char** em){
    if (!param_present(params, i)) return dflt;
    const rj_val* e = params->items[i];
    if (e->typ == RJ_BOOL) return e->str[0] == '1' ? 1 : 0;
    long long v;
    if (!rpc_param_i64(params, i, &v, ec, em)) return -999;
    return (int)v;
}
static int lookup_block_param(const rj_val* params, size_t i, int pnum, long* h, long* ec, const char** em){
    const char* s = rpc_param_str(params, i, ec, em); if (!s) return 0;
    u8 disp[32]; if (!parse_hash_param(s, pnum, disp, ec, em)) return 0;
    if (!height_by_hash(disp, h)){ *ec = -5; *em = "Block not found"; return 0; }
    return 1;
}

/* ---- commands ---- */
static int cmd_getblockcount(rj_val** res){ *res = rj_numf("%ld", refresh()); return 1; }
static int cmd_getdifficulty(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    u8 hdr[80]; if (read_block_prefix(tip, hdr, 80) != 1){ *ec = -1; *em = "Block not available"; return 0; }
    u32 bits = rd32(hdr + 72);
    *res = rj_double(difficulty_of(bits));   /* Core: difficulty of the current tip */
    return 1;
}

/* getnetworkhashps (Core rpc/mining.cpp GetNetworkHashPS): estimated network
 * hashes/sec from the cumulative-work delta over a window of `nblocks` blocks
 * ending at `height` (defaults 120, tip). Computed from chainwork.dat + header
 * timestamps -- no UTXO dependency, so verifiable now. arith_uint256.getdouble()
 * replicated word-by-word (high 32-bit word first). */
static double gnh_getdouble(const u8 w[16]){
    double r=0; for (int i=3;i>=0;i--) r = r*4294967296.0 + (double)rd32(w+i*4); return r;
}
static int cmd_getnetworkhashps(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec=-28; *em="Loading block index..."; return 0; }
    long nblocks=120, height=-1;
    if (param_present(params,0)){ long long v; if(!rpc_param_i64(params,0,&v,ec,em)) return 0; nblocks=(long)v; }
    if (param_present(params,1)){ long long v; if(!rpc_param_i64(params,1,&v,ec,em)) return 0; height=(long)v; }
    if (nblocks < -1 || nblocks == 0){ *ec=-8; *em="Invalid nblocks. Must be a positive number or -1."; return 0; }
    if (height < -1 || height > tip){ *ec=-8; *em="Block does not exist at specified height"; return 0; }
    long pbh = (height>=0) ? height : tip;
    if (pbh == 0){ *res=rj_numf("%d",0); return 1; }
    if (nblocks == -1) nblocks = pbh % 2016 + 1;
    if (nblocks > pbh) nblocks = pbh;
    u8 hdr[80];
    if (read_block_prefix(pbh, hdr, 80) != 1){ *ec=-1; *em="Block not available"; return 0; }
    long mn=(long)rd32(hdr+68), mx=mn, pb0=pbh;
    for (long i=0;i<nblocks;i++){ pb0--;
        if (read_block_prefix(pb0, hdr, 80) != 1){ *ec=-1; *em="Block not available"; return 0; }
        long t=(long)rd32(hdr+68); if(t<mn)mn=t; if(t>mx)mx=t; }
    if (mn==mx){ *res=rj_numf("%d",0); return 1; }
    u8 cw1[16], cw0[16];
    if (!chainwork_at(pbh,cw1) || !chainwork_at(pb0,cw0)){ *ec=-1; *em="Chainwork not available"; return 0; }
    u8 wd[16]; int borrow=0;
    for (int i=0;i<16;i++){ int d=(int)cw1[i]-(int)cw0[i]-borrow; if(d<0){d+=256;borrow=1;}else borrow=0; wd[i]=(u8)d; }
    *res = rj_double(gnh_getdouble(wd) / (double)(mx-mn));
    return 1;
}

/* getmininginfo (Core rpc/mining.cpp): the documented v31 field set -- blocks,
 * bits, difficulty, networkhashps, pooledtx, chain, warnings. The master oracle
 * adds bleeding-edge fields (target, next, blockmintxfee) the project policy
 * does not chase; the shared fields are oracle-verifiable. pooledtx reflects
 * THIS process's mempool (0 for the read-only rpcd / listen=0 node, as
 * getmempoolinfo). */
static int cmd_getmininginfo(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec=-28; *em="Loading block index..."; return 0; }
    u8 hdr[80]; if (read_block_prefix(tip, hdr, 80) != 1){ *ec=-1; *em="Block not available"; return 0; }
    u32 bits = rd32(hdr+72);
    rj_val* o = rj_obj();
    rj_obj_set(o,"blocks", rj_numf("%ld", tip));
    { char b[9]; snprintf(b,sizeof b,"%08x",(unsigned)bits); rj_obj_set(o,"bits", rj_str(b)); }
    rj_obj_set(o,"difficulty", rj_double(difficulty_of(bits)));
    { rj_val* nh=NULL; long e2; const char* m2;
      if (cmd_getnetworkhashps(NULL,&nh,&e2,&m2)) rj_obj_set(o,"networkhashps", nh);
      else rj_obj_set(o,"networkhashps", rj_numf("%d",0)); }
    rj_obj_set(o,"pooledtx", rj_numf("%d", 0));
    rj_obj_set(o,"chain", rj_str("main"));
    rj_obj_set(o,"warnings", rj_arr());     /* v31: empty array */
    *res = o;
    return 1;
}

/* ==== getblocktemplate (BIP22/23, Core rpc/mining.cpp) =====================
 * The deterministic frame -- previousblockhash, height, bits (incl the 2016-
 * block retarget), target, mintime (MTP+1), version/rules/limits -- comes
 * from our own chain state and is diffable against the oracle at the same
 * tip. The transaction list comes from the SHARED mempool via the same
 * injected hooks rpc_node uses (rpc_chain_set_mempool); with no pool
 * injected the template is simply empty -- valid, just feeless. NOT
 * implemented (documented): longpoll blocking (longpollid is emitted and
 * changes per tip/template, but a hanging longpoll request is not honored),
 * BIP23 proposal mode, and tx priority/ordering beyond parents-before-
 * children (Core package-feerate-orders; any parent-first order is a VALID
 * template, just not fee-optimal -- honesty note, not a correctness gap). */
static rpc_mempool_hooks g_gbt_mph;
static long (*g_gbt_sigop_cost)(const unsigned char*, unsigned long);
static u64 gbs_subsidy(long h);        /* defined with getblockstats below */
void rpc_chain_set_mempool(const void* hooks_rpc_mempool,
                           long (*sigop_cost)(const unsigned char*, unsigned long)){
    const rpc_mempool_hooks* h = (const rpc_mempool_hooks*)hooks_rpc_mempool;
    if (h) g_gbt_mph = *h; else memset(&g_gbt_mph, 0, sizeof g_gbt_mph);
    g_gbt_sigop_cost = sigop_cost;
}

/* arith_uint256::GetCompact (fNegative=false) over a big-endian 32-byte target */
static u32 gbt_compact(const u8 t[32]){
    int size = 32; while (size > 0 && t[32-size] == 0) size--;
    u32 word = 0;
    for (int i = 0; i < 3; i++){
        int pos = 32 - size + i;               /* top 3 bytes */
        word = (word << 8) | (u8)(pos < 32 && i < size ? t[pos] : 0);
    }
    if (size < 3) word <<= 8 * (3 - size);
    if (word & 0x00800000){ word >>= 8; size++; }
    return ((u32)size << 24) | (word & 0x007fffff);
}

/* Core pow.cpp CalculateNextWorkRequired: bits for height `tip+1`. */
#define GBT_TIMESPAN 1209600L                   /* 14 days */
/* Pure retarget arithmetic, exported for the hermetic KATs (vectors frozen
 * from an arith_uint256-faithful reference implementation). */
u32 rpc_chain_retarget(u32 old_bits, long ts){
    if (ts < GBT_TIMESPAN/4) ts = GBT_TIMESPAN/4;
    if (ts > GBT_TIMESPAN*4) ts = GBT_TIMESPAN*4;
    /* new_target = old_target * ts / GBT_TIMESPAN over a 40-byte big int
     * (little-endian limbs for the arithmetic, flipped from/to big-endian) */
    u8 be[32]; target_bytes(old_bits, be);
    u8 n[40]; memset(n, 0, sizeof n);
    for (int i = 0; i < 32; i++) n[i] = be[31-i];          /* -> LE */
    { unsigned long long carry = 0;                         /* *= ts */
      for (int i = 0; i < 40; i++){
          unsigned long long v = (unsigned long long)n[i] * (unsigned long long)ts + carry;
          n[i] = (u8)v; carry = v >> 8;
      } }
    { unsigned long long rem = 0;                           /* /= GBT_TIMESPAN */
      for (int i = 39; i >= 0; i--){
          unsigned long long v = (rem << 8) | n[i];
          n[i] = (u8)(v / (unsigned long long)GBT_TIMESPAN);
          rem = v % (unsigned long long)GBT_TIMESPAN;
      } }
    int over = 0; for (int i = 32; i < 40; i++) if (n[i]) over = 1;
    u8 out[32]; for (int i = 0; i < 32; i++) out[i] = n[31-i];   /* -> BE */
    u8 lim[32]; target_bytes(0x1d00ffff, lim);
    if (!over){ for (int i = 0; i < 32; i++){ if (out[i] > lim[i]){ over = 1; break; } if (out[i] < lim[i]) break; } }
    if (over) memcpy(out, lim, 32);
    return gbt_compact(out);
}
static u32 gbt_next_bits(long tip){
    u8 hdr[80];
    if (read_block_prefix(tip, hdr, 80) != 1) return 0;
    u32 old_bits = rd32(hdr + 72);
    if ((tip + 1) % 2016 != 0) return old_bits;
    u32 last_time = rd32(hdr + 68);
    if (read_block_prefix(tip - 2015, hdr, 80) != 1) return old_bits;
    u32 first_time = rd32(hdr + 68);
    return rpc_chain_retarget(old_bits, (long)last_time - (long)first_time);
}

/* Slot walk of the shared structural pool (bitcoin_mempool.asm's documented
 * layout; the same walk daemon/reorg.c and rpc_node.c use). */
typedef struct { const u8* txid; const u8* tx; unsigned long len; } gbt_ent;
static long gbt_slot(void* mp, unsigned long i, gbt_ent* e){
    u8* m = (u8*)mp;
    unsigned long long mask; memcpy(&mask, m+8, 8);
    if (i > mask) return -1;
    u8* sl = m + 40 + i*48;
    unsigned long long len; memcpy(&len, sl, 8);
    if (len == 0xFFFFFFFFFFFFFFFFULL) return 0;
    u8* blob; memcpy(&blob, m+16, 8);
    unsigned long long off; memcpy(&off, sl+40, 8);
    e->txid = sl+8; e->tx = blob+off; e->len = (unsigned long)len;
    return 1;
}

#define GBT_MAX_TX 4000
static int cmd_getblocktemplate(const rj_val* params, rj_val** res, long* ec, const char** em){
    /* template_request: rules MUST include "segwit" (Core-exact error) */
    int segwit_rule = 0;
    if (params && params->typ == RJ_ARR && params->nitems >= 1 && params->items[0]->typ == RJ_OBJ){
        const rj_val* req = params->items[0];
        const rj_val* rules = rj_obj_get((rj_val*)req, "rules");
        if (rules && rules->typ == RJ_ARR)
            for (unsigned long i = 0; i < rules->nitems; i++)
                if (rules->items[i]->typ == RJ_STR && !strcmp(rules->items[i]->str, "segwit")) segwit_rule = 1;
        const rj_val* mode = rj_obj_get((rj_val*)req, "mode");
        if (mode && mode->typ == RJ_STR && strcmp(mode->str, "template")){
            *ec = -8; *em = "Invalid mode"; return 0; }
    }
    if (!segwit_rule){
        *ec = -8; *em = "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})";
        return 0; }

    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    u8 hdr[80];
    if (read_block_prefix(tip, hdr, 80) != 1){ *ec = -1; *em = "Block not available"; return 0; }
    u8 tiphash[32]; sha256d(tiphash, hdr, 80);
    u32 bits = gbt_next_bits(tip);
    if (!bits){ *ec = -1; *em = "Block not available"; return 0; }
    long height = tip + 1;
    long mintime = median_time_past(tip) + 1;
    long curtime = (long)time(NULL); if (curtime < mintime) curtime = mintime;

    rj_val* o = rj_obj();
    { rj_val* caps = rj_arr(); rj_arr_push(caps, rj_str("proposal"));
      rj_obj_set(o, "capabilities", caps); }
    rj_obj_set(o, "version", rj_numf("%d", 536870912));      /* 0x20000000 */
    { rj_val* rls = rj_arr();
      rj_arr_push(rls, rj_str("csv")); rj_arr_push(rls, rj_str("!segwit"));
      rj_arr_push(rls, rj_str("taproot"));
      rj_obj_set(o, "rules", rls); }
    rj_obj_set(o, "vbavailable", rj_obj());
    rj_obj_set(o, "vbrequired", rj_numf("%d", 0));
    { char hx[65]; hex_rev(hx, tiphash, 32);
      rj_obj_set(o, "previousblockhash", rj_str(hx));
      static unsigned long long lp_ctr = 0;                  /* template id */
      char lp[80]; snprintf(lp, sizeof lp, "%s%llu", hx, ++lp_ctr);
      rj_obj_set(o, "longpollid", rj_str(lp)); }

    /* ---- transaction list: shared pool, parents before children ---- */
    unsigned long long fees_total = 0;
    rj_val* txs = rj_arr();
    if (g_gbt_mph.mp && g_gbt_mph.get){
        static gbt_ent ents[GBT_MAX_TX];
        static unsigned char emitted[GBT_MAX_TX];
        static int order[GBT_MAX_TX];
        long n = 0;
        if (g_gbt_mph.lock) g_gbt_mph.lock();
        { u8* m = (u8*)g_gbt_mph.mp; unsigned long long mask; memcpy(&mask, m+8, 8);
          for (unsigned long i = 0; i <= mask && n < GBT_MAX_TX; i++){
              gbt_ent e; if (gbt_slot(g_gbt_mph.mp, i, &e) == 1) ents[n++] = e; } }
        memset(emitted, 0, (size_t)(n ? n : 1));
        long emitted_n = 0;
        /* iterative parents-first ordering via the policy graph */
        for (long pass = 0; pass <= n && emitted_n < n; pass++){
            long progress = 0;
            for (long i = 0; i < n; i++){
                if (emitted[i]) continue;
                int ready = 1;
                mp_entry_info inf; long have = 0;
                if (g_gbt_mph.polstate && g_gbt_mph.pol_entry_info)
                    have = g_gbt_mph.pol_entry_info(g_gbt_mph.polstate, ents[i].txid, &inf);
                if (have){
                    mp_entry_info* pi = &inf;
                    for (int k = 0; k < pi->n_depends && ready; k++){
                        int found_unemitted = 0;
                        for (long j = 0; j < n; j++)
                            if (!emitted[j] && !memcmp(ents[j].txid, pi->depends[k], 32)){ found_unemitted = 1; break; }
                        if (found_unemitted) ready = 0;
                    }
                }
                if (!ready) continue;
                emitted[i] = 1; order[emitted_n++] = (int)i; progress = 1;
            }
            if (!progress) break;
        }
        /* render in order; depends[] are 1-based indices into this array */
        for (long oi = 0; oi < emitted_n; oi++){
            long i = order[oi];
            unsigned long long fee = 0, fsz = 0; long have_fee = 0;
            if (g_gbt_mph.polstate && g_gbt_mph.pol_entry)
                have_fee = g_gbt_mph.pol_entry(g_gbt_mph.polstate, ents[i].txid, &fee, &fsz);
            if (!have_fee) continue;    /* can't price it -> don't offer it */
            rj_val* t = rj_obj();
            { char* dhex = malloc(ents[i].len*2 + 1);
              if (dhex){ hex_of(dhex, ents[i].tx, ents[i].len);
                         rj_obj_set(t, "data", rj_str(dhex)); free(dhex); } }
            { char hx[65]; hex_rev(hx, ents[i].txid, 32); rj_obj_set(t, "txid", rj_str(hx)); }
            { u8 wt[32]; char hx[65];
              int is_segwit = ents[i].len > 5 && ents[i].tx[4] == 0x00 && ents[i].tx[5] == 0x01;
              if (is_segwit) sha256d(wt, ents[i].tx, ents[i].len); else memcpy(wt, ents[i].txid, 32);
              hex_rev(hx, wt, 32); rj_obj_set(t, "hash", rj_str(hx)); }
            { rj_val* dep = rj_arr();
              mp_entry_info inf;
              if (g_gbt_mph.polstate && g_gbt_mph.pol_entry_info &&
                  g_gbt_mph.pol_entry_info(g_gbt_mph.polstate, ents[i].txid, &inf)){
                  mp_entry_info* pi = &inf;
                  for (int k = 0; k < pi->n_depends; k++)
                      for (long pj = 0; pj < oi; pj++)
                          if (!memcmp(ents[order[pj]].txid, pi->depends[k], 32)){
                              rj_arr_push(dep, rj_numf("%ld", pj + 1)); break; }
              }
              rj_obj_set(t, "depends", dep); }
            rj_obj_set(t, "fee", rj_numf("%llu", fee));
            fees_total += fee;
            rj_obj_set(t, "sigops", rj_numf("%ld", g_gbt_sigop_cost ? g_gbt_sigop_cost(ents[i].tx, ents[i].len) : 0));
            { const u8* p = ents[i].tx; const u8* end = p + ents[i].len; txw_t w;
              rj_obj_set(t, "weight", rj_numf("%zu",
                  tx_walk(p, end, &w) ? (w.stripped * 3 + w.len) : ents[i].len * 4)); }
            rj_arr_push(txs, t);
        }
        if (g_gbt_mph.unlock) g_gbt_mph.unlock();
    }
    rj_obj_set(o, "transactions", txs);

    rj_obj_set(o, "coinbaseaux", rj_obj());
    rj_obj_set(o, "coinbasevalue", rj_numf("%llu", (unsigned long long)gbs_subsidy(height) + fees_total));
    { char hx[65]; target_hex(bits, hx); rj_obj_set(o, "target", rj_str(hx)); }
    rj_obj_set(o, "mintime", rj_numf("%ld", mintime));
    { rj_val* mut = rj_arr();
      rj_arr_push(mut, rj_str("time")); rj_arr_push(mut, rj_str("transactions"));
      rj_arr_push(mut, rj_str("prevblock"));
      rj_obj_set(o, "mutable", mut); }
    rj_obj_set(o, "noncerange", rj_str("00000000ffffffff"));
    rj_obj_set(o, "sigoplimit", rj_numf("%d", 80000));
    rj_obj_set(o, "sizelimit", rj_numf("%d", 4000000));
    rj_obj_set(o, "weightlimit", rj_numf("%d", 4000000));
    rj_obj_set(o, "curtime", rj_numf("%ld", curtime));
    { char bx[9]; snprintf(bx, sizeof bx, "%08x", bits); rj_obj_set(o, "bits", rj_str(bx)); }
    rj_obj_set(o, "height", rj_numf("%ld", height));

    /* default_witness_commitment: BIP141 -- wtxid merkle root with the
     * coinbase's wtxid as 32 zero bytes, committed with a zero nonce:
     * OP_RETURN 0x24 aa21a9ed sha256d(root || 0x00*32). Recomputed over the
     * template's own tx order. */
    { u8 (*leaves)[32] = malloc(32u * (unsigned)(txs->nitems + 1));
      if (leaves){
          memset(leaves[0], 0, 32);
          for (unsigned long i = 0; i < txs->nitems; i++){
              const char* hh = rj_obj_get(txs->items[i], "hash")->str;
              for (int b = 0; b < 32; b++){
                  unsigned hv; sscanf(hh + 2*b, "%2x", &hv);
                  leaves[i+1][31-b] = (u8)hv;              /* display -> wire */
              }
          }
          unsigned long cnt = txs->nitems + 1;
          while (cnt > 1){
              unsigned long w2 = 0;
              for (unsigned long i = 0; i < cnt; i += 2){
                  u8 pair[64];
                  memcpy(pair, leaves[i], 32);
                  memcpy(pair + 32, leaves[i + 1 < cnt ? i + 1 : i], 32);
                  sha256d(leaves[w2++], pair, 64);
              }
              cnt = w2;
          }
          u8 pair[64], commit[32];
          memcpy(pair, leaves[0], 32); memset(pair + 32, 0, 32);   /* nonce 0 */
          sha256d(commit, pair, 64);
          char spk[13 + 64 + 1];
          memcpy(spk, "6a24aa21a9ed", 12);
          hex_of(spk + 12, commit, 32);
          rj_obj_set(o, "default_witness_commitment", rj_str(spk));
          free(leaves);
      } }

    *res = o;
    return 1;
}

static int cmd_getbestblockhash(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    u8 rec[48];
    if (tip < 0 || !read_idx_rec(tip, rec)){ *ec = -1; *em = "Block not available"; return 0; }
    char hx[65]; hex_rev(hx, rec, 32); *res = rj_str(hx); return 1;
}
/* getchaintips: Core lists the active tip plus any known side-branch tips.
 * This node does not persist non-active tips (reorg candidates are dropped
 * once the best chain is chosen), so we report exactly the active tip -- which
 * is Core's output for a node with no stored forks (the common case). */
static int cmd_getchaintips(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    u8 rec[48];
    if (tip < 0 || !read_idx_rec(tip, rec)){ *ec = -1; *em = "Block not available"; return 0; }
    rj_val* arr = rj_arr();
    rj_val* o = rj_obj();
    rj_obj_set(o, "height", rj_numf("%ld", tip));
    char hx[65]; hex_rev(hx, rec, 32); rj_obj_set(o, "hash", rj_str(hx));
    rj_obj_set(o, "branchlen", rj_numf("%d", 0));
    rj_obj_set(o, "status", rj_str("active"));
    rj_arr_push(arr, o);
    *res = arr;
    return 1;
}
static int cmd_getblockhash(const rj_val* params, rj_val** res, long* ec, const char** em){
    long long h; if (!rpc_param_i64(params, 0, &h, ec, em)) return 0;
    long tip = refresh();
    if (h < 0 || h > tip){ *ec = -8; *em = "Block height out of range"; return 0; }
    u8 rec[48];
    if (!read_idx_rec((long)h, rec) || !rec_present(rec)){ *ec = -1; *em = "Block not available"; return 0; }
    char hx[65]; hex_rev(hx, rec, 32); *res = rj_str(hx); return 1;
}
static int cmd_getblockheader(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh(); long h;
    if (!lookup_block_param(params, 0, 1, &h, ec, em)) return 0;
    int verbose = 1;
    if (param_present(params, 1)){
        const rj_val* e = params->items[1];
        if (e->typ != RJ_BOOL){ *ec = -3; *em = "JSON value of type number is not of expected type bool"; return 0; }
        verbose = e->str[0] == '1';
    }
    if (!verbose){
        u8 hdr[80];
        if (read_block_prefix(h, hdr, 80) != 1){ *ec = -1; *em = "Block not available"; return 0; }
        char hx[161]; hex_of(hx, hdr, 80); *res = rj_str(hx); return 1;
    }
    return header_json(h, tip, res, ec, em);
}
static int cmd_getblock(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh(); long h;
    if (!lookup_block_param(params, 0, 1, &h, ec, em)) return 0;
    int verbosity = param_verbosity(params, 1, 1, ec, em);
    if (verbosity == -999) return 0;
    long len = read_block(h);
    if (len == -3){ *ec = -1; *em = "Block not available (pruned data)"; return 0; }
    if (len < 0){ *ec = -1; *em = "Block not found on disk"; return 0; }
    const u8* blk = g_blockbuf; const u8* end = blk + len;
    if (verbosity <= 0){
        char* hx = malloc((size_t)len*2 + 1); if (!hx){ *ec = -7; *em = "out of memory"; return 0; }
        hex_of(hx, blk, (size_t)len); *res = rj_str(hx); free(hx); return 1;
    }
    rj_val* o;
    if (!header_json(h, tip, &o, ec, em)) return 0;
    u64 c; u64 ntx = read_varint(blk + 80, end, &c);
    const u8* p = blk + 80 + c;
    size_t stripped = 80 + c;
    rj_val* txs = rj_arr();
    rj_val* cb = NULL;
    /* per-tx fees for verbosity 2: prevout values from the block's undo file
     * (in block order, non-coinbase inputs). undo_n < 0 -> undo pruned/absent
     * (fee omitted, honest -- we keep only a recent-heights window). */
    static u64 undo_vals[600000]; long undo_n = -1, undo_cur = 0;
    if (verbosity >= 2) undo_n = undo_block_values(h, undo_vals, (long)(sizeof undo_vals / sizeof undo_vals[0]));
    for (u64 i = 0; i < ntx; i++){
        txw_t w;
        if (!tx_walk(p, end, &w)){ rj_free(txs); if (cb) rj_free(cb); rj_free(o); *ec = -1; *em = "Block decode failed"; return 0; }
        stripped += w.stripped;
        if (i == 0){
            cb = rj_obj();
            rj_obj_set(cb, "version", rj_numf("%u", w.version));
            rj_obj_set(cb, "locktime", rj_numf("%u", w.locktime));
            const u8* q = w.vin; u64 cc; read_varint(q, end, &cc); q += cc; q += 36;
            u64 sl = read_varint(q, end, &cc); q += cc;
            rj_obj_set(cb, "sequence", rj_numf("%u", rd32(q + sl)));
            char* hx = malloc(sl*2 + 1); if (hx){ hex_of(hx, q, sl); rj_obj_set(cb, "coinbase", rj_str(hx)); free(hx); }
            if (w.wit){
                const u8* wq = w.wit; u64 ni = read_varint(wq, end, &cc); wq += cc;
                if (ni >= 1){ u64 il = read_varint(wq, end, &cc); wq += cc; char* wh = malloc(il*2+1); if (wh){ hex_of(wh, wq, il); rj_obj_set(cb, "witness", rj_str(wh)); free(wh); } }
            }
        }
        if (verbosity == 1){
            u8 txid[32]; u8* scratch = malloc(w.len); char hx[65];
            if (scratch){ tx_txid(txid, p, w.len, scratch, w.len); free(scratch); } else memset(txid, 0, 32);
            hex_rev(hx, txid, 32); rj_arr_push(txs, rj_str(hx));
        } else {
            long long in_total = -1;
            if (i > 0 && undo_n >= 0 && undo_cur + (long)w.n_in <= undo_n){
                in_total = 0;
                for (u64 k = 0; k < w.n_in; k++) in_total += (long long)undo_vals[undo_cur + k];
            }
            if (i > 0 && undo_n >= 0) undo_cur += (long)w.n_in;   /* advance even if capped */
            rj_arr_push(txs, tx_to_json(p, &w, in_total));
        }
        p += w.len;
    }
    rj_obj_set(o, "strippedsize", rj_numf("%zu", stripped));
    rj_obj_set(o, "size", rj_numf("%ld", len));
    rj_obj_set(o, "weight", rj_numf("%zu", stripped * 3 + (size_t)len));
    if (cb) rj_obj_set(o, "coinbase_tx", cb);
    rj_obj_set(o, "tx", txs);
    *res = o;
    return 1;
}
static long headers_height(long tip){
    struct stat sb;
    if (stat("headers.dat", &sb) == 0 && sb.st_size >= 112){
        long n = (long)(sb.st_size / 112) - 1;
        if (n > tip) return n;
    }
    return tip;
}
static long long size_on_disk(void){
    long long total = 0;
    DIR* d = opendir("."); if (!d) return 0;
    struct dirent* e;
    while ((e = readdir(d))){
        if (strncmp(e->d_name, "blk", 3) == 0 && strstr(e->d_name, ".dat")){
            struct stat sb; if (stat(e->d_name, &sb) == 0) total += sb.st_size;
        }
    }
    closedir(d);
    return total;
}
static int cmd_getblockchaininfo(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    u8 hdr[80]; if (read_block_prefix(tip, hdr, 80) != 1){ *ec = -1; *em = "Block not available"; return 0; }
    u8 rec[48]; read_idx_rec(tip, rec);
    char hx[65];
    rj_val* o = rj_obj();
    rj_obj_set(o, "chain", rj_str("main"));
    rj_obj_set(o, "blocks", rj_numf("%ld", tip));
    long hh = headers_height(tip);
    rj_obj_set(o, "headers", rj_numf("%ld", hh));
    hex_rev(hx, rec, 32); rj_obj_set(o, "bestblockhash", rj_str(hx));
    u32 bits = rd32(hdr + 72);
    rj_obj_set(o, "bits", rj_strf("%08x", bits));
    target_hex(bits, hx); rj_obj_set(o, "target", rj_str(hx));
    rj_obj_set(o, "difficulty", rj_double(difficulty_of(bits)));
    u32 t = rd32(hdr + 68);
    rj_obj_set(o, "time", rj_numf("%u", t));
    rj_obj_set(o, "mediantime", rj_numf("%ld", median_time_past(tip)));
    double prog = hh >= 0 ? (double)(tip + 1) / (double)(hh + 1) : 1.0;
    if (prog > 1.0) prog = 1.0;
    rj_obj_set(o, "verificationprogress", rj_double(prog));
    rj_obj_set(o, "initialblockdownload", rj_bool((time_t)t < time(NULL) - 24*3600));
    u8 cw[16]; if (chainwork_at(tip, cw)){ chainwork_hex(cw, hx); rj_obj_set(o, "chainwork", rj_str(hx)); }
    rj_obj_set(o, "size_on_disk", rj_numf("%lld", size_on_disk()));
    int pruned = g_prune_mib != 0 || ST_PRUNE_H(g_st) > 0;
    rj_obj_set(o, "pruned", rj_bool(pruned));
    if (pruned){
        rj_obj_set(o, "pruneheight", rj_numf("%d", ST_PRUNE_H(g_st)));
        int automatic = g_prune_mib > 1;
        rj_obj_set(o, "automatic_pruning", rj_bool(automatic));
        if (automatic) rj_obj_set(o, "prune_target_size", rj_numf("%lld", (long long)g_prune_mib * 1024 * 1024));
    }
    rj_obj_set(o, "warnings", rj_arr());
    *res = o;
    return 1;
}

static const char GENESIS_CB_TXID[] = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
static int cmd_getrawtransaction(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh();
    const char* txs = rpc_param_str(params, 0, ec, em); if (!txs) return 0;
    u8 want_disp[32]; if (!parse_hash_param(txs, 1, want_disp, ec, em)) return 0;
    if (strcmp(txs, GENESIS_CB_TXID) == 0){ *ec = -5; *em = "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved"; return 0; }
    int verbosity = param_verbosity(params, 1, 0, ec, em);
    if (verbosity == -999) return 0;
    if (!param_present(params, 2)){
        *ec = -5; *em = "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions.";
        return 0;
    }
    const char* bs = rpc_param_str(params, 2, ec, em); if (!bs) return 0;
    u8 bdisp[32]; if (!parse_hash_param(bs, 3, bdisp, ec, em)) return 0;
    long h;
    if (!height_by_hash(bdisp, &h)){ *ec = -5; *em = "Block hash not found"; return 0; }
    long len = read_block(h);
    if (len < 0){ *ec = -1; *em = "Block not available"; return 0; }
    const u8* blk = g_blockbuf; const u8* end = blk + len;
    u8 want[32]; for (int i = 0; i < 32; i++) want[i] = want_disp[31-i];
    u64 c; u64 ntx = read_varint(blk + 80, end, &c);
    const u8* p = blk + 80 + c;
    for (u64 i = 0; i < ntx; i++){
        txw_t w;
        if (!tx_walk(p, end, &w)) break;
        u8 txid[32]; u8* scratch = malloc(w.len);
        if (!scratch){ *ec = -7; *em = "out of memory"; return 0; }
        tx_txid(txid, p, w.len, scratch, w.len); free(scratch);
        if (memcmp(txid, want, 32) == 0){
            if (verbosity <= 0){
                char* hx = malloc(w.len*2 + 1); if (!hx){ *ec = -7; *em = "out of memory"; return 0; }
                hex_of(hx, p, w.len); *res = rj_str(hx); free(hx); return 1;
            }
            rj_val* o = rj_obj();
            rj_obj_set(o, "in_active_chain", rj_bool(1));
            rj_val* t = tx_to_json(p, &w, -1);   /* verbosity 1: no fee (Core parity) */
            /* splice TxToUniv's members into our object to keep Core's order */
            for (size_t k = 0; k < t->nmembers; k++){ rj_obj_set(o, t->members[k].key, t->members[k].val); t->members[k].val = NULL; }
            for (size_t k = 0; k < t->nmembers; k++) free(t->members[k].key);
            free(t->members); t->nmembers = 0; t->members = NULL; rj_free(t);
            rj_obj_set(o, "blockhash", rj_str(bs));
            rj_obj_set(o, "confirmations", rj_numf("%ld", tip - h + 1));
            u8 hdr[80]; read_block_prefix(h, hdr, 80);
            rj_obj_set(o, "time", rj_numf("%u", rd32(hdr + 68)));
            rj_obj_set(o, "blocktime", rj_numf("%u", rd32(hdr + 68)));
            *res = o; return 1;
        }
        p += w.len;
    }
    *ec = -5; *em = "No such transaction found in the provided block. Use gettransaction for wallet transactions.";
    return 0;
}
static int cmd_uptime(rj_val** res){
    if (g_start == 0) g_start = time(NULL);
    *res = rj_numf("%lld", (long long)(time(NULL) - g_start)); return 1;
}
static int cmd_stop(rj_val** res){
    *res = rj_str("Bitcoin Machine Code stopping");
    g_stop_fn();
    return 1;
}


/* ==== gettxoutproof / verifytxoutproof: BIP37 partial merkle tree ==========
 * Core: CMerkleBlock (blockencodings/merkleblock). A proof is the 80-byte
 * header || CPartialMerkleTree{ uint32 nTx, compactsize(nHashes), hashes,
 * compactsize(nBytes), flag bytes (LSB-first bits) }. Pure block data; no
 * txindex/mempool needed, so like getrawtransaction we REQUIRE the blockhash
 * param (Core's own behaviour with no txindex). */
static u32 pmt_width(u32 ntx, int height){ return (ntx + (1u<<height) - 1) >> height; }
static int pmt_height(u32 ntx){ int h=0; while (pmt_width(ntx,h) > 1) h++; return h; }

static void pmt_calc_hash(const u8 (*leaves)[32], u32 ntx, int height, u32 pos, u8 out[32]){
    if (height == 0){ memcpy(out, leaves[pos], 32); return; }
    u8 left[32], right[32];
    pmt_calc_hash(leaves, ntx, height-1, pos*2, left);
    if (pos*2u+1u < pmt_width(ntx, height-1)) pmt_calc_hash(leaves, ntx, height-1, pos*2+1, right);
    else memcpy(right, left, 32);
    u8 cat[64]; memcpy(cat, left, 32); memcpy(cat+32, right, 32);
    sha256d(out, cat, 64);
}

typedef struct { const u8 (*leaves)[32]; const u8* match; u32 ntx;
                 u8 (*hashes)[32]; u32 nhash; u8* bits; u32 nbits; } pmt_build_t;
static int pmt_match_sub(const u8* match, u32 ntx, int height, u32 pos){
    u64 lo = (u64)pos << height, hi = lo + ((u64)1<<height); if (hi>ntx) hi=ntx;
    for (u64 i=lo;i<hi;i++) if (match[i]) return 1; return 0;
}
static void pmt_build(pmt_build_t* b, int height, u32 pos){
    int parent = pmt_match_sub(b->match, b->ntx, height, pos);
    b->bits[b->nbits++] = (u8)parent;
    if (height==0 || !parent){
        pmt_calc_hash(b->leaves, b->ntx, height, pos, b->hashes[b->nhash++]);
    } else {
        pmt_build(b, height-1, pos*2);
        if (pos*2u+1u < pmt_width(b->ntx, height-1)) pmt_build(b, height-1, pos*2+1);
    }
}

typedef struct { const u8 (*hashes)[32]; u32 nhash, hpos; const u8* bits; u32 nbits, bpos;
                 u8 (*matched)[32]; u32 nmatched; int bad; } pmt_extract_t;
static void pmt_extract(pmt_extract_t* e, u32 ntx, int height, u32 pos, u8 out[32]){
    if (e->bpos >= e->nbits){ e->bad=1; memset(out,0,32); return; }
    int parent = e->bits[e->bpos++];
    if (height==0 || !parent){
        if (e->hpos >= e->nhash){ e->bad=1; memset(out,0,32); return; }
        memcpy(out, e->hashes[e->hpos++], 32);
        if (height==0 && parent) memcpy(e->matched[e->nmatched++], out, 32);
    } else {
        u8 left[32], right[32];
        pmt_extract(e, ntx, height-1, pos*2, left);
        if (pos*2u+1u < pmt_width(ntx, height-1)){
            pmt_extract(e, ntx, height-1, pos*2+1, right);
            if (!memcmp(left,right,32)) e->bad=1;   /* BIP37: no duplicate right */
        } else memcpy(right, left, 32);
        u8 cat[64]; memcpy(cat,left,32); memcpy(cat+32,right,32); sha256d(out,cat,64);
    }
}

/* small compactsize writer (values here are small) */
static int pmt_put_cs(u8* d, u64 v){
    if (v < 0xfd){ d[0]=(u8)v; return 1; }
    if (v <= 0xffff){ d[0]=0xfd; d[1]=(u8)v; d[2]=(u8)(v>>8); return 3; }
    d[0]=0xfe; d[1]=(u8)v; d[2]=(u8)(v>>8); d[3]=(u8)(v>>16); d[4]=(u8)(v>>24); return 5;
}
static int hex1(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }

/* --- test hooks (exercised by tests/test_txoutproof.c) --- */
int pmt_test_root(const u8 (*leaves)[32], u32 ntx, u8 out[32]){
    if (ntx == 0) return 0;
    pmt_calc_hash(leaves, ntx, pmt_height(ntx), 0, out);
    return 1;
}
/* build a proof for the single leaf `idx`, extract it back, and return the
 * extracted root + recovered txid: a full serialise-free build/extract cycle. */
int pmt_test_roundtrip(const u8 (*leaves)[32], u32 ntx, u32 idx, u8 out_root[32], u8 out_leaf[32]){
    if (idx >= ntx) return 0;
    u8* match = calloc(ntx, 1); if (!match) return 0; match[idx] = 1;
    u8 (*hashes)[32] = malloc(sizeof(*hashes)*(ntx+64));
    u8* bits = malloc((size_t)ntx*2 + 64);
    if (!hashes || !bits){ free(match); free(hashes); free(bits); return 0; }
    pmt_build_t b = { leaves, match, ntx, hashes, 0, bits, 0 };
    pmt_build(&b, pmt_height(ntx), 0);
    free(match);
    u8 (*matched)[32] = malloc(sizeof(*matched)*ntx);
    pmt_extract_t e = { (const u8(*)[32])hashes, b.nhash, 0, bits, b.nbits, 0, matched, 0, 0 };
    pmt_extract(&e, ntx, pmt_height(ntx), 0, out_root);
    int ok = !e.bad && e.hpos == b.nhash && e.nmatched == 1;
    if (ok) memcpy(out_leaf, matched[0], 32);
    free(hashes); free(bits); free(matched);
    return ok;
}

/* collect ordered wire-order txids of block h into leaves (caller-sized);
 * returns ntx, or -1 on decode error. */
static long pmt_block_txids(long h, u8 (*leaves)[32], u32 cap){
    long len = read_block(h);
    if (len < 80) return -1;
    const u8* blk = g_blockbuf; const u8* end = blk + len;
    u64 c; u64 ntx = read_varint(blk + 80, end, &c);
    if (!c || ntx == 0 || ntx > cap) return -1;
    const u8* p = blk + 80 + c;
    for (u64 i=0;i<ntx;i++){
        txw_t w;
        if (!tx_walk(p, end, &w)) return -1;
        u8* scratch = malloc(w.len); if (!scratch) return -1;
        tx_txid(leaves[i], p, w.len, scratch, w.len); free(scratch);
        p += w.len;
    }
    return (long)ntx;
}

#define PMT_MAX_TX 100000
static int cmd_gettxoutproof(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 || params->items[0]->typ != RJ_ARR){
        *ec = -8; *em = "Invalid parameter, expected array of txids"; return 0; }
    const rj_val* txarr = params->items[0];
    /* blockhash is required (no txindex) */
    if (!param_present(params, 1)){
        *ec = -5; *em = "Transaction not found in specified block (a blockhash is required with no txindex)"; return 0; }
    refresh(); long h;
    if (!lookup_block_param(params, 1, 1, &h, ec, em)) return 0;

    static u8 (*leaves)[32]; if (!leaves){ leaves = malloc(sizeof(*leaves)*PMT_MAX_TX); if(!leaves){*ec=-7;*em="oom";return 0;} }
    long ntx = pmt_block_txids(h, leaves, PMT_MAX_TX);
    if (ntx < 0){ *ec = -1; *em = "Block decode failed"; return 0; }

    u8* match = calloc((size_t)ntx, 1); if (!match){ *ec=-7; *em="oom"; return 0; }
    for (size_t t=0; t<txarr->nitems; t++){
        const rj_val* e = txarr->items[t];
        if (e->typ != RJ_STR || strlen(e->str) != 64){ free(match); *ec=-8; *em="Invalid txid"; return 0; }
        u8 want[32];  /* display hex -> wire order */
        for (int k=0;k<32;k++){ int hi=hex1(e->str[k*2]), lo=hex1(e->str[k*2+1]); if(hi<0||lo<0){free(match);*ec=-8;*em="Invalid txid";return 0;} want[31-k]=(u8)(hi<<4|lo); }
        int found=0; for (long i=0;i<ntx;i++) if (!memcmp(leaves[i], want, 32)){ match[i]=1; found=1; break; }
        if (!found){ free(match); *ec=-5; *em="Transaction not found in specified block"; return 0; }
    }
    /* build the partial merkle tree */
    static u8 (*hashes)[32]; if(!hashes){ hashes=malloc(sizeof(*hashes)*(PMT_MAX_TX+64)); if(!hashes){free(match);*ec=-7;*em="oom";return 0;} }
    static u8* bits; if(!bits){ bits=malloc(PMT_MAX_TX*2+64); if(!bits){free(match);*ec=-7;*em="oom";return 0;} }
    pmt_build_t b = { (const u8(*)[32])leaves, match, (u32)ntx, hashes, 0, bits, 0 };
    pmt_build(&b, pmt_height((u32)ntx), 0);
    free(match);
    /* serialize: header(80) || u32 ntx LE || cs(nhash) || hashes || cs(nbytes) || flags */
    u8 hdr[80]; if (read_block_prefix(h, hdr, 80) != 1){ *ec=-1; *em="Block not available"; return 0; }
    u32 nflagbytes = (b.nbits + 7) / 8;
    size_t cap = 80 + 4 + 9 + (size_t)b.nhash*32 + 9 + nflagbytes;
    u8* buf = malloc(cap); if (!buf){ *ec=-7; *em="oom"; return 0; }
    size_t o = 0;
    memcpy(buf+o, hdr, 80); o += 80;
    buf[o++]=(u8)ntx; buf[o++]=(u8)(ntx>>8); buf[o++]=(u8)((u32)ntx>>16); buf[o++]=(u8)((u32)ntx>>24);
    o += pmt_put_cs(buf+o, b.nhash);
    for (u32 i=0;i<b.nhash;i++){ memcpy(buf+o, hashes[i], 32); o += 32; }
    o += pmt_put_cs(buf+o, nflagbytes);
    memset(buf+o, 0, nflagbytes);
    for (u32 i=0;i<b.nbits;i++) if (bits[i]) buf[o + i/8] |= (u8)(1u << (i%8));
    o += nflagbytes;
    char* hx = malloc(o*2 + 1); if (!hx){ free(buf); *ec=-7; *em="oom"; return 0; }
    hex_of(hx, buf, o); free(buf);
    *res = rj_str(hx); free(hx);
    return 1;
}

static int cmd_verifytxoutproof(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* proof = rpc_param_str(params, 0, ec, em); if (!proof) return 0;
    size_t hn = strlen(proof); if (hn < (80+5)*2 || (hn & 1)){ *ec=-8; *em="Invalid proof"; return 0; }
    size_t bn = hn/2; u8* buf = malloc(bn); if (!buf){ *ec=-7; *em="oom"; return 0; }
    for (size_t i=0;i<bn;i++){ int hi=hex1(proof[i*2]),lo=hex1(proof[i*2+1]); if(hi<0||lo<0){free(buf);*ec=-8;*em="Invalid proof hex";return 0;} buf[i]=(u8)(hi<<4|lo); }
    const u8* p = buf; const u8* end = buf + bn;
    if (p + 84 > end){ free(buf); *ec=-8; *em="Invalid proof"; return 0; }
    const u8* hdr = p; p += 80;
    u32 ntx = rd32(p); p += 4;
    u64 c; u64 nhash = read_varint(p, end, &c); if (!c || nhash > ntx + 64){ free(buf); *ec=-8; *em="Invalid proof"; return 0; } p += c;
    if (p + nhash*32 > end){ free(buf); *ec=-8; *em="Invalid proof"; return 0; }
    static u8 (*hashes)[32]; if(!hashes){ hashes=malloc(sizeof(*hashes)*(PMT_MAX_TX+64)); }
    for (u64 i=0;i<nhash;i++){ memcpy(hashes[i], p, 32); p += 32; }
    u64 nfb = read_varint(p, end, &c); if (!c){ free(buf); *ec=-8; *em="Invalid proof"; return 0; } p += c;
    if (p + nfb > end || nfb*8 > PMT_MAX_TX*2+64){ free(buf); *ec=-8; *em="Invalid proof"; return 0; }
    static u8* bits; if(!bits){ bits=malloc(PMT_MAX_TX*2+64); }
    u32 nbits = (u32)(nfb*8);
    for (u32 i=0;i<nbits;i++) bits[i] = (p[i/8] >> (i%8)) & 1;
    if (ntx == 0 || ntx > PMT_MAX_TX){ free(buf); *ec=-8; *em="Invalid proof"; return 0; }
    static u8 (*matched)[32]; if(!matched){ matched=malloc(sizeof(*matched)*(PMT_MAX_TX)); }
    pmt_extract_t e = { (const u8(*)[32])hashes, (u32)nhash, 0, bits, nbits, 0, matched, 0, 0 };
    u8 root[32]; pmt_extract(&e, ntx, pmt_height(ntx), 0, root);
    /* BIP37 validity: every hash and every bit consumed, no error */
    int ok = !e.bad && e.hpos == nhash && ((e.bpos + 7)/8) == nfb;
    if (ok && memcmp(root, hdr + 36, 32) != 0) ok = 0;   /* root must match header */
    /* block must be in our chain */
    long h_out = -1;
    if (ok){ u8 bh[32], disp[32]; sha256d(bh, hdr, 80);   /* wire order */
        for (int i=0;i<32;i++) disp[i]=bh[31-i];           /* height_by_hash wants display order */
        if (!height_by_hash(disp, &h_out)) ok = 0; }
    rj_val* arr = rj_arr();
    if (ok){ for (u32 i=0;i<e.nmatched;i++){ char hx[65]; hex_rev(hx, matched[i], 32); rj_arr_push(arr, rj_str(hx)); } }
    free(buf);
    *res = arr;   /* empty array if the proof is invalid or not in chain, like Core */
    return 1;
}

/* ---- decodescript (util): classify a redeem/script hex like Core ----------
 * Faithful port of src/rpc/rawtransaction.cpp decodescript: ScriptToUniv
 * (no hex at top level) + the p2sh / segwit wrappers, gated exactly as Core
 * gates them (can_wrap / can_wrap_P2WSH). "desc" is the one documented
 * omission (no descriptor engine) -- everything else diffs against Core. */
static int ds_op_success(u8 op){            /* IsOpSuccess (tapscript) */
    return op==80 || op==98 || (op>=126&&op<=129) || (op>=131&&op<=134) ||
           (op>=137&&op<=138) || (op>=141&&op<=142) || (op>=149&&op<=153) ||
           (op>=187&&op<=254);
}
static int ds_valid_ops(const u8* s, size_t n){   /* CScript::HasValidOps */
    const u8* pc=s; const u8* end=s+n; u8 op; const u8* d; size_t dl;
    while (pc < end){
        if (!script_getop(&pc, end, &op, &d, &dl)) return 0;
        if (op > 0xb9 /*MAX_OPCODE=OP_NOP10*/) return 0;
        if (dl > 520 /*MAX_SCRIPT_ELEMENT_SIZE*/) return 0;
    }
    return 1;
}
static int ds_compressed_pk(const u8* d, size_t dl){ return dl==33 && (d[0]==0x02||d[0]==0x03); }
/* P2SH address of an arbitrary script; 1 on success. */
static int ds_p2sh_addr(const u8* s, size_t n, char* out, long cap){
    u8 h[20]; hash160(h, s, (long long)n);
    u8 spk[23]; spk[0]=0xa9; spk[1]=0x14; memcpy(spk+2,h,20); spk[22]=0x87;
    return wallet_script_to_address(out, cap, spk, 23) > 0 && out[0];
}

static int desc_checksum(const char* span, char out[9]);   /* defined below */

/* InferDescriptor for a bare scriptPubKey with no keystore (Core
 * descriptor.cpp InferScript fallbacks): pk()/multi() when the key material is
 * in the script, rawtr() for a taproot output key, addr() for a hash-only
 * standard type, else raw(). Returns the inner descriptor string (no
 * checksum), malloc'd; caller frees. */
static char* desc_inner_of(const u8* s, size_t n){
    const char* type = script_type(s, n);
    char* d = NULL;
    if (!strcmp(type,"pubkey")){
        size_t pl = s[0]; d = malloc(4 + pl*2 + 2);
        if (d){ memcpy(d,"pk(",3); hex_of(d+3, s+1, pl); strcpy(d+3+pl*2, ")"); }
    } else if (!strcmp(type,"multisig")){
        int m = 0; small_int(s[0], &m);
        d = malloc(n*2 + 32);
        if (d){ int off = sprintf(d, "multi(%d", m);
            const u8* pc=s+1; const u8* end=s+n-2; u8 op; const u8* dp; size_t dl;
            while (pc<end){ if(!script_getop(&pc,end,&op,&dp,&dl)) break; d[off++]=','; hex_of(d+off,dp,dl); off += (int)dl*2; }
            d[off++]=')'; d[off]=0; }
    } else if (!strcmp(type,"witness_v1_taproot")){
        d = malloc(6 + 64 + 2);
        if (d){ memcpy(d,"rawtr(",6); hex_of(d+6, s+2, 32); strcpy(d+6+64, ")"); }
    } else if (!strcmp(type,"pubkeyhash")||!strcmp(type,"scripthash")||
               !strcmp(type,"witness_v0_keyhash")||!strcmp(type,"witness_v0_scripthash")){
        char addr[128]; addr[0]=0;
        if (wallet_script_to_address(addr, sizeof addr, s, (long)n) > 0 && addr[0]){
            d = malloc(strlen(addr)+8); if (d) sprintf(d, "addr(%s)", addr);
        }
    }
    if (!d){                                              /* raw() fallback */
        d = malloc(n*2 + 8);
        if (d){ memcpy(d,"raw(",4); hex_of(d+4, s, n); strcpy(d+4+n*2, ")"); }
    }
    return d;
}
/* wrap an inner descriptor string with Core's #checksum; malloc'd, caller frees. */
static char* desc_with_checksum(const char* inner){
    if (!inner) return NULL;
    char cks[9]; if (!desc_checksum(inner, cks)) return NULL;
    char* out = malloc(strlen(inner) + 10);
    if (out) sprintf(out, "%s#%s", inner, cks);
    return out;
}

static int cmd_decodescript(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* hex = rpc_param_str(params, 0, ec, em); if (!hex) return 0;
    size_t hn = strlen(hex);
    if (hn & 1){ *ec = -8; *em = "argument must be hexadecimal string (not '...')"; return 0; }
    size_t n = hn/2;
    u8* s = n ? malloc(n) : (u8*)"";
    if (n && !s){ *ec=-7; *em="oom"; return 0; }
    for (size_t i=0;i<n;i++){ int hi=hex1(hex[i*2]),lo=hex1(hex[i*2+1]); if(hi<0||lo<0){ if(n)free(s); *ec=-8; *em="argument must be hexadecimal string"; return 0; } s[i]=(u8)(hi<<4|lo); }

    /* --- ScriptToUniv, include_hex=false, include_address=true --- */
    rj_val* o = rj_obj();
    char* a = script_asm(s, n, 0); rj_obj_set(o,"asm", rj_str(a?a:"")); free(a);
    { char* di = desc_inner_of(s, n); char* dc = desc_with_checksum(di);
      if (dc){ rj_obj_set(o,"desc", rj_str(dc)); free(dc); } free(di); }
    const char* type = script_type(s, n);
    { char addr[128]; addr[0]=0;
      if (wallet_script_to_address(addr, sizeof addr, s, (long)n) > 0 && addr[0]) rj_obj_set(o,"address", rj_str(addr)); }
    rj_obj_set(o,"type", rj_str(type));

    /* --- can_wrap --- */
    int cand = !strcmp(type,"multisig")||!strcmp(type,"nonstandard")||!strcmp(type,"pubkey")||
               !strcmp(type,"pubkeyhash")||!strcmp(type,"witness_v0_keyhash")||!strcmp(type,"witness_v0_scripthash");
    int can_wrap = 0;
    if (cand){
        can_wrap = ds_valid_ops(s,n) && !script_unspendable(s,n);
        if (can_wrap){                                   /* no OP_CHECKSIGADD / OP_SUCCESSx */
            const u8* pc=s; const u8* end=s+n; u8 op; const u8* d; size_t dl;
            while (pc<end){ if(!script_getop(&pc,end,&op,&d,&dl)){ can_wrap=0; break; }
                            if (op==0xba || ds_op_success(op)){ can_wrap=0; break; } }
        }
    }
    if (can_wrap){
        char p2sh[128]; if (ds_p2sh_addr(s,n,p2sh,sizeof p2sh)) rj_obj_set(o,"p2sh", rj_str(p2sh));

        /* --- can_wrap_P2WSH --- */
        int wsh = 0;
        if (!strcmp(type,"nonstandard")||!strcmp(type,"pubkeyhash")) wsh = 1;
        else if (!strcmp(type,"pubkey")){ wsh = ds_compressed_pk(s+1, s[0]); }
        else if (!strcmp(type,"multisig")){
            wsh = 1; const u8* pc=s+1; const u8* end=s+n-2; u8 op; const u8* d; size_t dl;
            while (pc<end){ if(!script_getop(&pc,end,&op,&d,&dl)){ wsh=0; break; }
                            if (dl!=1 && !ds_compressed_pk(d,dl)){ wsh=0; break; } }
        }
        if (wsh){
            u8 wspk[34]; size_t wl;
            if (!strcmp(type,"pubkey")){ u8 h[20]; hash160(h, s+1, (long long)s[0]); wspk[0]=0x00; wspk[1]=0x14; memcpy(wspk+2,h,20); wl=22; }
            else if (!strcmp(type,"pubkeyhash")){ wspk[0]=0x00; wspk[1]=0x14; memcpy(wspk+2, s+3, 20); wl=22; }
            else { u8 h[32]; sha256_full(h, s, (long long)n); wspk[0]=0x00; wspk[1]=0x20; memcpy(wspk+2,h,32); wl=34; }
            rj_val* sr = script_pubkey_json_x(wspk, wl, 0);   /* segwit supplies its own desc below */
            /* segwit desc: P2WPKH -> addr() (no inner known); P2WSH -> wsh(inner
             * descriptor of the original script), matching Core's provider. */
            char* sdc;
            if (wl == 22){ char* di = desc_inner_of(wspk, wl); sdc = desc_with_checksum(di); free(di); }
            else { char* di = desc_inner_of(s, n);
                   if (di && !strncmp(di, "raw(", 4)){    /* inner not a proper descriptor -> addr() */
                       free(di); di = desc_inner_of(wspk, wl); sdc = desc_with_checksum(di); free(di);
                   } else {
                       char* w = di ? malloc(strlen(di)+6) : NULL;
                       if (w) sprintf(w, "wsh(%s)", di);
                       sdc = desc_with_checksum(w); free(w); free(di);
                   } }
            if (sdc){ rj_obj_set(sr,"desc", rj_str(sdc)); free(sdc); }
            char pss[128]; if (ds_p2sh_addr(wspk, wl, pss, sizeof pss)) rj_obj_set(sr,"p2sh-segwit", rj_str(pss));
            rj_obj_set(o,"segwit", sr);
        }
    }
    if (n) free(s);
    *res = o;
    return 1;
}

/* ---- createmultisig (util): build an m-of-n multisig address ---------------
 * Core's rpc/output_script.cpp createmultisig + rpc/util.cpp
 * AddAndGetMultisigDestination. Pure: validate the pubkeys (on-curve, via
 * pubkey_parse = CPubKey::IsFullyValid), assemble the redeemScript, and derive
 * the address for the requested output type. Uncompressed keys force legacy
 * (and, if a segwit type was asked for, add Core's warning). The "descriptor"
 * field is the one omission -- no descriptor engine (same as decodescript's
 * "desc"). */
extern int pubkey_parse(const u8* pub, unsigned long publen, u64 qx[4], u64 qy[4]);

/* CScript << int for a 0..20 count: OP_0 / OP_1..OP_16, else a 1-byte push. */
static size_t cms_push_count(u8* d, int v){
    if (v == 0){ d[0] = 0x00; return 1; }
    if (v >= 1 && v <= 16){ d[0] = (u8)(0x50 + v); return 1; }
    d[0] = 0x01; d[1] = (u8)v; return 2;             /* CScriptNum, v <= 20 */
}
static int cms_p2sh_addr(const u8* s, size_t n, char* out, long cap){
    u8 h[20]; hash160(h, s, (long long)n);
    u8 spk[23]; spk[0]=0xa9; spk[1]=0x14; memcpy(spk+2,h,20); spk[22]=0x87;
    return wallet_script_to_address(out, cap, spk, 23) > 0 && out[0];
}

/* Core's descriptor checksum (descriptor.cpp DescriptorChecksum): appends the
 * 8-char "#..." suffix to a descriptor string. Fills out[9]; 0 if `span` holds
 * a char outside the descriptor input charset. */
static u64 desc_polymod(u64 c, int val){
    u8 c0 = (u8)(c >> 35);
    c = ((c & 0x7ffffffffULL) << 5) ^ (u64)val;
    if (c0 & 1)  c ^= 0xf5dee51989ULL;
    if (c0 & 2)  c ^= 0xa9fdca3312ULL;
    if (c0 & 4)  c ^= 0x1bab10e32dULL;
    if (c0 & 8)  c ^= 0x3706b1677aULL;
    if (c0 & 16) c ^= 0x644d626ffdULL;
    return c;
}
static int desc_checksum(const char* span, char out[9]){
    static const char* IN =
        "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    static const char* CK = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    u64 c = 1; int cls = 0, clscount = 0;
    for (const char* p = span; *p; p++){
        const char* q = strchr(IN, *p); if (!q) return 0;
        int pos = (int)(q - IN);
        c = desc_polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        if (++clscount == 3){ c = desc_polymod(c, cls); cls = 0; clscount = 0; }
    }
    if (clscount > 0) c = desc_polymod(c, cls);
    for (int j = 0; j < 8; ++j) c = desc_polymod(c, 0);
    c ^= 1;
    for (int j = 0; j < 8; ++j) out[j] = CK[(c >> (5 * (7 - j))) & 31];
    out[8] = 0;
    return 1;
}

/* ---- descriptor engine: getdescriptorinfo + deriveaddresses ----------------
 * Core rpc/output_script.cpp + descriptor.cpp. getdescriptorinfo parses a
 * descriptor, validates its checksum, and reports isrange/issolvable/
 * hasprivatekeys. deriveaddresses does BIP32 public derivation (CKDpub, in
 * bip32_ckdpub.c, verified byte-for-byte against Core) and builds addresses.
 *
 * Supported key material: an xpub (mainnet) or a raw compressed/uncompressed
 * pubkey. Supported output functions for address derivation: pkh, wpkh,
 * sh(wpkh(...)). pk()/tr()/combo() parse and checksum in getdescriptorinfo but
 * deriveaddresses reports them as not having a single corresponding address
 * (pk) or as unsupported (tr/combo) rather than fabricating one. */
extern int bip32_ckdpub_derive(const char* xpub, const unsigned* path, int n, u8 out[33]);
extern int bip32_xpub_parse(const char* xpub, u8 pub33[33], u8 cc32[32]);
extern int pubkey_parse(const u8* pub, unsigned long publen, u64 qx[4], u64 qy[4]);

enum { DSC_PKH=0, DSC_WPKH=1, DSC_SHWPKH=2, DSC_PK=3, DSC_COMBO=4, DSC_TR=5, DSC_ADDR=6, DSC_RAW=7, DSC_UNK=-1 };
typedef struct {
    int  script;
    char key[160];       /* xpub or hex pubkey; or the address text for addr() */
    int  keytype;        /* 0 raw-pubkey, 1 xpub, 2 has-private, 3 addr, 4 raw, -1 bad */
    unsigned path[32];
    int  pathlen;        /* fixed components (before any '*') */
    int  ranged;         /* trailing slash-star present */
    int  hardened;       /* any hardened path element */
    u8   rawpub[65];     /* decoded raw pubkey (keytype 0) */
    int  rawlen;
    u8   spk[520];       /* scriptPubKey for addr()/raw() */
    int  spklen;
} desc_t;

/* Parse the descriptor core string (checksum already stripped) into d.
 * Returns 1 on success; 0 with *ec / *em set on a parse/validation error. */
static int desc_parse_core(const char* core, desc_t* d, long* ec, const char** em){
    static char perr[192];
    memset(d, 0, sizeof *d); d->keytype = -1;
    size_t L = strlen(core);
    const char* inner; size_t ilen;
    if (!strncmp(core,"pkh(",4) && core[L-1]==')'){ d->script=DSC_PKH; inner=core+4; ilen=L-5; }
    else if (!strncmp(core,"wpkh(",5) && core[L-1]==')'){ d->script=DSC_WPKH; inner=core+5; ilen=L-6; }
    else if (!strncmp(core,"sh(wpkh(",8) && L>=10 && core[L-1]==')' && core[L-2]==')'){ d->script=DSC_SHWPKH; inner=core+8; ilen=L-10; }
    else if (!strncmp(core,"pk(",3) && core[L-1]==')'){ d->script=DSC_PK; inner=core+3; ilen=L-4; }
    else if (!strncmp(core,"combo(",6) && core[L-1]==')'){ d->script=DSC_COMBO; inner=core+6; ilen=L-7; }
    else if (!strncmp(core,"tr(",3) && core[L-1]==')'){ d->script=DSC_TR; inner=core+3; ilen=L-4; }
    else if (!strncmp(core,"addr(",5) && core[L-1]==')'){ d->script=DSC_ADDR; inner=core+5; ilen=L-6; }
    else if (!strncmp(core,"raw(",4) && core[L-1]==')'){ d->script=DSC_RAW; inner=core+4; ilen=L-5; }
    else { *ec=-5; *em="Invalid descriptor function"; return 0; }

    /* addr()/raw(): the content is an address or a raw hex script, not a key. */
    if (d->script==DSC_ADDR){
        char a[160]; if (ilen>=sizeof a){ *ec=-5; *em="Address too long"; return 0; }
        memcpy(a,inner,ilen); a[ilen]=0;
        int type=0; unsigned char ver=0, h160[20], prog[32];
        if (!wallet_validate_address(a,&type,&ver,h160,prog)){ snprintf(perr,sizeof perr,"Address is not valid: %s",a); *ec=-5; *em=perr; return 0; }
        int sl=0;
        switch (type){
            case 1: d->spk[0]=0x76;d->spk[1]=0xa9;d->spk[2]=0x14;memcpy(d->spk+3,h160,20);d->spk[23]=0x88;d->spk[24]=0xac;sl=25; break;  /* P2PKH */
            case 2: d->spk[0]=0x00;d->spk[1]=0x14;memcpy(d->spk+2,h160,20);sl=22; break;                                                 /* P2WPKH */
            case 3: d->spk[0]=0xa9;d->spk[1]=0x14;memcpy(d->spk+2,h160,20);d->spk[22]=0x87;sl=23; break;                                  /* P2SH */
            case 4: d->spk[0]=0x00;d->spk[1]=0x20;memcpy(d->spk+2,prog,32);sl=34; break;                                                 /* P2WSH */
            case 5: d->spk[0]=0x51;d->spk[1]=0x20;memcpy(d->spk+2,prog,32);sl=34; break;                                                 /* P2TR */
            default: snprintf(perr,sizeof perr,"Address is not valid: %s",a); *ec=-5; *em=perr; return 0;
        }
        d->spklen=sl; snprintf(d->key,sizeof d->key,"%s",a); d->keytype=3; return 1;
    }
    if (d->script==DSC_RAW){
        if ((ilen&1) || ilen/2>520){ *ec=-5; *em="Raw script invalid"; return 0; }
        d->spklen=(int)(ilen/2);
        for (int i=0;i<d->spklen;i++){ int hi=hex1(inner[i*2]), lo=hex1(inner[i*2+1]); if(hi<0||lo<0){ *ec=-5; *em="Raw script must be hex"; return 0; } d->spk[i]=(u8)((hi<<4)|lo); }
        d->keytype=4; return 1;
    }

    char key[256];
    if (ilen >= sizeof key){ *ec=-5; *em="Descriptor too long"; return 0; }
    memcpy(key, inner, ilen); key[ilen]=0;
    char* p = key;
    if (*p == '['){                                   /* skip [origin] */
        char* rb = strchr(p, ']');
        if (!rb){ *ec=-5; *em="key origin start '[' with no matching ']'"; return 0; }
        p = rb + 1;
    }
    /* keybody up to first '/' */
    char* slash = strchr(p, '/');
    size_t kb = slash ? (size_t)(slash - p) : strlen(p);
    if (kb == 0 || kb >= sizeof d->key){ *ec=-5; *em="Invalid key"; return 0; }
    memcpy(d->key, p, kb); d->key[kb]=0;

    if (!strncmp(d->key,"xpub",4)){
        u8 pub[33], cc[32];
        if (!bip32_xpub_parse(d->key, pub, cc)){
            snprintf(perr,sizeof perr,"key '%s' is not valid", d->key); *ec=-5; *em=perr; return 0; }
        d->keytype = 1;
    } else if (!strncmp(d->key,"xprv",4) || !strncmp(d->key,"tprv",4) || !strncmp(d->key,"tpub",4)){
        d->keytype = 2;                               /* recognized; derivation unsupported */
    } else {                                          /* raw hex pubkey */
        size_t hl = strlen(d->key); int ok = (hl==66||hl==130) && !(hl&1);
        for (size_t i=0; ok && i<hl; i++) if (hex1(d->key[i])<0) ok=0;
        if (ok){
            d->rawlen = (int)(hl/2);
            for (int i=0;i<d->rawlen;i++) d->rawpub[i]=(u8)((hex1(d->key[i*2])<<4)|hex1(d->key[i*2+1]));
            u64 qx[4], qy[4];
            if (!pubkey_parse(d->rawpub,(unsigned long)d->rawlen,qx,qy)){
                snprintf(perr,sizeof perr,"key '%s' is not valid", d->key); *ec=-5; *em=perr; return 0; }
            d->keytype = 0;
        } else { snprintf(perr,sizeof perr,"key '%s' is not valid", d->key); *ec=-5; *em=perr; return 0; }
    }
    /* path components */
    if (slash){
        char* q = slash;
        while (*q == '/'){
            q++;
            char comp[32]; int ci=0;
            while (*q && *q!='/' && ci<31) comp[ci++]=*q++;
            comp[ci]=0;
            if (!strcmp(comp,"*")){ d->ranged=1; if (*q=='/'){ *ec=-5; *em="'*' must be the last path element"; return 0; } break; }
            int hard=0; size_t cl=strlen(comp);
            if (cl && (comp[cl-1]=='\''||comp[cl-1]=='h'||comp[cl-1]=='H')){ hard=1; comp[cl-1]=0; cl--; }
            if (cl==0){ *ec=-5; *em="Invalid path element"; return 0; }
            unsigned v=0; for (size_t i=0;i<cl;i++){ if(comp[i]<'0'||comp[i]>'9'){ *ec=-5; *em="Invalid path element"; return 0; } v=v*10+(unsigned)(comp[i]-'0'); }
            if (d->pathlen>=32){ *ec=-5; *em="Path too deep"; return 0; }
            if (hard){ d->hardened=1; v|=0x80000000u; }
            d->path[d->pathlen++]=v;
        }
    }
    if (d->keytype==1 && d->hardened){ *ec=-5; *em="Cannot derive a hardened child from an xpub"; return 0; }
    return 1;
}

/* build the address for a derived/raw compressed-or-uncompressed pubkey into
 * out (>=128); returns 1 on success, 0 with *ec / *em on a no-address type. */
static int desc_addr_for_pub(int script, const u8* pub, int publen, char* out, long cap, long* ec, const char** em){
    u8 h[20]; hash160(h, pub, (long long)publen);
    if (script==DSC_PKH){ u8 s[25]={0x76,0xa9,0x14}; memcpy(s+3,h,20); s[23]=0x88; s[24]=0xac; wallet_script_to_address(out,cap,s,25); return 1; }
    if (script==DSC_WPKH){ if(publen!=33){ *ec=-5; *em="Uncompressed key not allowed for wpkh"; return 0; } u8 s[22]={0x00,0x14}; memcpy(s+2,h,20); wallet_script_to_address(out,cap,s,22); return 1; }
    if (script==DSC_SHWPKH){ if(publen!=33){ *ec=-5; *em="Uncompressed key not allowed for wpkh"; return 0; } u8 rd[22]={0x00,0x14}; memcpy(rd+2,h,20); u8 rh[20]; hash160(rh,rd,22); u8 s[23]={0xa9,0x14}; memcpy(s+2,rh,20); s[22]=0x87; wallet_script_to_address(out,cap,s,23); return 1; }
    if (script==DSC_PK){ *ec=-5; *em="Descriptor does not have a corresponding address"; return 0; }
    *ec=-5; *em="Descriptor derivation for this function is not supported"; return 0;
}

/* derive the compressed pubkey at range index `idx` (ignored when !ranged). */
static int desc_pub_at(const desc_t* d, long idx, u8 pub[65], int* publen){
    if (d->keytype==0){ memcpy(pub, d->rawpub, d->rawlen); *publen=d->rawlen; return 1; }
    if (d->keytype==1){
        unsigned path[33]; int n=d->pathlen;
        for (int i=0;i<n;i++) path[i]=d->path[i];
        if (d->ranged){ if (idx<0 || idx>0x7fffffffL) return 0; path[n++]=(unsigned)idx; }
        u8 c[33]; if (!bip32_ckdpub_derive(d->key, path, n, c)) return 0;
        memcpy(pub,c,33); *publen=33; return 1;
    }
    return 0;   /* keytype 2 (private) derivation unsupported */
}

static int cmd_getdescriptorinfo(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* in = rpc_param_str(params, 0, ec, em); if (!in) return 0;
    static char perr[192];
    char core[320]; const char* hash = strchr(in, '#');
    size_t cl = hash ? (size_t)(hash-in) : strlen(in);
    if (cl >= sizeof core){ *ec=-5; *em="Descriptor too long"; return 0; }
    memcpy(core, in, cl); core[cl]=0;
    char cks[9]; if (!desc_checksum(core, cks)){ *ec=-5; *em="Invalid characters in descriptor"; return 0; }
    if (hash){
        const char* prov = hash+1;
        if (strlen(prov)!=8 || strcmp(prov,cks)){
            snprintf(perr,sizeof perr,"Provided checksum '%s' does not match computed checksum '%s'", prov, cks);
            *ec=-5; *em=perr; return 0; }
    }
    desc_t d;
    if (!desc_parse_core(core, &d, ec, em)) return 0;
    char full[340]; snprintf(full,sizeof full,"%s#%s", core, cks);
    rj_val* o = rj_obj();
    rj_obj_set(o,"descriptor", rj_str(full));
    rj_obj_set(o,"checksum", rj_str(cks));
    rj_obj_set(o,"isrange", rj_bool(d.ranged));
    rj_obj_set(o,"issolvable", rj_bool(d.script != DSC_RAW && d.script != DSC_ADDR));  /* addr()/raw() carry no key */
    rj_obj_set(o,"hasprivatekeys", rj_bool(d.keytype==2));
    *res = o;
    return 1;
}

static int cmd_deriveaddresses(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* in = rpc_param_str(params, 0, ec, em); if (!in) return 0;
    static char perr[192];
    const char* hash = strchr(in, '#');
    if (!hash){ *ec=-5; *em="Missing checksum"; return 0; }
    size_t cl = (size_t)(hash-in);
    char core[320]; if (cl >= sizeof core){ *ec=-5; *em="Descriptor too long"; return 0; }
    memcpy(core, in, cl); core[cl]=0;
    char cks[9]; if (!desc_checksum(core, cks)){ *ec=-5; *em="Invalid characters in descriptor"; return 0; }
    const char* prov = hash+1;
    if (strlen(prov)!=8 || strcmp(prov,cks)){
        snprintf(perr,sizeof perr,"Provided checksum '%s' does not match computed checksum '%s'", prov, cks);
        *ec=-5; *em=perr; return 0; }
    desc_t d;
    if (!desc_parse_core(core, &d, ec, em)) return 0;

    /* range argument (params[1]): int N -> [0,N]; [a,b] -> [a,b]; inclusive. */
    long begin=0, end=0; int have_range=0;
    if (params && params->typ==RJ_ARR && params->nitems>=2){
        const rj_val* r = params->items[1];
        if (r->typ==RJ_NUM){ have_range=1; begin=0; end=(long)strtoll(r->str,NULL,10); }
        else if (r->typ==RJ_ARR && r->nitems==2 && r->items[0]->typ==RJ_NUM && r->items[1]->typ==RJ_NUM){
            have_range=1; begin=(long)strtoll(r->items[0]->str,NULL,10); end=(long)strtoll(r->items[1]->str,NULL,10); }
        else if (r->typ!=RJ_NULL){ *ec=-8; *em="Invalid range"; return 0; }
    }
    if (d.ranged && !have_range){ *ec=-8; *em="Range must be specified for a ranged descriptor"; return 0; }
    if (!d.ranged && have_range){ *ec=-8; *em="Range should not be specified for an un-ranged descriptor"; return 0; }
    if (have_range){
        if (begin<0 || end<0){ *ec=-8; *em="Range should be greater or equal than 0"; return 0; }
        if (end<begin){ *ec=-8; *em="Range specified as [begin,end] must not have begin after end"; return 0; }
        if (end-begin > 100000){ *ec=-8; *em="Range is too large"; return 0; }
    }
    if (d.keytype==2){ *ec=-5; *em="Address derivation from extended private keys is not supported"; return 0; }

    /* addr()/raw(): the address is the descriptor's own script's address. */
    if (d.script==DSC_ADDR || d.script==DSC_RAW){
        char addr[128]; addr[0]=0;
        if (wallet_script_to_address(addr, sizeof addr, d.spk, d.spklen) <= 0 || !addr[0]){
            *ec=-5; *em="Descriptor does not have a corresponding address"; return 0; }
        rj_val* arr = rj_arr(); rj_arr_push(arr, rj_str(addr));
        *res = arr; return 1;
    }

    rj_val* arr = rj_arr();
    long lo = d.ranged?begin:0, hi = d.ranged?end:0;
    for (long i=lo; i<=hi; i++){
        u8 pub[65]; int pl=0;
        if (!desc_pub_at(&d, i, pub, &pl)){ rj_free(arr); *ec=-5; *em="Key derivation failed"; return 0; }
        char addr[128]; addr[0]=0;
        if (!desc_addr_for_pub(d.script, pub, pl, addr, sizeof addr, ec, em)){ rj_free(arr); return 0; }
        rj_arr_push(arr, rj_str(addr));
    }
    *res = arr;
    return 1;
}

static int cmd_createmultisig(const rj_val* params, rj_val** res, long* ec, const char** em){
    long long req;
    if (!rpc_param_i64(params, 0, &req, ec, em)) return 0;
    if (!params || params->typ != RJ_ARR || params->nitems < 2 || params->items[1]->typ != RJ_ARR){
        *ec = -8; *em = "Invalid parameter, \"keys\" must be an array"; return 0; }
    const rj_val* keys = params->items[1];
    int n = (int)keys->nitems;

    /* 1. validate + collect every pubkey (Core: HexToPubKey before the count
     * checks, so a bad key is reported even when the count is also wrong). */
    static char keyerr[160];
    u8 (*pk)[65] = malloc((size_t)(n > 0 ? n : 1) * 65);
    int* pklen = malloc((size_t)(n > 0 ? n : 1) * sizeof(int));
    if (!pk || !pklen){ free(pk); free(pklen); *ec=-7; *em="oom"; return 0; }
    int uncompressed = 0;
    for (int i = 0; i < n; i++){
        const rj_val* e = keys->items[i];
        int bad = (e->typ != RJ_STR);
        size_t hl = bad ? 0 : strlen(e->str);
        int bytes = (int)(hl/2);
        if (bad || (hl & 1) || (bytes != 33 && bytes != 65)){
            snprintf(keyerr, sizeof keyerr, "Invalid public key: %s", bad ? "" : e->str);
            free(pk); free(pklen); *ec=-5; *em=keyerr; return 0; }
        for (int k = 0; k < bytes; k++){ int hi=hex1(e->str[k*2]),lo=hex1(e->str[k*2+1]);
            if (hi<0||lo<0){ snprintf(keyerr,sizeof keyerr,"Invalid public key: %s", e->str); free(pk);free(pklen);*ec=-5;*em=keyerr;return 0; }
            pk[i][k]=(u8)(hi<<4|lo); }
        u64 qx[4], qy[4];
        if (!pubkey_parse(pk[i], (unsigned long)bytes, qx, qy)){   /* on-curve / valid header */
            snprintf(keyerr, sizeof keyerr, "Invalid public key: %s", e->str);
            free(pk); free(pklen); *ec=-5; *em=keyerr; return 0; }
        pklen[i] = bytes;
        if (bytes == 65) uncompressed = 1;
    }

    /* 2. output type (default legacy) */
    const char* atype = "legacy";
    if (param_present(params, 2)){
        if (params->items[2]->typ != RJ_STR){ free(pk);free(pklen); *ec=-8; *em="Invalid address_type"; return 0; }
        atype = params->items[2]->str;
    }
    int otype;   /* 0 legacy, 1 p2sh-segwit, 2 bech32 */
    static char typeerr[96];
    if (!strcmp(atype,"legacy")) otype=0;
    else if (!strcmp(atype,"p2sh-segwit")) otype=1;
    else if (!strcmp(atype,"bech32")) otype=2;
    else if (!strcmp(atype,"bech32m")){ free(pk);free(pklen); *ec=-5; *em="createmultisig cannot create bech32m multisig addresses"; return 0; }
    else { snprintf(typeerr,sizeof typeerr,"Unknown address type '%s'", atype); free(pk);free(pklen); *ec=-5; *em=typeerr; return 0; }

    /* 3. count checks (AddAndGetMultisigDestination) */
    static char cnterr[160];
    if (req < 1){ free(pk);free(pklen); *ec=-8; *em="a multisignature address must require at least one key to redeem"; return 0; }
    if (n < req){ snprintf(cnterr,sizeof cnterr,"not enough keys supplied (got %d keys, but need at least %lld to redeem)", n, req); free(pk);free(pklen); *ec=-8; *em=cnterr; return 0; }
    if (n > 20){ snprintf(cnterr,sizeof cnterr,"Number of keys involved in the multisignature address creation > 20\nReduce the number"); free(pk);free(pklen); *ec=-8; *em=cnterr; return 0; }

    /* 4. redeemScript = OP_m <key>.. OP_n OP_CHECKMULTISIG */
    int requested_segwit = (otype != 0);
    if (uncompressed) otype = 0;                          /* force legacy */
    u8* redeem = malloc((size_t)n * 66 + 8); if (!redeem){ free(pk);free(pklen); *ec=-7;*em="oom"; return 0; }
    size_t rl = 0;
    rl += cms_push_count(redeem+rl, (int)req);
    for (int i=0;i<n;i++){ redeem[rl++]=(u8)pklen[i]; memcpy(redeem+rl,pk[i],pklen[i]); rl+=pklen[i]; }
    rl += cms_push_count(redeem+rl, n);
    redeem[rl++] = 0xae;
    /* descriptor inner (canonical lowercase keys): multi(m,k1,k2,...) */
    char* dinner = malloc((size_t)n * 132 + 32);
    size_t di = 0;
    if (dinner){
        di += (size_t)snprintf(dinner+di, 32, "multi(%d", (int)req);
        for (int i=0;i<n;i++){ dinner[di++]=','; hex_of(dinner+di, pk[i], (size_t)pklen[i]); di += (size_t)pklen[i]*2; }
        dinner[di++] = ')'; dinner[di] = 0;
    }
    free(pk); free(pklen);

    if (otype == 0 && rl > 520){
        static char szerr[96]; snprintf(szerr,sizeof szerr,"redeemScript exceeds size limit: %zu > 520", rl);
        free(redeem); free(dinner); *ec=-8; *em=szerr; return 0; }

    /* 5. address */
    char addr[128]; addr[0]=0;
    if (otype == 0){                                      /* legacy: P2SH(redeem) */
        cms_p2sh_addr(redeem, rl, addr, sizeof addr);
    } else if (otype == 2){                               /* bech32: P2WSH(redeem) */
        u8 h[32]; sha256_full(h, redeem, (long long)rl);
        u8 spk[34]; spk[0]=0x00; spk[1]=0x20; memcpy(spk+2,h,32);
        wallet_script_to_address(addr, sizeof addr, spk, 34);
    } else {                                              /* p2sh-segwit: P2SH(P2WSH(redeem)) */
        u8 h[32]; sha256_full(h, redeem, (long long)rl);
        u8 wspk[34]; wspk[0]=0x00; wspk[1]=0x20; memcpy(wspk+2,h,32);
        cms_p2sh_addr(wspk, 34, addr, sizeof addr);
    }

    rj_val* o = rj_obj();
    rj_obj_set(o, "address", rj_str(addr));
    { char* hx = malloc(rl*2+1); if (hx){ hex_of(hx, redeem, rl); rj_obj_set(o,"redeemScript", rj_str(hx)); free(hx); } }
    /* descriptor: sh(multi..) / wsh(multi..) / sh(wsh(multi..)) + checksum */
    if (dinner){
        char* dwrap = malloc(strlen(dinner) + 16);
        if (dwrap){
            if (otype == 0)      sprintf(dwrap, "sh(%s)", dinner);
            else if (otype == 2) sprintf(dwrap, "wsh(%s)", dinner);
            else                 sprintf(dwrap, "sh(wsh(%s))", dinner);
            char cks[9];
            if (desc_checksum(dwrap, cks)){
                char* desc = malloc(strlen(dwrap) + 10);
                if (desc){ sprintf(desc, "%s#%s", dwrap, cks); rj_obj_set(o,"descriptor", rj_str(desc)); free(desc); }
            }
            free(dwrap);
        }
    }
    if (requested_segwit && uncompressed){
        rj_val* w = rj_arr();
        rj_arr_push(w, rj_str("Unable to make chosen address type, please ensure no uncompressed public keys are present."));
        rj_obj_set(o, "warnings", w);
    }
    free(dinner);
    free(redeem);
    *res = o;
    return 1;
}

/* ---- getblockstats (Core rpc/blockchain.cpp) -------------------------------
 * Per-block statistics. Block-only fields (sizes/weights/counts/subsidy/times/
 * total_out/utxo_increase) are computed from block data and match Core exactly.
 * The fee/feerate fields and utxo_size_inc{,_actual} need the block's spent
 * prevout values+sizes (undo data); where undo is unavailable (our recent
 * window only) those keys are OMITTED -- an honest divergence from a full node
 * (which would error on a pruned block), consistent with getblock's fee
 * omission. Constants match Core: PER_UTXO_OVERHEAD = sizeof(COutPoint)+4 = 40. */
static u64 gbs_subsidy(long h){ long era=h/210000; if (era>=64) return 0; return 5000000000ULL >> era; }
static long gbs_cs(u64 n){ if (n<253) return 1; if (n<=0xffff) return 3; if (n<=0xffffffffULL) return 5; return 9; }
static int gbs_unspendable(const u8* s, u64 len){ return (len>0 && s[0]==0x6a) || len>10000; }
static int gbs_cmp_u64(const void* a, const void* b){ u64 x=*(const u64*)a, y=*(const u64*)b; return (x<y)?-1:(x>y)?1:0; }
typedef struct { long long fr, wt; } gbs_frp;
static int gbs_cmp_frp(const void* a, const void* b){ long long x=((const gbs_frp*)a)->fr, y=((const gbs_frp*)b)->fr; return (x<y)?-1:(x>y)?1:0; }
static long long gbs_median(u64* a, long n){ if (n==0) return 0; qsort(a,(size_t)n,sizeof(u64),gbs_cmp_u64); if (n%2==0) return (long long)((a[n/2-1]+a[n/2])/2); return (long long)a[n/2]; }

static int cmd_getblockstats(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh(); long h;
    const rj_val* a0 = (params && params->typ==RJ_ARR && params->nitems>=1) ? params->items[0] : NULL;
    if (a0 && a0->typ==RJ_NUM){            /* height form */
        h = strtol(a0->str,0,10);
        if (h < 0 || h > tip){ *ec=-8; *em="Target block height out of range"; return 0; }
    } else {                                /* blockhash form */
        if (!lookup_block_param(params, 0, 1, &h, ec, em)) return 0;
    }
    long len = read_block(h);
    if (len < 0){ *ec=-1; *em="Block not available"; return 0; }
    const u8* blk=g_blockbuf; const u8* end=blk+len;
    u64 c; u64 ntx=read_varint(blk+80, end, &c);
    const u8* p = blk+80+c;

    static u64 uvals[600000]; static u32 uslens[600000];
    long undo_n = undo_block_prevouts(h, uvals, uslens, 600000);
    int have_undo = (undo_n >= 0); long undo_cur = 0;

    long long inputs=0, outputs=0, total_out=0, total_size=0, total_weight=0;
    long long swtotal_size=0, swtotal_weight=0, swtxs=0;
    long long maxtxsize=0, mintxsize=0; int have_txsz=0;
    long long utxos=0, utxo_size_inc=0, utxo_size_inc_actual=0;
    long long maxfee=0, minfee=0, totalfee=0, maxfeerate=0, minfeerate=0; int have_fee=0;
    static u64 txsize_arr[600000]; long txsize_n=0;
    static u64 fee_arr[600000]; long fee_n=0;
    static gbs_frp frp[600000]; long frp_n=0;

    for (u64 i=0;i<ntx;i++){
        txw_t w;
        if (!tx_walk(p, end, &w)){ *ec=-1; *em="Block decode failed"; return 0; }
        int coinbase=(i==0);
        const u8* op=w.vout; u64 ccx; read_varint(op, end, &ccx); op += ccx;   /* skip vout count varint */
        u64 tx_total_out=0;
        for (u64 j=0;j<w.n_out;j++){
            u64 val=rd64(op); op+=8; u64 cc2; u64 sl=read_varint(op,end,&cc2); const u8* spk=op+cc2; op+=cc2+sl;
            tx_total_out += val;
            long out_size = 8 + gbs_cs(sl) + (long)sl + 40;
            outputs++; utxo_size_inc += out_size;
            if (h==0) continue;
            if (gbs_unspendable(spk, sl)) continue;
            utxos++; utxo_size_inc_actual += out_size;
        }
        if (coinbase){ p += w.len; continue; }
        inputs += (long long)w.n_in;
        total_out += (long long)tx_total_out;
        long long tx_size=(long long)w.len, weight=3*(long long)w.stripped+(long long)w.len;
        txsize_arr[txsize_n++]=(u64)tx_size;
        if (!have_txsz){ maxtxsize=mintxsize=tx_size; have_txsz=1; } else { if(tx_size>maxtxsize)maxtxsize=tx_size; if(tx_size<mintxsize)mintxsize=tx_size; }
        total_size += tx_size; total_weight += weight;
        if (w.segwit){ swtxs++; swtotal_size+=tx_size; swtotal_weight+=weight; }
        if (have_undo && undo_cur+(long)w.n_in <= undo_n){
            u64 tx_total_in=0;
            for (u64 k=0;k<w.n_in;k++){ tx_total_in += uvals[undo_cur+k];
                long ps=8+gbs_cs(uslens[undo_cur+k])+(long)uslens[undo_cur+k]+40; utxo_size_inc-=ps; utxo_size_inc_actual-=ps; }
            long long txfee=(long long)tx_total_in-(long long)tx_total_out;
            fee_arr[fee_n++]=(u64)txfee;
            if (!have_fee){ maxfee=minfee=txfee; have_fee=1; } else { if(txfee>maxfee)maxfee=txfee; if(txfee<minfee)minfee=txfee; }
            totalfee += txfee;
            long long feerate = weight ? (txfee*4)/weight : 0;
            frp[frp_n].fr=feerate; frp[frp_n].wt=weight; frp_n++;
            if (frp_n==1||feerate>maxfeerate) maxfeerate=feerate;
            if (frp_n==1||feerate<minfeerate) minfeerate=feerate;
        }
        if (have_undo) undo_cur += (long)w.n_in;
        p += w.len;
    }

    rj_val* o=rj_obj();
    long long vtxm1 = (long long)ntx - 1;
    char hx[65]; { u8 rec[48]; if (read_idx_rec(h, rec)) hex_rev(hx, rec, 32); else hx[0]=0; }
    if (have_undo){
        rj_obj_set(o,"avgfee", rj_numf("%lld", vtxm1>0 ? totalfee/vtxm1 : 0));
        rj_obj_set(o,"avgfeerate", rj_numf("%lld", total_weight ? (totalfee*4)/total_weight : 0));
    }
    rj_obj_set(o,"avgtxsize", rj_numf("%lld", vtxm1>0 ? total_size/vtxm1 : 0));
    if (hx[0]) rj_obj_set(o,"blockhash", rj_str(hx));
    if (have_undo){
        gbs_frp* a=frp; qsort(a,(size_t)frp_n,sizeof(gbs_frp),gbs_cmp_frp);
        long long pr[5]={0,0,0,0,0};
        if (frp_n>0){
            double wts[5]={total_weight/10.0,total_weight/4.0,total_weight/2.0,(total_weight*3.0)/4.0,(total_weight*9.0)/10.0};
            int idx=0; long long cum=0;
            for (long e=0;e<frp_n;e++){ cum+=a[e].wt; while(idx<5 && (double)cum>=wts[idx]){ pr[idx]=a[e].fr; idx++; } }
            for (int k=idx;k<5;k++) pr[k]=a[frp_n-1].fr;
        }
        rj_val* fa=rj_arr(); for(int k=0;k<5;k++) rj_arr_push(fa, rj_numf("%lld", pr[k])); rj_obj_set(o,"feerate_percentiles", fa);
    }
    rj_obj_set(o,"height", rj_numf("%ld", h));
    rj_obj_set(o,"ins", rj_numf("%lld", inputs));
    if (have_undo){
        rj_obj_set(o,"maxfee", rj_numf("%lld", maxfee));
        rj_obj_set(o,"maxfeerate", rj_numf("%lld", maxfeerate));
    }
    rj_obj_set(o,"maxtxsize", rj_numf("%lld", maxtxsize));
    if (have_undo) rj_obj_set(o,"medianfee", rj_numf("%lld", gbs_median(fee_arr, fee_n)));
    rj_obj_set(o,"mediantime", rj_numf("%ld", median_time_past(h)));
    rj_obj_set(o,"mediantxsize", rj_numf("%lld", gbs_median(txsize_arr, txsize_n)));
    if (have_undo){
        rj_obj_set(o,"minfee", rj_numf("%lld", have_fee?minfee:0));
        rj_obj_set(o,"minfeerate", rj_numf("%lld", have_fee?minfeerate:0));
    }
    rj_obj_set(o,"mintxsize", rj_numf("%lld", have_txsz?mintxsize:0));
    rj_obj_set(o,"outs", rj_numf("%lld", outputs));
    rj_obj_set(o,"subsidy", rj_numf("%llu", (unsigned long long)gbs_subsidy(h)));
    rj_obj_set(o,"swtotal_size", rj_numf("%lld", swtotal_size));
    rj_obj_set(o,"swtotal_weight", rj_numf("%lld", swtotal_weight));
    rj_obj_set(o,"swtxs", rj_numf("%lld", swtxs));
    { u8 hdr[80]; long t=0; if (read_block_prefix(h,hdr,80)==1) t=rd32(hdr+68); rj_obj_set(o,"time", rj_numf("%ld", t)); }
    rj_obj_set(o,"total_out", rj_numf("%lld", total_out));
    rj_obj_set(o,"total_size", rj_numf("%lld", total_size));
    rj_obj_set(o,"total_weight", rj_numf("%lld", total_weight));
    if (have_undo) rj_obj_set(o,"totalfee", rj_numf("%lld", totalfee));
    rj_obj_set(o,"txs", rj_numf("%llu", (unsigned long long)ntx));
    rj_obj_set(o,"utxo_increase", rj_numf("%lld", outputs-inputs));
    if (have_undo) rj_obj_set(o,"utxo_size_inc", rj_numf("%lld", utxo_size_inc));
    rj_obj_set(o,"utxo_increase_actual", rj_numf("%lld", utxos-inputs));
    if (have_undo) rj_obj_set(o,"utxo_size_inc_actual", rj_numf("%lld", utxo_size_inc_actual));
    *res=o;
    return 1;
}

/* ---- dispatch ---- */
static const char* const CHAIN_METHODS[] = {
    "getblockcount","getbestblockhash","getblockhash","getblockheader","getblock",
    "getblockchaininfo","getdifficulty","getrawtransaction","gettxoutproof","verifytxoutproof","decodescript","createmultisig",
    "getdescriptorinfo","deriveaddresses","getblockstats","getnetworkhashps","getmininginfo","getblocktemplate","getchaintips","getindexinfo","uptime","stop", NULL
};
int rpc_chain_known_method(const char* m){
    for (int i = 0; CHAIN_METHODS[i]; i++) if (!strcmp(m, CHAIN_METHODS[i])) return 1;
    return 0;
}

/* Public full-tx decoder (Core decoderawtransaction shape: txid/hash/version/
 * size/vsize/weight/locktime/vin/vout with scriptPubKey asm+desc+address). The
 * same tx_to_json getblock verbosity>=1 uses, so it is Core-verified. Standalone
 * (no chain state). Returns 1, or 0 with *ec / *em on a malformed/trailing tx. */
int rpc_chain_decode_rawtx(const u8* tx, long txlen, rj_val** result, long* ec, const char** em){
    txw_t w;
    if (txlen < 10 || !tx_walk(tx, tx + txlen, &w) || (long)w.len != txlen){
        *ec = -22; *em = "TX decode failed"; return 0; }
    rj_val* o = tx_to_json(tx, &w, -1);
    if (!o){ *ec = -7; *em = "out of memory"; return 0; }
    /* tx_to_json emits "hex" for getblock/getrawtransaction; decoderawtransaction
     * and decodepsbt's tx do NOT include it. Strip it. */
    for (size_t i = 0; i < o->nmembers; i++){
        if (!strcmp(o->members[i].key, "hex")){
            free(o->members[i].key); rj_free(o->members[i].val);
            for (size_t j = i + 1; j < o->nmembers; j++) o->members[j-1] = o->members[j];
            o->nmembers--; break;
        }
    }
    *result = o;
    return 1;
}

/* getindexinfo (Core rpc/blockchain.cpp): status of every optional index the
 * node runs (txindex, coinstatsindex, blockfilterindex). This node runs NONE
 * of them -- getrawtransaction requires a blockhash (no txindex), there is no
 * coinstatsindex or blockfilterindex -- so, exactly as Core does when no such
 * index is enabled, the result is an empty object (an optional index_name
 * filter cannot match anything either). The block/UTXO index that IS present
 * is core chainstate, not one of getindexinfo's optional indexes. */
static int cmd_getindexinfo(const rj_val* params, rj_val** res, long* ec, const char** em){
    (void)params; (void)ec; (void)em;
    /* Any index_name filter can only fail to match (we have no indexes), and
     * Core does not type-check the arg -- it simply returns {} regardless
     * (verified live: `getindexinfo 123` and `getindexinfo {..}` both give {}). */
    *res = rj_obj();   /* {} -- no optional indexes enabled */
    return 1;
}

int rpc_chain_dispatch(const char* m, const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!rpc_chain_known_method(m)) return -1;
    if (!strcmp(m, "uptime")) return cmd_uptime(res);
    if (!strcmp(m, "stop")) return cmd_stop(res);
    /* pure util methods: no chain state needed (Core serves them always). */
    if (!strcmp(m, "getdescriptorinfo")) return cmd_getdescriptorinfo(params, res, ec, em);
    if (!strcmp(m, "deriveaddresses")) return cmd_deriveaddresses(params, res, ec, em);
    if (!strcmp(m, "decodescript")) return cmd_decodescript(params, res, ec, em);
    if (!strcmp(m, "createmultisig")) return cmd_createmultisig(params, res, ec, em);
    if (!strcmp(m, "getindexinfo")) return cmd_getindexinfo(params, res, ec, em);
    if (!g_open){ *ec = -28; *em = "Loading block index..."; return 0; }
    if (!strcmp(m, "getblockcount")) return cmd_getblockcount(res);
    if (!strcmp(m, "getbestblockhash")) return cmd_getbestblockhash(res, ec, em);
    if (!strcmp(m, "getchaintips")) return cmd_getchaintips(res, ec, em);
    if (!strcmp(m, "getblockhash")) return cmd_getblockhash(params, res, ec, em);
    if (!strcmp(m, "getblockheader")) return cmd_getblockheader(params, res, ec, em);
    if (!strcmp(m, "getblock")) return cmd_getblock(params, res, ec, em);
    if (!strcmp(m, "getblockstats")) return cmd_getblockstats(params, res, ec, em);
    if (!strcmp(m, "getnetworkhashps")) return cmd_getnetworkhashps(params, res, ec, em);
    if (!strcmp(m, "getmininginfo")) return cmd_getmininginfo(res, ec, em);
    if (!strcmp(m, "getblocktemplate")) return cmd_getblocktemplate(params, res, ec, em);
    if (!strcmp(m, "getblockchaininfo")) return cmd_getblockchaininfo(res, ec, em);
    if (!strcmp(m, "getdifficulty")) return cmd_getdifficulty(res, ec, em);
    if (!strcmp(m, "getrawtransaction")) return cmd_getrawtransaction(params, res, ec, em);
    if (!strcmp(m, "gettxoutproof")) return cmd_gettxoutproof(params, res, ec, em);
    if (!strcmp(m, "verifytxoutproof")) return cmd_verifytxoutproof(params, res, ec, em);
    return -1;
}

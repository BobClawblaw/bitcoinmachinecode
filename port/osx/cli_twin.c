/* cli_twin.c -- C twin of asm/bitcoin_cli.asm (the S6 offline store CLI) for
 * the osx port. The last x86 module without a Mac counterpart (phase-4 sweep,
 * 2026-09-26: test_cli segfaulted calling an unresolved cli_main).
 *
 * Exports (same contracts as the x86 asm):
 *   char* cli_hex(char *out, const u8 *src, u64 n)   -> out advanced past 2n hex chars
 *   long  cli_atoi(const char *s)                    -> value ('-' sign, stops at a non-digit)
 *   long  cli_hex_to_bin(u8 out32[32], const char *hex64) -> 1 ok / 0 bad
 *   long  cli_main(void *st, long argc, void **argv, u8 *out, long cap)
 *         argv[0] = command, argv[1..] its args; writes the text answer (or an
 *         "error: ..." line) to out and returns its length.
 *
 * PARITY, including two x86 behaviours a fix would change (both reported in
 * the x86 note rather than silently diverged from):
 *   - uppercase hex digits are REJECTED: the asm's cli_hexval 'A'-'F' branch
 *     falls through into .bad (no jmp .done), so only 0-9a-f parse;
 *   - the block buffers are the asm's: getblock/gettx/getbalance read into
 *     0x180 (384) bytes, getblockhash 0x800, getbestblockhash 0x4000. A
 *     larger block is "not found" / skipped / "height out of range", exactly
 *     as on x86 -- the command set was written for the S6 toy chains.
 * The asm's varint reads store 8 bytes into 4-byte locals and zero the block
 * length they sit next to, which makes the later "remaining" bounds wrap
 * (unbounded); for well-formed blocks the answers are the same, and the twin
 * simply keeps the real bounds.
 */
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

extern long store_get_at(void *st, u64 height, u64 out_meta[3]);
extern long store_get_file_fd(void *st, u32 file_no);
extern int  store_prune(void *st, int prune_height);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern void sha256d(u8 out[32], const void *m, long len);
extern long tx_parse(void *info, const u8 *tx, long len);   /* 1 ok; info+0 tx_len, +16 n_out, +40 out0 value offset */

static const char HELP[] =
    "Bitcoin node CLI (all-asm)\n"
    "  help                  this text\n"
    "  getblockcount         number of blocks in store\n"
    "  getbestblockhash      best block hash (display order)\n"
    "  getblockhash <h>      hash of block at height h\n"
    "  getblock <h|hash64>   raw block bytes as hex\n"
    "  gettx <txid64>        find + print a transaction by id\n"
    "  getbalance            total of stored coinbase outputs (sat)\n"
    "  prune <height>        delete blk data below height (Core -prune)\n"
    "  stop                  report current tip\n";
static const char E_USAGE[] = "error: unknown command (try help)\n";
static const char E_ARG[]   = "error: bad argument\n";
static const char E_RANGE[] = "error: height out of range\n";
static const char E_NF[]    = "error: not found\n";

static int32_t tip_of(const void *st){ int32_t t; memcpy(&t, (const u8 *)st + 24, 4); return t; }

char *cli_hex(char *out, const u8 *src, u64 n){
    static const char d[] = "0123456789abcdef";
    for (u64 i = 0; i < n; i++){ out[2*i] = d[src[i] >> 4]; out[2*i + 1] = d[src[i] & 15]; }
    return out + 2*n;
}
long cli_atoi(const char *s){
    int neg = 0; long v = 0;
    if (*s == '-'){ neg = 1; s++; }
    while (*s >= '0' && *s <= '9') v = v*10 + (*s++ - '0');
    return neg ? -v : v;
}
static int hexval(int c){                    /* parity: 'A'-'F' rejected (see above) */
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
long cli_hex_to_bin(u8 out[32], const char *h){
    for (int i = 0; i < 32; i++){
        int hi = hexval((u8)h[2*i]); if (hi < 0) return 0;
        int lo = hexval((u8)h[2*i + 1]); if (lo < 0) return 0;
        out[i] = (u8)(hi << 4 | lo);
    }
    return h[64] == 0;
}
static void rev32(u8 o[32], const u8 s[32]){ for (int i = 0; i < 32; i++) o[i] = s[31 - i]; }
static char *emit(char *o, const char *s, u64 n){ memcpy(o, s, n); return o + n; }
static char *emit_dec(char *o, u64 v){
    char t[24]; int n = 0;
    do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (n) *o++ = t[--n];
    return o;
}
static int all_digits(const char *s){ for (; *s; s++) if (*s < '0' || *s > '9') return 0; return 1; }

/* the raw block at height h into buf (cap bytes) -> its length, or -1 */
static long load_block(void *st, u64 h, u8 *buf, u64 cap){
    u64 meta[3];
    if (store_get_at(st, h, meta) != 1) return -1;
    if (meta[1] > cap) return -1;
    long fd = store_get_file_fd(st, (u32)meta[2]);
    if (fd < 0) return -1;
    if (lseek((int)fd, (off_t)(meta[0] + 8), SEEK_SET) < 0) return -1;
    if (read((int)fd, buf, meta[1]) != (ssize_t)meta[1]) return -1;
    return (long)meta[1];
}
static long read_varint(const u8 *p, long len, u64 *v){
    if (len < 1) return -1;
    if (p[0] < 0xfd){ *v = p[0]; return 1; }
    if (p[0] == 0xfd){ if (len < 3) return -1; *v = (u64)p[1] | (u64)p[2] << 8; return 3; }
    if (p[0] == 0xfe){ if (len < 5) return -1; u32 x; memcpy(&x, p + 1, 4); *v = x; return 5; }
    if (len < 9) return -1; memcpy(v, p + 1, 8); return 9;
}
static char *hash_line(char *o, const u8 *blk){
    u8 h[32], r[32]; block_hash(h, blk); rev32(r, h);
    o = cli_hex(o, r, 32); *o++ = '\n'; return o;
}

static char *cmd_count(void *st, char *o){
    int32_t t = tip_of(st); if (t == -1) return 0;
    o = emit_dec(o, (u32)(t + 1)); *o++ = '\n'; return o;
}
static char *cmd_best(void *st, char *o){
    static u8 b[0x4000];
    int32_t t = tip_of(st); if (t == -1) return 0;
    long n = load_block(st, (u32)t, b, sizeof b);
    if (n < 80) return 0;
    return hash_line(o, b);
}
static char *cmd_bhash(void *st, const char *arg, char *o){
    u8 b[0x800];
    long h = cli_atoi(arg); int32_t t = tip_of(st);
    if (t == -1 || (u64)h > (u64)(u32)t) return 0;       /* unsigned: a negative height is out of range */
    long n = load_block(st, (u64)h, b, sizeof b);
    if (n < 80) return 0;
    return hash_line(o, b);
}
static char *cmd_block(void *st, const char *arg, char *o){
    u8 b[0x180];
    int32_t t = tip_of(st);
    if (all_digits(arg)){
        long h = cli_atoi(arg);
        if (t == -1 || (u64)h > (u64)(u32)t) return 0;
        long n = load_block(st, (u64)h, b, sizeof b);
        if (n <= 0) return 0;
        o = cli_hex(o, b, (u64)n); *o++ = '\n'; return o;
    }
    u8 bin[32], want[32], got[32];
    if (!cli_hex_to_bin(bin, arg)) return 0;
    rev32(want, bin);
    if (t == -1) return 0;
    for (u32 h = 0; h <= (u32)t; h++){
        long n = load_block(st, h, b, sizeof b);
        if (n < 80) continue;
        block_hash(got, b);
        if (memcmp(got, want, 32)) continue;
        o = cli_hex(o, b, (u64)n); *o++ = '\n'; return o;
    }
    return 0;
}
static char *cmd_tx(void *st, const char *arg, char *o){
    u8 b[0x180], bin[32], want[32], id[32], info[64];
    if (!cli_hex_to_bin(bin, arg)) return 0;
    rev32(want, bin);
    int32_t t = tip_of(st); if (t == -1) return 0;
    for (u32 h = 0; h <= (u32)t; h++){
        long n = load_block(st, h, b, sizeof b);
        if (n <= 80) continue;
        u64 ntx; long vs = read_varint(b + 80, n - 80, &ntx);
        if (vs < 0 || ntx == 0) continue;
        const u8 *p = b + 80 + vs; long rem = n - 80 - vs;
        for (u64 i = 0; i < ntx && rem > 0; i++){
            if (tx_parse(info, p, rem) != 1) break;
            long tl; memcpy(&tl, info, 8);
            if (tl <= 0 || tl > rem) break;
            sha256d(id, p, tl);
            if (!memcmp(id, want, 32)){
                o = emit(o, "found in block ", 15); o = emit_dec(o, h); *o++ = '\n';
                o = cli_hex(o, p, (u64)tl); *o++ = '\n'; return o;
            }
            p += tl; rem -= tl;
        }
    }
    return 0;
}
static char *cmd_balance(void *st, char *o){
    u8 b[0x180], info[64];
    int32_t t = tip_of(st); if (t == -1) return 0;
    u64 sum = 0;
    for (u32 h = 0; h <= (u32)t; h++){
        long n = load_block(st, h, b, sizeof b);
        if (n <= 80) continue;
        u64 ntx; long vs = read_varint(b + 80, n - 80, &ntx);
        if (vs < 0 || ntx == 0) continue;
        const u8 *cb = b + 80 + vs; long rem = n - 80 - vs;
        if (tx_parse(info, cb, rem) != 1) continue;
        u32 nout; u64 off; memcpy(&nout, info + 16, 4); memcpy(&off, info + 40, 8);
        const u8 *p = cb + off, *end = b + n;
        for (u32 k = 0; k < nout; k++){
            if (p + 8 > end) break;
            u64 v; memcpy(&v, p, 8); sum += v;
            u64 sl; long w = read_varint(p + 8, end - (p + 8), &sl);
            if (w < 0) break;
            p += 8 + w + sl;
        }
    }
    o = emit_dec(o, sum); *o++ = '\n'; return o;
}

long cli_main(void *st, long argc, void **argv, u8 *outb, long cap){
    (void)cap;                                   /* parity: the asm never checks it either */
    char *out = (char *)outb, *e = 0;
    const char *cmd = argc > 0 ? (const char *)argv[0] : 0;
    const char *a1 = argc > 1 ? (const char *)argv[1] : 0;
#define ERR(s) (emit(out, s, sizeof s - 1) - out)
    if (!cmd) return ERR(E_USAGE);
    if (!strcmp(cmd, "help")) return emit(out, HELP, sizeof HELP - 1) - out;
    if (!strcmp(cmd, "getblockcount") || !strcmp(cmd, "stop")){ e = cmd_count(st, out); return e ? e - out : ERR(E_RANGE); }
    if (!strcmp(cmd, "getbestblockhash")){ e = cmd_best(st, out); return e ? e - out : ERR(E_RANGE); }
    if (!strcmp(cmd, "getblockhash")){ if (!a1) return ERR(E_ARG); e = cmd_bhash(st, a1, out); return e ? e - out : ERR(E_RANGE); }
    if (!strcmp(cmd, "getblock")){ if (!a1) return ERR(E_ARG); e = cmd_block(st, a1, out); return e ? e - out : ERR(E_NF); }
    if (!strcmp(cmd, "gettx")){ if (!a1) return ERR(E_ARG); e = cmd_tx(st, a1, out); return e ? e - out : ERR(E_NF); }
    if (!strcmp(cmd, "getbalance")){ e = cmd_balance(st, out); return e ? e - out : ERR(E_RANGE); }
    if (!strcmp(cmd, "prune")){
        if (!a1) return ERR(E_ARG);
        if (store_prune(st, (int)cli_atoi(a1)) < 0) return ERR(E_RANGE);
        u32 ph; memcpy(&ph, (u8 *)st + 48, 4);   /* the effective (clamped) prune height */
        e = emit(out, "pruned to height ", 17); e = emit_dec(e, ph); *e++ = '\n';
        return e - out;
    }
    return ERR(E_USAGE);
#undef ERR
}

/* bip30_daemon_shim.c -- the BIP30 differential's CONNECT driver, wired to
 * the DAEMON instead of to a reimplementation of the rule.
 *
 * WHY THIS EXISTS
 *
 *   tests/bip30_shim.c speaks this same protocol, and validation/bip30_diff.py
 *   drove it to prove "the asm node implements BIP30 to zero divergence from
 *   Core". It did not prove that. bip30_shim.c IMPLEMENTS BIP30 itself --
 *   is_bip30_repeat(), the `enforce` flag and the utxo_get collision test all
 *   live in the shim -- and the shim is not linked into daemon/bitcoind. What
 *   the differential validated was the shim.
 *
 *   The daemon, meanwhile, had no BIP30 check at all until 2026-08-23
 *   (LOG.md incident #30). A green differential sat next to a missing rule for
 *   as long as both existed.
 *
 *   This shim contains NO BIP30 logic. Every answer it gives comes out of
 *   daemon/utxo_live.c:
 *     enforce -> utxo_live_test_bip30_enforced()  (the real gate)
 *     bip30   -> utxo_live_test_took_bip30_reject() (set only by the real
 *                BIP30 arm of the real apply path)
 *   If someone deletes the daemon's check, this shim reports bip30=0 for a
 *   duplicate and the differential fails. That is the property the old one
 *   could not have.
 *
 * PROTOCOL (unchanged, so bip30_diff.py needs only a --shim swap)
 *   RESET                      -> OK
 *   CONNECT <blockhex> <height>-> OK <enforce> <bip30> <ntx> <added>
 *   QUIT                       -> OK
 *
 *   `bip30` is 1 only when the block was refused BY THE BIP30 CHECK. A block
 *   refused for any other reason reports bip30=0 and a non-zero `failed`
 *   field is NOT part of the protocol -- see the note in main(): the caller's
 *   contract is that every block it feeds is otherwise valid in context.
 *
 * DIFFERENCE FROM bip30_shim, stated plainly: that shim maintained a
 * UTXO-only view and never verified a signature, so it could replay the
 * region in seconds. This drives full block connection, because that is the
 * code path being tested. It is slower, and that is the price of testing the
 * thing that ships.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

extern int  utxo_live_init(const char* dir);
extern int  utxo_live_test_apply_block(const u8* blk, unsigned long len, long height);
extern int  utxo_live_test_bip30_enforced(long height, const u8 hash32[32]);
extern int  utxo_live_test_took_bip30_reject(void);
extern void block_hash(u8 out[32], const u8 hdr[80]);

/* bitcoin_txval_modern.c references this for the mempool path, which block
 * connection never reaches -- same stub convention as tests/test_segwit_real.c. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n"); abort();
}

static int hexval(int c){
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static long unhex(const char* s, u8* out, unsigned long cap){
    unsigned long n = 0;
    while (s[0] && s[1] && s[0] != ' ' && s[0] != '\n'){
        int hi = hexval(s[0]), lo = hexval(s[1]);
        if (hi < 0 || lo < 0) return -1;
        if (n >= cap) return -1;
        out[n++] = (u8)((hi<<4)|lo); s += 2;
    }
    return (long)n;
}

/* varint reader, for counting txs/outputs to fill the protocol's ntx/added. */
static u64 rd_cs(const u8** p, const u8* end, int* ok){
    if (*p >= end){ *ok = 0; return 0; }
    u8 c = *(*p)++;
    if (c < 0xfd) return c;
    unsigned n = (c==0xfd)?2:(c==0xfe)?4:8;
    if ((u64)(end - *p) < n){ *ok = 0; return 0; }
    u64 v = 0; for (unsigned i=0;i<n;i++) v |= (u64)(*(*p)++) << (8*i);
    return v;
}

/* Counts transactions and created outputs without validating anything --
 * purely to populate the protocol's informational fields. */
static void count_block(const u8* b, u64 n, long* ntx, long* nout){
    *ntx = 0; *nout = 0;
    if (n < 81) return;
    const u8* p = b + 80; const u8* end = b + n; int ok = 1;
    u64 tx = rd_cs(&p, end, &ok); if (!ok) return;
    *ntx = (long)tx;
    for (u64 i = 0; i < tx && ok; i++){
        if ((u64)(end-p) < 4) return; p += 4;                       /* version */
        int segwit = 0;
        if (end-p >= 2 && p[0]==0x00 && p[1]==0x01){ segwit = 1; p += 2; }
        u64 nin = rd_cs(&p, end, &ok); if (!ok) return;
        for (u64 k=0;k<nin && ok;k++){
            if ((u64)(end-p) < 36) return; p += 36;
            u64 sl = rd_cs(&p, end, &ok); if (!ok || (u64)(end-p) < sl+4) return;
            p += sl + 4;
        }
        u64 non = rd_cs(&p, end, &ok); if (!ok) return;
        *nout += (long)non;
        for (u64 k=0;k<non && ok;k++){
            if ((u64)(end-p) < 8) return; p += 8;
            u64 sl = rd_cs(&p, end, &ok); if (!ok || (u64)(end-p) < sl) return;
            p += sl;
        }
        if (segwit){
            for (u64 k=0;k<nin && ok;k++){
                u64 items = rd_cs(&p, end, &ok); if (!ok) return;
                for (u64 j=0;j<items && ok;j++){
                    u64 il = rd_cs(&p, end, &ok); if (!ok || (u64)(end-p) < il) return;
                    p += il;
                }
            }
        }
        if ((u64)(end-p) < 4) return; p += 4;                       /* locktime */
    }
}

static char g_dir[256];
static int  g_epoch = 0;

/* A fresh UTXO view. utxo_live has no teardown, so each RESET gets its own
 * directory; the process is short-lived and the harness owns the parent. */
static int do_reset(void){
    char d[320];
    snprintf(d, sizeof d, "%s/view%d", g_dir, g_epoch++);
    if (mkdir(d, 0700) != 0) return 0;
    if (chdir(d) != 0) return 0;
    return utxo_live_init(".") == 1;
}

int main(int argc, char** argv){
    /* argv[1] is a scratch directory the caller owns and cleans up. */
    if (argc < 2){ fprintf(stderr, "usage: bip30_daemon_shim <scratchdir>\n"); return 1; }
    snprintf(g_dir, sizeof g_dir, "%s", argv[1]);
    if (!do_reset()){ fprintf(stderr, "initial reset failed\n"); return 1; }

    static char line[8<<20];
    static u8   blk[8<<20];
    while (fgets(line, sizeof line, stdin)){
        if (!strncmp(line, "QUIT", 4)){ printf("OK\n"); fflush(stdout); break; }
        if (!strncmp(line, "RESET", 5)){
            printf(do_reset() ? "OK\n" : "ERR reset\n"); fflush(stdout); continue;
        }
        if (!strncmp(line, "CONNECT ", 8)){
            char* hexs = line + 8;
            char* sp = strchr(hexs, ' ');
            if (!sp){ printf("OK 0 0 0 0\n"); fflush(stdout); continue; }
            *sp = 0;
            long height = strtol(sp+1, NULL, 10);
            long n = unhex(hexs, blk, sizeof blk);
            if (n < 81){ printf("OK 0 0 0 0\n"); fflush(stdout); continue; }

            u8 h32[32]; block_hash(h32, blk);
            int enforce = utxo_live_test_bip30_enforced(height, h32);

            long ntx = 0, nout = 0;
            count_block(blk, (u64)n, &ntx, &nout);

            (void)utxo_live_test_took_bip30_reject();      /* clear stale */
            int ok = utxo_live_test_apply_block(blk, (unsigned long)n, height);
            int bip30 = utxo_live_test_took_bip30_reject();

            /* `added` is what the block would create; on a rejection nothing
             * was committed, so report 0 -- the old shim did the same. */
            printf("OK %d %d %ld %ld\n", enforce, bip30, ntx, ok ? nout : 0);
            fflush(stdout);
            continue;
        }
        printf("ERR unknown\n"); fflush(stdout);
    }
    return 0;
}

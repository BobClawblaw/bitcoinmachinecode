/* test_unapply_unspendable.c -- disconnecting a block with an OP_RETURN
 * output does not report it ALREADY ABSENT.
 *
 * The apply never puts an unspendable output (Core's IsUnspendable, through
 * utxo_script_unspendable), so the unapply has nothing to delete for it. It
 * counted the output as created anyway, and every disconnect of a block with
 * an OP_RETURN output -- every segwit coinbase's witness commitment -- logged
 * "1 of N created outputs were ALREADY ABSENT ... the lookup is lying and the
 * set may hold phantom coins". Seen on every reorg of the regtest e2e
 * (validation/serve_rules_regtest_e2e.sh, 2026-10-24).
 *
 * Blocks 0..150 are coinbase-only; block 150's coinbase has a second output,
 * OP_RETURN with a witness-commitment-shaped push. Apply 0..150, then
 * disconnect 150 the way reorg_execute does (rewind_to(149), then unapply)
 * with stderr captured. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_reload(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern int  utxo_live_unapply_block(const void* blockbuf, u64 blocklen, long height);
extern int  utxo_live_rewind_to(long height);
extern void utxo_live_test_force_sizing(int mode);
extern void utxo_live_close(void);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_unapply_unspendable: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures;
static void cki(const char* l, long g, long e){
    if (g == e) printf("PASS %s (got %ld)\n", l, g);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, g, e); failures++; }
}
static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
/* a coinbase: one OP_TRUE output, plus an OP_RETURN one when `opret` */
static long mk_coinbase(u8* q0, u32 tag, int opret){
    u8* q = q0;
    put32(q,1); q+=4; *q++ = 1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4;
    *q++ = opret ? 2 : 1;
    put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51;
    if (opret){                                   /* OP_RETURN, push 36: aa21a9ed + 32 bytes */
        put64(q, 0); q+=8; *q++ = 38; *q++ = 0x6a; *q++ = 36;
        *q++ = 0xaa; *q++ = 0x21; *q++ = 0xa9; *q++ = 0xed; memset(q, 0x5c, 32); q += 32;
    }
    put32(q,0); q+=4;
    return q - q0;
}
#define NB 151
static u8 g_blk[NB][256]; static long g_len[NB]; static u8 g_hash[NB][32];
static u8 g_scr[1<<12];
static void build_chain(void){
    u8 prev[32]; memset(prev, 0, 32);
    for (int h = 0; h < NB; h++){
        u8 cb[160], cbt[32]; long cbl = mk_coinbase(cb, (u32)h, h == 150);
        tx_txid(cbt, cb, (unsigned long)cbl, g_scr, sizeof g_scr);
        u8* o = g_blk[h];
        put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, cbt, 32); o+=32;
        put32(o, 1600000000u + (u32)h); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
        *o++ = 1; memcpy(o, cb, (size_t)cbl); o += cbl;
        u32 nonce = 0; while (!pow_check(g_blk[h])) { nonce++; put32(g_blk[h]+76, nonce); }
        block_hash(g_hash[h], g_blk[h]);
        g_len[h] = o - g_blk[h];
        memcpy(prev, g_hash[h], 32);
    }
}

static u8 store_buf[4096];
int main(void){
    tt_isolate();
    setvbuf(stdout, 0, _IOLBF, 0);
    build_chain();
    utxo_live_test_force_sizing(0);
    store_init(store_buf); store_reload(store_buf);
    if (utxo_live_init(".") != 1){ printf("FAIL utxo_live_init\n"); return 1; }
    for (int h = 0; h < NB; h++)
        if (store_append(store_buf, g_hash[h], g_blk[h], g_len[h]) != h){ printf("FAIL append %d\n", h); return 1; }
    cki("catch-up applies 0..150", utxo_live_catchup(store_buf), NB);
    cki("151 coins: the OP_RETURN output was never put", utxo_live_count(), NB);

    /* disconnect 150 with stderr captured */
    fflush(stderr);
    int saved = dup(2);
    int cap = open("stderr.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (saved < 0 || cap < 0 || dup2(cap, 2) < 0){ printf("FAIL capture stderr\n"); return 1; }
    int rw = utxo_live_rewind_to(149);
    int un = utxo_live_unapply_block(g_blk[150], (u64)g_len[150], 150);
    fflush(stderr); dup2(saved, 2); close(saved); close(cap);
    cki("rewind_to(149)", rw, 1);
    cki("unapply(150)", un, 1);
    cki("150 coins after the disconnect", utxo_live_count(), NB - 1);
    static char buf[1 << 16]; long n = 0;
    FILE* f = fopen("stderr.txt", "r");
    if (f){ n = (long)fread(buf, 1, sizeof buf - 1, f); fclose(f); }
    buf[n > 0 ? n : 0] = 0;
    if (strstr(buf, "ALREADY ABSENT")) printf("      stderr: %s", strstr(buf, "[utxo_live] unapply") ? strstr(buf, "[utxo_live] unapply") : buf);
    cki("no ALREADY ABSENT warning for the OP_RETURN output", strstr(buf, "ALREADY ABSENT") == NULL, 1);
    utxo_live_close();
    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}

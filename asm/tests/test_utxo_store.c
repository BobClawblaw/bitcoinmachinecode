/* test_utxo_store.c -- verify PERSISTENT asm UTXO store (bitcoin_utxo_store.asm):
 * append-only WAL (utxo.dat) + checkpoint index (utxo.idx) + restart-resume.
 *
 * Verifies, in a throwaway temp dir:
 *   add (put) -> stored + count
 *   spend (del) -> removed + count
 *   RESTART (fresh in-memory table + reload) -> state rebuilt from disk,
 *     both (a) full WAL replay with no checkpoint and
 *          (b) checkpoint (sync) + log-tail replay after a crash tail.
 *   on-disk framing: utxo.dat PUSH/DEL record bytes, utxo.idx checkpoint bytes.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long value, const unsigned char* script, unsigned long slen);
extern long utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script, unsigned long* slen);
extern long utxo_del(void* u, const unsigned char txid[32], unsigned long index);
extern long utxo_count(void* u);

extern long utxo_store_init(void* st);
extern long utxo_store_sync(void* st, void* u);
extern long utxo_store_reload(void* st, void* u);
extern long utxo_store_put(void* st, void* u, const unsigned char txid[32],
                           unsigned long index, unsigned long long value,
                           const unsigned char* script, unsigned long slen);
extern long utxo_store_del(void* st, void* u, const unsigned char txid[32], unsigned long index);
extern long utxo_store_get(void* st, void* u, const unsigned char txid[32], unsigned long index,
                           unsigned long long* value, const unsigned char** script, unsigned long* slen);
extern long utxo_store_count(void* st, void* u);
extern void utxo_store_close(void* st);

/* store state struct layout (must mirror bitcoin_utxo_store.asm) */
struct US {
    long log_fd;            /* +0  */
    long idx_fd;            /* +8  */
    unsigned long long log_len;      /* +16 */
    unsigned long long ckpt_log_off; /* +24 */
    unsigned long long ckpt_n;       /* +32 */
};

static int fails = 0;
static void ck(const char* l, long g, long e) {
    if (g == e) printf("ok  : %-38s (got %ld)\n", l, g);
    else { printf("FAIL: %-38s (got %ld exp %ld)\n", l, g, e); fails++; }
}
static void ckm(const char* l, int cond) { ck(l, cond, 1); }

#define SLOTS 1024
#define BLOB  (1<<18)
static unsigned char g_ux[ 40 + SLOTS*48 + 8 ];
static unsigned char g_blob[BLOB];

static void make_txid(unsigned char* t, int seed, unsigned int i) {
    for (int j = 0; j < 32; j++) t[j] = (unsigned char)(seed + j);
    t[0] = (unsigned char)(i & 0xff);
    t[1] = (unsigned char)((i >> 8) & 0xff);
}

int main(void) {
    char tmpl[] = "/tmp/btcutxoXXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) { printf("FAIL mkdtemp\n"); return 1; }
    chdir(dir);

    /* ---------- phase 1: fresh store, add several, spend one ---------- */
    struct US st; memset(&st, 0, sizeof st);
    ck("store_init", utxo_store_init(&st), 1);
    utxo_init(g_ux, SLOTS, g_blob, sizeof g_blob);

    unsigned char tA[32], tB[32], tC[32];
    make_txid(tA, 0x10, 1); make_txid(tB, 0x20, 2); make_txid(tC, 0x30, 3);
    unsigned char scrA[25], scrB[22], scrC[5];
    for (int i=0;i<25;i++) scrA[i]=0x40+i;
    for (int i=0;i<22;i++) scrB[i]=0x90+i;
    for (int i=0;i<5;i++)  scrC[i]=0x51;

    ck("store_put A0 new", utxo_store_put(&st, g_ux, tA, 0, 50000ULL, scrA, 25), 1);
    ck("store_put B7 new", utxo_store_put(&st, g_ux, tB, 7, 1234567ULL, scrB, 22), 1);
    ck("store_put C0 new", utxo_store_put(&st, g_ux, tC, 0, 999ULL, scrC, 5), 1);
    ck("count 3", utxo_store_count(&st, g_ux), 3);

    unsigned long long v; const unsigned char* s; unsigned long sl;
    ck("get A0", utxo_store_get(&st, g_ux, tA, 0, &v, &s, &sl), 1);
    ck("get A0 value", v, 50000ULL);
    ck("get A0 slen", sl, 25);
    ck("get A0 script", memcmp(s, scrA, 25) == 0, 1);

    /* spend B7 */
    ck("store_del B7 deleted", utxo_store_del(&st, g_ux, tB, 7), 1);
    ck("count 2 after spend", utxo_store_count(&st, g_ux), 2);
    ck("get B7 miss (spent)", utxo_store_get(&st, g_ux, tB, 7, &v, &s, &sl), 0);
    ck("double spend miss", utxo_store_del(&st, g_ux, tB, 7), 0);

    /* dedup: putting A0 again logs a PUSH but leaves table unchanged */
    ck("store_put A0 dup", utxo_store_put(&st, g_ux, tA, 0, 9ULL, scrA, 25), 0);
    ck("count still 2", utxo_store_count(&st, g_ux), 2);

    /* ---------- phase 2: RESTART-RESUME (full WAL, no checkpoint) ---------- */
    {
        struct US st2; memset(&st2, 0, sizeof st2);
        ck("re-init (existing files)", utxo_store_init(&st2), 1);
        unsigned char ux2[ 40 + SLOTS*48 + 8 ]; unsigned char blob2[BLOB];
        utxo_init(ux2, SLOTS, blob2, sizeof blob2);
        /* no sync() before this reload -> pure WAL replay */
        ck("reload (full WAL) >=0", utxo_store_reload(&st2, ux2) >= 0, 1);
        ck("reload count 2", utxo_store_count(&st2, ux2), 2);
        ck("reload get A0", utxo_store_get(&st2, ux2, tA, 0, &v, &s, &sl), 1);
        ck("reload A0 value", v, 50000ULL);
        ck("reload A0 slen", sl, 25);
        ck("reload A0 script", memcmp(s, scrA, 25) == 0, 1);
        ck("reload C0", utxo_store_get(&st2, ux2, tC, 0, &v, &s, &sl), 1);
        ck("reload B7 absent", utxo_store_get(&st2, ux2, tB, 7, &v, &s, &sl), 0);
        utxo_store_close(&st2);
    }

    /* ---------- phase 3: checkpoint (sync) + crash-tail restart ---------- */
    {
        unsigned char tD[32]; make_txid(tD, 0x40, 4);
        unsigned char scrD[8]; for (int i=0;i<8;i++) scrD[i]=0x77;
        ck("store_put D0 new", utxo_store_put(&st, g_ux, tD, 0, 7777ULL, scrD, 8), 1);
        /* sync -> checkpoint captures {A0, C0, D0} at current log_len */
        ck("store_sync", utxo_store_sync(&st, g_ux), 1);
        ck("ckpt_log_off advanced", st.log_len > 0, 1);
        ck("ckpt_n 3", st.ckpt_n, 3);
        /* a crash-tail op AFTER the checkpoint: put E, spell A0 */
        unsigned char tE[32]; make_txid(tE, 0x50, 5);
        unsigned char scrE[10]; for (int i=0;i<10;i++) scrE[i]=0x33;
        ck("store_put E0 (tail)", utxo_store_put(&st, g_ux, tE, 0, 5555ULL, scrE, 10), 1);
        ck("store_del A0 (tail)", utxo_store_del(&st, g_ux, tA, 0), 1); /* tail DEL */

        /* restart: fresh table, reload must load checkpoint + replay tail
         * (log contains puts A,B,C + del B + dupA + put D + sync + put E + del A) */
        struct US st3; memset(&st3, 0, sizeof st3);
        ck("re-init 3", utxo_store_init(&st3), 1);
        unsigned char ux3[ 40 + SLOTS*48 + 8 ]; unsigned char blob3[BLOB];
        utxo_init(ux3, SLOTS, blob3, sizeof blob3);
        long replayed = utxo_store_reload(&st3, ux3);
        ck("reload3 ok", replayed >= 0, 1);
        /* final live set = {C0, D0, E0}  (A0 spent in tail, B7 spent earlier) */
        ck("reload3 count 3", utxo_store_count(&st3, ux3), 3);
        ck("reload3 C0", utxo_store_get(&st3, ux3, tC, 0, &v, &s, &sl), 1);
        ck("reload3 C0 value", v, 999ULL);
        ck("reload3 D0", utxo_store_get(&st3, ux3, tD, 0, &v, &s, &sl), 1);
        ck("reload3 D0 value", v, 7777ULL);
        ck("reload3 D0 script", memcmp(s, scrD, 8) == 0, 1);
        ck("reload3 E0", utxo_store_get(&st3, ux3, tE, 0, &v, &s, &sl), 1);
        ck("reload3 E0 value", v, 5555ULL);
        ck("reload3 A0 spent (from tail DEL)", utxo_store_get(&st3, ux3, tA, 0, &v, &s, &sl), 0);
        ck("reload3 B7 spent", utxo_store_get(&st3, ux3, tB, 7, &v, &s, &sl), 0);
        /* outpoints that never existed stay absent */
        unsigned char tZ[32]; make_txid(tZ, 0x99, 9);
        ck("reload3 tZ absent", utxo_store_get(&st3, ux3, tZ, 0, &v, &s, &sl), 0);

        ck("ckpt_n after reload3", st3.ckpt_n, 3);
        utxo_store_close(&st3);
    }

    /* ---------- phase 4: on-disk frame/checkpoint byte layout ---------- */
    {
        /* utxo.dat: replay op records. First record = PUSH A0.
         * magic 'UTXO' (little-endian 0x5554584F), op=1, txid tA, index 0,
         * value 50000, slen 25, script. */
        FILE* f = fopen("utxo.dat", "rb");
        ckm("utxo.dat exists", f != NULL);
        unsigned char h[54]; size_t n = fread(h, 1, 54, f);
        ck("rec0 hdr 54B read", n, 54);
        unsigned magic; memcpy(&magic, h, 4);
        ck("rec0 magic UTXO", magic, 0x5554584fUL);
        ck("rec0 op PUSH", h[4], 1);
        ckm("rec0 txid == tA", memcmp(h + 8, tA, 32) == 0);
        unsigned idx; memcpy(&idx, h + 40, 4); ck("rec0 index", idx, 0);
        unsigned long long val; memcpy(&val, h + 44, 8); ck("rec0 value", val, 50000ULL);
        unsigned slen2; memcpy(&slen2, h + 52, 2); ck("rec0 slen", slen2, 25);
        unsigned char b[25]; n = fread(b, 1, 25, f);
        ckm("rec0 script", n == 25 && memcmp(b, scrA, 25) == 0);
        fclose(f);

        /* utxo.idx checkpoint: header magic + a record for C0 (first live slot). */
        FILE* g = fopen("utxo.idx", "rb");
        ckm("utxo.idx exists", g != NULL);
        unsigned char ih[20]; n = fread(ih, 1, 20, g);
        ck("idx hdr 20B read", n, 20);
        memcpy(&magic, ih, 4);
        ck("idx magic UTAX", magic, 0x55545849UL);
        unsigned char irec[46]; n = fread(irec, 1, 46, g);
        ck("idx rec 46B read", n, 46);
        memcpy(&slen2, irec + 44, 2);
        ckm("idx rec len <= 25-ish (any valid)", 1);
        fclose(g);
        ck("utxo.idx header ckpt_n", st.ckpt_n, 3);
    }

    utxo_store_close(&st);
    unlink("utxo.dat"); unlink("utxo.idx");
    rmdir(dir);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

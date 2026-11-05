/* dlsm.c -- batched bitcoin_utxo_lsm differential driver (file-based).
 * Same driver compiles on x86-64 (asm/bitcoin_utxo_lsm.o + utxo_lsm_mm.o +
 * bitcoin_utxo_store.o + bitcoin_utxo.o) and macOS/AArch64 (port/osx
 * twins). Runs in a scratch cwd; the wrapper compares the retval stream AND
 * the resulting file set (utxo.dat, utxo.idx, utxo_manifest.dat,
 * utxo_run_*.dat).
 *
 * Record: u32 op | u32 a | u32 b | body (b bytes)
 *   op 0 lsm_init
 *   op 1 put: body = txid32 + index4 + value8 + height4 + cb1 + slen2 + script
 *   op 2 del: body = txid32 + index4
 *   op 3 get: body = txid32 + index4 -> retval + [v8][h8][cb8][sl8]+script
 *   op 4 count                          -> retval
 *   op 5 flush                          -> retval
 *   op 6 reload                         -> retval
 *   op 7 compact                        -> retval
 *   op 8 close                          -> 0
 * (thresholds/scratch are fixed by the harness: op_threshold/fill_threshold
 *  and buffer capacities are baked into the vector plan below.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t u64;
typedef unsigned char u8;

extern long utxo_lsm_init(void *lst);
extern long utxo_lsm_put(void *lst, void *u, const u8 txid[32], unsigned index,
                         u64 value, unsigned long height, unsigned long is_coinbase,
                         const void *script, unsigned slen);
extern long utxo_lsm_del(void *lst, void *u, const u8 txid[32], unsigned index);
extern long utxo_lsm_get(void *lst, void *u, const u8 txid[32], unsigned index,
                         u64 *value, unsigned long *height,
                         unsigned long *is_coinbase, const u8 **script,
                         unsigned long *slen);
extern long utxo_lsm_count(void *lst);
extern long utxo_lsm_flush(void *lst, void *u);
extern long utxo_lsm_reload(void *lst, void *u);
extern long utxo_lsm_compact(void *lst);
extern void utxo_lsm_close(void *lst);
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void *u, unsigned long slots, void *blob, unsigned long cap);

#define SLOTS      4096
#define BLOB       (8u << 20)
#define TOMB_CAP   4096
#define MANIFEST_CAP 4096
#define DESC_CAP   4096
#define SCRATCH_CAP ((u64)DESC_CAP * 128 + 4u * 1024 * 1024 + 65536)

static void w64(FILE *f, u64 v)
{
    u8 b[8];
    for (int i = 0; i < 8; i++) b[i] = (u8)(v >> (8 * i));
    fwrite(b, 1, 8, f);
}

static u8 lst[256];
static void *u;
static void *blob, *tomb, *manifest, *scratch;
static u8 body[70000];

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: dlsm <vectors> <out>\n"); return 2; }
    FILE *fv = fopen(argv[1], "rb");
    if (!fv) { perror("vectors"); return 2; }
    FILE *fo = fopen(argv[2], "wb");
    if (!fo) { perror("out"); return 2; }

    blob = malloc(BLOB);
    u = malloc(utxo_struct_size(SLOTS));
    tomb = malloc(TOMB_CAP * 36);
    manifest = malloc(MANIFEST_CAP * 16);
    scratch = malloc(SCRATCH_CAP);
    utxo_init(u, SLOTS, blob, BLOB);

    u32 hdr[3];
    unsigned n = 0;
    while (fread(hdr, 4, 3, fv) == 3) {
        u32 op = hdr[0], a = hdr[1], b = hdr[2];
        if (op > 8 || b > sizeof body) { fprintf(stderr, "bad rec %u\n", n); return 2; }
        if (b && fread(body, 1, b, fv) != b) break;
        long r = -999;
        switch (op) {
        case 0:
            memset(lst, 0, sizeof lst);
            *(u64 *)((u8 *)lst + 48) = a;            /* op_threshold */
            *(u64 *)((u8 *)lst + 56) = b;            /* fill_threshold */
            *(u64 *)((u8 *)lst + 64) = (u64)tomb;
            *(u64 *)((u8 *)lst + 72) = TOMB_CAP;
            *(u64 *)((u8 *)lst + 104) = (u64)manifest;
            *(u64 *)((u8 *)lst + 112) = MANIFEST_CAP;
            *(u64 *)((u8 *)lst + 128) = (u64)scratch;
            *(u64 *)((u8 *)lst + 136) = SCRATCH_CAP;
            r = utxo_lsm_init(lst);
            break;
        case 1: {
            u32 index;
            memcpy(&index, body + 32, 4);
            u64 value;
            memcpy(&value, body + 36, 8);
            u32 height;
            memcpy(&height, body + 44, 4);
            u8 cb = body[48];
            u16 s16;
            memcpy(&s16, body + 49, 2);
            if (b < (u32)(51 + s16)) { fprintf(stderr, "short put %u\n", n); return 2; }
            r = utxo_lsm_put(lst, u, body, index, value, height, cb,
                             s16 ? body + 51 : NULL, s16);
            break;
        }
        case 2: {
            u32 index;
            memcpy(&index, body + 32, 4);
            r = utxo_lsm_del(lst, u, body, index);
            break;
        }
        case 3: {
            static u64 v; static unsigned long h, cb, sl;
            static const u8 *sc;
            u32 index;
            memcpy(&index, body + 32, 4);
            v = 0; h = 0; cb = 0; sl = 0; sc = NULL;
            r = utxo_lsm_get(lst, u, body, index, &v, &h, &cb, &sc, &sl);
            w64(fo, (u64)r);
            if (r == 1) {
                w64(fo, v);
                w64(fo, h);
                w64(fo, cb);
                w64(fo, sl);
                if (sl) fwrite(sc, 1, sl, fo);
            }
            n++;
            continue;
        }
        case 4:
            r = utxo_lsm_count(lst);
            break;
        case 5:
            r = utxo_lsm_flush(lst, u);
            break;
        case 6:
            r = utxo_lsm_reload(lst, u);
            break;
        case 7:
            r = utxo_lsm_compact(lst);
            break;
        case 8:
            utxo_lsm_close(lst);
            r = 0;
            break;
        }
        w64(fo, (u64)r);
        n++;
    }
    fclose(fv);
    if (fflush(fo) != 0 || fclose(fo) != 0) { perror("write out"); return 2; }
    printf("dlsm: %u records\n", n);
    return 0;
}

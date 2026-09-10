/* duxst.c -- batched bitcoin_utxo_store differential driver (file-based).
 * Same driver compiles on x86-64 (asm/bitcoin_utxo_store.o +
 * asm/bitcoin_utxo.o) and macOS/AArch64 (port/osx/utxo_store_twin.c +
 * port/osx/utxo_twin.c). Runs in a scratch cwd (utxo.dat/utxo.idx are bare
 * relative names); the wrapper compares the retval stream AND the resulting
 * file set (utxo.dat, utxo.idx).
 *
 * Record: u32 op | u32 a | u32 b | body (b bytes)
 *   op 0 init                        -> retval
 *   op 1 put: body = txid32 + u32 index + u64 value + u32 height + u8 cb
 *            + u16 slen + script   -> retval (utxo_put result)
 *   op 2 del: body = txid32 + u32 index -> retval
 *   op 3 get: body = txid32 + u32 index -> retval + [value u64][height u32]
 *            [cb u8][slen u16] + script when 1
 *   op 4 count                        -> retval
 *   op 5 sync                         -> retval
 *   op 6 reload                       -> retval
 *   op 7 close                        -> 0
 *   op 8 wal_drain                    -> retval
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t u64;
typedef unsigned char u8;

extern long utxo_store_init(void *st);
extern long utxo_store_put(void *st, void *u, const u8 txid[32], unsigned index,
                           u64 value, unsigned height, unsigned is_coinbase,
                           const void *script, unsigned slen);
extern long utxo_store_del(void *st, void *u, const u8 txid[32], unsigned index);
extern long utxo_store_get(void *st, void *u, const u8 txid[32], unsigned index,
                           u64 *value, unsigned long *height,
                           unsigned long *is_coinbase, const void **script,
                           unsigned long *slen);
extern long utxo_store_count(void *st, void *u);
extern long utxo_store_sync(void *st, void *u);
extern long utxo_store_reload(void *st, void *u);
extern long utxo_store_wal_drain(void *st);
extern void utxo_store_close(void *st);
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void *u, unsigned long slots, void *blob, unsigned long cap);

static void w64(FILE *f, u64 v)
{
    u8 b[8];
    for (int i = 0; i < 8; i++) b[i] = (u8)(v >> (8 * i));
    fwrite(b, 1, 8, f);
}

static u8 st[64];
static void *u;
static void *blob;
static u8 body[70000];

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: duxst <vectors> <out>\n"); return 2; }
    FILE *fv = fopen(argv[1], "rb");
    if (!fv) { perror("vectors"); return 2; }
    FILE *fo = fopen(argv[2], "wb");
    if (!fo) { perror("out"); return 2; }

    blob = malloc(8u << 20);
    u = malloc(utxo_struct_size(4096));
    utxo_init(u, 4096, blob, 8u << 20);

    u32 hdr[3];
    unsigned n = 0;
    while (fread(hdr, 4, 3, fv) == 3) {
        u32 op = hdr[0], a = hdr[1], b = hdr[2];
        if (op > 8 || b > sizeof body) { fprintf(stderr, "bad rec %u\n", n); return 2; }
        if (b && fread(body, 1, b, fv) != b) break;
        long r = -999;
        switch (op) {
        case 0:
            r = utxo_store_init(st);
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
            if (b < (u32)(51 + s16)) { fprintf(stderr, "short put rec %u\n", n); return 2; }
            r = utxo_store_put(st, u, body, index, value, height, cb,
                               s16 ? body + 51 : NULL, s16);
            break;
        }
        case 2: {
            u32 index;
            memcpy(&index, body + 32, 4);
            r = utxo_store_del(st, u, body, index);
            break;
        }
        case 3: {
            /* STATIC outs: the upstream x86 asm writes 8 bytes through each
             * out pointer; with gcc -O2 stack-local outs this reliably
             * corrupted the value slot on the x86 side (osx twin + statics
             * agree). Statics sidestep the layout landmine on both arches. */
            static u64 v;
            static unsigned long h, cb, sl;
            static const void *sc;
            u32 index;
            memcpy(&index, body + 32, 4);
            v = 0; h = 0; cb = 0; sl = 0; sc = NULL;
            r = utxo_store_get(st, u, body, index, &v, &h, &cb, &sc, &sl);
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
            r = utxo_store_count(st, u);
            break;
        case 5:
            r = utxo_store_sync(st, u);
            break;
        case 6:
            r = utxo_store_reload(st, u);
            break;
        case 7:
            utxo_store_close(st);
            r = 0;
            break;
        case 8:
            r = utxo_store_wal_drain(st);
            break;
        }
        w64(fo, (u64)r);
        n++;
    }
    fclose(fv);
    if (fflush(fo) != 0 || fclose(fo) != 0) { perror("write out"); return 2; }
    printf("duxst: %u records\n", n);
    return 0;
}

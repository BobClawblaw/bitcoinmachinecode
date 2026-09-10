/* dstore.c -- batched bitcoin_store differential driver (file-based).
 * Same driver compiles on x86-64 (asm/bitcoin_store.o) and macOS/AArch64
 * (port/osx/store_twin.c). The harness must run in a scratch cwd: the store
 * opens index.dat/blk%05u.dat/prune.dat by bare relative name. After the run
 * the wrapper tars the resulting file set; `cmp` compares the retval stream
 * AND the tarballs byte-for-byte.
 *
 * Record: u32 op | u32 a | u32 b | body (b bytes when b>0)
 *   op 0 store_init                      -> retval
 *   op 1 store_append: a=len_lo, b=len_hi, body=32 hash + len raw
 *   op 2 store_get_at: a=height          -> retval + 24B meta when 1
 *   op 3 store_get_tip                   -> retval + 24B meta when 1
 *   op 4 store_reload                    -> retval
 *   op 5 store_set_prune: a=h            -> retval
 *   op 6 store_prune: a=h                -> retval
 *   op 7 store_truncate_to: a=target (i32) -> retval
 *   op 8 store_truncate_index_only: a=t  -> retval
 *   op 9 store_get_tip_hash              -> retval + 32B when 1
 *  op 10 store_validates_prevhash: b=80, body=header -> retval
 *  op 11 store_layout_monotonic: a=upto -> retval
 *  op 12 store_set_sync: a=on           -> 0
 *  op 13 store_get_sync                 -> retval
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint32_t u32;
typedef int32_t i32;
typedef uint64_t u64;
typedef int64_t i64;
typedef unsigned char u8;

extern int   store_init(void *st);
extern int   store_append(void *st, const void *hash, const void *raw, unsigned long long len);
extern int   store_get_at(void *st, unsigned long long height, unsigned long long *meta);
extern int   store_get_tip(void *st, unsigned long long *meta);
extern int   store_reload(void *st);
extern int   store_set_prune(void *st, int h);
extern int   store_prune(void *st, int h);
extern long long store_truncate_to(void *st, long long target);
extern int   store_truncate_index_only(void *st, long long t);
extern int   store_get_tip_hash(void *st, unsigned char out[32]);
extern int   store_validates_prevhash(void *st, const unsigned char hdr[80]);
extern int   store_layout_monotonic(void *st, long upto);
extern void  store_set_sync(int on);
extern int   store_get_sync(void);

static void w64(FILE *f, u64 v)
{
    u8 b[8];
    for (int i = 0; i < 8; i++) b[i] = (u8)(v >> (8 * i));
    fwrite(b, 1, 8, f);
}

static u8 st[256];
static u8 body[1u << 20];

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: dstore <vectors> <out>\n"); return 2; }
    FILE *fv = fopen(argv[1], "rb");
    if (!fv) { perror("vectors"); return 2; }
    FILE *fo = fopen(argv[2], "wb");
    if (!fo) { perror("out"); return 2; }

    u32 hdr[3];
    unsigned n = 0;
    while (fread(hdr, 4, 3, fv) == 3) {
        u32 op = hdr[0], a = hdr[1], b = hdr[2];
        if (op > 13 || b > sizeof body) { fprintf(stderr, "bad rec %u\n", n); return 2; }
        if (b && fread(body, 1, b, fv) != b) break;
        long long r = -999;
        switch (op) {
        case 0:
            r = store_init(st);
            break;
        case 1: {
            /* body = hash[32] + raw; len = b - 32 */
            if (b < 32) { fprintf(stderr, "short append rec %u\n", n); return 2; }
            r = store_append(st, body, body + 32, (u64)(b - 32));
            break;
        }
        case 2: {
            u64 meta[3];
            memset(meta, 0, sizeof meta);   /* high dwords are caller-owned */
            r = store_get_at(st, a, meta);
            w64(fo, (u64)r);
            if (r == 1) { w64(fo, meta[0]); w64(fo, meta[1]); w64(fo, meta[2]); }
            n++;
            continue;
        }
        case 3: {
            u64 meta[3];
            memset(meta, 0, sizeof meta);
            r = store_get_tip(st, meta);
            w64(fo, (u64)r);
            if (r == 1) { w64(fo, meta[0]); w64(fo, meta[1]); w64(fo, meta[2]); }
            n++;
            continue;
        }
        case 4:
            r = store_reload(st);
            break;
        case 5:
            r = store_set_prune(st, (int)(i32)a);
            break;
        case 6:
            r = store_prune(st, (int)(i32)a);
            break;
        case 7:
            r = store_truncate_to(st, (long long)(i32)a);
            break;
        case 8:
            r = store_truncate_index_only(st, (long long)(i32)a);
            break;
        case 9: {
            u8 h[32];
            r = store_get_tip_hash(st, h);
            w64(fo, (u64)r);
            if (r == 1) fwrite(h, 1, 32, fo);
            n++;
            continue;
        }
        case 10:
            r = store_validates_prevhash(st, body);
            break;
        case 11:
            r = store_layout_monotonic(st, (long)(i32)a);
            break;
        case 12:
            store_set_sync((int)a);
            r = 0;
            break;
        case 13:
            r = store_get_sync();
            break;
        }
        w64(fo, (u64)r);
        n++;
    }
    fclose(fv);
    if (fflush(fo) != 0 || fclose(fo) != 0) { perror("write out"); return 2; }
    printf("dstore: %u records\n", n);
    return 0;
}

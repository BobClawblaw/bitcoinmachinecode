/* didx.c -- batched bitcoin_idx differential driver (file-based).
 * Same driver compiles on x86-64 (asm/bitcoin_idx.o) and macOS/AArch64
 * (port/osx/idx_twin.c). Ops cover put/get/count semantics AND
 * idx_build_from_file over a generated index.dat; the table image itself
 * is a second output channel (the wrapper copies the raw index bytes and
 * the generated index.dat; `cmp` compares all three streams).
 *
 * Record: u32 op | u32 a | u32 b | body (b bytes when b>0)
 *   op 0 idx_init:  a=slots_pow2_cap -> retval 0
 *   op 1 idx_put:   a=height, b=32, body=hash -> retval 1/0/2
 *   op 2 idx_get:   b=32, body=hash -> retval + i64 height when found
 *   op 3 idx_count: -> retval
 *   op 4 idx_build_from_file: b=len(path), body=path -> retval
 *   op 5 dump:      a=slots -> writes a*48 raw slot bytes + 24B header
 *
 * The driver works on ONE index object per vector file (ops 0..5 in order);
 * a second init resets it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;
typedef unsigned char u8;

extern void idx_init(void *idx, unsigned long slots);
extern int  idx_put(void *idx, const unsigned char hash[32], long height);
extern int  idx_get(void *idx, const unsigned char hash[32], long *height);
extern long idx_count(void *idx);
extern long idx_build_from_file(void *idx, const char *path);

static void w64(FILE *f, u64 v)
{
    u8 b[8];
    for (int i = 0; i < 8; i++) b[i] = (u8)(v >> (8 * i));
    fwrite(b, 1, 8, f);
}

static u8 idxbuf[24 + (1u << 21) * 48];   /* max table the vectors init */
static u8 body[4096];

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: didx <vectors> <out>\n"); return 2; }
    FILE *fv = fopen(argv[1], "rb");
    if (!fv) { perror("vectors"); return 2; }
    FILE *fo = fopen(argv[2], "wb");
    if (!fo) { perror("out"); return 2; }

    u32 hdr[3];
    unsigned n = 0;
    while (fread(hdr, 4, 3, fv) == 3) {
        u32 op = hdr[0], a = hdr[1], b = hdr[2];
        if (op > 5 || b > sizeof body) { fprintf(stderr, "bad rec %u\n", n); return 2; }
        if (b && fread(body, 1, b, fv) != b) break;
        long r = -999;
        switch (op) {
        case 0:
            idx_init(idxbuf, a);
            r = 0;
            break;
        case 1:
            r = idx_put(idxbuf, body, (long)(int)a);
            break;
        case 2: {
            long h = -1;
            r = idx_get(idxbuf, body, &h);
            w64(fo, (u64)r);
            if (r == 1) w64(fo, (u64)h);
            n++;
            continue;
        }
        case 3:
            r = idx_count(idxbuf);
            break;
        case 4: {
            char path[512];
            memcpy(path, body, b);
            path[b] = 0;
            r = idx_build_from_file(idxbuf, path);
            break;
        }
        case 5:
            fwrite(idxbuf, 1, 24 + (size_t)a * 48, fo);
            r = 0;
            break;
        }
        w64(fo, (u64)r);
        n++;
    }
    fclose(fv);
    if (fflush(fo) != 0 || fclose(fo) != 0) { perror("write out"); return 2; }
    printf("didx: %u records\n", n);
    return 0;
}

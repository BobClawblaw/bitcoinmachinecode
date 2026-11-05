/* dp2p.c -- batched bitcoin_p2p differential driver (file-based, no popen).
 * Same driver compiles on x86-64 (asm/bitcoin_p2p.o) and macOS/AArch64
 * (port/osx/p2p_twin.c). Reads op records, appends u64 LE results + raw
 * payload outputs to the stream; `cmp` the two streams byte-for-byte.
 *
 * Record: u32 op | u32 a | u32 b | body bytes (see below)
 *   op 0 getheaders: a=count, b=0, body = count*32 locator + 32 stop
 *   op 1 getdata:    a=0, b=0, body = 32 hash
 *   op 2 ping:       a=nonce_lo, b=nonce_hi, body = none
 *   op 3 headers_count: a=plen, b=0, body = plen bytes
 *   op 4 inv_count:  a=plen, b=0, body = plen bytes
 *   op 5 inv_get:    a=index, b=plen, body = plen bytes
 * Output per record: u64 LE retval, then for ops 0/1/2 the u64 retval bytes
 * of the output buffer (only when retval > 0), for op 5 the u32 type LE +
 * 32 hash bytes (only when retval == 1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned char u8;

extern long p2p_getheaders(void *out, const void *locator, long count, const void *stop);
extern long p2p_getdata_block(void *out, const void *hash);
extern long p2p_ping(void *out, unsigned long long nonce);
extern long p2p_headers_count(const void *payload, long plen);
extern long p2p_inv_count(const void *payload, long plen);
extern long p2p_inv_get(const void *payload, long i, unsigned *out_type, void *out_hash);

static void w64(FILE *f, u64 v)
{
    u8 b[8];
    for (int i = 0; i < 8; i++) b[i] = (u8)(v >> (8 * i));
    fwrite(b, 1, 8, f);
}

static void w32(FILE *f, u32 v)
{
    u8 b[4];
    for (int i = 0; i < 4; i++) b[i] = (u8)(v >> (8 * i));
    fwrite(b, 1, 4, f);
}

static u8 body[131072];   /* fd-varint headers shapes reach 4+3+1000*81 = 81007 */
static u8 out[131072];

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: dp2p <vectors> <out>\n"); return 2; }
    FILE *fv = fopen(argv[1], "rb");
    if (!fv) { perror("vectors"); return 2; }
    FILE *fo = fopen(argv[2], "wb");
    if (!fo) { perror("out"); return 2; }

    u32 hdr[3];
    unsigned n = 0;
    while (fread(hdr, 4, 3, fv) == 3) {
        u32 op = hdr[0], a = hdr[1], b = hdr[2];
        /* op 2 (ping): a/b are nonce halves, b is NOT a body length */
        if (op > 5 || (op != 2 && b > sizeof body)) { fprintf(stderr, "bad rec %u\n", n); return 2; }
        if (op != 2 && b && fread(body, 1, b, fv) != b) break;
        if (op != 2) b = 0;   /* body consumed; op 2 has none */
        long r;
        switch (op) {
        case 0: {
            r = p2p_getheaders(out, body, (long)(int)a, body + (size_t)a * 32);
            w64(fo, (u64)r);
            if (r > 0) fwrite(out, 1, (size_t)r, fo);
            break;
        }
        case 1:
            r = p2p_getdata_block(out, body);
            w64(fo, (u64)r);
            if (r > 0) fwrite(out, 1, (size_t)r, fo);
            break;
        case 2: {
            unsigned long long nonce = (unsigned long long)a | ((unsigned long long)b << 32);
            r = p2p_ping(out, nonce);
            w64(fo, (u64)r);
            if (r > 0) fwrite(out, 1, (size_t)r, fo);
            break;
        }
        case 3:
            r = p2p_headers_count(body, (long)a);
            w64(fo, (u64)r);
            break;
        case 4:
            r = p2p_inv_count(body, (long)a);
            w64(fo, (u64)r);
            break;
        case 5: {
            unsigned t;
            u8 h[32];
            r = p2p_inv_get(body, (long)(int)a, &t, h);
            w64(fo, (u64)r);
            if (r == 1) { w32(fo, t); fwrite(h, 1, 32, fo); }
            break;
        }
        }
        n++;
    }
    fclose(fv);
    if (fflush(fo) != 0 || fclose(fo) != 0) { perror("write out"); return 2; }
    printf("dp2p: %u records\n", n);
    return 0;
}

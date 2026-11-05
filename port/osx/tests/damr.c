/* damr.c -- batched bitcoin_addrmgr differential driver (file-based).
 * Same driver compiles on x86-64 (asm/bitcoin_addrmgr.o) and macOS/AArch64
 * (port/osx/addrmgr_twin.c). Reads op records, writes u64 LE results (+ for
 * op 6/7 the encoded payload, for op 8 the parser retval). The peers.dat
 * file itself is a second output channel: the wrapper script copies the book
 * after the run and `cmp` compares both streams.
 *
 * Record: u32 op | u32 a | u32 b | body bytes (b bytes, except op 2)
 *   op 0 amr_init:    no body. retval 1/-1. (caller must chdir to a scratch dir)
 *   op 1 amr_add:     a=ip, b=0, body=8 bytes: u32 port(BE as passed),
 *                     u32 lastseen. services comes from the ip seed (LCG in
 *                     the generator is deterministic but hard to invert; use
 *                     body services instead) -> body = u32 port, u32 lastseen,
 *                     u64 services. b=12.
 *   op 2 amr_get_i:   a=index -> writes 18 record bytes to stream when ret 1
 *   op 3 amr_lookup:  a=ip -> index or -1
 *   op 4 amr_count:   no body -> count
 *   op 5 amr_close:   no body (close(fd) so the book is complete when copied)
 *   op 6 p2p_addr_v1:  a=n, b=18n, body=n*18 record bytes -> retval + payload
 *   op 7 p2p_addr_v2:  a=n, b=18n, body=n*18 record bytes -> retval + payload
 *   op 8 p2p_addr_count: a=plen, b=plen, body=plen bytes -> retval only
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned char u8;

extern int  amr_init(void *ab);
extern long amr_count(void *ab);
extern int  amr_add(void *ab, unsigned ip, unsigned short port,
                    unsigned long long services, unsigned lastseen);
extern int  amr_get_i(void *ab, long i, void *out);
extern long amr_lookup(void *ab, unsigned ip);
extern long p2p_addr_v1(void *out, const void *src, long n);
extern long p2p_addr_v2(void *out, const void *src, long n);
extern long p2p_addr_count(const void *pl, long plen);

static void w64(FILE *f, u64 v)
{
    u8 b[8];
    for (int i = 0; i < 8; i++) b[i] = (u8)(v >> (8 * i));
    fwrite(b, 1, 8, f);
}

static u8 ab[64];
static u8 body[8192];
static u8 out[16384];

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: damr <vectors> <out>\n"); return 2; }
    FILE *fv = fopen(argv[1], "rb");
    if (!fv) { perror("vectors"); return 2; }
    FILE *fo = fopen(argv[2], "wb");
    if (!fo) { perror("out"); return 2; }

    u32 hdr[3];
    unsigned n = 0;
    while (fread(hdr, 4, 3, fv) == 3) {
        u32 op = hdr[0], a = hdr[1], b = hdr[2];
        if (op > 8 || (op != 0 && op != 2 && op != 3 && op != 4 && op != 5 && b > sizeof body)) {
            fprintf(stderr, "bad rec %u\n", n); return 2;
        }
        if (op != 0 && op != 2 && op != 3 && op != 4 && op != 5 &&
            b && fread(body, 1, b, fv) != b) break;
        long r = -999;
        switch (op) {
        case 0:
            r = amr_init(ab);
            break;
        case 1: {
            u32 port, lastseen;
            u64 services;
            memcpy(&port, body, 4);
            memcpy(&lastseen, body + 4, 4);
            memcpy(&services, body + 8, 8);
            r = amr_add(ab, a, (unsigned short)port, services, lastseen);
            break;
        }
        case 2:
            r = amr_get_i(ab, (long)(int)a, out);
            w64(fo, (u64)r);
            if (r == 1) fwrite(out, 1, 18, fo);
            break;
        case 3:
            r = amr_lookup(ab, a);
            break;
        case 4:
            r = amr_count(ab);
            break;
        case 5:
            close(*(int *)ab);
            r = 0;
            break;
        case 6:
        case 7: {
            r = (op == 6) ? p2p_addr_v1(out, body, (long)a)
                          : p2p_addr_v2(out, body, (long)a);
            w64(fo, (u64)r);
            if (r > 0) fwrite(out, 1, (size_t)r, fo);
            n++;
            continue;
        }
        case 8:
            r = p2p_addr_count(body, (long)a);
            break;
        }
        w64(fo, (u64)r);
        n++;
    }
    fclose(fv);
    if (fflush(fo) != 0 || fclose(fo) != 0) { perror("write out"); return 2; }
    printf("damr: %u records\n", n);
    return 0;
}

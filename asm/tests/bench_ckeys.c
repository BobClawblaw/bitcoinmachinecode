/* tests/bench_ckeys.c -- one-shot microbench of the C crypto primitives that
 * still have no asm twin, to size a conversion (chacha20, poly1305, C siphash
 * via a representative block_filter-sized input, sha3-256). Print-only; run
 * by hand, not in `make test`.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "crypto_chacha20.h"
#include "crypto_poly1305.h"

extern void sha3_256(unsigned char out[32], const void* data, unsigned long len);

static double now(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec + 1e-9*ts.tv_nsec; }

#define BUFN (1u<<20)

int main(void){
    static unsigned char buf[BUFN], out[BUFN], key[32], nonce[12];
    memset(buf, 0x5a, sizeof buf); memset(key, 11, 32); memset(nonce, 7, 12);

    /* chacha20: keystream over 1 MB */
    {
        chacha20_ctx c; chacha20_init(&c, key); chacha20_seek(&c, nonce, 0);
        double t0 = now(); long iters = 0;
        while (now()-t0 < 0.4){ chacha20_crypt(&c, buf, out, BUFN); iters++; }
        double dt = now()-t0;
        printf("chacha20      : %7.1f MB/s\n", (iters*(double)BUFN/dt)/1e6);
    }
    /* poly1305 over 1 MB */
    {
        unsigned char k2[32] = {0}; poly1305_ctx p;
        double t0 = now(); long iters = 0;
        while (now()-t0 < 0.4){
            poly1305_init(&p, k2); poly1305_update(&p, buf, BUFN);
            unsigned char tag[16]; poly1305_finish(&p, tag); iters++;
        }
        double dt = now()-t0;
        printf("poly1305      : %7.1f MB/s\n", (iters*(double)BUFN/dt)/1e6);
    }
    /* chacha20poly1305 (the BIP324 per-message primitive) 1 KB messages */
    {
        unsigned char tag[16];
        double t0 = now(); long iters = 0;
        while (now()-t0 < 0.4){
            chacha20poly1305_encrypt(out, tag, buf, 1024, NULL, 0, key, nonce);
            iters++;
        }
        double dt = now()-t0;
        printf("aead 1KB msgs : %7.1f MB/s\n", (iters*1024.0/dt)/1e6);
    }
    /* sha3-256 over 1 MB */
    {
        double t0 = now(); long iters = 0; unsigned char h[32];
        while (now()-t0 < 0.4){ sha3_256(h, buf, BUFN); iters++; }
        double dt = now()-t0;
        printf("sha3-256      : %7.1f MB/s\n", (iters*(double)BUFN/dt)/1e6);
    }
    /* reference: asm sha256d throughput for scale (bitcoin_hash.asm) */
    extern void sha256_full(void* out, const void* msg, unsigned long len);
    {
        double t0 = now(); long iters = 0; unsigned char h[32];
        while (now()-t0 < 0.4){ sha256_full(h, buf, BUFN); iters++; }
        double dt = now()-t0;
        printf("sha256 (asm)  : %7.1f MB/s  (reference)\n", (iters*(double)BUFN/dt)/1e6);
    }
    return 0;
}

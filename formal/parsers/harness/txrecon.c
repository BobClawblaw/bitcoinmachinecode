/* P-TXRCN: the version-payload reader behind BIP330 (daemon/txrecon.c
 * txrecon_build_offer -> version_relays_txs) and txrecon_parse (the peer's
 * sendtxrcncl), both on bytes an unauthenticated peer sent during the
 * handshake. Payloads of nondeterministic content and length <= FP_N
 * (FP_N >= 4+8+8+26+26+8+1+4+1 = 86 reaches the fRelay byte).
 * Environment: /dev/urandom (open/read) free.
 * Claims: memory safety; an offer is built only from a payload whose user
 * agent and start_height lie inside it. */
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "nd.h"
int open(const char* p, int fl, ...){ (void)p; (void)fl; return nondet_int() ? -1 : 9; }
ssize_t read(int fd, void* b, size_t n){ (void)fd; CHECK(__CPROVER_w_ok(b, n), "read buffer"); return nondet_int() ? (ssize_t)n : -1; }
int close(int fd){ (void)fd; return 0; }
void sha256_full(unsigned char* out, const void* m, long long l){ CHECK(l >= 0 && __CPROVER_r_ok(m, (size_t)l), "sha input"); for (int i = 0; i < 32; i++) out[i] = nondet_uchar(); }
#include SRC
#ifndef FP_N
#define FP_N 90
#endif
int main(void){
    size_t len = nondet_size(); ASSUME(len <= FP_N);
    unsigned char* p = nd_buf(len);
    unsigned char out[12]; unsigned long long salt;
    int r = txrecon_build_offer(p, (long)len, nondet_int(), nondet_int(), nondet_int(), nondet_int(), out, &salt);
    if (r){
        CHECK(len >= 81, "offer only after the nonce");
        unsigned long w = p[80] < 0xfd ? 1 : 3, ua = p[80] < 0xfd ? p[80] : (len >= 83 ? (unsigned long)(p[81] | (p[82] << 8)) : 0);
        CHECK(p[80] <= 0xfd && 80 + w + ua + 4 <= len, "offer only from a version payload whose user agent and start_height fit");
    }
    unsigned v; unsigned long long s;
    int q = txrecon_parse(p, (long)len, &v, &s);
    if (q) CHECK(len >= 12, "sendtxrcncl needs 12 bytes");
    free(p);
    COVER(r, "an offer built");
    return 0;
}

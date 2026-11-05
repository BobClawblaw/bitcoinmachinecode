/* P-ASMAP: asmap_lookup_raw (daemon/asmap.c), Core's ASMap bytecode
 * interpreter, run on the -asmap file's bytes for every address the book
 * buckets (addresses arrive from peers; the bytecode is a file the operator
 * named -- possibly downloaded). Bytecode of nondeterministic content and
 * length <= FP_N, an address of any 0..16 bytes.
 * Claims: memory safety (no read outside code[0..len) or ip[0..16)), no
 * signed/unsigned wrap in the decoder, termination within 8*len + 1
 * instructions (unwinding assertions), and a returned ASN is either 0 or a
 * decoded RETURN/DEFAULT value (< 2^25). */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
#include SRC
#ifndef FP_N
#define FP_N 6
#endif
int main(void){
    size_t len = nondet_size(); ASSUME(len <= FP_N);
    unsigned char* code = nd_buf(len);
    int nb = nondet_int(); ASSUME(nb >= 0 && nb <= 16);
    unsigned char* ip = nd_buf((size_t)nb);        /* exactly nbytes: a read past the address is caught */
    unsigned asn = asmap_lookup_raw(code, len, ip, nb);
    CHECK(asn < (1u << 25), "ASN within the 24-bit classes");
    free(code); free(ip);
    COVER(asn != 0, "an ASN returned");
    COVER(asn == 0 && len >= 4, "no answer from a long map");
    return 0;
}

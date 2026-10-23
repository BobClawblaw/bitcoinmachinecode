/* P-HTTP: http_request_parse (rpc_net.c), the request-line / header split of
 * every JSON-RPC and REST request, run BEFORE authentication on whatever an
 * allowed source sends. A buffer of nondeterministic content and length
 * <= FP_N (the caller NUL-terminates at buf[got]; the harness does the same).
 * Claims: memory safety; on success method, path and body lie inside the
 * buffer, method + ' ' + path + ' ' precede the first CR, the request line
 * holds no control byte, and body + body_len ends exactly at the buffer end. */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
#include SRC
#ifndef FP_N
#define FP_N 24
#endif
int main(void){
    size_t len = nondet_size(); ASSUME(len <= FP_N);
    char* buf = (char*)nd_buf(len + 1); buf[len] = 0;
    const char *m, *p, *b; size_t ml, pl, bl;
    int r = http_request_parse(buf, len, &m, &ml, &p, &pl, &b, &bl);
    if (r){
        CHECK(m == buf && p == m + ml + 1 && p + pl < buf + len, "method and path inside");
        CHECK(b >= buf + 4 && b + bl == buf + len, "body runs to the end");
        CHECK(m[ml] == ' ' && p[pl] == ' ', "separated by spaces");
        for (const char* q = buf; q < p + pl; q++) CHECK((unsigned char)*q >= 0x20 && *q != 0x7f, "no control byte in the request line");
    }
    free(buf);
    COVER(r && ml == 4 && pl >= 1, "a POST-sized request parsed");
    COVER(r && bl >= 2, "with a body");
    return 0;
}

/* P-INV: serve_inv_bounds (daemon/serve_invbounds.c) -- the inv / getdata /
 * notfound vector header, reached by any unauthenticated peer.
 * Claims, for every payload of length 0..N:
 *   - memory safety (no read outside pl[0..plen)),
 *   - result 1 => *off <= plen, the count's encoding is canonical (Core's
 *     ReadCompactSize), count <= MAX_INV_SZ (50000), and off + 36*count <= plen
 *     (the walk the asm caller makes stays in the payload: the DoS bound),
 *   - a non-canonical count is never accepted, a count > 50000 never accepted. */
#include <stdlib.h>
#include <limits.h>
#include "nd.h"
#include SRC
int idx_get(void* idx, const unsigned char hash[32], long* height){ (void)idx; (void)hash; *height = nondet_long(); return nondet_int(); }
long idxscan_tip(void){ return nondet_long(); }
#ifndef N
#define N ((size_t)1 << 40)   /* effectively unbounded: no loop depends on plen */
#endif
int main(void){
    size_t plen = nondet_size(); ASSUME(plen <= (size_t)LONG_MAX && plen <= N);
    unsigned char* pl = nd_buf(plen);
    unsigned long long count; long off;
    int r = serve_inv_bounds(pl, (long)plen, &count, &off);
    CHECK(r == 1 || r == 0 || r == -1, "result in {1,0,-1}");
    if (r == 1){
        CHECK(off >= 1 && (size_t)off <= plen, "off within payload");
        CHECK(fp_cs_canonical(pl, plen), "accepted count is canonical (Core ReadCompactSize)");
        CHECK(count <= 50000, "count <= MAX_INV_SZ");
        CHECK((unsigned long long)off + 36ull * count <= plen, "vector fits the payload");
    }
    if (r == -1) CHECK(fp_cs_canonical(pl, plen), "scored only on a canonical count");
    free(pl);
    COVER(r == 1 && count == 2, "two entries accepted");
    COVER(r == -1, "oversize count scored");
    COVER(r == 1 && pl[0] == 0xfd, "3-byte form reachable (needs N>=3)");
    return 0;
}

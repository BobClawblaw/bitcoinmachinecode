/* P-LOC: serve_locator_from (daemon/serve_invbounds.c) -- the getheaders /
 * getblocks body (nVersion | CompactSize n | n*32 locator | 32 stop), reached
 * by any unauthenticated peer. idx_get (the hash index) is environmental and
 * answers nondeterministically, but only reads its 32-byte key, which the stub
 * checks lies inside the payload.
 * Claims, for every payload length (unbounded: the only payload-dependent
 * loop is over n <= 101, which the code bounds itself):
 *   - memory safety; every idx_get key and the stop hash lie in pl[0..plen),
 *   - result 1 => n <= MAX_LOCATOR_SZ (101) and 4 + |cs| + 32n + 32 <= plen,
 *   - idx_get is called at most 101 times (the DoS bound, before any work),
 *   - FP_CORE_STRICT: an accepted count is canonical (Core's ReadCompactSize). */
#include <stdlib.h>
#include <limits.h>
#include "nd.h"
static const unsigned char* g_pl; static size_t g_plen; static unsigned g_calls;
int idx_get(void* idx, const unsigned char hash[32], long* height){
    (void)idx; g_calls++;
    CHECK(hash >= g_pl && hash + 32 <= g_pl + g_plen, "idx_get key inside the payload");
    *height = nondet_long(); ASSUME(*height >= 0 && *height < LONG_MAX); return nondet_int();
}
long idxscan_tip(void){ return nondet_long(); }
#include SRC
int main(void){
    size_t plen = nondet_size(); ASSUME(plen <= (size_t)LONG_MAX / 2);
    unsigned char* pl = nd_buf(plen); g_pl = pl; g_plen = plen;
    long from, stop; char htidx;
    int r = serve_locator_from(pl, plen, &htidx, &from, &stop);
    CHECK(g_calls <= 102, "at most 101 locator lookups + the stop hash");
    if (r == 1){
        CHECK(plen >= 5, "accepted payload has a count");
        unsigned long long n; size_t w;
        if (pl[4] < 0xfd){ n = pl[4]; w = 1; } else if (pl[4] == 0xfd){ n = pl[5] | (pl[6] << 8); w = 3; }
        else if (pl[4] == 0xfe){ n = 0; for (int i = 0; i < 4; i++) n |= (unsigned long long)pl[5+i] << (8*i); w = 5; }
        else { n = 0; for (int i = 0; i < 8; i++) n |= (unsigned long long)pl[5+i] << (8*i); w = 9; }
        CHECK(n <= 101, "count <= MAX_LOCATOR_SZ");
        CHECK(4 + w + 32 * n + 32 <= plen, "locator and stop hash fit");
#ifdef FP_CORE_STRICT
        CHECK(fp_cs_canonical(pl + 4, plen - 4), "CORE: accepted locator count is canonical");
#endif
    }
    free(pl);
    COVER(r == 1 && pl[4] == 2, "two-entry locator accepted");
    COVER(r == 1 && from > 0, "a locator hit");
    COVER(r == 1 && stop >= 0, "a known stop hash");
    COVER(r == 0 && plen > 40, "a long malformed payload refused");
    return 0;
}

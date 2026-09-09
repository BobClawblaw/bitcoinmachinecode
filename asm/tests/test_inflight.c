/* tests/test_inflight.c -- one request per block across the legs (daemon/inflight.c) */
#include <stdio.h>
#include <string.h>
#include "../daemon/inflight.h"
static int fails = 0;
static void ck(const char* l, long g, long e){ if (g == e) printf("  ok  %s (%ld)\n", l, g); else { printf("  FAIL %s (got %ld exp %ld)\n", l, g, e); fails++; } }
int main(void){
    inflight_t t; inflight_init(&t); unsigned char a[32], b[32]; memset(a, 0xaa, 32); memset(b, 0xbb, 32); long long now = 1000;
    ck("leg 0 claims block a", inflight_claim(&t, a, 0, now), 1);
    ck("leg 1 is refused block a", inflight_claim(&t, a, 1, now + 5), 0);
    ck("leg 0 may fetch its own claim again", inflight_claim(&t, a, 0, now + 5), 1);
    ck("leg 1 claims block b", inflight_claim(&t, b, 1, now), 1);
    ck("two in flight", inflight_count(&t), 2);
    inflight_release_leg(&t, 0);
    ck("leg 0's pass ended: its claim is gone", inflight_count(&t), 1);
    ck("... and leg 1 may take block a now", inflight_claim(&t, a, 1, now + 6), 1);
    ck("a claim older than 10 min is stale: leg 2 takes block b over", inflight_claim(&t, b, 2, now + INFLIGHT_STALE_S), 1);
    ck("... and leg 1 is refused its former claim", inflight_claim(&t, b, 1, now + INFLIGHT_STALE_S + 1), 0);
    inflight_release(&t, b);
    ck("released by hash", inflight_count(&t), 1);
    for (int i = 0; i < INFLIGHT_MAX + 3; i++){ unsigned char h[32]; memset(h, (unsigned char)i, 32); h[0] = 0x77; inflight_claim(&t, h, 3, now + 100 + i); }
    ck("a full table never refuses: the oldest entry is recycled", inflight_count(&t), INFLIGHT_MAX);
    ck("refusals counted", (long)t.refused, 2);
    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

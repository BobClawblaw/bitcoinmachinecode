/* tests/live_money_range_chain.c -- replay REAL mainnet transactions through
 * the money-range check (audit finding 5b).
 *
 * The unit test pins the boundary; this pins the thing that actually matters.
 * A consensus check that is too strict does not produce a bug report, it
 * produces a chain split: the node rejects a block the rest of the network
 * accepted and stops following the chain. Core accepted every transaction
 * below, so any rejection here is a divergence from consensus, not a finding.
 *
 * Reads hex transactions on stdin, one per line, and reports how many the
 * parser accepts. Driven by scripts/live_money_range_check.sh, which pulls
 * them from the running node over RPC.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

extern int mv_test_parse(const uint8_t* tx, long txlen, uint32_t* wl0_out);
long mempool_resolve_confirmed_utxo(void* u, const uint8_t* t, unsigned long i,
    unsigned long long* v, const uint8_t** sp, unsigned long* sl){
    (void)u;(void)t;(void)i;(void)v;(void)sp;(void)sl; return 0; }

static int unhex(const char* h, uint8_t* out, long cap){
    long n = 0;
    for (; h[0] && h[1] && h[0] != '\n'; h += 2){
        if (n >= cap) return -1;
        int hi = (h[0] <= '9') ? h[0]-'0' : (h[0]|32)-'a'+10;
        int lo = (h[1] <= '9') ? h[1]-'0' : (h[1]|32)-'a'+10;
        if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

int main(void){
    static char line[8 << 20];
    static uint8_t tx[4 << 20];
    long total = 0, ok = 0, bad = 0, skipped = 0;

    while (fgets(line, sizeof line, stdin)){
        if (line[0] == '\n' || line[0] == 0) continue;
        int n = unhex(line, tx, (long)sizeof tx);
        if (n <= 0){ skipped++; continue; }
        total++;
        if (mv_test_parse(tx, n, 0)) ok++;
        else {
            bad++;
            if (bad <= 5){
                printf("  REJECTED a real mainnet transaction (%d bytes): %.80s...\n", n, line);
            }
        }
    }
    printf("  parsed %ld real transactions: %ld accepted, %ld rejected", total, ok, bad);
    if (skipped) printf(" (%ld unparseable input lines)", skipped);
    printf("\n");
    if (bad == 0 && total > 0){ printf("  ok  every real transaction still parses\n"); return 0; }
    if (total == 0){ printf("  FAIL no transactions were fed in -- the check proved nothing\n"); return 2; }
    printf("  FAIL %ld real transactions were rejected -- this is a CONSENSUS DIVERGENCE\n", bad);
    return 1;
}

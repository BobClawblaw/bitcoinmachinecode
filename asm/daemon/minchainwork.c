/* daemon/minchainwork.c -- Core's -minimumchainwork floor.
 *
 * Lifted out of reorg.c so it can be tested on its own: reorg.c pulls in the
 * whole p2p and locator stack, and a 40-line comparison has no business
 * needing a socket layer to be linked before it can be checked. reorg.c calls
 * reorg_work_meets_minimum() at its fork-choice decision.
 */
#include <string.h>

extern long chainwork_cmp(const unsigned char a[16], const unsigned char b[16]);

/* ---- minimum chain work (Core -minimumchainwork) -------------------------
 * The floor a candidate chain must clear before this node will commit work
 * to it. Without one, a peer can feed an arbitrarily long low-difficulty
 * header chain and make us spend memory and CPU on it; Core has carried
 * nMinimumChainWork for exactly this since 0.15.
 *
 * Core stores it as a uint256; this node's cumulative work accumulator is
 * SIXTEEN bytes. Every real value fits -- mainnet's is 0x…01128750f82f4c36…
 * with 16 leading zero bytes -- but "fits today" is not a guarantee, so a
 * floor whose high half is non-zero is reported and treated as unreachable
 * rather than silently truncated into something weaker than configured. */
static int g_minwork_set;                 /* 0 = no floor configured        */
static int g_minwork_unrepresentable;     /* high 16 bytes were non-zero    */
static unsigned char g_minwork16[16];

void reorg_set_min_chain_work(const unsigned char be32[32]){
    g_minwork_set = 0; g_minwork_unrepresentable = 0;
    if (!be32) return;
    int all0 = 1;
    for (int i = 0; i < 32; i++) if (be32[i]) { all0 = 0; break; }
    if (all0) return;                     /* explicit "no floor" (regtest)  */
    for (int i = 0; i < 16; i++) if (be32[i]) { g_minwork_unrepresentable = 1; break; }
    /* Core spells nMinimumChainWork BIG-endian (a uint256 hex string); this
     * node's cumulative accumulator is 16 bytes LITTLE-endian (see
     * bitcoin_chainwork.asm: "chainwork.dat holds one 16-byte little-endian
     * cumulative-chainwork", and chainwork_cmp reads the high qword from
     * offset +8). Comparing them without reversing silently inverts the test
     * -- a low-work chain passes and a heavy one is refused. Caught by
     * tests/test_core_parity, not by review. */
    for (int i = 0; i < 16; i++) g_minwork16[i] = be32[31 - i];
    g_minwork_set = 1;
}

/* 1 when `work` clears the floor (or no floor is set). */
int reorg_work_meets_minimum(const unsigned char work[16]){
    if (!g_minwork_set) return 1;
    if (g_minwork_unrepresentable) return 0;   /* fail CLOSED, never open */
    return chainwork_cmp(work, g_minwork16) >= 0;
}
int reorg_min_chain_work_unrepresentable(void){ return g_minwork_unrepresentable; }
int reorg_min_chain_work_set(void){ return g_minwork_set; }

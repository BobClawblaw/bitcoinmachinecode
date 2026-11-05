/* chacha20_paths_osx.c -- the Mac's answer to crypto_chacha20.c's second
 * path (2026-09-28, x86 main #331: chacha20_xor_avx2 in chacha20_avx2.asm).
 * There is no AVX2 on Apple silicon, so the probe says no and every call
 * takes the C block; the vector entry point exists only so the shared C
 * links, and can never be reached (chacha20_use_avx2 gates it on the probe).
 * A NEON body (four blocks in flight, one per 128-bit register) would be the
 * counterpart when the v2 transport's cipher shows up in a Mac profile. */
#include <stdlib.h>
int chacha20_cpu_has_avx2(void){ return 0; }
void chacha20_xor_avx2(unsigned char* out, const unsigned char* in, const unsigned s[16], unsigned long nblocks){
    (void)out; (void)in; (void)s; (void)nblocks;
    abort();   /* unreachable: the probe above is 0 */
}
/* bitcoin_muhash.asm's keystream dispatcher grew the same knob (test_muhash
 * drives both bodies); the Mac's bitcoin_muhash.S has the one body. */
void chacha20_k0_force_path(int p){ (void)p; }

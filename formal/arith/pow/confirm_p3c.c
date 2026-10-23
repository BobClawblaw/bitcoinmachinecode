/* Confirms P3c on the REAL compiled bitcoin_pow_rules.o: a retarget whose new
 * target is below 2^16 gets a wrong compact. Expected values are Core's
 * (core_port.h core_calc_next_work, cross-checked against Python by
 * check_core_port.py). Exit 0 iff the divergence reproduces. */
#include <stdio.h>
#include "core_port.h"
unsigned int pow_retarget_bits(unsigned int base_bits, long actual_timespan, unsigned int pow_limit_bits);
int main(void){
    static const struct { unsigned bits; long ts; } v[] = {
        { 0x03000100u, 302400L },     /* target 256 -> 64:    size 1 */
        { 0x03012345u, 1209600L },    /* target 0x12345 unchanged: size 3, control */
        { 0x03004000u, 302400L },     /* target 0x4000 -> 0x1000: size 2 */
    };
    int repro = 0;
    cu256 lim = core_pow_limit(0x1d00ffffu);
    for (unsigned i = 0; i < sizeof v / sizeof v[0]; i++){
        unsigned b = pow_retarget_bits(v[i].bits, v[i].ts, 0x1d00ffffu);
        unsigned c = core_calc_next_work(v[i].bits, v[i].ts, &lim);
        printf("base=0x%08x ts=%ld  bmc=0x%08x  core=0x%08x  %s\n", v[i].bits, v[i].ts, b, c, b == c ? "equal" : "DIFFER");
        if (i != 1 && b != c) repro++;
        if (i == 1 && b != c) return 2;
    }
    return repro == 2 ? 0 : 1;
}

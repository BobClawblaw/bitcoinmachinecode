/* P3: bmc powr_compact (asm/bitcoin_pow_rules.c, static; the real file is
 * #included) == Core arith_uint256::GetCompact(false) for EVERY 256-bit
 * target. Also P2a: powr_target_bytes == Core SetCompact on the domain where
 * Core's fNegative/fOverflow are clear. CBMC, all loops fully unwound (fixed
 * trip counts), so the check is complete (unbounded in the inputs).
 * Before the F1 fix (e0476262) it held only for t == 0 or t >= 2^16; run.sh's
 * P3-F1 mutant puts the removed shift back and must be caught. */
#include BMC_POW_RULES_C
#include "../core_port.h"

unsigned char nondet_uchar(void);
unsigned int nondet_uint(void);

void p3(void){
    u8 t[32];
    for (int i = 0; i < 32; i++) t[i] = nondet_uchar();
    cu256 c = cu_from_be32(t);
    u32 core = cu_get_compact(&c, 0);
    u32 bmc  = powr_compact(t);
    __CPROVER_assert(bmc == core, "P3 powr_compact == Core GetCompact (all targets)");
}

void p2a(void){
    u32 bits = nondet_uint();
    int neg, ovf;
    cu256 c = cu_set_compact(bits, &neg, &ovf);
    __CPROVER_assume(!neg && !ovf);
    u8 t[32]; powr_target_bytes(bits, t);
    u8 ce[32]; cu_to_be32(&c, ce);
    int eq = 1; for (int i = 0; i < 32; i++) if (t[i] != ce[i]) eq = 0;
    u32 e = bits >> 24, w = bits & 0x007fffffu;
    __CPROVER_assert(e > 32 || eq,
                     "P2a powr_target_bytes == Core SetCompact (flags clear, exponent <= 32)");
    /* complement: exponent 33/34 with a nonzero mantissa (not an overflow)
     * decodes to 0 in bmc and to a nonzero target in Core */
    __CPROVER_assert(e <= 32 || w == 0 || !eq,
                     "P2c exponent 33/34, nonzero mantissa: bmc target 0 != Core");
}

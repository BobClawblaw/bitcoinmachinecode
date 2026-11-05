/* P4-CAP: the powLimit cap agrees although bmc and Core cap against
 * different values. bmc caps the new target at powr_target_bytes(limit
 * bits) = decode(Lb) (the real function, file #included); Core caps at the
 * FULL consensus.powLimit and then calls GetCompact. Claim, per chain
 * (-DCHAIN_BITS): (a) decode(Lb) <= full; (b) GetCompact(decode(Lb)) == Lb
 * == powr_compact(decode(Lb)); (c) for EVERY 256-bit x with
 * decode(Lb) < x <= full, Core's GetCompact(x) == Lb. So whenever bmc's
 * quotient exceeds decode(Lb), bmc returns Lb and Core returns
 * GetCompact(min(x, full)) == Lb. Complete (fixed loops only). */
#include BMC_POW_RULES_C
#include "../core_port.h"
unsigned char nondet_uchar(void);
int main(void){
    u8 lb[32]; powr_target_bytes(CHAIN_BITS, lb);
    cu256 dec = cu_from_be32(lb), full = core_pow_limit(CHAIN_BITS);
    __CPROVER_assert(cu_cmp(&dec, &full) <= 0, "P4-CAP (a) decode(Lb) <= full powLimit");
    __CPROVER_assert(cu_get_compact(&dec, 0) == CHAIN_BITS && powr_compact(lb) == CHAIN_BITS,
                     "P4-CAP (b) GetCompact(decode(Lb)) == powr_compact(decode(Lb)) == Lb");
    u8 t[32]; for (int i = 0; i < 32; i++) t[i] = nondet_uchar();
    cu256 x = cu_from_be32(t);
    __CPROVER_assume(cu_cmp(&x, &dec) > 0 && cu_cmp(&x, &full) <= 0);
    __CPROVER_assert(cu_get_compact(&x, 0) == CHAIN_BITS, "P4-CAP (c) GetCompact(x) == Lb on (decode(Lb), full]");
#ifdef REACH
    __CPROVER_assert(0, "REACH: the interval (decode(Lb), full] is non-empty (must FAIL on main/testnet4)");
#endif
    return 0;
}

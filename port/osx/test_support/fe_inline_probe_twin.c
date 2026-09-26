/* port/osx/test_support/fe_inline_probe_twin.c -- the Mac stand-in for
 * tests/fe_inline_probe.asm. Test-only (outside the port/osx C twins).
 *
 * On x86 that probe wraps the inline field macros (secp256k1_fe_inline.inc:
 * FE_ADDM / FE_SUBM and FE_ADD_TAIL's merged reduction) that the x86 point
 * code expands in place of `call fe_add` / `call fe_sub`, so tests/
 * test_fe_inline can check them against the shipped routines AND against a
 * 320-bit C oracle.
 *
 * The Mac has no inline form: port/osx/point_twin.c and point_ct_twin.c call
 * fe_add / fe_sub directly (point_ct_twin.c's fe_dbl2 is fe_add(a, a)). So
 * here the *_inl entry points ARE the shipped routines, and on the Mac:
 *   - test_fe_inline's check 1 (inline == shipped) is vacuous, by design;
 *   - its check 2 is the real content: the shipped fe_add / fe_sub / 2a that
 *     every Mac point routine uses, against the independent 320-bit oracle,
 *     over the constructed carry-boundary family (sums at p-1, p, p+1,
 *     2^256-1, 2^256, 2^256+C, 2p-1, ...) and the structured operands;
 *   - its section 3 note reports "agree": there is no second form to differ.
 */
#include <stdint.h>

typedef uint64_t u64;

extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);

void fe_add_inl(u64 r[4], const u64 a[4], const u64 b[4]){ fe_add(r, a, b); }
void fe_sub_inl(u64 r[4], const u64 a[4], const u64 b[4]){ fe_sub(r, a, b); }
void fe_dbl_inl(u64 r[4], const u64 a[4]){ fe_add(r, a, a); }

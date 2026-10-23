/* Shared main() for the CompactSize harnesses. The including file defines
 *   static int bmc_rd(const u8* b, const u8* end, uint64_t* v, unsigned* used)
 * as a thin adapter (no logic: it only maps the reader's own signature onto
 * ok/value/width) over the REAL reader text pulled into gen/ by gen.sh.
 *
 * The input is ANY byte string the reader can see: avail in [0, 9] nondet
 * bytes. No reader reads more than 9 bytes. The bytes sit at the front of a
 * 16-byte object whose tail [avail, 16) is ALSO nondet, and the reader runs
 * twice, on two copies that share the first avail bytes but have independent
 * tails; equal outputs prove the result never depends on a byte at or past
 * `end` (a read past the end would make them differ). The 16-byte object keeps
 * the readers' `p + 9 > end` comparisons inside one object, so the check is
 * about the bytes read, not about forming a one-past pointer. Bytes beyond
 * the ninth are never read: the proof is complete, not bounded.
 *
 * Properties (pick with -D):
 *   (default) FULL: ok == Core ReadCompactSize(range_check=true), and on ok
 *             the value and the consumed width are Core's.
 *   NO_RANGE: the same against Core with range_check=false (readers that
 *             leave MAX_SIZE to their caller).
 *   SUPERSET: whatever Core accepts the reader accepts with Core's value and
 *             width (the reader may accept more).
 *   REACH:    witnesses that each width is accepted and that a rejection
 *             happens -- must FAIL (vacuity check). */
#include "../../lib/nondet.h"
#include "../core_cs.h"
int main(void){
    unsigned avail = nondet_u32();
    ASSUME(avail <= 9);
    u8 b[16], b2[16];
    for (unsigned i = 0; i < 16; i++){
        b[i] = nondet_u8();
        b2[i] = (i < avail) ? b[i] : nondet_u8();
    }
    uint64_t bv = 0xdeadbeefULL, bv2 = 0xdeadbeefULL; unsigned bu = 77, bu2 = 77;
    int bok  = bmc_rd(b,  b  + avail, &bv,  &bu);
    int bok2 = bmc_rd(b2, b2 + avail, &bv2, &bu2);
    CHECK(bok == bok2 && (!bok || (bv == bv2 && bu == bu2)),
          "result independent of the bytes past end");
    uint64_t cv = 0; unsigned cu = 0;
#if defined(NO_RANGE)
    int cok = core_read_compact_size(b, avail, 0, &cv, &cu);
#else
    int cok = core_read_compact_size(b, avail, 1, &cv, &cu);
#endif
#if defined(REACH)
    CHECK(!(bok && bu == 1), "REACH width 1 accepted");
    CHECK(!(bok && bu == 3), "REACH width 3 accepted");
    CHECK(!(bok && bu == 5), "REACH width 5 accepted");
    CHECK(!(cok == 0 && bok == 0), "REACH a rejection");
#elif defined(SUPERSET)
    if (cok){ CHECK(bok, "Core accepts => bmc accepts");
              CHECK(bv == cv && bu == cu, "same value and width"); }
#else
    CHECK(bok == cok, "accept/reject equals Core");
    if (cok && bok) CHECK(bv == cv && bu == cu, "same value and width");
#endif
    return 0;
}

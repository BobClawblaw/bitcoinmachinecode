/* tests/test_compactsize_canonical.c -- VAL-10 / SER-3 (audit 2026-09-03):
 * blocks Core cannot deserialize must not be accepted here.
 *
 * TWO DEFECTS, both of which let a block through that every Core node on the
 * network refuses outright -- and because txids are computed over the
 * verbatim bytes, the merkle root still matches, so nothing downstream
 * noticed either.
 *
 *  (a) NON-CANONICAL CompactSize. `fd 01 00` decoded as 1 in every varint
 *      reader here. Core's ReadCompactSize throws "non-canonical
 *      ReadCompactSize()" for a value encoded in a wider form than it needs,
 *      and "size too large" above MAX_SIZE (0x02000000).
 *
 *  (b) SUPERFLUOUS WITNESS RECORD. A transaction carrying the segwit marker
 *      `00 01` whose every witness stack is empty parsed cleanly and left
 *      has_witness at 0, so a legacy-input transaction wearing a marker
 *      verified through legacy_tx_view. Core's UnserializeTransaction throws
 *      "Superfluous witness record": such a transaction must have been
 *      serialized without the marker.
 *
 * The walker under test is daemon/block_witness.c's bw_walk_tx, reached
 * through block_check_witness_commitment. segwit_active is 0 so the
 * commitment logic stays out of the way and the return value reflects
 * PARSING alone: 1 for a well-formed block, -1 with "coinbase: malformed tx"
 * for one this node must refuse.
 *
 * Every negative is a one-field edit of a transaction the SAME harness has
 * just had accepted, so a rejection cannot be blamed on the fixture.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../daemon/block_witness.h"

typedef uint8_t u8; typedef uint64_t u64;

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

/* A minimal coinbase: version, 1 input (null prevout), 1 output, locktime. */
static u64 mk_coinbase(u8* o, int wide_nin, int marker, int empty_stacks){
    u8* p = o;
    *p++=1;*p++=0;*p++=0;*p++=0;                     /* version */
    if (marker){ *p++=0x00; *p++=0x01; }             /* segwit marker+flag */
    if (wide_nin){ *p++=0xfd; *p++=0x01; *p++=0x00; } /* NON-CANONICAL 1 */
    else         { *p++=0x01; }                       /* canonical 1 */
    memset(p, 0, 32); p += 32;                        /* null prevout hash */
    *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;          /* prevout index -1 */
    *p++=0x02; *p++=0x51; *p++=0x00;                  /* scriptSig: 2 bytes */
    *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;          /* sequence */
    *p++=0x01;                                        /* 1 output */
    for (int i=0;i<8;i++) *p++ = 0;                   /* value 0 */
    *p++=0x01; *p++=0x51;                             /* spk: OP_TRUE */
    if (marker){
        /* one stack, either empty (the defect) or with one item */
        if (empty_stacks){ *p++=0x00; }
        else { *p++=0x01; *p++=0x20; memset(p,0xAB,32); p+=32; }
    }
    *p++=0;*p++=0;*p++=0;*p++=0;                      /* locktime */
    return (u64)(p - o);
}

static long run(const u8* tx, u64 len, const char** reason){
    bw_txref_t ref = { tx, (u64)len };
    static u8 scratch[1<<16];
    *reason = "";
    return block_check_witness_commitment(&ref, 1, sizeof ref, 0 /* segwit_active */,
                                          scratch, sizeof scratch, reason);
}

int main(void){
    u8 tx[512]; u64 n; const char* why;

    printf("== control: a canonical coinbase is accepted ==\n");
    n = mk_coinbase(tx, 0, 0, 0);
    { long r = run(tx, n, &why);
      printf("      (len %llu -> %ld %s)\n", (unsigned long long)n, r, why);
      ck("canonical legacy coinbase accepted", r == 1); }

    printf("\n== control: a canonical coinbase WITH a real witness PARSES ==\n");
    /* segwit_active is 0 here, so a coinbase that carries a witness is
     * correctly refused as "unexpected-witness" -- by the COMMITMENT rule,
     * after parsing succeeded. That reason, rather than "malformed tx", is
     * what shows the walker accepted the bytes: it is the control that keeps
     * the two negatives below from passing for the wrong reason. */
    n = mk_coinbase(tx, 0, 1, 0);
    { long r = run(tx, n, &why);
      printf("      (len %llu -> %ld %s)\n", (unsigned long long)n, r, why);
      ck("a marker with a NON-empty stack parses (refused only by the commitment rule)",
         strstr(why, "unexpected-witness") != NULL);
      ck("...and specifically NOT as a malformed transaction",
         strstr(why, "malformed") == NULL); }

    printf("\n== VAL-10 (a): n_in encoded as `fd 01 00` is REFUSED ==\n");
    n = mk_coinbase(tx, 1 /* wide */, 0, 0);
    { long r = run(tx, n, &why);
      printf("      (len %llu -> %ld %s)\n", (unsigned long long)n, r, why);
      ck("non-canonical 3-byte encoding of 1 is refused", r != 1);
      ck("...as a malformed transaction", strstr(why, "malformed") != NULL); }

    printf("\n== VAL-10 (b): marker present, every stack empty, is REFUSED ==\n");
    n = mk_coinbase(tx, 0, 1 /* marker */, 1 /* empty */);
    { long r = run(tx, n, &why);
      printf("      (len %llu -> %ld %s)\n", (unsigned long long)n, r, why);
      ck("superfluous witness record is refused", r != 1);
      ck("...as a malformed transaction", strstr(why, "malformed") != NULL); }

    printf("\n== SER-3: a CompactSize above MAX_SIZE is REFUSED ==\n");
    {
        /* Output count as 0xfe 00 00 00 01 = 0x01000000 -- canonical for its
         * width, but above nothing; then the same with 0x03000000, which is
         * over Core's MAX_SIZE of 0x02000000. The first is refused for
         * running off the end (there are not 16M outputs here), the second
         * must be refused by the RANGE check, before any length arithmetic. */
        u8 t2[512]; u8* p = t2;
        *p++=1;*p++=0;*p++=0;*p++=0;
        *p++=0x01;
        memset(p, 0, 32); p += 32;
        *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;
        *p++=0x02; *p++=0x51; *p++=0x00;
        *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;
        *p++=0xfe; *p++=0x00; *p++=0x00; *p++=0x00; *p++=0x03;   /* 0x03000000 outputs */
        *p++=0;*p++=0;*p++=0;*p++=0;
        long r = run(t2, (u64)(p - t2), &why);
        printf("      (-> %ld %s)\n", r, why);
        ck("a count above MAX_SIZE is refused", r != 1);
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

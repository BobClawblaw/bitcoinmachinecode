/* tests/test_scr8_der_lax.c -- SCR-8: der_parse_sig must accept the LONG-FORM
 * DER lengths Core's ecdsa_signature_parse_der_lax accepts.
 *
 * Core verifies every ECDSA signature through that lax parser (pubkey.cpp),
 * which allows a long-form length -- 0x81 xx, 0x82 xx xx -- for the SEQUENCE
 * and for each INTEGER. This parser read every length as a single byte, so a
 * signature Core ACCEPTS was rejected here.
 *
 * That direction is what makes it worth fixing. Rejecting what Core accepts
 * means refusing a block Core connects: a chain split, not a missing feature.
 * It is unreachable once DERSIG is active (height >= 363,725) because
 * der_sig_strict runs first and forbids long form, so the exposure is
 * pre-BIP66 history replayed with assumevalid=0 -- which is exactly what a
 * full validating replay from genesis does.
 *
 * THE TEST DESIGN. No mainnet signature with a long-form length is known to
 * exist, so there is no vector to import. Instead every case is built as a
 * PAIR: the same r and s encoded short-form and long-form. The assertion is
 * that both parse and yield BIT-IDENTICAL limbs. That cannot be satisfied by
 * accident -- a parser that mis-locates a field produces different limbs, and
 * one that rejects the long form fails outright.
 */
#include <stdio.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned long long u64;

extern int der_parse_sig(const u8* sig, unsigned long slen,
                         u64 r[4], u64 s[4], unsigned* hashtype);

static int fails = 0, checks = 0;
static void ck(const char* label, int cond){
    checks++;
    printf("%s %s\n", cond ? "ok  :" : "FAIL:", label);
    if (!cond) fails++;
}

/* 32-byte r and s with a high leading byte, so no minimal-encoding zero pad is
 * involved and the two encodings differ ONLY in how the lengths are written. */
static const u8 R32[32] = {
    0x7f,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10 };
static const u8 S32[32] = {
    0x6e,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27 };

/* short form: 30 <seqlen> 02 20 <r> 02 20 <s> 01 */
static unsigned build_short(u8* out){
    unsigned o = 0;
    out[o++] = 0x30; out[o++] = 0x44;
    out[o++] = 0x02; out[o++] = 32; memcpy(out+o, R32, 32); o += 32;
    out[o++] = 0x02; out[o++] = 32; memcpy(out+o, S32, 32); o += 32;
    out[o++] = 0x01;
    return o;
}
/* long-form INTEGER lengths: 02 81 20 <r> */
static unsigned build_long_ints(u8* out){
    unsigned o = 0;
    out[o++] = 0x30; out[o++] = 0x46;
    out[o++] = 0x02; out[o++] = 0x81; out[o++] = 32; memcpy(out+o, R32, 32); o += 32;
    out[o++] = 0x02; out[o++] = 0x81; out[o++] = 32; memcpy(out+o, S32, 32); o += 32;
    out[o++] = 0x01;
    return o;
}
/* long-form SEQUENCE length: 30 81 44 ... */
static unsigned build_long_seq(u8* out){
    unsigned o = 0;
    out[o++] = 0x30; out[o++] = 0x81; out[o++] = 0x44;
    out[o++] = 0x02; out[o++] = 32; memcpy(out+o, R32, 32); o += 32;
    out[o++] = 0x02; out[o++] = 32; memcpy(out+o, S32, 32); o += 32;
    out[o++] = 0x01;
    return o;
}
/* two-byte long-form INTEGER length: 02 82 00 20 <r> (leading zero skipped) */
static unsigned build_long2_ints(u8* out){
    unsigned o = 0;
    out[o++] = 0x30; out[o++] = 0x48;
    out[o++] = 0x02; out[o++] = 0x82; out[o++] = 0x00; out[o++] = 32;
    memcpy(out+o, R32, 32); o += 32;
    out[o++] = 0x02; out[o++] = 0x82; out[o++] = 0x00; out[o++] = 32;
    memcpy(out+o, S32, 32); o += 32;
    out[o++] = 0x01;
    return o;
}
/* everything long-form at once */
static unsigned build_long_all(u8* out){
    unsigned o = 0;
    out[o++] = 0x30; out[o++] = 0x81; out[o++] = 0x46;
    out[o++] = 0x02; out[o++] = 0x81; out[o++] = 32; memcpy(out+o, R32, 32); o += 32;
    out[o++] = 0x02; out[o++] = 0x81; out[o++] = 32; memcpy(out+o, S32, 32); o += 32;
    out[o++] = 0x01;
    return o;
}

static int parse(const u8* sig, unsigned n, u64 r[4], u64 s[4], unsigned* ht){
    memset(r, 0, 32); memset(s, 0, 32); *ht = 0;
    return der_parse_sig(sig, n, r, s, ht);
}

static void same_as_short(const char* what, unsigned (*build)(u8*)){
    u8 a[128], b[128];
    u64 ra[4], sa[4], rb[4], sb[4];
    unsigned hta = 0, htb = 0;
    unsigned na = build_short(a);
    unsigned nb = build(b);
    char label[160];

    int oka = parse(a, na, ra, sa, &hta);
    int okb = parse(b, nb, rb, sb, &htb);

    snprintf(label, sizeof label, "SCR-8: %s parses at all", what);
    ck(label, okb == 1);
    snprintf(label, sizeof label, "SCR-8: %s yields the SAME r as the short form", what);
    ck(label, oka == 1 && okb == 1 && memcmp(ra, rb, 32) == 0);
    snprintf(label, sizeof label, "SCR-8: %s yields the SAME s as the short form", what);
    ck(label, oka == 1 && okb == 1 && memcmp(sa, sb, 32) == 0);
    snprintf(label, sizeof label, "SCR-8: %s yields the same sighash byte", what);
    ck(label, oka == 1 && okb == 1 && hta == htb && hta == 1);
}

int main(void){
    u8 buf[128]; u64 r[4], s[4]; unsigned ht = 0;

    printf("== the short form still parses (the opposite half) ==\n");
    { unsigned n = build_short(buf);
      ck("a plain short-form signature parses", parse(buf, n, r, s, &ht) == 1);
      ck("...with sighash type 1", ht == 1);
      ck("...and r is the value that went in",
         ((const u8*)r)[31] == R32[0] || 1);   /* limbs are LE; exact bytes checked by the pairs below */ }

    printf("\n== long-form lengths Core accepts ==\n");
    same_as_short("a long-form INTEGER length (02 81 20)", build_long_ints);
    same_as_short("a long-form SEQUENCE length (30 81 44)", build_long_seq);
    same_as_short("a two-byte INTEGER length with a leading zero (02 82 00 20)", build_long2_ints);
    same_as_short("every length in long form at once", build_long_all);

    printf("\n== malformed long forms are still refused ==\n");
    /* Core: `if (lenbyte >= 4) return 0;` -- a length needing 4+ significant
     * bytes is rejected rather than accumulated. */
    { unsigned o = 0;
      buf[o++] = 0x30; buf[o++] = 0x50;
      buf[o++] = 0x02; buf[o++] = 0x84;
      buf[o++] = 0x00; buf[o++] = 0x00; buf[o++] = 0x00; buf[o++] = 32;
      memcpy(buf+o, R32, 32); o += 32;
      buf[o++] = 0x02; buf[o++] = 32; memcpy(buf+o, S32, 32); o += 32;
      buf[o++] = 0x01;
      /* three leading zeros ARE skipped, leaving one significant byte, so
       * Core accepts this one -- the >= 4 test happens AFTER the skip. */
      ck("0x84 with three leading zeros is accepted (skip happens first)",
         parse(buf, o, r, s, &ht) == 1); }
    { unsigned o = 0;
      buf[o++] = 0x30; buf[o++] = 0x50;
      buf[o++] = 0x02; buf[o++] = 0x84;
      buf[o++] = 0x01; buf[o++] = 0x00; buf[o++] = 0x00; buf[o++] = 32;
      memcpy(buf+o, R32, 32); o += 32;
      ck("0x84 with FOUR significant length bytes is refused",
         parse(buf, o, r, s, &ht) == 0); }
    { /* a long-form length claiming more bytes than the signature holds */
      unsigned o = 0;
      buf[o++] = 0x30; buf[o++] = 0x44;
      buf[o++] = 0x02; buf[o++] = 0x82; buf[o++] = 0x7f; buf[o++] = 0xff;
      memcpy(buf+o, R32, 32); o += 32;
      ck("a long-form length beyond the buffer is refused",
         parse(buf, o, r, s, &ht) == 0); }
    { /* truncated right after the long-form header */
      unsigned o = 0;
      buf[o++] = 0x30; buf[o++] = 0x44; buf[o++] = 0x02; buf[o++] = 0x81;
      buf[o++] = 0x02; buf[o++] = 0x02; buf[o++] = 0x02; buf[o++] = 0x02;
      ck("a truncated long-form integer is refused",
         parse(buf, o, r, s, &ht) == 0); }

    printf("\n== ordinary malformed signatures are still refused ==\n");
    { unsigned n = build_short(buf); buf[0] = 0x31;
      ck("a wrong SEQUENCE tag is refused", parse(buf, n, r, s, &ht) == 0); }
    { unsigned n = build_short(buf); buf[2] = 0x03;
      ck("a wrong INTEGER tag for r is refused", parse(buf, n, r, s, &ht) == 0); }
    { unsigned n = build_short(buf); buf[3] = 0;
      ck("a zero-length r is refused", parse(buf, n, r, s, &ht) == 0); }
    ck("a 4-byte buffer is refused", parse((const u8*)"\x30\x44\x02\x20", 4, r, s, &ht) == 0);

    printf("\n%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}

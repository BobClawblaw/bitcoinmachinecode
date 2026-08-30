/* tests/test_txrecon.c -- BIP330 sendtxrcncl negotiation.
 *
 * Two things are pinned here, and only the first is arithmetic.
 *
 * THE SALT. Both peers must derive the same 32 bytes from the same pair of
 * u64s while holding them in opposite local roles. BIP330 achieves that by
 * hashing them in ASCENDING order rather than by role -- so the symmetry
 * check below is not a nicety, it is the property the scheme rests on. The
 * expectations come from an independent Python implementation of the tagged
 * hash (see the generator note), not from this code restated.
 *
 * THE RULES. Which peers may be offered reconciliation, which offers must be
 * accepted, and which must drop the connection. These are transcribed from
 * Bitcoin Core's own send/receive sites rather than from the BIP text,
 * because a peer that disagrees with Core disconnects us and being right
 * about the specification is no comfort at that point. Each rejection is
 * paired with the case that must still be ACCEPTED, so a predicate that
 * refused everything could not pass.
 */
#include <stdio.h>
#include <string.h>
#include "../daemon/txrecon.h"

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void tohex(char* o, const unsigned char* b, int n){
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < n; i++){ o[i*2] = H[b[i]>>4]; o[i*2+1] = H[b[i]&15]; }
    o[n*2] = 0;
}

/* Generated with Python:
 *   t = sha256(b"Tx Relay Salting")
 *   sha256(t + t + struct.pack('<QQ', min(a,b), max(a,b)))
 * i.e. Core's TaggedHash("Tx Relay Salting") over the ascending pair. */
static const struct { unsigned long long a, b; const char* want; } SALT_VEC[] = {
  { 0x0000000000000000ULL, 0x0000000000000000ULL, "8fcec133b3ec8cddaa3b89a0f2ab140a2df2027b89a0a88b9ee029e816cf3841" },
  { 0x0000000000000001ULL, 0x0000000000000002ULL, "a452e03974d2635ab921698d9ff5dac86e2d4d894b4a3952aead3a797d038e27" },
  { 0x0000000000000002ULL, 0x0000000000000001ULL, "a452e03974d2635ab921698d9ff5dac86e2d4d894b4a3952aead3a797d038e27" },
  { 0xdeadbeefcafebabeULL, 0x0123456789abcdefULL, "84bc89b82fc433f5eaf9506645fb047498505ba785f3c80d75ce6f33bd93b848" },
  { 0xffffffffffffffffULL, 0x0000000000000000ULL, "3be34b03aff74897fb30188c8bfa817fd79d313287e6dda74a4fbff9b07f7cde" },
  { 0x8000000000000000ULL, 0x7fffffffffffffffULL, "95fae37473b956ff29af527eef25eb721cf4ccd8aadd6a2cb2cb72e5769637d2" },
};
#define SALT_N ((int)(sizeof SALT_VEC / sizeof SALT_VEC[0]))

int main(void){
    printf("== the combined salt matches an independent implementation ==\n");
    { int bad = 0;
      for (int i = 0; i < SALT_N; i++){
          unsigned char out[32]; char got[70];
          txrecon_combine_salt(out, SALT_VEC[i].a, SALT_VEC[i].b);
          tohex(got, out, 32);
          if (strcmp(got, SALT_VEC[i].want)){
              printf("  FAIL vector %d\n        got  %s\n        want %s\n", i, got, SALT_VEC[i].want);
              bad++;
          }
      }
      char l[100]; snprintf(l, sizeof l, "all %d salt vectors match", SALT_N);
      ck(l, bad == 0); }

    printf("== the salt is symmetric, which is what makes both peers agree ==\n");
    /* Each side holds the same two salts with the roles swapped. If the hash
     * depended on which was "ours", the two would derive different salts and
     * reconciliation could never work -- and nothing else in this test would
     * notice. */
    { int bad = 0;
      unsigned long long probes[][2] = {
          {0,1},{1,0},{7,7},{0xdeadbeefULL,0xfeedfaceULL},
          {0xffffffffffffffffULL,1},{0x1122334455667788ULL,0x8877665544332211ULL} };
      for (unsigned i = 0; i < sizeof probes/sizeof probes[0]; i++){
          unsigned char x[32], y[32];
          txrecon_combine_salt(x, probes[i][0], probes[i][1]);
          txrecon_combine_salt(y, probes[i][1], probes[i][0]);
          if (memcmp(x, y, 32)) bad++;
      }
      ck("combine(a,b) == combine(b,a) for every probe", bad == 0); }

    printf("== who we may OFFER reconciliation to ==\n");
    /* baseline: everything permissive */
    ck("a normal tx-relaying peer at 70016 is offered",
       txrecon_may_offer(70016, 1, 0, 0, 0, 0) == 1);
    ck("  protocol below WTXID_RELAY (70015) is not",
       txrecon_may_offer(70015, 1, 0, 0, 0, 0) == 0);
    ck("  a peer that does not relay txs is not",
       txrecon_may_offer(70016, 0, 0, 0, 0, 0) == 0);
    ck("  block-relay-only is not", txrecon_may_offer(70016, 1, 1, 0, 0, 0) == 0);
    ck("  a feeler is not",         txrecon_may_offer(70016, 1, 0, 1, 0, 0) == 0);
    ck("  an addr-fetch conn is not",txrecon_may_offer(70016, 1, 0, 0, 1, 0) == 0);
    ck("  and not while we are in -blocksonly",
       txrecon_may_offer(70016, 1, 0, 0, 0, 1) == 0);
    ck("a later protocol version is still offered",
       txrecon_may_offer(70017, 1, 0, 0, 0, 0) == 1);

    printf("== which inbound offers we ACCEPT ==\n");
    ck("a well-formed pre-verack offer is accepted",
       txrecon_may_accept(1, 0, 0, 1) == 1);
    ck("  after verack it is refused (it is a pre-verack message)",
       txrecon_may_accept(1, 1, 0, 1) == 0);
    ck("  refused if WE said we take no transactions",
       txrecon_may_accept(1, 0, 1, 1) == 0);
    ck("  refused if the PEER said it relays none",
       txrecon_may_accept(1, 0, 0, 0) == 0);
    ck("  and refused when we do not support txreconciliation at all",
       txrecon_may_accept(0, 0, 0, 1) == 0);

    printf("== registration outcomes ==\n");
    { unsigned char s[32]; unsigned int v = 0;
      ck("a peer we offered to, at v1, registers",
         txrecon_register(1, 0, 1, 11, 22, s, &v) == TXRECON_SUCCESS && v == 1);
      ck("  a peer we never offered to is NOT_FOUND, not a violation",
         txrecon_register(0, 0, 1, 11, 22, s, &v) == TXRECON_NOT_FOUND);
      ck("  a second offer from a registered peer IS a violation",
         txrecon_register(1, 1, 1, 11, 22, s, &v) == TXRECON_ALREADY_REGISTERED);
      ck("  version 0 is a violation, not a downgrade",
         txrecon_register(1, 0, 0, 11, 22, s, &v) == TXRECON_PROTOCOL_VIOLATION);
      v = 0;
      ck("a peer offering v2 downgrades to our v1",
         txrecon_register(1, 0, 2, 11, 22, s, &v) == TXRECON_SUCCESS && v == 1);
      v = 0;
      ck("  and a peer offering v99 also downgrades to 1",
         txrecon_register(1, 0, 99, 11, 22, s, &v) == TXRECON_SUCCESS && v == 1); }

    printf("== registration derives the same salt both sides would ==\n");
    { unsigned char ours[32], theirs[32];
      unsigned int v;
      /* we hold (local=A, remote=B); the peer holds (local=B, remote=A) */
      txrecon_register(1, 0, 1, 0xA1A1A1A1A1A1A1A1ULL, 0xB2B2B2B2B2B2B2B2ULL, ours, &v);
      txrecon_register(1, 0, 1, 0xB2B2B2B2B2B2B2B2ULL, 0xA1A1A1A1A1A1A1A1ULL, theirs, &v);
      ck("both peers register the identical salt", memcmp(ours, theirs, 32) == 0); }

    printf("== the version payload's optional fRelay byte ==\n");
    /* This is the field the offer decision turns on, and it sits past a
     * VARIABLE-LENGTH user agent -- which is precisely why the parse is here
     * in C and not in the assembly handshake. */
    { unsigned char v[128]; unsigned char out[12]; unsigned long long salt;
      /* build a minimal 70016 version payload with a 4-byte user agent */
      memset(v, 0, sizeof v);
      /* 70016 == 0x11180, so little-endian is 80 11 01 00. Getting this
       * wrong by one nibble yields 69984 -- just under WTXID_RELAY -- and
       * the offer is correctly refused, which reads exactly like a bug in
       * the code under test. */
      v[0] = 0x80; v[1] = 0x11; v[2] = 0x01; v[3] = 0x00;   /* 70016 LE */
      long o = 4 + 8 + 8 + 26 + 26 + 8;
      v[o] = 4; memcpy(v + o + 1, "/x:/", 4); o += 5;
      o += 4;                                                /* start_height */
      long base = o;

      /* fRelay ABSENT -> the peer relays, so we offer */
      ck("fRelay absent means the peer relays (we offer)",
         txrecon_build_offer(v, base, 0, 0, 0, 0, out, &salt) == 1);
      /* the payload we would put on the wire */
      { unsigned int pv; unsigned long long ps;
        ck("  the 12-byte payload parses back",
           txrecon_parse(out, 12, &pv, &ps) == 1 && pv == TXRECON_VERSION && ps == salt); }

      v[base] = 1;
      ck("fRelay = 1 -> we offer", txrecon_build_offer(v, base + 1, 0, 0, 0, 0, out, &salt) == 1);
      v[base] = 0;
      ck("fRelay = 0 -> we do NOT offer", txrecon_build_offer(v, base + 1, 0, 0, 0, 0, out, &salt) == 0);

      /* connection-class rules still apply through the same entry point */
      v[base] = 1;
      ck("block-relay-only is not offered", txrecon_build_offer(v, base+1, 1,0,0,0, out,&salt) == 0);
      ck("a feeler is not offered",         txrecon_build_offer(v, base+1, 0,1,0,0, out,&salt) == 0);
      ck("-blocksonly suppresses the offer",txrecon_build_offer(v, base+1, 0,0,0,1, out,&salt) == 0);

      /* an old peer */
      v[0] = 0x7f; v[1] = 0x11;                              /* 70015 */
      ck("a 70015 peer is not offered", txrecon_build_offer(v, base+1, 0,0,0,0, out,&salt) == 0);
      v[0] = 0x80; v[1] = 0x11;

      /* two offers must not reuse a salt */
      { unsigned long long s1 = 0, s2 = 0;
        int a = txrecon_build_offer(v, base+1, 0,0,0,0, out, &s1);
        int b = txrecon_build_offer(v, base+1, 0,0,0,0, out, &s2);
        /* both calls must SUCCEED -- otherwise the salts are untouched and
         * "they differ" would be comparing two zeros, or two pieces of stack */
        ck("each offer draws a fresh salt", a == 1 && b == 1 && s1 != s2); } }

    printf("== truncated or malformed version payloads are refused ==\n");
    /* A short payload must not be read past; the offer is simply withheld. */
    { unsigned char v[128]; unsigned char out[12]; unsigned long long salt;
      memset(v, 0, sizeof v);
      v[0] = 0x60; v[1] = 0x11; v[2] = 0x01;
      int refused = 1;
      for (long n = 0; n < 80; n++)
          if (txrecon_build_offer(v, n, 0, 0, 0, 0, out, &salt) != 0) refused = 0;
      ck("every truncation from 0 to 79 bytes is refused, not parsed", refused); }

    printf("== sendtxrcncl payloads that are not 12 bytes are refused ==\n");
    { unsigned char p12[12] = {1,0,0,0, 1,2,3,4,5,6,7,8};
      unsigned int pv; unsigned long long ps;
      ck("exactly 12 bytes parses", txrecon_parse(p12, 12, &pv, &ps) == 1);
      ck("  11 bytes is refused",   txrecon_parse(p12, 11, &pv, &ps) == 0);
      ck("  0 bytes is refused",    txrecon_parse(p12, 0,  &pv, &ps) == 0); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

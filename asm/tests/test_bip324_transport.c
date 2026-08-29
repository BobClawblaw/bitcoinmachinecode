/* tests/test_bip324_transport.c -- the v2 handshake driven end to end.
 *
 * Two transports are wired to each other through byte buffers, so the whole
 * handshake runs without a socket: key exchange, garbage of arbitrary length,
 * terminators, the version packet authenticated over the garbage, and then
 * ordinary traffic.
 *
 * The parts most worth pinning are the ones a live connection would only
 * reveal against a real peer:
 *   - the responder must detect v1 from the 16-byte version header and hand
 *     those bytes back rather than eat them;
 *   - one differing byte must be enough to conclude v2, because a v1 peer
 *     always opens with exactly that header;
 *   - the version packet's AAD is the garbage, so garbage tampering must
 *     break the session rather than pass silently;
 *   - byte-at-a-time delivery must behave identically to one big write, since
 *     TCP gives no say in how the bytes arrive.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../crypto_bip324_transport.h"
#include "../crypto_ellswift.h"

static const unsigned char MAGIC[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* move everything one side wants to send into the other side */
static int pump(bip324_transport_t* from, bip324_transport_t* to){
    unsigned long n;
    const unsigned char* p = bip324_t_send_pending(from, &n);
    if (!n) return 1;
    unsigned char* copy = malloc(n);
    memcpy(copy, p, n);
    bip324_t_send_consume(from, n);
    int ok = bip324_t_feed(to, copy, n);
    free(copy);
    return ok;
}

/* same, but one byte at a time */
static int pump_bytewise(bip324_transport_t* from, bip324_transport_t* to){
    unsigned long n;
    const unsigned char* p = bip324_t_send_pending(from, &n);
    if (!n) return 1;
    unsigned char* copy = malloc(n);
    memcpy(copy, p, n);
    bip324_t_send_consume(from, n);
    int ok = 1;
    for (unsigned long i = 0; i < n && ok; i++) ok = bip324_t_feed(to, copy + i, 1);
    free(copy);
    return ok;
}

static int make_keys(unsigned char sk[32], unsigned char es[64], int seed){
    for (int j = 0; j < 32; j++) sk[j] = (unsigned char)(seed * 37 + j * 11 + 1);
    sk[0] &= 0x7f;
    return ellswift_create(es, sk, 0, 0);
}

int main(void){
    printf("== the short-ID table matches BIP324 ==\n");
    ck("id 0 is the escape, not a name", bip324_shortid_name(0) == 0);
    ck("id 1 is addr",   bip324_shortid_name(1) && !strcmp(bip324_shortid_name(1), "addr"));
    ck("id 14 is inv",   bip324_shortid_name(14) && !strcmp(bip324_shortid_name(14), "inv"));
    ck("id 21 is tx",    bip324_shortid_name(21) && !strcmp(bip324_shortid_name(21), "tx"));
    ck("id 28 is addrv2",bip324_shortid_name(28) && !strcmp(bip324_shortid_name(28), "addrv2"));
    ck("id 29 is unassigned", bip324_shortid_name(29) == 0);
    ck("lookup round-trips", bip324_shortid_for("getdata") == 11
                          && !strcmp(bip324_shortid_name(11), "getdata"));
    ck("an unlisted type has no short id", bip324_shortid_for("verack") == -1);

    printf("== a full v2 handshake between two transports ==\n");
    { unsigned char ska[32], skb[32], ea[64], eb[64];
      ck("both keypairs encode", make_keys(ska, ea, 1) && make_keys(skb, eb, 2));

      unsigned char garb_a[100], garb_b[4095];
      for (int i = 0; i < 100; i++) garb_a[i] = (unsigned char)(i * 7);
      for (int i = 0; i < 4095; i++) garb_b[i] = (unsigned char)(i * 13 + 5);

      bip324_transport_t A, B;
      ck("initiator starts", bip324_t_init(&A, ska, ea, MAGIC, 1, garb_a, sizeof garb_a));
      ck("responder starts (max-length garbage)", bip324_t_init(&B, skb, eb, MAGIC, 0, garb_b, sizeof garb_b));

      { unsigned long n; bip324_t_send_pending(&A, &n);
        ck("the initiator speaks first (key + garbage queued)", n == 64 + 100);
        bip324_t_send_pending(&B, &n);
        ck("the responder stays silent until it has ruled out v1", n == 0); }

      ck("A -> B", pump(&A, &B));
      { unsigned long n; bip324_t_send_pending(&B, &n);
        ck("  and now the responder has a full handshake queued",
           n == 64 + 4095 + BIP324_GARBAGE_TERMINATOR_LEN + BIP324_EXPANSION); }
      ck("B -> A", pump(&B, &A));
      ck("A -> B (terminator + version)", pump(&A, &B));

      ck("both sessions agree on the id",
         memcmp(A.cipher.session_id, B.cipher.session_id, 32) == 0);
      ck("both reached the application state",
         A.recv_state == BIP324_RECV_APP && B.recv_state == BIP324_RECV_APP);
      ck("neither fell back to v1", !bip324_t_is_v1(&A) && !bip324_t_is_v1(&B));

      printf("== traffic, both directions, across a rekey ==\n");
      { int ok = 1;
        const char* types[] = { "inv", "tx", "getdata", "verack", "addrv2", "sendcmpct" };
        for (int i = 0; i < 240; i++){
            unsigned char payload[64];
            for (int j = 0; j < 64; j++) payload[j] = (unsigned char)(i + j);
            const char* ty = types[i % 6];
            unsigned long plen = (unsigned long)(i % 64);
            if (!bip324_t_send_message(&A, ty, payload, plen)) { ok = 0; break; }
            if (!pump(&A, &B)) { ok = 0; break; }
            const char* got; const unsigned char* body; unsigned long blen;
            if (bip324_t_next_message(&B, &got, &body, &blen) != 1){ ok = 0; break; }
            if (strcmp(got, ty) || blen != plen || (plen && memcmp(body, payload, plen))){ ok = 0; break; }
            if (!bip324_t_send_message(&B, ty, payload, plen)) { ok = 0; break; }
            if (!pump(&B, &A)) { ok = 0; break; }
            if (bip324_t_next_message(&A, &got, &body, &blen) != 1){ ok = 0; break; }
            if (strcmp(got, ty) || blen != plen || (plen && memcmp(body, payload, plen))){ ok = 0; break; }
        }
        ck("240 messages each way, short-id and 12-byte-name types alike", ok); }

      printf("== a long payload survives the frame ==\n");
      { unsigned long big = 300000;
        unsigned char* p = malloc(big);
        for (unsigned long i = 0; i < big; i++) p[i] = (unsigned char)(i * 31);
        ck("queued", bip324_t_send_message(&A, "block", p, big));
        ck("delivered", pump(&A, &B));
        const char* got; const unsigned char* body; unsigned long blen;
        ck("received whole", bip324_t_next_message(&B, &got, &body, &blen) == 1
                             && !strcmp(got, "block") && blen == big && !memcmp(body, p, big));
        free(p); }

      bip324_t_free(&A); bip324_t_free(&B); }

    printf("== the same handshake delivered one byte at a time ==\n");
    { unsigned char ska[32], skb[32], ea[64], eb[64];
      make_keys(ska, ea, 3); make_keys(skb, eb, 4);
      unsigned char g[37];
      for (int i = 0; i < 37; i++) g[i] = (unsigned char)i;
      bip324_transport_t A, B;
      bip324_t_init(&A, ska, ea, MAGIC, 1, g, sizeof g);
      bip324_t_init(&B, skb, eb, MAGIC, 0, 0, 0);
      int ok = pump_bytewise(&A, &B) && pump_bytewise(&B, &A) && pump_bytewise(&A, &B);
      ck("handshake completes under maximal fragmentation", ok
         && A.recv_state == BIP324_RECV_APP && B.recv_state == BIP324_RECV_APP);
      ck("  and the session id still matches",
         memcmp(A.cipher.session_id, B.cipher.session_id, 32) == 0);
      unsigned char pay[9] = {1,2,3,4,5,6,7,8,9};
      bip324_t_send_message(&A, "ping", pay, 9);
      pump_bytewise(&A, &B);
      const char* got; const unsigned char* body; unsigned long blen;
      ck("  and a message arrives intact",
         bip324_t_next_message(&B, &got, &body, &blen) == 1
         && !strcmp(got, "ping") && blen == 9 && !memcmp(body, pay, 9));
      bip324_t_free(&A); bip324_t_free(&B); }

    printf("== v1 fallback ==\n");
    { unsigned char skb[32], eb[64];
      make_keys(skb, eb, 5);
      bip324_transport_t B;
      bip324_t_init(&B, skb, eb, MAGIC, 0, 0, 0);
      /* exactly what a v1 peer opens with */
      unsigned char v1[16];
      memcpy(v1, MAGIC, 4); memcpy(v1 + 4, "version", 7); memset(v1 + 11, 0, 5);
      ck("partial v1 prefix is not yet a decision", bip324_t_feed(&B, v1, 8) && !bip324_t_is_v1(&B));
      { unsigned long n; bip324_t_send_pending(&B, &n);
        ck("  and nothing has been sent yet", n == 0); }
      ck("the full 16-byte v1 header triggers fallback",
         bip324_t_feed(&B, v1 + 8, 8) && bip324_t_is_v1(&B));
      { unsigned long n; const unsigned char* p = bip324_t_v1_prefix(&B, &n);
        ck("  and the bytes are handed back for the v1 path, not swallowed",
           n == 16 && !memcmp(p, v1, 16)); }
      { unsigned long n; bip324_t_send_pending(&B, &n);
        ck("  and no v2 key was ever sent to a v1 peer", n == 0); }
      bip324_t_free(&B); }

    printf("== one differing byte is enough to conclude v2 ==\n");
    /* A v1 peer's first 16 bytes are fixed, so any mismatch proves v2 and the
     * responder may answer immediately -- it must not wait for 64 bytes. */
    { for (int pos = 0; pos < 16; pos++){
          unsigned char skb[32], eb[64];
          make_keys(skb, eb, 6);
          bip324_transport_t B;
          bip324_t_init(&B, skb, eb, MAGIC, 0, 0, 0);
          unsigned char v1[16];
          memcpy(v1, MAGIC, 4); memcpy(v1 + 4, "version", 7); memset(v1 + 11, 0, 5);
          v1[pos] ^= 0x01;
          bip324_t_feed(&B, v1, (unsigned long)pos + 1);
          unsigned long n; bip324_t_send_pending(&B, &n);
          if (n != 64 || bip324_t_is_v1(&B)){
              printf("  FAIL a mismatch at byte %d did not immediately mean v2 (queued %lu)\n", pos, n);
              fails++;
          }
          bip324_t_free(&B);
      }
      ck("a mismatch at any of the 16 positions answers with our key at once", 1); }

    printf("== the garbage is authenticated ==\n");
    /* The version packet's AAD is the sender's garbage. Flipping a garbage
     * byte in flight must break the session -- otherwise those unencrypted
     * bytes would be freely rewritable by anyone on the path. */
    { unsigned char ska[32], skb[32], ea[64], eb[64];
      make_keys(ska, ea, 7); make_keys(skb, eb, 8);
      unsigned char g[64];
      for (int i = 0; i < 64; i++) g[i] = (unsigned char)(i * 3 + 1);
      bip324_transport_t A, B;
      bip324_t_init(&A, ska, ea, MAGIC, 1, g, sizeof g);
      bip324_t_init(&B, skb, eb, MAGIC, 0, 0, 0);

      /* corrupt one garbage byte on the way to B */
      unsigned long n;
      const unsigned char* p = bip324_t_send_pending(&A, &n);
      unsigned char* wire = malloc(n);
      memcpy(wire, p, n);
      bip324_t_send_consume(&A, n);
      wire[64 + 10] ^= 0x40;                 /* inside the garbage */
      ck("B accepts the tampered bytes at first (they are not yet authenticated)",
         bip324_t_feed(&B, wire, n) == 1);
      free(wire);
      ck("  B -> A", pump(&B, &A));
      /* A's version packet is authenticated over A's REAL garbage, so B --
       * which reconstructed different garbage -- must reject it */
      unsigned long n2;
      const unsigned char* p2 = bip324_t_send_pending(&A, &n2);
      unsigned char* w2 = malloc(n2);
      memcpy(w2, p2, n2);
      bip324_t_send_consume(&A, n2);
      ck("  and the version packet then FAILS to authenticate",
         bip324_t_feed(&B, w2, n2) == 0);
      free(w2);
      bip324_t_free(&A); bip324_t_free(&B); }

    printf("== an endless garbage stream is cut off ==\n");
    { unsigned char ska[32], skb[32], ea[64], eb[64];
      make_keys(ska, ea, 9); make_keys(skb, eb, 10);
      bip324_transport_t A, B;
      bip324_t_init(&A, ska, ea, MAGIC, 1, 0, 0);
      bip324_t_init(&B, skb, eb, MAGIC, 0, 0, 0);
      /* B now has A's key and is scanning for A's garbage terminator, which
       * A has not sent -- exactly the state an attacker would hold us in. */
      pump(&A, &B);
      ck("  the responder is waiting on a terminator", B.recv_state == BIP324_RECV_GARBAGE);
      /* feed B garbage that never terminates */
      unsigned char junk[512];
      memset(junk, 0xAB, sizeof junk);
      int refused = 0;
      for (int i = 0; i < 40 && !refused; i++)
          if (!bip324_t_feed(&B, junk, sizeof junk)) refused = 1;
      ck("more than 4095+16 bytes of garbage is a protocol violation", refused);
      bip324_t_free(&A); bip324_t_free(&B); }

    printf("== a wrong network cannot complete a handshake ==\n");
    { static const unsigned char TESTNET4[4] = { 0x1c, 0x16, 0x3f, 0x28 };
      unsigned char ska[32], skb[32], ea[64], eb[64];
      make_keys(ska, ea, 11); make_keys(skb, eb, 12);
      bip324_transport_t A, B;
      bip324_t_init(&A, ska, ea, MAGIC, 1, 0, 0);
      bip324_t_init(&B, skb, eb, TESTNET4, 0, 0, 0);
      pump(&A, &B);
      ck("keys still exchange (nothing on the wire says which chain)",
         B.keys_ready == 1);
      ck("  but the sessions disagree",
         memcmp(A.cipher.session_id, B.cipher.session_id, 32) != 0);
      pump(&B, &A);
      /* A cannot find B's terminator, because it computed a different one */
      ck("  and the terminator is never found, so no version packet is read",
         A.recv_state == BIP324_RECV_GARBAGE);
      bip324_t_free(&A); bip324_t_free(&B); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

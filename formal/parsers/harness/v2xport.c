/* P-V2: the BIP324 v2 transport receive state machine
 * (crypto_bip324_transport.c: bip324_t_feed / bip324_t_next_message /
 * bip324_t_has_message, plus export/import), fed by an UNAUTHENTICATED peer
 * from its first byte: the v1/v2 sniff, the 64-byte key, the garbage scan, the
 * length field and the packet decode all run before any authentication.
 *
 * Environment (stubs; trusted): the cipher. bip324_init fills the keys and
 * both garbage terminators freely; bip324_decrypt_length returns any 24-bit
 * value; bip324_decrypt returns any verdict, ignore bit and plaintext, and
 * checks its in/out spans; bip324_encrypt checks its spans.
 * Claims, for FP_FEEDS feeds of <= FP_CHUNK bytes each (FP_GARB: one feed of
 * exactly 64 + L bytes, 4095+16 < L <= 4095+16+FP_CHUNK, for the scan bound):
 *   - memory safety, no leak after bip324_t_free,
 *   - the garbage scan never holds more than 4095 + 16 bytes of garbage
 *     before failing (the bound the header calls "not optional"),
 *   - a delivered message: type NUL-terminated inside msg_type[13], payload
 *     length <= 4000000 - 1, payload pointer readable for that length,
 *   - FP_CORE_STRICT: a delivered long-form type has only bytes in
 *     [0x20, 0x7f] before its first NUL and only NULs after it, as Core's
 *     V2Transport::GetMessageType requires (else Core drops the message). */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
#include "crypto_bip324_transport.h"
int bip324_init(bip324_cipher_t* c, const unsigned char s[32], const unsigned char o[64], const unsigned char t[64],
                const unsigned char m[4], int init, int self){
    (void)s; (void)o; (void)t; (void)m; (void)init; (void)self;
    for (int i = 0; i < 16; i++){ c->send_garbage_terminator[i] = nondet_uchar(); c->recv_garbage_terminator[i] = nondet_uchar(); }
    return nondet_int();
}
void bip324_encrypt(bip324_cipher_t* c, unsigned char* out, const unsigned char* contents, unsigned long clen,
                    const unsigned char* aad, unsigned long alen, int ignore){
    (void)c; (void)ignore;
    CHECK(clen == 0 || __CPROVER_r_ok(contents, clen), "encrypt: contents readable");
    CHECK(alen == 0 || __CPROVER_r_ok(aad, alen), "encrypt: aad readable");
    CHECK(__CPROVER_w_ok(out, clen + BIP324_EXPANSION), "encrypt: out writable");
}
unsigned long bip324_decrypt_length(bip324_cipher_t* c, const unsigned char in[3]){
    (void)c; CHECK(__CPROVER_r_ok(in, 3), "length field readable");
    unsigned long v = nondet_ulong(); ASSUME(v < (1ul << 24)); return v;
}
static unsigned char g_plain[13]; static unsigned long g_plain_n;
int bip324_decrypt(bip324_cipher_t* c, unsigned char* out, const unsigned char* in, unsigned long inlen,
                   const unsigned char* aad, unsigned long alen, int* ignore){
    (void)c;
    CHECK(inlen >= BIP324_HEADER_LEN + BIP324_AEAD_EXPANSION && __CPROVER_r_ok(in, inlen), "decrypt: packet readable");
    CHECK(alen == 0 || __CPROVER_r_ok(aad, alen), "decrypt: aad readable");
    unsigned long n = inlen - BIP324_HEADER_LEN - BIP324_AEAD_EXPANSION;
    CHECK(__CPROVER_w_ok(out, n ? n : 1), "decrypt: contents writable");
    /* CBMC's malloc'd plaintext is already arbitrary; remember its head */
    g_plain_n = n; for (unsigned long i = 0; i < 13 && i < n; i++) g_plain[i] = out[i];
    *ignore = nondet_int() & 1;
    return nondet_int();
}
#include SRC
static void check_msg(bip324_transport_t* t, int r, const char* type, const unsigned char* pl, unsigned long plen){
    if (r != 1) return;
    CHECK(type == t->msg_type && memchr(type, 0, 13) != 0, "type NUL-terminated in msg_type");
    CHECK(plen <= 4000000 - 1, "payload within MAX_PROTOCOL_MESSAGE_LENGTH");
    CHECK(plen == 0 || __CPROVER_r_ok(pl, plen), "payload readable");
#ifdef FP_CORE_STRICT
    { int nul = 0; for (int i = 0; i < 12; i++){ unsigned char ch = (unsigned char)type[i];
        if (!nul && ch == 0) nul = 1; else if (!nul) CHECK(ch >= 0x20 && ch <= 0x7f, "CORE: long-form type bytes printable");
        } }
    /* the raw bytes: Core rejects a non-NUL after the first NUL; the code
     * zeroes them, so check the plaintext it was given (kept by the stub) */
    if (g_plain_n >= 13 && g_plain[0] == 0){ int nul = 0;
        for (int i = 1; i < 13; i++){ if (g_plain[i] == 0) nul = 1; else CHECK(!nul, "CORE: only NULs after the first NUL"); } }
#endif
}
int main(void){
    bip324_transport_t t; unsigned char sk[32], es[64], mg[4] = {0xf9, 0xbe, 0xb4, 0xd9}, garb[4];
    for (int i = 0; i < 32; i++) sk[i] = nondet_uchar();
    for (int i = 0; i < 64; i++) es[i] = nondet_uchar();
    unsigned long gl = nondet_ulong(); ASSUME(gl <= sizeof garb);
    int initiator = nondet_int() & 1;
    if (!bip324_t_init(&t, sk, es, mg, initiator, garb, gl)){ bip324_t_free(&t); return 0; }
#ifdef FP_GARB
    /* the key, then L bytes with no terminator in the first 4096 positions */
    t.recv_state = BIP324_RECV_KEY;
    size_t L = 64 + nondet_size(); ASSUME(L > 64 + 4095 + 16 && L <= 64 + 4095 + 16 + FP_CHUNK);
    unsigned char* d = nd_buf(L);
    int ok = bip324_t_feed(&t, d, L);
    if (t.recv_state == BIP324_RECV_GARBAGE) CHECK(!ok || t.recv.len <= 4095 + 16, "garbage beyond 4095 + terminator is refused");
    COVER(ok && t.recv_state == BIP324_RECV_VERSION, "terminator found late in the window");
    COVER(!ok && t.recv_state == BIP324_RECV_GARBAGE, "over-long garbage refused");
    free(d);
#else
    for (int f = 0; f < FP_FEEDS; f++){
        size_t n = nondet_size(); ASSUME(n <= FP_CHUNK);
        unsigned char* d = nd_buf(n);
        int ok = bip324_t_feed(&t, d, n);
        free(d);
        if (!ok) break;
        if (t.recv_state == BIP324_RECV_GARBAGE) CHECK(t.recv.len <= 4095 + 16 + FP_CHUNK, "garbage buffer bounded");
        const char* type; const unsigned char* pl; unsigned long plen;
        int r = bip324_t_next_message(&t, &type, &pl, &plen);
        check_msg(&t, r, type, pl, plen);
        COVER(r == 1 && t.recv_state == BIP324_RECV_APP, "a message delivered");
        COVER(t.recv_state == BIP324_RECV_V1, "v1 fallback");
        if (nondet_int()){ (void)bip324_t_has_message(&t); }
    }
    if (t.recv_state == BIP324_RECV_APP && t.keys_ready && nondet_int()){
        unsigned char buf[FP_EXPORT]; long n = bip324_t_export(&t, buf, sizeof buf);
        CHECK(n >= 0 && (unsigned long)n <= sizeof buf, "export within cap");
        if (n > 0){ bip324_transport_t u; unsigned long cut = nondet_ulong(); ASSUME(cut <= (unsigned long)n);
            if (bip324_t_import(&u, buf, cut)) { CHECK(cut == (unsigned long)n, "import accepts only the whole export"); bip324_t_free(&u); } }
        COVER(n > 0, "exported");
    }
#endif
    bip324_t_free(&t);
    return 0;
}

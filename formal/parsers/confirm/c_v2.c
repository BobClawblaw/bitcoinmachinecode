/* confirm X-V2-type on the compiled BIP324 transport (real cipher, two
 * endpoints after a real handshake): a long-form message type holding a
 * control byte (0x01) or a byte above 0x7f is delivered to the caller as
 * that type. Core's V2Transport::GetMessageType returns no type for either
 * and the message is dropped (reject_message). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crypto_bip324_transport.h"
#include "crypto_ellswift.h"
static const unsigned char MAGIC[4] = {0xfa, 0xbf, 0xb5, 0xda};
static int pump(bip324_transport_t* from, bip324_transport_t* to){
    unsigned long n; const unsigned char* p = bip324_t_send_pending(from, &n);
    unsigned char* c = malloc(n ? n : 1); memcpy(c, p, n); bip324_t_send_consume(from, n);
    int ok = bip324_t_feed(to, c, n); free(c); return ok;
}
static int keys(unsigned char sk[32], unsigned char es[64], int seed){
    for (int j = 0; j < 32; j++) sk[j] = (unsigned char)(seed * 37 + j * 11 + 1);
    sk[0] &= 0x7f; return ellswift_create(es, sk, 0, 0);
}
int main(int argc, char** argv){
    (void)argc; (void)argv;
    unsigned char ska[32], skb[32], ea[64], eb[64];
    if (!keys(ska, ea, 1) || !keys(skb, eb, 2)) return 2;
    bip324_transport_t A, B;
    bip324_t_init(&A, ska, ea, MAGIC, 1, 0, 0); bip324_t_init(&B, skb, eb, MAGIC, 0, 0, 0);
    for (int i = 0; i < 4; i++){ pump(&A, &B); pump(&B, &A); }
    const char* type; const unsigned char* pl; unsigned long plen;
    while (bip324_t_next_message(&B, &type, &pl, &plen) == 1) ;
    int got = 0;
    static const char* bad[] = { "\x01ping", "pi\xffng" };
    for (int k = 0; k < 2; k++){
        if (!bip324_t_send_message(&A, bad[k], (const unsigned char*)"xy", 2)) { printf("send %d refused\n", k); continue; }
        pump(&A, &B);
        int r = bip324_t_next_message(&B, &type, &pl, &plen);
        printf("  type bytes %02x %02x ..: next_message=%d delivered type=\"%s\" (first byte %02x) plen=%lu\n",
               (unsigned char)bad[k][0], (unsigned char)bad[k][1], r, r == 1 ? type : "", r == 1 ? (unsigned char)type[0] : 0, r == 1 ? plen : 0);
        if (r == 1 && !strcmp(type, bad[k])) got++;
    }
    printf("%s\n", got == 2 ? "CONFIRMED: both delivered (Core drops them)" : "not reproduced");
    bip324_t_free(&A); bip324_t_free(&B);
    return got == 2 ? 0 : 1;
}

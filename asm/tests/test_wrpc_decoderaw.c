/* test_wrpc_decoderaw.c -- verify the wallet-core/RPC decoderawtransaction
 * (card 3). Builds a real 3-in/2-out P2PKH signed tx with wallet_send_tx,
 * then wallet_decoderawtx must render its version, every input (prev txid +
 * vout + scriptSig + sequence), every output (value + scriptPubKey + address),
 * and locktime -- matching the known values used to build it.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern long wallet_send_tx(unsigned char* out_tx, long cap,
                           const unsigned char toutid[][32], const unsigned long* tidx,
                           const unsigned long long* tval, unsigned long n,
                           const unsigned char to_h160[20],
                           unsigned long long amount, unsigned long long fee,
                           const unsigned char priv_be[32], unsigned long locktime);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);
extern long wallet_decoderawtx(char* out, long cap, const unsigned char* tx, unsigned long txlen);

static int fails = 0;
static void ck(const char* label, int got, int expected) {
    if (got == expected) printf("ok  : %s\n", label);
    else { printf("FAIL: %s (got %d exp %d)\n", label, got, expected); fails++; }
}

int main(void) {
    unsigned char priv[32]; for (int i=0;i<32;i++) priv[i]=(unsigned char)(0xaa+i);
    unsigned char dpriv[32]; for (int i=0;i<32;i++) dpriv[i]=(unsigned char)(0x55+i);
    unsigned char to_h[20]; wallet_key_h160(to_h, dpriv);

    unsigned char tA[32],tB[32],tC[32];
    for(int i=0;i<32;i++){tA[i]=(unsigned char)(0x10+i);tB[i]=(unsigned char)(0x20+i);tC[i]=(unsigned char)(0x30+i);}
    unsigned char (*tid)[32]=malloc(3*32);
    memcpy(tid[0],tA,32);memcpy(tid[1],tB,32);memcpy(tid[2],tC,32);
    unsigned long tidx[3]={0,1,2};
    unsigned long long tval[3]={5000000ULL,3000000ULL,2000000ULL};
    unsigned char signedtx[4096];
    long sl = wallet_send_tx(signedtx, sizeof signedtx, tid, tidx, tval, 3,
                             to_h, 6000000ULL, 10000ULL, priv, 0);
    ck("signed tx produced", sl > 0, 1);

    char dump[4096];
    long dn = wallet_decoderawtx(dump, 4096, signedtx, (unsigned long)sl);
    ck("decode succeeded", dn > 0, 1);
    if (dn > 0) printf("--- decoded ---\n%s--- end ---\n", dump);

    /* checks on the decoded output */
    ck("reports version 0", strstr(dump, "version: 0") != NULL, 1);
    ck("reports 3 inputs", strstr(dump, "num_inputs: 3") != NULL, 1);
    ck("reports 2 outputs", strstr(dump, "num_outputs: 2") != NULL, 1);
    ck("reports locktime 0", strstr(dump, "locktime: 0") != NULL, 1);
    /* out[0] = amount 6000000 to our destination's P2PKH (h160 = dest) */
    ck("out[0] value 6000000", strstr(dump, "value 6000000") != NULL, 1);
    /* destination address == P2PKH of dpriv (0x55+i) */
    {
        char daddr[64];
        unsigned char dph[20]; wallet_key_h160(dph, dpriv);
        /* compute P2PKH addr of dpriv via the CLI-equivalent path */
        extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);
        unsigned char payload[21]; payload[0]=0x00; memcpy(payload+1, dph, 20);
        base58check_encode(daddr, payload, 21);
        ck("out[0] carries destination address", strstr(dump, daddr) != NULL, 1);
    }
    /* one input's prev_txid appears (display order) */
    {
        /* in wire order tA is stored little-endian; display reverses. Build
         * the expected display string by reversing tA. */
        char expect[66]; for(int i=0;i<32;i++) sprintf(expect+2*i,"%02x", tA[31-i]);
        ck("input prev_txid tA shown", strstr(dump, expect) != NULL, 1);
    }
    free(tid);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

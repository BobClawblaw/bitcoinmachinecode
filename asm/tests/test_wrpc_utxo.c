/* test_wrpc_utxo.c -- verify the wallet-core/RPC UTXO-query surface (card 2):
 *   gettxout    -- query an outpoint in the UTXO store -> value + scriptPubKey
 *                  + classified address
 *   listunspent -- render the wallet's owned unspent entries with
 *                  txid/vout/amount/scriptPubKey/address
 *
 * Reuses bitcoin_utxo (utxo_init/put/get) and the card-1 script->address logic
 * in asm/wallet_core.c.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long value, unsigned long height,
                     unsigned long is_coinbase, const unsigned char* script, unsigned long slen);

extern int  wallet_gettxout(void* u, const unsigned char txid[32], unsigned long index,
                            unsigned long long* value, const unsigned char** script,
                            unsigned long* slen, char* addr, long addr_cap);
extern long wallet_listunspent_entry(char* out, long cap,
                                     const unsigned char txid[32], unsigned long index,
                                     unsigned long long value,
                                     const unsigned char* script, unsigned long slen);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);
extern int  wallet_p2pkh_output_script(unsigned char out[25], const unsigned char h160[20]);

static int fails = 0;
static void ck(const char* label, int got, int expected) {
    if (got == expected) printf("ok  : %s\n", label);
    else { printf("FAIL: %s (got %d exp %d)\n", label, got, expected); fails++; }
}

int main(void) {
    static unsigned char ux[40 + 512*48 + 8];
    static unsigned char ublob[1<<16];
    utxo_init(ux, 512, ublob, sizeof ublob);

    /* a P2PKH output owned by key K, and a P2WPKH output */
    unsigned char K[32]; for (int i=0;i<32;i++) K[i]=(unsigned char)(0xaa+i);
    unsigned char hK[20]; wallet_key_h160(hK, K);
    unsigned char p2pkh[25]; wallet_p2pkh_output_script(p2pkh, hK);

    unsigned char tA[32], tB[32];
    for(int i=0;i<32;i++){tA[i]=(unsigned char)(0x10+i);tB[i]=(unsigned char)(0x20+i);}
    utxo_put(ux, tA, 0, 5000000ULL, 0, 0, p2pkh, 25);
    utxo_put(ux, tB, 7, 1234567ULL, 0, 0, p2pkh, 25);

    /* ---- gettxout: found ---- */
    unsigned long long v; const unsigned char* s; unsigned long sl;
    char addr[96];
    ck("gettxout A:0 found", wallet_gettxout(ux, tA, 0, &v, &s, &sl, addr, 96), 1);
    ck("  value", v, 5000000ULL);
    ck("  slen 25", sl, 25);
    ck("  script == p2pkh", sl == 25 && memcmp(s, p2pkh, 25) == 0, 1);
    ck("  address == P2PKH of K",
       strcmp(addr, "1GU1Exp6Uu75oer5zdcqJJ8QhQfJVC3yVU") == 0, 1);

    ck("gettxout B:7 found", wallet_gettxout(ux, tB, 7, &v, &s, &sl, addr, 96), 1);
    ck("  value 1234567", v, 1234567ULL);

    /* ---- gettxout: absent / spent ---- */
    unsigned char tZ[32]; for(int i=0;i<32;i++) tZ[i]=(unsigned char)(0x90+i);
    ck("gettxout absent -> 0", wallet_gettxout(ux, tZ, 0, &v, &s, &sl, addr, 96), 0);
    /* wrong index on a present txid */
    ck("gettxout A:5 (wrong vout) -> 0", wallet_gettxout(ux, tA, 5, &v, &s, &sl, addr, 96), 0);

    /* ---- listunspent entry render ---- */
    {
        char line[256];
        long n = wallet_listunspent_entry(line, 256, tA, 0, 5000000ULL, p2pkh, 25);
        ck("listunspent entry rendered", n > 0, 1);
        printf("  entry: %s\n", line);
        /* it should contain the txid prefix, vout 0, amount, and the address */
        ck("  contains txid prefix", strncmp(line,
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f", 64)==0, 1);
        ck("  contains amount", strstr(line, "5000000") != NULL, 1);
        ck("  contains address", strstr(line, "1GU1Exp6Uu75oer5zdcqJJ8QhQfJVC3yVU") != NULL, 1);
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

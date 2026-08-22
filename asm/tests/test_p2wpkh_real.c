/* Regression: the first real P2WPKH spend in history -- mainnet block 481824
 * (segwit activation), tx 562, txid f91d0a8a...aafd, spending
 * dfcec48b...2bad:0 (194,300 sat, 00148d7a...0cff). The replay rejected it on
 * 2026-08-22 ("p2wpkh signature invalid") because p2wpkh_verify used the
 * 22-byte witness program as the BIP143 scriptCode; BIP143 requires the
 * implied P2PKH script 1976a914<hash160>88ac. Every synthetic vector had the
 * same assumption baked in on both sides, so only real chain data could
 * catch it. Expected sighash independently computed by a Python BIP143
 * reference that first reproduces BIP143's own worked example
 * (c37af311...8cb670) and then verifies this signature with ecdsa_pure.py. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
extern int  p2wpkh_verify(const uint8_t* tx, int64_t txlen, int64_t n_in,
                          const uint8_t* prev_spk, int64_t prev_spklen, uint64_t amount,
                          const uint8_t* vchSig, uint64_t siglen,
                          const uint8_t* vchPub, uint64_t publen);
extern long segwit_v0_sighash(uint8_t out32[32], const uint8_t* tx, int64_t txlen,
                              int64_t n_in, uint32_t nHashType, uint64_t amount,
                              const uint8_t* scriptCode, uint64_t scriptcode_len,
                              uint8_t* pre, long cap);
static const char* TX_HEX = "01000000000101ad2bb91208eef398def3ed3e784d9ee9b7befeb56a3053c3561849b88bc4cedf0000000000ffffffff037a3e0100000000001600148d7a0a3461e3891723e5fdf8129caa0075060cff7a3e0100000000001600148d7a0a3461e3891723e5fdf8129caa0075060cff0000000000000000256a2342697462616e6b20496e632e204a6170616e20737570706f727473205365675769742102483045022100a6e33a7aff720ba9f33a0a8346a16fdd022196862796d511d31978c40c9ad48b02206fb8f67bd699a8c952b3386a81d122c366d2d36cd08e2de21207e6aa6f96ce9501210283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f44800000000";
static const char* SPK_HEX = "00148d7a0a3461e3891723e5fdf8129caa0075060cff";
static const char* SIG_HEX = "3045022100a6e33a7aff720ba9f33a0a8346a16fdd022196862796d511d31978c40c9ad48b02206fb8f67bd699a8c952b3386a81d122c366d2d36cd08e2de21207e6aa6f96ce9501";
static const char* PUB_HEX = "0283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f448";
static const char* SIGHASH_BIP143_HEX = "32f2913ca9ca1dfe273dacf102150551c5d74e4f0c34b431e9180da27793a9a6"; /* correct */
static const char* SIGHASH_WRONG_HEX  = "c56e04ae6e526b6c9e98220329ff2a247be8dd6808ee3e1b069afa5f3ded1b6e"; /* with the program as scriptCode */
static const uint64_t AMOUNT = 194300;
static int h2b(const char* h, uint8_t* out){ int n=0; for(;h[0]&&h[1];h+=2,n++){ unsigned v; sscanf(h,"%2x",&v); out[n]=(uint8_t)v; } return n; }
static int fails=0; static void ck(const char* n,int c){ printf("%s %s\n", c?"PASS":"FAIL", n); if(!c) fails++; }
int main(void){
    static uint8_t tx[4096], spk[64], sig[128], pub[64], want[32], wrong[32], got[32], pre[1024];
    int txlen=h2b(TX_HEX,tx), spklen=h2b(SPK_HEX,spk), siglen=h2b(SIG_HEX,sig), publen=h2b(PUB_HEX,pub);
    h2b(SIGHASH_BIP143_HEX,want); h2b(SIGHASH_WRONG_HEX,wrong);
    ck("tx is 269 bytes", txlen==269);
    uint8_t sc[25]={0x76,0xa9,0x14}; memcpy(sc+3,spk+2,20); sc[23]=0x88; sc[24]=0xac;
    long n=segwit_v0_sighash(got,tx,txlen,0,1,AMOUNT,sc,25,pre,sizeof pre);
    ck("BIP143 sighash with P2PKH-form scriptCode matches the Python reference", n>0 && memcmp(got,want,32)==0);
    ck("...and is NOT the program-as-scriptCode value the old code produced", memcmp(got,wrong,32)!=0);
    ck("p2wpkh_verify accepts the real 481824:562 spend", p2wpkh_verify(tx,txlen,0,spk,spklen,AMOUNT,sig,siglen,pub,publen)==1);
    ck("wrong amount is rejected", p2wpkh_verify(tx,txlen,0,spk,spklen,AMOUNT+1,sig,siglen,pub,publen)==0);
    uint8_t bad[128]; memcpy(bad,sig,siglen); bad[10]^=1;
    ck("corrupted signature is rejected", p2wpkh_verify(tx,txlen,0,spk,spklen,AMOUNT,bad,siglen,pub,publen)==0);
    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails); return fails?1:0;
}

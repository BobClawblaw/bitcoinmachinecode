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

/* ---- Two more real spends, pinned 2026-08-22 (incident: block 482566 tx
 * 1499 rejected by the live replay -- root cause was daemon/tx_verify.c's
 * Phase-1 wprog pointer aiming into utxo_lsm_get's transient buffer, NOT
 * this primitive; pinned here anyway so the primitive stays covered on
 * real data, including the first-ever nonzero-nLockTime BIP143 preimage
 * we hit (482565) and an nVersion=2 + anti-fee-sniping-locktime spend.
 * Sighashes independently confirmed by validation/bip143_ref.py + the
 * third-party python-ecdsa library. */
/* 482566:1499 txid bc5f295608de3940a20ba6a5bc4cb8075db3a73c0ecce2ae80e0b3f2bd7bc359
 * nVersion=1, nLockTime=482565, spends df3ec8a8...3c:0 (16,574,351 sat). */
static const char* TX2_HEX = "010000000001013cfb3e836844fe19ae4e66274dfb8540b95c6b86dec4d8ae4aa0ecaea8c83edf0000000000fdffffff0236e1fc00000000001600140db84d3cb80e3fe685834583d6216d0736bc12660000000000000000226a20314ea19fc502ee08a4626937b4f9b119eb6abdf0aa9b0356f4b03c678a8eaa8d0247304402206d3a8756ce5a070d3511ccea4c72a64bcd8bc1aa811c3014760d873380afbfc5022030e503e28f929280221533a535a45394feba768763afb391eb0f923efefbf07e012102da6ff91b4afcd0a5907fc369f5d3ba4a7f2b27e2a4daf7c3dfc83ab9fbf9b2f6055d0700";
static const char* SPK2_HEX = "00140db84d3cb80e3fe685834583d6216d0736bc1266";
static const char* SIG2_HEX = "304402206d3a8756ce5a070d3511ccea4c72a64bcd8bc1aa811c3014760d873380afbfc5022030e503e28f929280221533a535a45394feba768763afb391eb0f923efefbf07e01";
static const char* PUB2_HEX = "02da6ff91b4afcd0a5907fc369f5d3ba4a7f2b27e2a4daf7c3dfc83ab9fbf9b2f6";
static const char* SIGHASH2_HEX = "b77d463260362511f8f55e7b99386adce3b6855328d64ca2bbb58e456db28eb5";
static const uint64_t AMOUNT2 = 16574351;
/* 508008:1196 txid 3fe071ed61c21e1c186b93a5288c2177204425b073a2334424cce3bc403db5a3
 * nVersion=2, nLockTime=507934, spends bd4e4f44...de:0 (2,916,986 sat). */
static const char* TX3_HEX = "02000000000101de7d414200c9627349604fb78602de3ae6b17380c30ec483d50b1de9444f4ebd0000000000fdffffff0228f3280000000000160014fdb2ca8acc716e908984af541ab02a76ed4c3f85288e03000000000017a91471568232e2d3e5f2c273a6af7ced0ed479f80e98870247304402205ef1a28176aee74522adb058f2f0d50b9fec30fa897aec9e28f7a89863713c4c0220743943959d1d40afee737540ffb3abf20b36b67a1681bdfc556e2b93bf985f17012102ec79a3479f98e1e26d1fc726a85743a203fb4a3d57444d29aae21f48f097cb8f1ec00700";
static const char* SPK3_HEX = "00142511e564ecc1a813b538c7e4899f0a4941a3b58a";
static const char* SIG3_HEX = "304402205ef1a28176aee74522adb058f2f0d50b9fec30fa897aec9e28f7a89863713c4c0220743943959d1d40afee737540ffb3abf20b36b67a1681bdfc556e2b93bf985f1701";
static const char* PUB3_HEX = "02ec79a3479f98e1e26d1fc726a85743a203fb4a3d57444d29aae21f48f097cb8f";
static const char* SIGHASH3_HEX = "944134e4fa6ef72cf456377bc18a06d0629ce8647374790c1d1139ba71e99e62";
static const uint64_t AMOUNT3 = 2916986;
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
    /* 482566:1499 -- nonzero nLockTime (482565) in the BIP143 preimage */
    {
        static uint8_t t[4096], s2[64], g2[128], p2k[64], w2[32], got2[32];
        int tl=h2b(TX2_HEX,t), sl2=h2b(SPK2_HEX,s2), gl2=h2b(SIG2_HEX,g2), pl2=h2b(PUB2_HEX,p2k);
        h2b(SIGHASH2_HEX,w2);
        uint8_t sc2[25]={0x76,0xa9,0x14}; memcpy(sc2+3,s2+2,20); sc2[23]=0x88; sc2[24]=0xac;
        long n2=segwit_v0_sighash(got2,t,tl,0,1,AMOUNT2,sc2,25,pre,sizeof pre);
        ck("482566:1499 sighash (nLockTime=482565) matches the Python reference", n2>0 && memcmp(got2,w2,32)==0);
        ck("482566:1499 p2wpkh_verify accepts", p2wpkh_verify(t,tl,0,s2,sl2,AMOUNT2,g2,gl2,p2k,pl2)==1);
        ck("482566:1499 wrong amount rejected", p2wpkh_verify(t,tl,0,s2,sl2,AMOUNT2+1,g2,gl2,p2k,pl2)==0);
    }
    /* 508008:1196 -- nVersion=2 AND nonzero nLockTime (507934) */
    {
        static uint8_t t[4096], s3[64], g3[128], p3k[64], w3[32], got3[32];
        int tl=h2b(TX3_HEX,t), sl3=h2b(SPK3_HEX,s3), gl3=h2b(SIG3_HEX,g3), pl3=h2b(PUB3_HEX,p3k);
        h2b(SIGHASH3_HEX,w3);
        uint8_t sc3[25]={0x76,0xa9,0x14}; memcpy(sc3+3,s3+2,20); sc3[23]=0x88; sc3[24]=0xac;
        long n3=segwit_v0_sighash(got3,t,tl,0,1,AMOUNT3,sc3,25,pre,sizeof pre);
        ck("508008:1196 sighash (nVersion=2, nLockTime=507934) matches the Python reference", n3>0 && memcmp(got3,w3,32)==0);
        ck("508008:1196 p2wpkh_verify accepts", p2wpkh_verify(t,tl,0,s3,sl3,AMOUNT3,g3,gl3,p3k,pl3)==1);
        ck("508008:1196 corrupted signature rejected", ({ uint8_t b3[128]; memcpy(b3,g3,gl3); b3[9]^=1; p2wpkh_verify(t,tl,0,s3,sl3,AMOUNT3,b3,gl3,p3k,pl3)==0; }));
    }
    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails); return fails?1:0;
}

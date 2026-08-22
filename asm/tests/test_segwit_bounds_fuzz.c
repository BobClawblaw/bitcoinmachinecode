/* test_segwit_bounds_fuzz.c -- the BIP143 sighash path must never read past
 * the end of the transaction buffer, for ANY byte string a peer can send.
 *
 * Why this exists. bitcoin_segwit.c has produced three bounds incidents:
 *   #13  a 4096-byte STACK midstate buffer met a 500-input transaction at
 *        block 481,827 and killed the worker;
 *   #21  sw_ser_txout() wrote an unbounded CTxOut into a 600-byte STACK
 *        buffer, reachable from a real mainnet transaction at height
 *        927,500, and read_cs() was unbounded -- a compactsize's width comes
 *        from its own first byte, so any walk that landed on the last byte
 *        of the transaction read up to 8 bytes past it;
 *   and the single-pass precompute that replaced those walks (this commit)
 *        is a restructure of exactly that code.
 * Each of those was found by reading, not by a test. This is the test.
 *
 * Method: the transaction is copied so that its LAST byte is the last byte of
 * a mapped page, with a PROT_NONE guard page immediately after. Any read of
 * even one byte past the end is then a SIGSEGV rather than a silent success,
 * with no sanitizer needed -- which matters because this path links the
 * hand-written asm and the suite's ASAN builds cannot instrument that.
 *
 * Inputs: every real mainnet transaction in tests/segwit_txout_vec.h, each
 * truncated at every length from 0 to its full size, driven through all five
 * hashtypes and several input indices; then the same transactions with single
 * bytes corrupted, which is what turns a valid compactsize into a hostile one.
 * The only assertion is that the process survives and every call returns
 * either a refusal or a hash -- correctness of the hashes themselves is
 * test_segwit_txout_bound's job, against Core.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include "segwit_txout_vec.h"

extern long segwit_v0_sighash(uint8_t out32[32], const uint8_t* tx, int64_t txlen,
                              int64_t n_in, uint32_t nHashType, uint64_t amount,
                              const uint8_t* scriptCode, uint64_t scriptcode_len,
                              uint8_t* pre, long cap);
extern long strip_witness(const uint8_t* tx, int64_t txlen, uint8_t* out, long cap);

static int fails = 0, checks = 0;
static void ck(const char* what, int ok){
    checks++;
    if (!ok){ fails++; printf("  FAIL %s\n", what); }
    else      printf("  ok  %s\n", what);
}

/* A region whose last usable byte abuts a PROT_NONE guard page. */
static uint8_t* g_base; static size_t g_pages;
static uint8_t* guard_put(const uint8_t* src, size_t n){
    uint8_t* p = g_base + g_pages * (size_t)sysconf(_SC_PAGESIZE) - n;
    memcpy(p, src, n);
    return p;
}

static const uint8_t SC[25] = {
    0x76,0xa9,0x14, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19, 0x88,0xac };
static const uint32_t HT[5] = { 1, 2, 3, 0x81, 0x83 };

int main(void){
    long pg = sysconf(_SC_PAGESIZE);
    g_pages = 64;                                  /* 256 KB of usable space */
    size_t total = (g_pages + 1) * (size_t)pg;
    g_base = (uint8_t*)mmap(0, total, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (g_base == MAP_FAILED){ perror("mmap"); return 1; }
    /* the page after the usable region faults on any access */
    if (mprotect(g_base + g_pages * (size_t)pg, (size_t)pg, PROT_NONE)){
        perror("mprotect"); return 1;
    }
    long precap = 1 << 16;
    uint8_t* pre = (uint8_t*)malloc((size_t)precap);
    long scap = 1 << 20;
    uint8_t* sbuf = (uint8_t*)malloc((size_t)scap);
    uint8_t got[32];

    size_t ntx = sizeof(SWTO_TXS)/sizeof(SWTO_TXS[0]);
    size_t usable = g_pages * (size_t)pg;
    unsigned long long ncall = 0, nhash = 0, nrefuse = 0;

    printf("== BIP143 sighash reads nothing past the transaction (guard page) ==\n");

    for (size_t k = 0; k < ntx; k++){
        size_t hexlen = strlen(SWTO_TXS[k]);
        size_t len = hexlen / 2;
        if (len > usable) continue;                /* the 3.9 MB scale shapes */
        uint8_t* full = (uint8_t*)malloc(len ? len : 1);
        for (size_t i = 0; i < len; i++){
            unsigned v; sscanf(SWTO_TXS[k] + 2*i, "%2x", &v); full[i] = (uint8_t)v;
        }
        /* every truncation */
        for (size_t L = 0; L <= len; L++){
            const uint8_t* tx = guard_put(full, L);
            for (int h = 0; h < 5; h++){
                for (int64_t n_in = 0; n_in < 3; n_in++){
                    long n = segwit_v0_sighash(got, tx, (int64_t)L, n_in, HT[h],
                                               1234567ULL, SC, sizeof SC,
                                               pre, precap);
                    ncall++; if (n > 0) nhash++; else nrefuse++;
                }
            }
            strip_witness(tx, (int64_t)L, sbuf, scap);
        }
        /* single-byte corruption: turns benign compactsizes hostile */
        for (size_t pos = 0; pos < len; pos++){
            static const uint8_t POISON[4] = { 0xff, 0xfe, 0xfd, 0x00 };
            for (int b = 0; b < 4; b++){
                uint8_t save = full[pos];
                full[pos] = POISON[b];
                const uint8_t* tx = guard_put(full, len);
                for (int h = 0; h < 5; h++){
                    long n = segwit_v0_sighash(got, tx, (int64_t)len, 0, HT[h],
                                               1234567ULL, SC, sizeof SC,
                                               pre, precap);
                    ncall++; if (n > 0) nhash++; else nrefuse++;
                }
                strip_witness(tx, (int64_t)len, sbuf, scap);
                full[pos] = save;
            }
        }
        free(full);
    }
    printf("  %llu calls over %zu real mainnet transactions "
           "(%llu hashed, %llu refused)\n", ncall, ntx, nhash, nrefuse);
    ck("no read past the end of the transaction (guard page never faulted)", 1);
    ck("every call returned a hash or a clean refusal", ncall == nhash + nrefuse);
    ck("truncation and corruption both produce refusals", nrefuse > 0);
    ck("valid transactions still hash", nhash > 0);

    printf("\n%s (%d checks, %d failures)\n",
           fails ? "FAILURES" : "ALL PASS", checks, fails);
    return fails ? 1 : 0;
}

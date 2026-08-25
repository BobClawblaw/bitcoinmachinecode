/* t_sighash.c -- differential driver for legacy_sighash (bitcoin_sighash.S).
 *
 * Reads cases from a file (one per line):
 *   <txhex> <nIn> <schex> <hashtype>
 * For each, calls legacy_sighash() and prints:  ret <0|1> <32-byte-hex>
 * The Python side (fuzz_sighash.py) computes the expected value with its own
 * independent Legacy SignatureHash implementation and compares.
 *
 * 9-arg ABI note: legacy_sighash(out, tx, txlen, nIn, scriptCode, scLen,
 *                 hashtype, preimg, cap). cap is the 9th arg (AAPCS64: on
 *                 the stack). Pass it explicitly and make the preimg buffer
 *                 that large.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int legacy_sighash(uint8_t out[32], const uint8_t* tx, uint64_t txlen,
                          uint64_t nIn, const uint8_t* scriptCode,
                          uint64_t scLen, int32_t hashtype,
                          uint8_t* preimg, uint64_t cap);

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t hex2bin(const char* hx, uint8_t* out, size_t max) {
    size_t n = strlen(hx) / 2;
    if (n > max) n = max;
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(hx[2*i]);
        int lo = hexval(hx[2*i+1]);
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}
static void bin2hex(const uint8_t* b, size_t n, char* out) {
    static const char* hx = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i]   = hx[b[i] >> 4];
        out[2*i+1] = hx[b[i] & 0xf];
    }
    out[2*n] = 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: t_sighash <cases>\n"); return 2; }
    FILE* f = fopen(argv[1], "r");
    if (!f) { perror("open"); return 2; }
    char* line = NULL; size_t cap = 0;
    static uint8_t tx[1<<20], sc[1<<20], out[32], preimg[4 << 20];
    char hashhex[65], txhex[1<<21], schex[1<<21];
    unsigned long long nIn, ht;
    while (1) {
        if (getline(&line, &cap, f) < 0) break;
        if (sscanf(line, "%2097151s %llu %2097151s %llu",
                   txhex, &nIn, schex, &ht) != 4) continue;
        size_t txlen = (txhex[0]=='-') ? 0 : hex2bin(txhex, tx, sizeof tx);
        size_t sclen = (schex[0]=='-') ? 0 : hex2bin(schex, sc, sizeof sc);
        uint64_t cap4 = sizeof preimg;
        int r = legacy_sighash(out, tx, txlen, nIn, sc, sclen,
                               (int32_t)(uint32_t)ht, preimg, cap4);
        bin2hex(out, 32, hashhex);
        printf("%d %s\n", r, hashhex);
    }
    free(line);
    fclose(f);
    return 0;
}
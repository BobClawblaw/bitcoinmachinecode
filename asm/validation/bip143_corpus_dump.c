/* bip143_corpus_dump.c -- print "name<TAB>sighash<TAB>preimage_len" for every
 * vector in a flat corpus file, one per line:
 *
 *     <name> <n_in> <hashtype_dec> <amount> <tx_hex> <scriptcode_hex>
 *
 * Built by validation/diff_bip143_corpus.py against a chosen copy of
 * bitcoin_segwit.c, so two builds can be diffed byte for byte and both can be
 * compared against Bitcoin Core's own SignatureHash. Deliberately dumb: it
 * decodes, calls, prints, and asserts nothing -- the script is the judge.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern long segwit_v0_sighash(uint8_t out32[32], const uint8_t* tx, int64_t txlen,
                              int64_t n_in, uint32_t nHashType, uint64_t amount,
                              const uint8_t* scriptCode, uint64_t scriptcode_len,
                              uint8_t* pre, long cap);

static size_t unhex(const char* h, uint8_t* b){
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++){
        unsigned v; sscanf(h + 2*i, "%2x", &v); b[i] = (uint8_t)v;
    }
    return n;
}

int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr, "usage: %s <corpus>\n", argv[0]); return 2; }
    FILE* f = fopen(argv[1], "r");
    if (!f){ perror("open"); return 1; }
    size_t lcap = 1u<<24;                  /* a 4 MiB transaction in hex + slack */
    char* line = (char*)malloc(lcap);
    char* name = (char*)malloc(4096);
    char* txh  = (char*)malloc(lcap);
    char* sch  = (char*)malloc(1u<<20);
    uint8_t* tx = (uint8_t*)malloc(lcap/2 + 16);
    uint8_t* sc = (uint8_t*)malloc((1u<<19) + 16);
    long precap = 1 << 16;                 /* the real consensus caller's cap */
    uint8_t* pre = (uint8_t*)malloc((size_t)precap);
    while (fgets(line, (int)lcap, f)){
        long long n_in, ht; unsigned long long amt;
        if (sscanf(line, "%4095s %lld %lld %llu %s %s",
                   name, &n_in, &ht, &amt, txh, sch) != 6) continue;
        size_t txlen = unhex(txh, tx);
        size_t sclen = strcmp(sch, "-") ? unhex(sch, sc) : 0;
        uint8_t got[32];
        long n = segwit_v0_sighash(got, tx, (int64_t)txlen, (int64_t)n_in,
                                   (uint32_t)ht, amt, sc, (uint64_t)sclen,
                                   pre, precap);
        printf("%s\t", name);
        if (n > 0) for (int i = 0; i < 32; i++) printf("%02x", got[i]);
        else printf("REFUSED");
        printf("\t%ld\n", n);
    }
    fclose(f);
    return 0;
}

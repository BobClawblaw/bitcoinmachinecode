/* bip341_corpus_dump.c -- print "name<TAB>sighash<TAB>preimage_len" for every
 * vector in a flat corpus file, one per line:
 *
 *   <name> <n_in> <ht_dec> <ext_flag> <codesep_dec> <annex_hex|-> <tapleaf_hex|->
 *   <tx_hex> <num_inputs> <prevouts_hex> <amounts_hex> <spks_hex>
 *
 * <tx_hex> is the WITNESS-STRIPPED serialization, which is what the daemon
 * hands taproot_verify_input (daemon/tx_verify.c calls strip_witness first).
 * <prevouts_hex> is 36*num_inputs bytes, <amounts_hex> 8*num_inputs, and
 * <spks_hex> is one compactsize+scriptPubKey per input, concatenated -- the
 * exact three arrays bitcoin_taproot_sighash.c's tapctx_t takes.
 *
 * Built by validation/diff_bip341_corpus.py against a chosen copy of
 * bitcoin_taproot_sighash.c, so two builds can be diffed byte for byte and
 * both compared against Bitcoin Core's own SignatureHashSchnorr. Deliberately
 * dumb: it decodes, calls, prints, and asserts nothing -- the script judges.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    const uint8_t* tx;   int64_t txlen;
    int64_t  n_in;
    uint8_t  hash_type;
    const uint8_t* prevouts;
    const uint8_t* amounts;
    const uint8_t* spks;
    int64_t  num_inputs;
    int      ext_flag;
    const uint8_t* tapleaf;
    uint32_t codesep_pos;
    const uint8_t* annex;
    uint64_t annexlen;
} tapctx_t;
extern long taproot_sighash(uint8_t* out32, const tapctx_t* c, uint8_t* pre, long cap);

static size_t unhex(const char* h, uint8_t* b){
    if (!strcmp(h, "-")) return 0;
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
    size_t lcap = 1u<<25;                  /* one line holds tx + three arrays */
    char*    line = (char*)malloc(lcap);
    char*    name = (char*)malloc(4096);
    char*    anxh = (char*)malloc(1u<<22);
    char*    leah = (char*)malloc(256);
    char*    txh  = (char*)malloc(lcap);
    char*    poh  = (char*)malloc(lcap);
    char*    amh  = (char*)malloc(lcap);
    char*    sph  = (char*)malloc(lcap);
    uint8_t* anx  = (uint8_t*)malloc((1u<<21) + 16);
    uint8_t* lea  = (uint8_t*)malloc(64);
    uint8_t* tx   = (uint8_t*)malloc(lcap/2 + 16);
    uint8_t* po   = (uint8_t*)malloc(lcap/2 + 16);
    uint8_t* am   = (uint8_t*)malloc(lcap/2 + 16);
    uint8_t* sp   = (uint8_t*)malloc(lcap/2 + 16);
    long precap = 1 << 16;                 /* the real consensus caller's cap */
    uint8_t* pre = (uint8_t*)malloc((size_t)precap);
    while (fgets(line, (int)lcap, f)){
        long long n_in, ht, ext, csp, numin;
        if (sscanf(line, "%4095s %lld %lld %lld %lld %s %s %s %lld %s %s %s",
                   name, &n_in, &ht, &ext, &csp, anxh, leah, txh, &numin,
                   poh, amh, sph) != 12) continue;
        size_t txlen = unhex(txh, tx);
        size_t anxlen = unhex(anxh, anx);
        size_t lealen = unhex(leah, lea);
        unhex(poh, po); unhex(amh, am); unhex(sph, sp);
        tapctx_t c;
        c.tx = tx; c.txlen = (int64_t)txlen;
        c.n_in = (int64_t)n_in; c.hash_type = (uint8_t)ht;
        c.prevouts = po; c.amounts = am; c.spks = sp;
        c.num_inputs = (int64_t)numin;
        c.ext_flag = (int)ext;
        c.tapleaf = lealen ? lea : NULL;
        c.codesep_pos = (uint32_t)csp;
        c.annex = strcmp(anxh, "-") ? anx : NULL;
        c.annexlen = (uint64_t)anxlen;
        uint8_t got[32];
        long n = taproot_sighash(got, &c, pre, precap);
        printf("%s\t", name);
        if (n > 0) for (int i = 0; i < 32; i++) printf("%02x", got[i]);
        else printf("REFUSED");
        printf("\t%ld\n", n);
    }
    fclose(f);
    return 0;
}

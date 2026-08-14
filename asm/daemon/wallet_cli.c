/* daemon/wallet_cli.c -- wallet CLI front-end.
 *
 * Usage:
 *   wallet_cli gen
 *   wallet_cli addr <privkey_hex>
 *   wallet_cli sign <tx_hex> <privkey_hex> <input_idx>
 *
 * Pure wallet commands: no block store needed. All crypto is the repo's
 * verified asm primitives, glued by asm/wallet_core.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* core API from asm/wallet_core.c */
extern void wallet_pubkey(unsigned char pub[33], const unsigned char priv_be[32]);
extern int  wallet_address(char out[64], const unsigned char priv_be[32]);
extern int  wallet_sighash(unsigned char out32[32], const unsigned char* tx,
                           unsigned long txlen, unsigned long input_index,
                           const unsigned char* script, unsigned long script_len);
extern int  wallet_ecdsa_sign(uint64_t out_r[4], uint64_t out_s[4],
                              const unsigned char z_be[32], const unsigned char priv_be[32]);
extern long wallet_sign_tx(unsigned char* out_tx, long cap,
                           const unsigned char* tx, unsigned long txlen,
                           long input_index, const unsigned char priv_be[32]);
extern long wallet_send_tx(unsigned char* out_tx, long cap,
                           const unsigned char toutid[][32], const unsigned long* tidx,
                           const unsigned long long* tval, unsigned long n,
                           const unsigned char to_h160[20],
                           unsigned long long amount, unsigned long long fee,
                           const unsigned char priv_be[32], unsigned long locktime);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);
extern unsigned long long wallet_get_balance(const unsigned long long* tval, unsigned long n);
/* BIP39 mnemonic <-> seed, paired with BIP32 (recoverable wallets). */
extern int  wallet_mnemonic_generate(char out[256]);
extern int  wallet_mnemonic_validate(const char* mn);
extern int  wallet_mnemonic_seed(unsigned char seed[64], const char* mn,
                                 const char* pass, long passlen);
extern int  wallet_seed_master_xprv(char xprv[128], const unsigned char seed[64]);
extern int  wallet_seed_bip44_address(char addr[64], const unsigned char seed[64]);

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
/* parse exactly hexlen hex chars into bytes; returns 1 on ok */
static int hex_to_bytes(unsigned char* out, const char* hex, int hexlen) {
    if ((int)strlen(hex) != hexlen) return 0;
    for (int i = 0; i < hexlen / 2; i++) {
        int hi = hexval(hex[i*2]), lo = hexval(hex[i*2+1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}
static void print_hex(const unsigned char* b, int n) {
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
}

static int cmd_gen(void) {
    unsigned char priv[32];
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f || fread(priv, 1, 32, f) != 32) {
        if (f) fclose(f);
        fprintf(stderr, "gen: cannot read /dev/urandom\n");
        return 1;
    }
    fclose(f);
    unsigned char pub[33]; wallet_pubkey(pub, priv);
    char addr[64]; wallet_address(addr, priv);
    printf("key:  "); print_hex(priv, 32); printf("\n");
    printf("pub:  "); print_hex(pub, 33); printf("\n");
    printf("addr: %s\n", addr);
    return 0;
}

static int cmd_addr(const char* keyhex) {
    unsigned char priv[32];
    if (!hex_to_bytes(priv, keyhex, 64)) { fprintf(stderr, "addr: bad private key hex\n"); return 1; }
    unsigned char pub[33]; wallet_pubkey(pub, priv);
    char addr[64]; wallet_address(addr, priv);
    printf("pub:  "); print_hex(pub, 33); printf("\n");
    printf("addr: %s\n", addr);
    return 0;
}

static int cmd_sign(const char* txhex, const char* keyhex, const char* idxhex) {
    unsigned char priv[32], tx[8192];
    long txlen;
    long input_index = strtol(idxhex, NULL, 10);

    if (!hex_to_bytes(priv, keyhex, 64)) { fprintf(stderr, "sign: bad private key hex\n"); return 1; }
    int hl = (int)strlen(txhex);
    if (hl % 2) { fprintf(stderr, "sign: bad tx hex length\n"); return 1; }
    if (hl / 2 > (int)sizeof tx) { fprintf(stderr, "sign: tx too large\n"); return 1; }
    if (!hex_to_bytes(tx, txhex, hl)) { fprintf(stderr, "sign: bad tx hex\n"); return 1; }
    txlen = hl / 2;

    /* build the P2PKH signing script for the key (same as core does) */
    unsigned char pub[33], h[20], script[25];
    extern void scalar_to_pubkey(unsigned char p[33], const unsigned char k[32]);
    extern void hash160(unsigned char o[20], const void* in, long long len);
    scalar_to_pubkey(pub, priv);
    hash160(h, pub, 33);
    script[0] = 0x76; script[1] = 0xa9; script[2] = 0x14;
    memcpy(script + 3, h, 20); script[23] = 0x88; script[24] = 0xac;

    unsigned char z[32];
    if (!wallet_sighash(z, tx, (unsigned long)txlen, (unsigned long)input_index, script, 25)) {
        fprintf(stderr, "sign: sighash failed\n");
        return 1;
    }
    printf("z:    "); print_hex(z, 32); printf("\n");

    uint64_t r[4], s[4];
    wallet_ecdsa_sign(r, s, z, priv);

    unsigned char signedtx[8192];
    long n = wallet_sign_tx(signedtx, (long)sizeof signedtx, tx, (unsigned long)txlen,
                            input_index, priv);
    if (n < 0) { fprintf(stderr, "sign: failed to assemble signed tx\n"); return 1; }
    printf("signed-tx (%ld bytes):\n", n);
    print_hex(signedtx, (int)n);
    printf("\n");
    return 0;
}

static int cmd_send(int argc, char** argv) {
    /* usage: wallet_cli send <priv_hex> <dest_h160_hex> <amount> <fee> <txid:idx:value> ... */
    if (argc < 7) {
        fprintf(stderr, "usage: wallet_cli send <priv_hex> <dest_h160_hex40> "
                        "<amount_sat> <fee_sat> <txid_hex64:idx:value_sat> [...more inputs]\n");
        return 2;
    }
    unsigned char priv[32];
    if (!hex_to_bytes(priv, argv[2], 64)) { fprintf(stderr, "send: bad private key hex\n"); return 1; }
    unsigned char to_h[20];
    if (!hex_to_bytes(to_h, argv[3], 40)) { fprintf(stderr, "send: bad destination h160\n"); return 1; }
    long long amount = strtoll(argv[4], NULL, 10);
    long long fee    = strtoll(argv[5], NULL, 10);
    if (amount < 0 || fee < 0) { fprintf(stderr, "send: negative amount/fee\n"); return 1; }

    int n = argc - 6;
    unsigned char (*tid)[32] = malloc(n * 32);
    unsigned long*    tidx   = malloc(n * sizeof(unsigned long));
    unsigned long long* tval = malloc(n * sizeof(unsigned long long));
    if (!tid || !tidx || !tval) { free(tid); free(tidx); free(tval); fprintf(stderr, "send: oom\n"); return 1; }
    for (int i = 0; i < n; i++) {
        char* s = argv[6 + i];
        char* c1 = strchr(s, ':');
        if (!c1) { fprintf(stderr, "send: input %d must be <txid>:<idx>:<value>\n", i); return 1; }
        *c1 = 0;
        char* c2 = strchr(c1 + 1, ':');
        if (!c2) { fprintf(stderr, "send: input %d must be <txid>:<idx>:<value>\n", i); return 1; }
        *c2 = 0;
        if (!hex_to_bytes(tid[i], s, 64)) { fprintf(stderr, "send: input %d bad txid hex\n", i); return 1; }
        tidx[i] = (unsigned long)strtoul(c1 + 1, NULL, 10);
        tval[i] = (unsigned long long)strtoull(c2 + 1, NULL, 10);
    }

    unsigned char signedtx[16384];
    long sl = wallet_send_tx(signedtx, (long)sizeof signedtx, tid, tidx, tval,
                             (unsigned long)n, to_h, (unsigned long long)amount,
                             (unsigned long long)fee, priv, 0);
    free(tid); free(tidx); free(tval);
    if (sl < 0) { fprintf(stderr, "send: could not build/sign (underfunded or bad inputs?)\n"); return 1; }
    printf("signed-tx (%ld bytes):\n", sl);
    print_hex(signedtx, (int)sl);
    printf("\n");
    return 0;
}

static int cmd_balance(int argc, char** argv) {
    /* usage: wallet_cli balance <value_sat> ...  -> sum of the wallet's UTXOs */
    if (argc < 3) {
        fprintf(stderr, "usage: wallet_cli balance <utxo_value_sat> [...more]  (sums your unspent prevout values)\n");
        return 2;
    }
    unsigned long long n = (unsigned long)(argc - 2);
    unsigned long long* v = malloc(n * sizeof(unsigned long long));
    if (!v) return 1;
    for (unsigned long i = 0; i < n; i++) v[i] = (unsigned long long)strtoull(argv[2 + i], NULL, 10);
    unsigned long long tot = wallet_get_balance(v, n);
    free(v);
    printf("%llu\n", tot);
    return 0;
}

static int cmd_mnemonic(void) {
    /* produce a fresh recoverable seed: random mnemonic -> seed -> BIP32. */
    char mn[256];
    if (!wallet_mnemonic_generate(mn)) {
        fprintf(stderr, "mnemonic: cannot read /dev/urandom\n");
        return 1;
    }
    unsigned char seed[64];
    wallet_mnemonic_seed(seed, mn, NULL, 0);
    char xprv[128], addr[64];
    wallet_seed_master_xprv(xprv, seed);
    wallet_seed_bip44_address(addr, seed);
    printf("mnemonic: %s\n", mn);
    printf("seed:     "); print_hex(seed, 64); printf("\n");
    printf("xprv:     %s\n", xprv);
    printf("m/44'/0'/0'/0/0: %s\n", addr);
    return 0;
}

static int cmd_seed(int argc, char** argv) {
    /* restore a recoverable seed from a mnemonic (and optional passphrase):
     *   wallet_cli seed "<w0 w1 ... wn>" [passphrase]   (sentence in quotes) */
    if (argc < 3) {
        fprintf(stderr, "usage: wallet_cli seed \"<mnemonic sentence>\" [passphrase]\n");
        return 2;
    }
    const char* mn = argv[2];
    int nw = wallet_mnemonic_validate(mn);
    if (nw <= 0) {
        fprintf(stderr, "seed: invalid mnemonic (bad wordlist entry or checksum)\n");
        return 1;
    }
    const char* pass = (argc >= 4) ? argv[3] : NULL;
    long passlen = pass ? (long)strlen(pass) : 0;
    unsigned char seed[64];
    wallet_mnemonic_seed(seed, mn, pass, passlen);
    char xprv[128], addr[64];
    wallet_seed_master_xprv(xprv, seed);
    wallet_seed_bip44_address(addr, seed);
    printf("words:    %d\n", nw);
    if (pass) printf("passphrase: %s\n", pass);
    printf("seed:     "); print_hex(seed, 64); printf("\n");
    printf("xprv:     %s\n", xprv);
    printf("m/44'/0'/0'/0/0: %s\n", addr);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: wallet_cli <gen|addr|sign|send|balance|mnemonic|seed> [args...]\n");
        return 2;
    }
    if (!strcmp(argv[1], "gen")) return cmd_gen();
    if (!strcmp(argv[1], "mnemonic")) return cmd_mnemonic();
    if (!strcmp(argv[1], "seed")) return cmd_seed(argc, argv);
    if (!strcmp(argv[1], "addr")) {
        if (argc < 3) { fprintf(stderr, "usage: wallet_cli addr <privkey_hex>\n"); return 2; }
        return cmd_addr(argv[2]);
    }
    if (!strcmp(argv[1], "sign")) {
        if (argc < 5) { fprintf(stderr, "usage: wallet_cli sign <tx_hex> <privkey_hex> <input_idx>\n"); return 2; }
        return cmd_sign(argv[2], argv[3], argv[4]);
    }
    if (!strcmp(argv[1], "send")) return cmd_send(argc, argv);
    if (!strcmp(argv[1], "balance")) return cmd_balance(argc, argv);
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}

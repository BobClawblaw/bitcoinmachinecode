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
extern int  wallet_address_net(char out[64], const unsigned char priv_be[32],
                               unsigned pk_version);
extern long wallet_p2wpkh_address_hrp(char* out, long cap, const unsigned char h160[20],
                                      const char* hrp);
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
extern long wallet_derive_p2wpkh_address(char* out, long cap, const unsigned char seed[64], unsigned index);
extern long wallet_derive_p2wpkh_change(char* out, long cap, const unsigned char seed[64], unsigned index);
extern int  wallet_validate_address(const char* str, int* type_, unsigned char* version, unsigned char h160[20], unsigned char prog32[32]);
extern int  wallet_gettxout(void* u, const unsigned char txid[32], unsigned long index,
                            unsigned long long* value, const unsigned char** script,
                            unsigned long* slen, char* addr, long addr_cap);
extern long wallet_listunspent_entry(char* out, long cap,
                                     const unsigned char txid[32], unsigned long index,
                                     unsigned long long value,
                                     const unsigned char* script, unsigned long slen);
extern long wallet_decoderawtx(char* out, long cap, const unsigned char* tx, unsigned long txlen);
extern long wallet_signrawtx_withkeys(unsigned char* out_tx, long cap,
    const unsigned char* tx, unsigned long txlen,
    const unsigned char keys[][32], unsigned long nkeys,
    const unsigned char prevout[][25], unsigned long n_in, unsigned char* signed_mask_out);
extern long wallet_sendtoaddress(unsigned char* out_tx, long cap,
    const unsigned char our_txid[][32], const unsigned long* our_idx,
    const unsigned long long* our_val, unsigned long n_ours,
    const unsigned char to_h160[20],
    unsigned long long amount, unsigned long long fee,
    const unsigned char priv_be[32],
    unsigned long long* out_change, unsigned long* out_picked,
    unsigned long long* out_picked_val);
extern unsigned long long wallet_get_balance(const unsigned long long* tval, unsigned long n);
extern int  wallet_script_to_address(char* out, long cap, const unsigned char* script, long slen);
/* wallet address-type enum mirrors (asm/wallet_core.c) */
#define WAL_ADDR_INVALID 0
#define WAL_ADDR_P2PKH   1
#define WAL_ADDR_P2WPKH  2
#define WAL_ADDR_P2SH    3
#define WAL_ADDR_P2WSH   4
/* BIP39 mnemonic <-> seed, paired with BIP32 (recoverable wallets). */
extern int  wallet_mnemonic_generate(char out[256]);
extern int  wallet_mnemonic_validate(const char* mn);
extern int  wallet_mnemonic_seed(unsigned char seed[64], const char* mn,
                                 const char* pass, long passlen);
extern int  wallet_seed_master_xprv(char xprv[128], const unsigned char seed[64]);
extern int  wallet_seed_bip44_address(char addr[64], const unsigned char seed[64]);

/* persistent wallet store (asm/wallet_store.c) */
extern int  wallet_store_create(const char* path, const char* mnemonic, const char* pass);
extern int  wallet_store_load(const char* path, char* mnemonic_out, int cap,
                              char* pass_out, int pcap);
/* BIP32 path derivation (asm/wallet_core.c) -> private key for signing */
extern int  bip32_derive_path(unsigned char k[32], unsigned char c[32],
                              const unsigned char seed[64], unsigned seedlen,
                              const unsigned indexes[], unsigned n);

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

/* netaddr <privkey_hex>: print regtest/testnet-valid addresses for a key so a
 * regtest node will accept them (0x6f P2PKH, bcrt P2WPKH). Core regtest rejects
 * mainnet-version addresses, so this is required for a real send test. */
static int cmd_netaddr(const char* keyhex) {
    unsigned char priv[32], pub[33], h[20];
    extern void hash160(unsigned char o[20], const void* in, long long len);
    if (!hex_to_bytes(priv, keyhex, 64)) { fprintf(stderr, "netaddr: bad private key hex\n"); return 1; }
    wallet_pubkey(pub, priv);
    hash160(h, pub, 33);   /* declared in wallet_core.h usage; call extern below */
    char p2pkh[64], p2wpkh[96];
    wallet_address_net(p2pkh, priv, 0x6f);          /* testnet/regtest version */
    wallet_p2wpkh_address_hrp(p2wpkh, 96, h, "bcrt"); /* regtest HRP */
    printf("reg_p2pkh : %s\n", p2pkh);
    printf("reg_p2wpkh: %s\n", p2wpkh);
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

static int cmd_getnewaddress(int argc, char** argv, int is_change) {
    /* usage: wallet_cli getnewaddress <seed_hex64> [index]   (P2WPKH receive)
     *        wallet_cli getrawchangeaddress <seed_hex64> [index]   (change) */
    if (argc < 3) {
        fprintf(stderr, "usage: wallet_cli %s <seed_hex64> [index]\n",
                is_change ? "getrawchangeaddress" : "getnewaddress");
        return 2;
    }
    unsigned char seed[64];
    if (!hex_to_bytes(seed, argv[2], 128)) { fprintf(stderr, "bad seed hex\n"); return 1; }
    unsigned index = (argc >= 4) ? (unsigned)strtoul(argv[3], NULL, 10) : 0;
    char out[96];
    long n = is_change ? wallet_derive_p2wpkh_change(out, 96, seed, index)
                       : wallet_derive_p2wpkh_address(out, 96, seed, index);
    if (n < 0) { fprintf(stderr, "derive failed\n"); return 1; }
    printf("%s\n", out);
    return 0;
}

static int cmd_validateaddress(int argc, char** argv, int info) {
    /* usage: wallet_cli validateaddress <addr>   or  getaddressinfo <addr> */
    if (argc < 3) {
        fprintf(stderr, "usage: wallet_cli %s <address>\n", info ? "getaddressinfo" : "validateaddress");
        return 2;
    }
    int type; unsigned char ver, h160[20], prog32[32];
    int ok = wallet_validate_address(argv[2], &type, &ver, h160, prog32);
    const char* tn = (type == 1) ? "p2pkh" : (type == 2) ? "p2wpkh"
                   : (type == 3) ? "p2sh" : (type == 4) ? "p2wsh"
                   : (type == 5) ? "p2tr" : "unknown";
    if (!info) { /* validateaddress: isvalid + type */
        printf("isvalid: %s\n", ok ? "true" : "false");
        if (ok) printf("scriptPubKey-type: %s\n", tn);
        return 0;
    }
    /* getaddressinfo: full detail */
    printf("isvalid: %s\n", ok ? "true" : "false");
    if (ok) {
        printf("type: %s\n", tn);
        printf("version: %d\n", ver);
        printf("hash(hex): ");
        print_hex(h160, 20); printf("\n");
    }
    return 0;
}

/* shared helper: dump value + unspendable script when no address classifies */
static int ck_script_dump(const unsigned char* script, int slen, unsigned long long value) {
    printf("value: %llu\n", value);
    printf("scriptPubKey (hex): ");
    for (int i = 0; i < slen; i++) printf("%02x", script[i]);
    printf("\n");
    printf("address: (unrecognized)\n");
    return 0;
}

static int cmd_gettxout(int argc, char** argv) {
    /* usage: wallet_cli gettxout <txid_hex64> <vout> <value_sat> <script_hex> */
    if (argc < 6) { fprintf(stderr, "usage: wallet_cli gettxout <txid_hex64> <vout> <value> <script_hex>\n"); return 2; }
    unsigned char txid[32];
    if (!hex_to_bytes(txid, argv[2], 64)) { fprintf(stderr, "bad txid hex\n"); return 1; }
    unsigned long vout = strtoul(argv[3], NULL, 10);
    unsigned long long value = strtoull(argv[4], NULL, 10);
    unsigned char script[128];
    int sl = (int)strlen(argv[5]);
    if (sl % 2 || sl / 2 > 128 || !hex_to_bytes(script, argv[5], sl)) { fprintf(stderr, "bad script hex\n"); return 1; }
    char addr[96];
    int t = wallet_script_to_address(addr, 96, script, sl / 2);
    if (t == WAL_ADDR_INVALID) addr[0] = 0;
    unsigned char* u = (unsigned char*)&value; /* gettxout semantics: value+script+address */
    (void)u;
    if (t != WAL_ADDR_INVALID) {
        printf("value: %llu\n", value);
        printf("scriptPubKey: %s\n", argv[5]);
        printf("address: %s\n", addr);
    } else {
        ck_script_dump(script, sl / 2, value);
    }
    return 0;
}

static int cmd_listunspent(int argc, char** argv) {
    /* usage: wallet_cli listunspent <txid:idx:value:script_hex> [...] */
    if (argc < 3) { fprintf(stderr, "usage: wallet_cli listunspent <txid:idx:value:script_hex> [...]\n"); return 2; }
    char line[512];
    for (int i = 2; i < argc; i++) {
        char* s = argv[i];
        char* c1 = strchr(s, ':'); if (!c1) { fprintf(stderr, "bad entry\n"); return 1; } *c1 = 0;
        char* c2 = strchr(c1 + 1, ':'); if (!c2) { fprintf(stderr, "bad entry\n"); return 1; } *c2 = 0;
        char* c3 = strchr(c2 + 1, ':'); if (!c3) { fprintf(stderr, "bad entry\n"); return 1; } *c3 = 0;
        unsigned char txid[32];
        if (!hex_to_bytes(txid, s, 64)) { fprintf(stderr, "bad txid\n"); return 1; }
        unsigned long idx = strtoul(c1 + 1, NULL, 10);
        unsigned long long value = strtoull(c2 + 1, NULL, 10);
        unsigned char script[128];
        int hl = (int)strlen(c3 + 1);
        if (hl % 2 || hl / 2 > 128 || !hex_to_bytes(script, c3 + 1, hl)) { fprintf(stderr, "bad script\n"); return 1; }
        long n = wallet_listunspent_entry(line, 512, txid, idx, value, script, (unsigned long)(hl / 2));
        if (n > 0) printf("%s\n", line);
    }
    return 0;
}

static int cmd_decoderawtx(int argc, char** argv) {
    /* usage: wallet_cli decoderawtransaction <tx_hex> */
    if (argc < 3) { fprintf(stderr, "usage: wallet_cli decoderawtransaction <tx_hex>\n"); return 2; }
    int hl = (int)strlen(argv[2]);
    if (hl % 2 || hl / 2 > 16384) { fprintf(stderr, "bad tx hex\n"); return 1; }
    unsigned char* tx = malloc((size_t)(hl / 2));
    if (!tx) return 1;
    if (!hex_to_bytes(tx, argv[2], hl)) { free(tx); fprintf(stderr, "bad tx hex\n"); return 1; }
    char* dump = malloc(65536);
    if (!dump) { free(tx); return 1; }
    long n = wallet_decoderawtx(dump, 65536, tx, (unsigned long)(hl / 2));
    free(tx);
    if (n < 0) { free(dump); fprintf(stderr, "decoderaw: malformed tx\n"); return 1; }
    printf("%s", dump);
    free(dump);
    return 0;
}

static int cmd_signraw(int argc, char** argv) {
    /* usage: wallet_cli signrawtransactionwithkey <tx_hex> <in>...  where each
     * <in> = <privkey_hex64>:<prevout_p2pkh_script_hex50> (one per input). */
    if (argc < 4) { fprintf(stderr, "usage: wallet_cli signrawtransactionwithkey <tx_hex> <priv:prevout_script_hex50> [<priv:prevout_script_hex50> ...]\n"); return 2; }
    int hl = (int)strlen(argv[2]);
    if (hl % 2 || hl / 2 > 16384) { fprintf(stderr, "bad tx hex\n"); return 1; }
    unsigned char* tx = malloc((size_t)(hl / 2));
    if (!tx) return 1;
    if (!hex_to_bytes(tx, argv[2], hl)) { free(tx); fprintf(stderr, "bad tx hex\n"); return 1; }
    int nin = argc - 3;
    unsigned char (*keys)[32] = malloc(nin * 32);
    unsigned char (*prev)[25] = malloc(nin * 25);
    if (!keys || !prev) { free(tx); free(keys); free(prev); return 1; }
    for (int i = 0; i < nin; i++) {
        char* s = argv[3 + i];
        char* c = strchr(s, ':');
        if (!c) { fprintf(stderr, "entry %d must be <priv>:<prevout_script50>\n", i); return 1; }
        *c = 0;
        if (!hex_to_bytes(keys[i], s, 64)) { fprintf(stderr, "entry %d bad key hex\n", i); return 1; }
        if (!hex_to_bytes(prev[i], c + 1, 50)) { fprintf(stderr, "entry %d bad 25-byte prevout script hex\n", i); return 1; }
    }
    unsigned char* out = malloc(32768);
    if (!out) { free(tx); free(keys); free(prev); return 1; }
    unsigned char mask[32]; memset(mask, 0, sizeof mask);
    long sl = wallet_signrawtx_withkeys(out, 32768, tx, (unsigned long)(hl / 2),
                                        keys, (unsigned long)nin, prev, (unsigned long)nin, mask);
    free(tx); free(keys); free(prev);
    if (sl < 0) { free(out); fprintf(stderr, "signraw: failed\n"); return 1; }
    int n_signed = 0;
    for (int i = 0; i < nin; i++) if (mask[i]) n_signed++;
    printf("complete: %s\n", (n_signed == nin) ? "true" : "false");
    printf("signed-inputs: %d/%d\n", n_signed, nin);
    printf("signed-tx (%ld bytes):\n", sl);
    print_hex(out, (int)sl);
    printf("\n");
    free(out);
    return 0;
}

static int cmd_sendtoaddress(int argc, char** argv) {
    /* usage: wallet_cli sendtoaddress <priv_hex> <dest_h160_hex40> <amount>
     *        <fee> <our_txid:idx:value> ...   (wallet's own UTXOs for selection) */
    if (argc < 8) {
        fprintf(stderr, "usage: wallet_cli sendtoaddress <priv_hex> <dest_h160_hex40> "
                        "<amount_sat> <fee_sat> <our_txid:idx:value> [...more of your UTXOs]\n");
        return 2;
    }
    unsigned char priv[32];
    if (!hex_to_bytes(priv, argv[2], 64)) { fprintf(stderr, "sendtoaddress: bad key hex\n"); return 1; }
    unsigned char to_h[20];
    if (!hex_to_bytes(to_h, argv[3], 40)) { fprintf(stderr, "sendtoaddress: bad dest h160\n"); return 1; }
    long long amount = strtoll(argv[4], NULL, 10);
    long long fee    = strtoll(argv[5], NULL, 10);
    int n = argc - 6;
    unsigned char (*txt)[32] = malloc(n * 32);
    unsigned long* idx = malloc(n * sizeof(unsigned long));
    unsigned long long* val = malloc(n * sizeof(unsigned long long));
    if (!txt || !idx || !val) { free(txt); free(idx); free(val); return 1; }
    for (int i = 0; i < n; i++) {
        char* s = argv[6 + i];
        char* c1 = strchr(s, ':'); if (!c1) { fprintf(stderr, "input %d must be txid:idx:value\n", i); return 1; } *c1 = 0;
        char* c2 = strchr(c1 + 1, ':'); if (!c2) { fprintf(stderr, "input %d must be txid:idx:value\n", i); return 1; } *c2 = 0;
        if (!hex_to_bytes(txt[i], s, 64)) { fprintf(stderr, "input %d bad txid\n", i); return 1; }
        idx[i] = (unsigned long)strtoul(c1 + 1, NULL, 10);
        val[i] = (unsigned long long)strtoull(c2 + 1, NULL, 10);
    }
    unsigned long long bal_before = wallet_get_balance(val, (unsigned long)n);
    unsigned char signedtx[16384];
    unsigned long long change = 0, picked_val = 0; unsigned long picked = 0;
    long sl = wallet_sendtoaddress(signedtx, sizeof signedtx, txt, idx, val, (unsigned long)n,
                                   to_h, (unsigned long long)amount, (unsigned long long)fee,
                                   priv, &change, &picked, &picked_val);
    free(txt); free(idx); free(val);
    if (sl < 0) { fprintf(stderr, "sendtoaddress: insufficient funds (balance %llu, need %lld+fee)\n", bal_before, amount >= 0 ? amount : 0); return 1; }
    printf("balance: %llu\n", bal_before);
    printf("amount: %lld\n", amount);
    printf("fee: %lld\n", fee);
    printf("change: %llu\n", change);
    printf("inputs-used: %lu\n", picked);
    printf("inputs-value: %llu\n", picked_val);
    printf("new-balance: %llu\n", bal_before - (unsigned long long)amount - (unsigned long long)fee);
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

/* Persistent wallet management: store the recoverable mnemonic to disk and
 * derive addresses deterministically. Everything derives from the mnemonic via
 * the verified wallet_core API, so `init` once + `getaddress`/`load` after is a
 * usable persistent wallet for real small-amount sends. */

static int seed_address(const char* mn, const char* pass, char* addr, int cap,
                        unsigned char* seed_out) {
    int nw = wallet_mnemonic_validate(mn);
    if (nw <= 0) return 0;
    unsigned char seed[64];
    long pl = pass ? (long)strlen(pass) : 0;
    wallet_mnemonic_seed(seed, mn, pass, pl);
    if (seed_out) memcpy(seed_out, seed, 64);
    return wallet_seed_bip44_address(addr, seed) ? 1 : 0;
}

static const char* default_wallet_path(void) { return "config/wallet.dat"; }

static int cmd_init(int argc, char** argv) {
    /* create a persistent wallet:
     *   wallet_cli init [passphrase] [path]   (path defaults to config/wallet.dat) */
    const char* pass = (argc >= 3) ? argv[2] : NULL;
    const char* path = (argc >= 4) ? argv[3] : default_wallet_path();
    char mn[256];
    if (!wallet_mnemonic_generate(mn)) {
        fprintf(stderr, "init: cannot read /dev/urandom\n");
        return 1;
    }
    if (wallet_store_create(path, mn, pass)) {
        fprintf(stderr, "init: cannot write %s\n", path);
        return 1;
    }
    char addr[64];
    seed_address(mn, pass, addr, (int)sizeof addr, NULL);
    printf("wallet:   %s\n", path);
    printf("mnemonic: %s\n", mn);
    if (pass) printf("passphrase: %s\n", pass);
    printf("m/44'/0'/0'/0/0: %s\n", addr);
    printf("(recoverable: wallet_cli load %s / getaddress <i> to re-derive)\n", path);
    return 0;
}

static int cmd_load(int argc, char** argv) {
    /* load a persistent wallet:
     *   wallet_cli load [path] [passphrase]   (passphrase required for v2-encrypted wallets) */
    const char* path = (argc >= 3) ? argv[2] : default_wallet_path();
    const char* cli_pass = (argc >= 4) ? argv[3] : getenv("BMC_WALLET_PASS");
    char mn[768], pass[256];
    /* pre-fill the secret as INPUT to load (v2 decrypt), if supplied */
    if (cli_pass && cli_pass[0]) snprintf(pass, sizeof pass, "%s", cli_pass);
    else pass[0] = 0;
    if (wallet_store_load(path, mn, (int)sizeof mn, pass, (int)sizeof pass)) {
        fprintf(stderr, "load: cannot load wallet %s (v2-encrypted? supply the passphrase; or use init)\n", path);
        return 1;
    }
    unsigned char seed[64];
    char addr[64];
    if (!seed_address(mn, pass, addr, (int)sizeof addr, seed)) {
        fprintf(stderr, "load: stored mnemonic invalid\n");
        return 1;
    }
    printf("wallet:  %s\n", path);
    printf("mnemonic: %s\n", mn);
    if (pass[0]) printf("passphrase: (secret, not in file)\n");
    printf("seed:   "); print_hex(seed, 64); printf("\n");
    printf("m/44'/0'/0'/0/0: %s\n", addr);
    return 0;
}

static int cmd_getaddress(int argc, char** argv) {
    /* derive address index i from the persistent wallet:
     *   wallet_cli getaddress [index] [path]   (index default 0) */
    unsigned idx = 0;
    const char* path = default_wallet_path();
    if (argc >= 3) idx = (unsigned)strtoul(argv[2], NULL, 10);
    if (argc >= 4) path = argv[3];
    char mn[768], pass[256];
    {
        const char* sec = getenv("BMC_WALLET_PASS");
        if (sec && sec[0]) snprintf(pass, sizeof pass, "%s", sec); else pass[0] = 0;
    }
    if (wallet_store_load(path, mn, (int)sizeof mn, pass, (int)sizeof pass)) {
        fprintf(stderr, "getaddress: cannot load wallet %s (encrypted? set BMC_WALLET_PASS)\n", path);
        return 1;
    }
    unsigned char seed[64];
    long pl = pass[0] ? (long)strlen(pass) : 0;
    wallet_mnemonic_seed(seed, mn, pass[0] ? pass : NULL, pl);
    char addr[96];
    long n = wallet_derive_p2wpkh_address(addr, 96, seed, idx);
    if (n <= 0) n = wallet_seed_bip44_address(addr, seed), idx = 0;
    printf("%s\n", addr);
    return 0;
}

static int cmd_getprivkey(int argc, char** argv) {
    /* derive the PRIVATE KEY (hex) for address index i of the persistent wallet,
     * for use with send/sendtoaddress/sign:   wallet_cli getprivkey [index] [path] */
    unsigned idx = 0;
    const char* path = default_wallet_path();
    if (argc >= 3) idx = (unsigned)strtoul(argv[2], NULL, 10);
    if (argc >= 4) path = argv[3];
    char mn[768], pass[256];
    {
        const char* sec = getenv("BMC_WALLET_PASS");
        if (sec && sec[0]) snprintf(pass, sizeof pass, "%s", sec); else pass[0] = 0;
    }
    if (wallet_store_load(path, mn, (int)sizeof mn, pass, (int)sizeof pass)) {
        fprintf(stderr, "getprivkey: cannot load wallet %s (encrypted? set BMC_WALLET_PASS)\n", path);
        return 1;
    }
    unsigned char seed[64];
    long pl = pass[0] ? (long)strlen(pass) : 0;
    wallet_mnemonic_seed(seed, mn, pass[0] ? pass : NULL, pl);
    /* BIP44 account 0, external, index idx: m/44'/0'/0'/0/idx */
    unsigned char k[32], c[32];
    unsigned indexes[5] = { 44 | 0x80000000u, 0x80000000u, 0x80000000u, 0, idx };
    if (bip32_derive_path(k, c, seed, 64, indexes, 5) != 1) {
        fprintf(stderr, "getprivkey: derivation failed\n");
        return 1;
    }
    print_hex(k, 32); printf("\n");
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
        fprintf(stderr, "usage: wallet_cli <gen|addr|netaddr|sign|send|sendtoaddress|balance|getnewaddress|getrawchangeaddress|validateaddress|getaddressinfo|gettxout|listunspent|decoderawtransaction|signrawtransactionwithkey|mnemonic|seed|init|load|getaddress|getprivkey> [args...]\n");
        return 2;
    }
    if (!strcmp(argv[1], "gen")) return cmd_gen();
    if (!strcmp(argv[1], "mnemonic")) return cmd_mnemonic();
    if (!strcmp(argv[1], "seed")) return cmd_seed(argc, argv);
    if (!strcmp(argv[1], "init")) return cmd_init(argc, argv);
    if (!strcmp(argv[1], "load")) return cmd_load(argc, argv);
    if (!strcmp(argv[1], "getaddress")) return cmd_getaddress(argc, argv);
    if (!strcmp(argv[1], "getprivkey")) return cmd_getprivkey(argc, argv);
    if (!strcmp(argv[1], "addr")) {
        if (argc < 3) { fprintf(stderr, "usage: wallet_cli addr <privkey_hex>\n"); return 2; }
        return cmd_addr(argv[2]);
    }
    if (!strcmp(argv[1], "netaddr")) {
        if (argc < 3) { fprintf(stderr, "usage: wallet_cli netaddr <privkey_hex>\n"); return 2; }
        return cmd_netaddr(argv[2]);
    }
    if (!strcmp(argv[1], "sign")) {
        if (argc < 5) { fprintf(stderr, "usage: wallet_cli sign <tx_hex> <privkey_hex> <input_idx>\n"); return 2; }
        return cmd_sign(argv[2], argv[3], argv[4]);
    }
    if (!strcmp(argv[1], "send")) return cmd_send(argc, argv);
    if (!strcmp(argv[1], "balance")) return cmd_balance(argc, argv);
    if (!strcmp(argv[1], "getnewaddress")) return cmd_getnewaddress(argc, argv, 0);
    if (!strcmp(argv[1], "getrawchangeaddress")) return cmd_getnewaddress(argc, argv, 1);
    if (!strcmp(argv[1], "validateaddress")) return cmd_validateaddress(argc, argv, 0);
    if (!strcmp(argv[1], "getaddressinfo")) return cmd_validateaddress(argc, argv, 1);
    if (!strcmp(argv[1], "gettxout")) return cmd_gettxout(argc, argv);
    if (!strcmp(argv[1], "listunspent")) return cmd_listunspent(argc, argv);
    if (!strcmp(argv[1], "decoderawtransaction")) return cmd_decoderawtx(argc, argv);
    if (!strcmp(argv[1], "signrawtransactionwithkey")) return cmd_signraw(argc, argv);
    if (!strcmp(argv[1], "sendtoaddress")) return cmd_sendtoaddress(argc, argv);
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}

/* test_wrpc_addr.c -- verify the wallet-core/RPC address surface (card 1):
 *   getnewaddress / getrawchangeaddress  (P2WPKH from a BIP84 seed path)
 *   getaddressinfo / validateaddress      (parse + classify base58check & bech32)
 *   wallet_base58check_decode             (round-trip vs encode + checksum check)
 *
 * Reuses the verified asm crypto via asm/wallet_core.c and bech32.asm.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* wallet core (asm/wallet_core.c) */
extern long wallet_p2wpkh_address(char* out, long cap, const unsigned char h160[20]);
extern long wallet_derive_p2wpkh_address(char* out, long cap, const unsigned char seed[64], unsigned index);
extern long wallet_derive_p2wpkh_change(char* out, long cap, const unsigned char seed[64], unsigned index);
extern int  wallet_validate_address(const char* str, int* type_, unsigned char* version, unsigned char h160[20]);
extern int  wallet_base58check_decode(unsigned char* out, long cap, long* outlen, const char* str);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);
extern int  wallet_address(char out[64], const unsigned char priv_be[32]);
extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);

enum wal_addr_type { WAL_ADDR_INVALID = 0, WAL_ADDR_P2PKH, WAL_ADDR_P2WPKH,
                     WAL_ADDR_P2SH, WAL_ADDR_P2WSH, WAL_ADDR_UNKNOWN };

static int fails = 0;
static void ck(const char* label, int got, int expected) {
    if (got == expected) printf("ok  : %s\n", label);
    else { printf("FAIL: %s (got %d exp %d)\n", label, got, expected); fails++; }
}
static void hex_in(unsigned char* out, const char* h) {
    int n = (int)(strlen(h)) / 2;
    for (int i = 0; i < n; i++) { unsigned int v; sscanf(h + 2*i, "%2x", &v); out[i] = (unsigned char)v; }
}

int main(void) {
    unsigned char ver, h160[20];
    int type;

    /* ---- getaddressinfo / validateaddress on known real addresses ---- */
    /* P2PKH 1BgGZ9tc... h160 = 751e76e8199196d454941c45d1b3a323f1433bd6 */
    ck("valid P2PKH 1BgGZ", wallet_validate_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", &type, &ver, h160), 1);
    ck("  type P2PKH", type, WAL_ADDR_P2PKH);
    ck("  version 0x00", ver, 0x00);
    {
        unsigned char expect[20]; hex_in(expect, "751e76e8199196d454941c45d1b3a323f1433bd6");
        ck("  h160 matches", memcmp(h160, expect, 20) == 0, 1);
    }
    /* P2SH 3J98t1WpEZ... version 5, h160 b472a266d0bd89c13706a4132ccfb16f7c3b9fcb */
    ck("valid P2SH 3J98", wallet_validate_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", &type, &ver, h160), 1);
    ck("  type P2SH", type, WAL_ADDR_P2SH);
    ck("  version 0x05", ver, 0x05);
    {
        unsigned char expect[20]; hex_in(expect, "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
        ck("  h160 matches", memcmp(h160, expect, 20) == 0, 1);
    }
    /* P2WPKH bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4, h160 751e...3bd6 */
    ck("valid P2WPKH bc1qw508", wallet_validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", &type, &ver, h160), 1);
    ck("  type P2WPKH", type, WAL_ADDR_P2WPKH);
    {
        unsigned char expect[20]; hex_in(expect, "751e76e8199196d454941c45d1b3a323f1433bd6");
        ck("  h160 matches", memcmp(h160, expect, 20) == 0, 1);
    }
    /* P2WSH bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3 */
    ck("valid P2WSH bc1qrp33", wallet_validate_address("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", &type, &ver, h160), 1);
    ck("  type P2WSH", type, WAL_ADDR_P2WSH);

    /* ---- invalid handles ---- */
    ck("garbage rejected", wallet_validate_address("notanaddress!!", &type, &ver, h160), 0);
    ck("  type invalid", type, WAL_ADDR_INVALID);
    /* corrupt a checksum byte in a valid P2PKH string */
    {
        char bad[] = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        bad[5] = (bad[5] == 'Z') ? 'Y' : 'Z';
        ck("corrupt checksum rejected", wallet_validate_address(bad, &type, &ver, h160), 0);
    }

    /* ---- base58check round-trip: encode P2PKH payload, decode back ---- */
    {
        unsigned char payload[21]; payload[0] = 0x00;
        hex_in(payload + 1, "751e76e8199196d454941c45d1b3a323f1433bd6");
        char enc[80];
        base58check_encode(enc, payload, 21);
        ck("encode -> 1BgGZ...", strcmp(enc, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") == 0, 1);
        unsigned char back[64]; long blen;
        ck("decode round-trip", wallet_base58check_decode(back, 64, &blen, enc), 1);
        ck("  decoded len 21", blen == 21, 1);
        ck("  decoded payload matches", memcmp(back, payload, 21) == 0, 1);
    }

    /* ---- getnewaddress / getrawchangeaddress (P2WPKH from seed path) ---- */
    {
        /* a fixed 64-byte seed (deterministic test) */
        unsigned char seed[64];
        for (int i = 0; i < 64; i++) seed[i] = (unsigned char)(0x10 + i);
        char recv[96], chg[96], recv2[96];
        long r1 = wallet_derive_p2wpkh_address(recv, 96, seed, 0);
        long r2 = wallet_derive_p2wpkh_change( chg, 96, seed, 0);
        long r3 = wallet_derive_p2wpkh_address(recv2, 96, seed, 1);
        ck("getnewaddress idx0 derived", r1 > 0, 1);
        ck("getrawchangeaddress idx0 derived", r2 > 0, 1);
        ck("getnewaddress idx1 derived", r3 > 0, 1);
        /* each validates as P2WPKH with a 20-byte hash */
        ck("recv[idx0] validates as P2WPKH",
           wallet_validate_address(recv, &type, &ver, h160) == 1 && type == WAL_ADDR_P2WPKH, 1);
        ck("chg[idx0] validates as P2WPKH",
           wallet_validate_address(chg, &type, &ver, h160) == 1 && type == WAL_ADDR_P2WPKH, 1);
        ck("recv[idx1] validates as P2WPKH",
           wallet_validate_address(recv2, &type, &ver, h160) == 1 && type == WAL_ADDR_P2WPKH, 1);
        /* receive(idx0) != change(idx0) != receive(idx1)  (distinct keys) */
        ck("receive idx0 != change idx0", strcmp(recv, chg) != 0, 1);
        ck("receive idx0 != receive idx1", strcmp(recv, recv2) != 0, 1);
        /* the P2WPKH string begins with bc1q */
        ck("prefix bc1q", strncmp(recv, "bc1q", 4) == 0, 1);
        printf("  derived: %s (idx0 receive)\n", recv);
        printf("  derived: %s (idx0 change)\n", chg);
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

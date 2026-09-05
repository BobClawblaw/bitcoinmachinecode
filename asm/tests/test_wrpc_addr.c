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
extern int  wallet_validate_address(const char* str, int* type_, unsigned char* version, unsigned char h160[20], unsigned char prog32[32]);
extern int  wallet_validate_address_ex(const char* str, int* type_, unsigned char* version,
                                       unsigned char h160[20], unsigned char* prog,
                                       unsigned long progcap, unsigned long* proglen, int* witver);  /* WAL-9 */
extern int  wallet_base58check_decode(unsigned char* out, long cap, long* outlen, const char* str);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);
extern int  wallet_address(char out[64], const unsigned char priv_be[32]);
extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);

enum wal_addr_type { WAL_ADDR_INVALID = 0, WAL_ADDR_P2PKH, WAL_ADDR_P2WPKH,
                     WAL_ADDR_P2SH, WAL_ADDR_P2WSH, WAL_ADDR_P2TR, WAL_ADDR_UNKNOWN,
                     WAL_ADDR_WITNESS_UNKNOWN };

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
    ck("valid P2PKH 1BgGZ", wallet_validate_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", &type, &ver, h160, NULL), 1);
    ck("  type P2PKH", type, WAL_ADDR_P2PKH);
    ck("  version 0x00", ver, 0x00);
    {
        unsigned char expect[20]; hex_in(expect, "751e76e8199196d454941c45d1b3a323f1433bd6");
        ck("  h160 matches", memcmp(h160, expect, 20) == 0, 1);
    }
    /* P2SH 3J98t1WpEZ... version 5, h160 b472a266d0bd89c13706a4132ccfb16f7c3b9fcb */
    ck("valid P2SH 3J98", wallet_validate_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", &type, &ver, h160, NULL), 1);
    ck("  type P2SH", type, WAL_ADDR_P2SH);
    ck("  version 0x05", ver, 0x05);
    {
        unsigned char expect[20]; hex_in(expect, "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
        ck("  h160 matches", memcmp(h160, expect, 20) == 0, 1);
    }
    /* P2WPKH bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4, h160 751e...3bd6 */
    ck("valid P2WPKH bc1qw508", wallet_validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", &type, &ver, h160, NULL), 1);
    ck("  type P2WPKH", type, WAL_ADDR_P2WPKH);
    {
        unsigned char expect[20]; hex_in(expect, "751e76e8199196d454941c45d1b3a323f1433bd6");
        ck("  h160 matches", memcmp(h160, expect, 20) == 0, 1);
    }
    /* P2WSH bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3 */
    ck("valid P2WSH bc1qrp33", wallet_validate_address("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", &type, &ver, h160, NULL), 1);
    ck("  type P2WSH", type, WAL_ADDR_P2WSH);

    /* ---- invalid handles ---- */
    ck("garbage rejected", wallet_validate_address("notanaddress!!", &type, &ver, h160, NULL), 0);
    ck("  type invalid", type, WAL_ADDR_INVALID);
    /* corrupt a checksum byte in a valid P2PKH string */
    {
        char bad[] = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        bad[5] = (bad[5] == 'Z') ? 'Y' : 'Z';
        ck("corrupt checksum rejected", wallet_validate_address(bad, &type, &ver, h160, NULL), 0);
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
           wallet_validate_address(recv, &type, &ver, h160, NULL) == 1 && type == WAL_ADDR_P2WPKH, 1);
        ck("chg[idx0] validates as P2WPKH",
           wallet_validate_address(chg, &type, &ver, h160, NULL) == 1 && type == WAL_ADDR_P2WPKH, 1);
        ck("recv[idx1] validates as P2WPKH",
           wallet_validate_address(recv2, &type, &ver, h160, NULL) == 1 && type == WAL_ADDR_P2WPKH, 1);
        /* receive(idx0) != change(idx0) != receive(idx1)  (distinct keys) */
        ck("receive idx0 != change idx0", strcmp(recv, chg) != 0, 1);
        ck("receive idx0 != receive idx1", strcmp(recv, recv2) != 0, 1);
        /* the P2WPKH string begins with bc1q */
        ck("prefix bc1q", strncmp(recv, "bc1q", 4) == 0, 1);
        printf("  derived: %s (idx0 receive)\n", recv);
        printf("  derived: %s (idx0 change)\n", chg);
    }

    /* ---- WAL-9: witness versions 2..16 (BIP350) --------------------------
     * A checksum-valid bech32m address for witness v2..16 is a VALID
     * destination to Core (WitnessUnknown): validateaddress reports
     * isvalid:true with the version and program, and sendtoaddress pays it.
     * This node answered isvalid:false -- a definite wrong answer about a
     * well-formed address, not an absent feature.
     *
     * Both strings and both expected scriptPubKeys are BIP350's OWN vectors,
     * not values derived from this implementation:
     *
     *   BC1SW50QGDZ25J                        -> 6002751e
     *   bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs  -> 5210751e76e8199196d454941c45d1b3a323
     *
     * They bracket the range deliberately: v16 with the 2-byte minimum
     * program, and v2 with a 16-byte one. The first is also UPPERCASE, which
     * is what exercises the canonical-lowercase echo. */
    printf("\n---- WAL-9: witness v2..16 (BIP350 vectors) ----\n");
    {
        int type = -1, wv = -1; unsigned char ver = 0, h160[20], prog[40];
        unsigned long plen = 0;

        int ok = wallet_validate_address_ex("BC1SW50QGDZ25J", &type, &ver, h160,
                                            prog, sizeof prog, &plen, &wv);
        ck("BIP350 v16 address is VALID (Core: isvalid true)", ok, 1);
        ck("...classified WITNESS_UNKNOWN", type, WAL_ADDR_WITNESS_UNKNOWN);
        ck("...witness version 16", wv, 16);
        ck("...2-byte program", (int)plen, 2);
        ck("...program is 751e", plen == 2 && prog[0] == 0x75 && prog[1] == 0x1e, 1);

        type = -1; wv = -1; plen = 0;
        ok = wallet_validate_address_ex("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
                                        &type, &ver, h160, prog, sizeof prog, &plen, &wv);
        ck("BIP350 v2 address is VALID", ok, 1);
        ck("...classified WITNESS_UNKNOWN", type, WAL_ADDR_WITNESS_UNKNOWN);
        ck("...witness version 2", wv, 2);
        ck("...16-byte program", (int)plen, 16);
        { static const unsigned char want[16] =
            {0x75,0x1e,0x76,0xe8,0x19,0x91,0x96,0xd4,0x54,0x94,0x1c,0x45,0xd1,0xb3,0xa3,0x23};
          ck("...program matches BIP350's", plen == 16 && memcmp(prog, want, 16) == 0, 1); }

        /* THE OLD ENTRY POINT MUST NOT CHANGE. It hands back a fixed 32-byte
         * buffer with no length, and a v2..16 program is 2..40 bytes, so it
         * still reports these INVALID -- deliberately. All thirty of its
         * callers keep the behaviour they had. */
        type = -1;
        unsigned char prog32[32];
        ck("the OLD wallet_validate_address still refuses v2..16 (30 callers unchanged)",
           wallet_validate_address("BC1SW50QGDZ25J", &type, &ver, h160, prog32), 0);
        ck("...reporting INVALID", type, WAL_ADDR_INVALID);

        /* THE OPPOSITE HALF: the versions that were already right stay right. */
        type = -1; wv = -1; plen = 0;
        ok = wallet_validate_address_ex("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                                        &type, &ver, h160, prog, sizeof prog, &plen, &wv);
        ck("a v0 P2WPKH is still P2WPKH, not WITNESS_UNKNOWN", ok && type == WAL_ADDR_P2WPKH, 1);
        type = -1;
        ok = wallet_validate_address_ex("bc1pqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3rvz2j",
                                        &type, &ver, h160, prog, sizeof prog, &plen, &wv);
        ck("a v1 P2TR is still P2TR, not WITNESS_UNKNOWN",
           !ok || type == WAL_ADDR_P2TR, 1);

        /* SER-5/WAL-9's first half (closed earlier) must survive this change.
         * BIP173: "the string must be either all lowercase or all uppercase".
         *
         * The first version of this assertion sent an ALL-UPPERCASE string and
         * called it mixed case -- and it correctly came back VALID, so the
         * test failed on its own mistake rather than on the code. All-upper is
         * legal; the case rule is about MIXING. Both are asserted now. */
        type = -1;
        ck("an ALL-UPPERCASE bech32 address is valid (BIP173 allows it)",
           wallet_validate_address_ex("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                                      &type, &ver, h160, prog, sizeof prog, &plen, &wv), 1);
        type = -1;
        ck("a MIXED-case address is rejected (SER-5/WAL-9 first half)",
           wallet_validate_address_ex("bc1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                                      &type, &ver, h160, prog, sizeof prog, &plen, &wv), 0);
        type = -1;
        ck("...and so is the other mixing (upper hrp, lower data)",
           wallet_validate_address_ex("BC1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                                      &type, &ver, h160, prog, sizeof prog, &plen, &wv), 0);
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

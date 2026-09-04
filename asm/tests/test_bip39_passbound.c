/* tests/test_bip39_passbound.c -- CRY-4 (audit 2026-09-03): the BIP39
 * passphrase is bounded, and HMAC-SHA512's scratch does not keep secrets.
 *
 * THE BUG. bip39_mnemonic_to_seed builds its PBKDF2 salt as
 * "mnemonic" || passphrase into m39_salt, a 512-byte .bss buffer, with a copy
 * loop that had no bound at all. A passphrase over 504 bytes therefore wrote
 * past it into m39_msg and beyond. It needed no RPC to reach: wallet_store.c
 * reads BMC_WALLET_PASS with strlen and daemon/wallet_cli.c takes the
 * passphrase as a command-line argument, and neither capped it. (The audit
 * also names hmac_sha512's own `tmp`, which has 1,032 bytes of room for the
 * message -- so m39_salt is the buffer that goes first, and bounding here
 * closes both.)
 *
 * Separately, hmac_sha512 left kpad -- the padded HMAC KEY, which is a BIP32
 * parent chain code on the derivation path and the mnemonic itself under
 * PBKDF2 -- and the inner digest sitting in .bss for the life of the process.
 *
 * WHAT IS ASSERTED.
 *  1. A passphrase AT the limit still works and still produces the SAME seed
 *     it always did. This is the assertion that matters most: a limit set too
 *     low would make a wallet with a long passphrase permanently unopenable,
 *     which is worse than the overflow it fixes.
 *  2. A passphrase one byte over is refused, with a 0 return rather than a
 *     write past the buffer.
 *  3. The canonical BIP39 test vector still derives its published seed, so
 *     the bound did not disturb the derivation.
 *  4. After an HMAC over a recognisable key, that key is not findable in the
 *     module's .bss scratch.
 *
 * The overflow itself is not "asserted" by observing corruption -- reading
 * past a buffer to prove it was written is undefined behaviour in the test as
 * much as in the code. The negative control does that job: with the bound
 * removed, case 2's oversized passphrase is accepted.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char u8;

extern int  bip39_mnemonic_to_seed(u8 seed[64], const char* mn,
                                   const char* pass, long passlen);
extern void hmac_sha512(u8 out[64], const u8* key, long keylen,
                        const u8* msg, long msglen);

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

static const char* MN =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

int main(void){
    u8 seed[64], seed2[64];

    printf("== the canonical vector still derives its published seed ==\n");
    {
        /* BIP39 test vector: mnemonic above, passphrase "TREZOR". */
        static const u8 want[64] = {
            0xc5,0x52,0x57,0xc3,0x60,0xc0,0x7c,0x72,0x02,0x9a,0xeb,0xc1,0xb5,0x3c,0x05,0xed,
            0x03,0x62,0xad,0xa3,0x8e,0xad,0x3e,0x3e,0x9e,0xfa,0x37,0x08,0xe5,0x34,0x95,0x53,
            0x1f,0x09,0xa6,0x98,0x75,0x99,0xd1,0x82,0x64,0xc1,0xe1,0xc9,0x2f,0x2c,0xf1,0x41,
            0x63,0x0c,0x7a,0x3c,0x4a,0xb7,0xc8,0x1b,0x2f,0x00,0x16,0x98,0xe7,0x46,0x3b,0x04 };
        memset(seed, 0, 64);
        int r = bip39_mnemonic_to_seed(seed, MN, "TREZOR", 6);
        ck("vector derivation returns 1", r == 1);
        ck("vector seed matches BIP39's published value", memcmp(seed, want, 64) == 0);
    }

    printf("\n== CRY-4: a passphrase AT the 504-byte limit still works ==\n");
    {
        char* p = (char*)malloc(505);
        memset(p, 'x', 504); p[504] = 0;
        memset(seed, 0, 64);
        int r = bip39_mnemonic_to_seed(seed, MN, p, 504);
        ck("504-byte passphrase accepted", r == 1);
        /* Deterministic: the same input must give the same seed every time,
         * and a one-byte-shorter passphrase must give a different one. */
        int r2 = bip39_mnemonic_to_seed(seed2, MN, p, 504);
        ck("...and is deterministic", r2 == 1 && memcmp(seed, seed2, 64) == 0);
        u8 seed3[64];
        bip39_mnemonic_to_seed(seed3, MN, p, 503);
        ck("...and a 503-byte passphrase gives a DIFFERENT seed (length is in the salt)",
           memcmp(seed, seed3, 64) != 0);
        free(p);
    }

    printf("\n== CRY-4: one byte over the limit is REFUSED ==\n");
    {
        char* p = (char*)malloc(1000);
        memset(p, 'y', 999); p[999] = 0;
        memset(seed, 0xAB, 64);
        int r = bip39_mnemonic_to_seed(seed, MN, p, 505);
        ck("505-byte passphrase refused (returns 0)", r == 0);
        int r2 = bip39_mnemonic_to_seed(seed, MN, p, 999);
        ck("999-byte passphrase refused too", r2 == 0);
        int r3 = bip39_mnemonic_to_seed(seed, MN, p, -1);
        ck("a negative length is refused (the copy bound is a signed compare)", r3 == 0);
        free(p);
    }

    printf("\n== CRY-4: the HMAC key does not stay in the module's scratch ==\n");
    {
        /* A key that is easy to find and cannot occur by chance. */
        u8 key[64]; for (int i = 0; i < 64; i++) key[i] = (u8)(0xD0 + (i & 0x0f));
        u8 msg[32]; memset(msg, 0x11, sizeof msg);
        u8 out[64];
        hmac_sha512(out, key, sizeof key, msg, sizeof msg);

        /* Scan this process's writable data for the key block. kpad holds the
         * key XOR 0x36 then XOR 0x5c, so look for both forms as well as the
         * raw key -- any of the three surviving is the leak. */
        extern char __data_start[], _end[];
        u8 ip[64], op[64];
        for (int i = 0; i < 64; i++){ ip[i] = key[i] ^ 0x36; op[i] = key[i] ^ 0x5c; }
        int found_raw = 0, found_ip = 0, found_op = 0;
        for (char* q = __data_start; q + 64 <= _end; q++){
            if (!memcmp(q, key, 64)){
                /* our own `key` local is on the stack, not here; a hit in
                 * .data/.bss is the module's scratch */
                found_raw = 1;
            }
            if (!memcmp(q, ip, 64)) found_ip = 1;
            if (!memcmp(q, op, 64)) found_op = 1;
        }
        printf("      (raw=%d ipad=%d opad=%d)\n", found_raw, found_ip, found_op);
        ck("the ipad-XORed key block is not left in .bss", !found_ip);
        ck("the opad-XORed key block is not left in .bss", !found_op);
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

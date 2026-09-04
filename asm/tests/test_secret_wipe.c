/* tests/test_secret_wipe.c -- WAL-3 (audit 2026-09-03): a locked wallet must
 * not still be holding its secrets.
 *
 * THE BUG. `walletlock` (and timer expiry) zeroed g_seed and g_wallet_seed,
 * which gave the appearance of Core's locked state. Three things were left
 * behind anyway:
 *
 *   (a) bip39_mnemonic_to_seed leaves the 64-byte seed in m39_acc -- the
 *       PBKDF2 accumulator IS the seed, and the copy to the caller left the
 *       original in .bss -- plus PBKDF2 intermediates in m39_prev/m39_cur and
 *       the BIP39 passphrase in m39_salt/m39_msg.
 *   (b) wcrypt_derive keeps `pass || salt` in a STATIC 128-byte scratch, so
 *       the wallet passphrase stayed resident after every KDF call.
 *   (c) main.c held the mnemonic and its BIP39 passphrase in statics for the
 *       life of the process, even after encryptwallet had sealed them and
 *       unlinked the plaintext store -- so the provider went on serving them.
 *
 * And every wipe in the tree was a plain memset on a buffer that is dead
 * afterwards, which -O2 may legally delete. secure_zero (daemon/secure_zero.h)
 * adds the compiler barrier that makes the store observable, the same
 * mechanism as Core's memory_cleanse.
 *
 * HOW THIS IS TESTED. The module scratch under test lives in .bss, so after
 * exercising each routine with a recognisable secret this scans the process's
 * own writable data segment for that secret. A hit is the leak. The test's own
 * copies live on the stack and on the heap, which the scan does not cover.
 *
 * WHAT IS NOT TESTED HERE: swap, hibernation and core dumps. Those need mlock
 * and MADV_DONTDUMP, which are not done and remain open under WAL-3.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char u8;

extern int  bip39_mnemonic_to_seed(u8 seed[64], const char* mn,
                                   const char* pass, long passlen);
extern void wcrypt_derive(const char* pass, long passlen, const u8 salt[8],
                          unsigned iters, u8 key[32], u8 iv[16]);

extern char __data_start[], _end[];

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

/* Is `needle` present anywhere in this process's writable data segment? */
static int in_static_data(const void* needle, size_t n){
    for (char* q = __data_start; q + (long)n <= _end; q++)
        if (!memcmp(q, needle, n)) return 1;
    return 0;
}

static const char* MN =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

int main(void){
    printf("== WAL-3 (a): the BIP39 seed and passphrase do not stay in .bss ==\n");
    {
        /* A passphrase that cannot occur by chance in any other buffer. */
        static const char PASS[] = "WAL3-PASSPHRASE-b7f2c19d-do-not-retain";
        u8* seed = (u8*)malloc(64);          /* heap, outside the scanned range */
        int r = bip39_mnemonic_to_seed(seed, MN, PASS, (long)strlen(PASS));
        ck("derivation succeeded", r == 1);

        ck("the derived SEED is not left in .bss (m39_acc)",
           !in_static_data(seed, 64));
        ck("the BIP39 passphrase is not left in .bss (m39_salt / m39_msg)",
           !in_static_data(PASS, strlen(PASS)));
        /* The salt is "mnemonic" || passphrase; check the joined form too,
         * since a partial wipe could leave that and not the bare passphrase. */
        {
            char joined[128];
            int jn = snprintf(joined, sizeof joined, "mnemonic%s", PASS);
            ck("...nor the \"mnemonic\"||passphrase salt it was built into",
               !in_static_data(joined, (size_t)jn));
        }
        free(seed);
    }

    printf("\n== WAL-3 (b): the wallet passphrase does not stay in the KDF scratch ==\n");
    {
        static const char WPASS[] = "WAL3-WALLETPASS-4e81aa06-do-not-retain";
        u8 salt[8]; for (int i=0;i<8;i++) salt[i] = (u8)(0xE0 + i);
        u8* key = (u8*)malloc(32); u8* iv = (u8*)malloc(16);
        /* One iteration: this is about residue, not about the KDF's cost. */
        wcrypt_derive(WPASS, (long)strlen(WPASS), salt, 1, key, iv);
        ck("the wallet passphrase is not left in wcrypt_derive's static scratch",
           !in_static_data(WPASS, strlen(WPASS)));
        ck("...nor is the derived key",
           !in_static_data(key, 32));
        free(key); free(iv);
    }

    printf("\n== control: the scan CAN find something that is really there ==\n");
    {
        /* Without this, every assertion above would pass on a scan that simply
         * never matches anything -- the failure mode that makes a
         * memory-residue test worthless. */
        static char planted[64] = "WAL3-CONTROL-PLANTED-cafe1234";
        ck("a deliberately planted string IS found in .bss",
           in_static_data(planted, strlen(planted)));
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

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

/* CRY-3 (audit 2026-10-23): stack residue. */
#include <stdint.h>
extern long wcrypt_seal(const char* pass, long passlen, const u8* seed, long seedlen, u8* out, long cap);
extern long wcrypt_open(const char* pass, long passlen, const u8* blob, long len, u8* seed_out, long cap);
extern long aes256_cbc_decrypt(const u8 key[32], const u8 iv[16], const u8* in, long inlen, u8* out, long cap);
extern long aes256_cbc_encrypt(const u8 key[32], const u8 iv[16], const u8* in, long inlen, u8* out, long cap);
extern int  wallet_ecdsa_sign(uint64_t out_r[4], uint64_t out_s[4], const u8 z_be[32], const u8 priv_be[32]);
extern int  bip340_sign(u8 sig[64], const u8* msg, unsigned long msglen, const u8 priv_be[32], const u8 aux[32]);
extern void sha256d(u8 out[32], const void* msg, long len);

/* The dead stack below a caller's frame is where its callees' locals were.
 * run_then_snap runs the routine under test, then -- with an open-coded loop,
 * so no call of its own lands on the frames being read -- copies the
 * STACK_SCAN bytes below its stack pointer into a heap snapshot. The
 * secrets are computed afterwards (some, like a sealed container's KEK, can
 * only be derived once the call has returned) and searched for in the
 * snapshot. stack_pregrow touches the region first, so the pages exist. */
#define STACK_SCAN (96 * 1024)
static __attribute__((noinline)) void stack_pregrow(void){
    volatile char pad[STACK_SCAN + 8192];
    for (size_t i = 0; i < sizeof pad; i += 64) pad[i] = 0;
}
static u8* g_snap;
static __attribute__((noinline)) void run_then_snap(int which, void* a, void* b, void* c, void* d){
    switch (which){
    case 0: wcrypt_seal((const char*)a, (long)strlen((const char*)a), (const u8*)b, 32, (u8*)c, 4096); break;
    case 1: wcrypt_open((const char*)a, (long)strlen((const char*)a), (const u8*)b, (long)(intptr_t)d, (u8*)c, 64); break;
    case 2: { static uint64_t r[4], s_[4]; wallet_ecdsa_sign(r, s_, (const u8*)a, (const u8*)b); break; }
    case 3: bip340_sign((u8*)c, (const u8*)a, 32, (const u8*)b, (const u8*)d); break;
    case 4: aes256_cbc_encrypt((const u8*)a, (const u8*)b, (const u8*)d, 32, (u8*)c, 64); break;
    case 5: { /* control: a callee that leaves a secret behind */
        extern void plant_in_dead_frame(const u8* secret);
        plant_in_dead_frame((const u8*)a); break; }
    }
    const volatile u8* hi; __asm__ volatile("mov %%rsp, %0" : "=r"(hi));
    const volatile u8* lo = hi - STACK_SCAN;
    for (size_t i = 0; i < STACK_SCAN; i++) g_snap[i] = lo[i];
}
static int snap_has(const void* needle, size_t n){
    for (size_t i = 0; i + n <= STACK_SCAN; i++)
        if (!memcmp(g_snap + i, needle, n)) return 1;
    return 0;
}
/* the control's callee: copies a secret into a local and returns, wiping
 * nothing -- what every routine above did before CRY-3 */
__attribute__((noinline)) void plant_in_dead_frame(const u8* secret){
    volatile u8 local[32];
    for (int i = 0; i < 32; i++) local[i] = secret[i];
    __asm__ volatile("" : : "r"(local) : "memory");
}


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

    printf("\n== CRY-3: no key material left in dead stack frames ==\n");
    {
        g_snap = malloc(STACK_SCAN);
        stack_pregrow();
        static const char PW[] = "CRY3-PASS-5c0f";
        u8* seed = malloc(64); u8* blob = malloc(4096); u8* out = malloc(64);
        u8* kek = malloc(32); u8* iv = malloc(16); u8* mk = malloc(64);
        for (int i = 0; i < 32; i++) seed[i] = (u8)(0x90 + i);

        /* the seal; then recompute its KEK from the stored salt and unwrap
         * its master key, and look for both in what the seal left behind */
        run_then_snap(0, (void*)PW, seed, blob, NULL);
        wcrypt_derive(PW, (long)strlen(PW), blob + 8, 100000, kek, iv);
        unsigned short wl; memcpy(&wl, blob + 20, 2);
        long mkl = aes256_cbc_decrypt(kek, iv, blob + 22, wl, mk, 64);
        ck("CRY-3 the sealed container's master key unwraps (setup)", mkl == 32);
        ck("CRY-3 wcrypt_seal leaves no KEK on the stack", !snap_has(kek, 32));
        ck("CRY-3 wcrypt_seal leaves no master key on the stack", !snap_has(mk, 32));

        /* the open of the same container */
        long bl = 8 + 8 + 4 + 2 + wl + 16 + 4 + 48 + 32;   /* 32-byte seed -> 48 bytes of CBC */
        run_then_snap(1, (void*)PW, blob, out, (void*)(intptr_t)bl);
        ck("CRY-3 wcrypt_open opened it (the snapshot follows real work)", !memcmp(out, seed, 32));
        ck("CRY-3 wcrypt_open leaves no KEK on the stack", !snap_has(kek, 32));
        ck("CRY-3 wcrypt_open leaves no master key on the stack", !snap_has(mk, 32));

        /* AES alone: the expanded key starts with the key itself */
        u8* akey = malloc(32); u8* aiv = malloc(16); u8* apt = malloc(32); u8* act = malloc(64);
        for (int i = 0; i < 32; i++){ akey[i] = (u8)(0x5a ^ (i * 29)); apt[i] = (u8)i; }
        memset(aiv, 0x11, 16);
        run_then_snap(4, akey, aiv, act, apt);
        ck("CRY-3 aes256_cbc_encrypt leaves no round keys on the stack", !snap_has(akey, 32));

        /* ECDSA: the private key (in the nonce preimage) and the nonce */
        u8* priv = malloc(32); u8* z = malloc(32); u8* pre = malloc(64); u8* nonce = malloc(32);
        for (int i = 0; i < 32; i++){ priv[i] = (u8)(0x21 + 3 * i); z[i] = (u8)(0xc4 ^ i); }
        memcpy(pre, z, 32); memcpy(pre + 32, priv, 32); sha256d(nonce, pre, 64);
        run_then_snap(2, z, priv, NULL, NULL);
        ck("CRY-3 wallet_ecdsa_sign leaves no private key on the stack", !snap_has(priv, 32));
        ck("CRY-3 wallet_ecdsa_sign leaves no nonce on the stack", !snap_has(nonce, 32));

        /* BIP340: the key as little-endian limbs (d0) */
        u8* sig = malloc(64); u8* aux = malloc(32); memset(aux, 0, 32);
        uint64_t* limbs = malloc(32);
        for (int i = 0; i < 4; i++){ limbs[i] = 0; for (int j = 0; j < 8; j++) limbs[i] |= (uint64_t)priv[31 - (i * 8 + j)] << (8 * j); }
        run_then_snap(3, z, priv, sig, aux);
        ck("CRY-3 bip340_sign leaves no private key limbs on the stack", !snap_has(limbs, 32));

        /* control: the snapshot DOES see a secret a callee left behind --
         * without it every check above would pass on a scan that never
         * matches */
        u8* planted = malloc(32); for (int i = 0; i < 32; i++) planted[i] = (u8)(0xe1 ^ (i * 7));
        run_then_snap(5, planted, NULL, NULL, NULL);
        ck("CRY-3 control: a secret left in a dead frame IS found", snap_has(planted, 32));

        free(seed); free(blob); free(out); free(kek); free(iv); free(mk);
        free(akey); free(aiv); free(apt); free(act); free(priv); free(z); free(pre); free(nonce);
        free(sig); free(aux); free(limbs); free(planted); free(g_snap);
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

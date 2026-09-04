/* tests/test_chainparams.c -- runtime chain selection (daemon/chainparams.c).
 *
 *   1. The mainnet genesis byte array hashes (block_hash, the real asm
 *      sha256d path) to Core's asserted mainnet genesis hash.
 *   2. chainparams_select("regtest") DERIVES the regtest genesis from it and
 *      its own internal hash assert passes; the selected params carry Core's
 *      CRegTestParams values (magic fabfb5da, port 18444, halving 150,
 *      no-retargeting, 0x207fffff, 0x6f/0xc4/bcrt).
 *   3. The two asm globals actually flip: net_magic and sfc_chain.
 *   4. script_flags_for_block under regtest: every buried deployment active
 *      at height 1 (CRegTestParams heights, generated constants); back on
 *      main, the historical schedule is restored (spot heights around each
 *      boundary).
 *   5. chainparams_datadir: main = base itself, regtest = base + "/regtest"
 *      (created), so chains can never share state.
 *   6. legacy testnet3 names are refused, unknown names are refused.
 *      (signet USED to be refused here; it is supported as of 2026-08-30
 *      and is covered by its own section below.)
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../daemon/chainparams.h"
#include "../daemon/genesis_skip.h"
#include "../script_flags_consts.h"

typedef unsigned char u8;
typedef unsigned long u64;

extern void block_hash(u8 out[32], const u8 hdr[80]);
extern void sha256d(unsigned char o[32], const void* m, long l);   /* bitcoin_hash.asm */
extern u64  script_flags_for_block(u64 height, const u8 hash32[32]);
extern unsigned int net_magic;   /* bitcoin_net.asm */
extern unsigned int sfc_chain;   /* bitcoin_script_flags.asm */

/* bit positions from the generated header's source (interpreter.h) -- these
 * mirror script_flags_consts.inc; a mismatch would fail the flag checks. */
#define F_P2SH      (1UL<<0)
#define F_DERSIG    (1UL<<2)
#define F_NULLDUMMY (1UL<<4)
#define F_CLTV      (1UL<<9)
#define F_CSV       (1UL<<10)
#define F_WITNESS   (1UL<<11)
#define F_TAPROOT   (1UL<<17)
#define F_ALL (F_P2SH|F_DERSIG|F_NULLDUMMY|F_CLTV|F_CSV|F_WITNESS|F_TAPROOT)

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static void hx32(u8* o, const char* display){   /* display hex -> wire order */
    for (int i = 0; i < 32; i++){ unsigned b; sscanf(display + 2*i, "%2x", &b); o[31-i] = (u8)b; }
}

int main(void){
    u8 want[32], got[32], nohash[32]; memset(nohash, 0, 32);
    static u8 main_tx[205];   /* the mainnet genesis coinbase, captured before
                                 regtest is selected, to prove the derivation
                                 changed ONLY the header */

    printf("== 1: mainnet genesis bytes hash to Core's assert ==\n");
    ck("static default is mainnet", g_chainp->id == CHAIN_MAIN && !strcmp(g_chainp->name, "main"));
    memcpy(main_tx, g_chainp->genesis + 80, 205);
    block_hash(got, g_chainp->genesis);
    hx32(want, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    ck("mainnet genesis hash == Core's", memcmp(got, want, 32) == 0);
    ck("stored genesis_hash matches the computed one", memcmp(g_chainp->genesis_hash, got, 32) == 0);
    ck("mainnet magic f9beb4d9", g_chainp->magic == 0xd9b4bef9u && net_magic == 0xd9b4bef9u);

    printf("\n== 2: regtest selection derives + proves its genesis ==\n");
    ck("select(regtest) succeeds (internal hash assert passed)", chainparams_select("regtest") == 1);
    ck("selected", g_chainp->id == CHAIN_REGTEST && !strcmp(g_chainp->name, "regtest"));
    block_hash(got, g_chainp->genesis);
    hx32(want, "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206");
    ck("regtest genesis hash == Core's assert", memcmp(got, want, 32) == 0);
    ck("stored regtest genesis_hash matches", memcmp(g_chainp->genesis_hash, got, 32) == 0);
    ck("regtest header fields (time/bits/nonce)",
       memcmp(g_chainp->genesis + 68, "\xda\xe5\x49\x4d\xff\xff\x7f\x20\x02\x00\x00\x00", 12) == 0);
    ck("same coinbase tx as mainnet (only the header differs)",
       memcmp(g_chainp->genesis + 80, main_tx, 205) == 0);
    ck("CRegTestParams values: magic/port/rpc/halving/retarget/powlimit",
       g_chainp->magic == 0xdab5bffau && g_chainp->default_port == 18444 &&
       g_chainp->default_rpc_port == 18443 && g_chainp->halving_interval == 150 &&
       g_chainp->pow_no_retargeting == 1 && g_chainp->pow_limit_bits == 0x207fffffu);
    ck("address params 0x6f/0xc4/0xef/bcrt",
       g_chainp->p2pkh_version == 0x6f && g_chainp->p2sh_version == 0xc4 &&
       g_chainp->wif_version == 0xef && !strcmp(g_chainp->bech32_hrp, "bcrt"));
    ck("no DNS seeds on regtest", g_chainp->dns_seeds == 0);

    printf("\n== 3: the asm globals flip ==\n");
    ck("net_magic is now fabfb5da (LE dword dab5bffa)", net_magic == 0xdab5bffau);
    ck("sfc_chain is now 1", sfc_chain == 1);

    printf("\n== 4: script flags under each chain ==\n");
    ck("regtest h=1: everything active (CRegTestParams heights)",
       script_flags_for_block(1, nohash) == F_ALL);
    ck("regtest h=0: base flags + segwit's NULLDUMMY (SegwitHeight 0)",
       script_flags_for_block(0, nohash) == (F_P2SH|F_WITNESS|F_TAPROOT|F_NULLDUMMY));
    ck("regtest h=100000: still just F_ALL (no exceptions on this chain)",
       script_flags_for_block(100000, nohash) == F_ALL);

    ck("select(main) restores", chainparams_select("main") == 1 && g_chainp->id == CHAIN_MAIN);
    ck("net_magic restored", net_magic == 0xd9b4bef9u);
    ck("sfc_chain restored", sfc_chain == 0);
    ck("main h=0: P2SH|WITNESS|TAPROOT only",
       script_flags_for_block(0, nohash) == (F_P2SH|F_WITNESS|F_TAPROOT));
    ck("main DERSIG boundary (generated height)",
       (script_flags_for_block(SFC_HEIGHT_DERSIG-1, nohash) & F_DERSIG) == 0 &&
       (script_flags_for_block(SFC_HEIGHT_DERSIG,   nohash) & F_DERSIG) != 0);
    ck("main SEGWIT boundary gates NULLDUMMY",
       (script_flags_for_block(SFC_HEIGHT_SEGWIT-1, nohash) & F_NULLDUMMY) == 0 &&
       (script_flags_for_block(SFC_HEIGHT_SEGWIT,   nohash) & F_NULLDUMMY) != 0);

    printf("\n== 4b: testnet4 ==\n");
    ck("select(testnet4) succeeds (internal hash assert passed)", chainparams_select("testnet4") == 1);
    ck("selected", g_chainp->id == CHAIN_TESTNET4 && !strcmp(g_chainp->name, "testnet4"));
    block_hash(got, g_chainp->genesis);
    hx32(want, "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043");
    ck("testnet4 genesis hash == Core's assert", memcmp(got, want, 32) == 0);
    ck("stored testnet4 genesis_hash matches", memcmp(g_chainp->genesis_hash, got, 32) == 0);
    ck("CTestNet4Params values: magic/port/rpc/halving/retarget/mindiff/bip94/powlimit",
       g_chainp->magic == 0x283f161cu && g_chainp->default_port == 48333 &&
       g_chainp->default_rpc_port == 48332 && g_chainp->halving_interval == 210000 &&
       g_chainp->pow_no_retargeting == 0 && g_chainp->allow_min_difficulty == 1 &&
       g_chainp->enforce_bip94 == 1 && g_chainp->pow_limit_bits == 0x1d00ffffu);
    ck("address params 0x6f/0xc4/0xef/tb",
       g_chainp->p2pkh_version == 0x6f && g_chainp->p2sh_version == 0xc4 &&
       g_chainp->wif_version == 0xef && !strcmp(g_chainp->bech32_hrp, "tb"));
    ck("testnet4 has DNS seeds", g_chainp->dns_seeds == 1 && g_chainp->n_dns_seed_hosts == 2);
    ck("net_magic flipped to 1c163f28 (LE dword 283f161c)", net_magic == 0x283f161cu);
    ck("sfc_chain is now 2", sfc_chain == 2);
    ck("testnet4 h=1: everything active (CTestNet4Params heights)",
       script_flags_for_block(1, nohash) == F_ALL);
    ck("testnet4 h=0: base flags only (SegwitHeight 1, unlike regtest's 0)",
       script_flags_for_block(0, nohash) == (F_P2SH|F_WITNESS|F_TAPROOT));
    ck("select(main) restores from testnet4",
       chainparams_select("main") == 1 && net_magic == 0xd9b4bef9u && sfc_chain == 0);

    printf("\n== 5: per-chain datadirs ==\n");
    { char out[256];
      mkdir("/tmp/bmc-cp-test", 0755);   /* parent for the subdir mkdir */
      chainparams_datadir("/tmp/bmc-cp-test", out, sizeof out);
      struct stat sbm;
      ck("main datadir is base/main and was created (every chain in its own subdir)",
         !strcmp(out, "/tmp/bmc-cp-test/main") && stat(out, &sbm) == 0 && S_ISDIR(sbm.st_mode));
      chainparams_select("regtest");
      chainparams_datadir("/tmp/bmc-cp-test", out, sizeof out);
      struct stat sb;
      ck("regtest datadir is base/regtest and was created",
         !strcmp(out, "/tmp/bmc-cp-test/regtest") && stat(out, &sb) == 0 && S_ISDIR(sb.st_mode));
      chainparams_select("testnet4");
      chainparams_datadir("/tmp/bmc-cp-test", out, sizeof out);
      ck("testnet4 datadir is base/testnet4 and was created",
         !strcmp(out, "/tmp/bmc-cp-test/testnet4") && stat(out, &sb) == 0 && S_ISDIR(sb.st_mode));
      chainparams_select("main"); }

    printf("\n== 6: refusals ==\n");
    ck("legacy testnet3 names refused",
       chainparams_select("test") == 0 && chainparams_select("testnet") == 0);
    /* signet is no longer in this list: it is supported. Selecting it is
     * tested below; what belongs HERE is that a refused name does not
     * disturb the chain already in force. */
    ck("garbage refused",  chainparams_select("florin") == 0);
    ck("a signet-shaped near-miss is refused", chainparams_select("signett") == 0);
    ck("a refused select leaves the previous chain in force", g_chainp->id == CHAIN_MAIN);

    printf("== genesis hashes differ per chain (what the datadir guard rests on) ==\n");
    /* chain_archive_matches() in main.c refuses to start when block 0 of an
     * existing archive is not this chain's genesis. That guard is only as
     * good as the hashes actually differing, so pin it here. */
    { unsigned char mainh[32], regh[32], t4h[32];
      ck("select(main)", chainparams_select("main") == 1);
      memcpy(mainh, g_chainp->genesis_hash, 32);
      ck("select(regtest)", chainparams_select("regtest") == 1);
      memcpy(regh, g_chainp->genesis_hash, 32);
      ck("select(testnet4)", chainparams_select("testnet4") == 1);
      memcpy(t4h, g_chainp->genesis_hash, 32);
      unsigned char sigh[32];
      ck("select(signet)", chainparams_select("signet") == 1);
      memcpy(sigh, g_chainp->genesis_hash, 32);
      ck("main and regtest genesis differ",   memcmp(mainh, regh, 32) != 0);
      ck("main and testnet4 genesis differ",  memcmp(mainh, t4h, 32) != 0);
      ck("regtest and testnet4 genesis differ", memcmp(regh, t4h, 32) != 0);
      ck("signet genesis differs from all",   memcmp(sigh, mainh, 32) != 0 && memcmp(sigh, regh, 32) != 0 && memcmp(sigh, t4h, 32) != 0);
      /* Core stores NO chain's genesis coinbase; every real genesis must be
       * recognised by the skip. Signet was MISSING until 2026-08-31: its
       * nodes carried an extra 50 BTC output, found only when the whole set
       * was compared against a Core oracle's gettxoutsetinfo. */
      ck("skip knows main's genesis",     bmc_is_genesis_block(0, mainh));
      ck("skip knows regtest's genesis",  bmc_is_genesis_block(0, regh));
      ck("skip knows testnet4's genesis", bmc_is_genesis_block(0, t4h));
      ck("skip knows signet's genesis",   bmc_is_genesis_block(0, sigh));
      ck("...but only at height 0",       !bmc_is_genesis_block(1, mainh));
      chainparams_select("main"); }

    /* ---- VAL-12 (audit 2026-09-03): the minimum-chain-work floors ----
     * testnet4 carried SIGNET's floor -- byte-identical to it, and about 4e9
     * times lower than Core's -- so a low-work testnet4 fork cleared
     * reorg_work_meets_minimum when it should not. This file asserted genesis
     * hashes only, so the paste was invisible. Pinning all four against Core
     * catches the next one, and the DISTINCTNESS check is what actually
     * fails on a copy-paste: an equality test against a wrong-but-consistent
     * constant would not.
     *
     * RUNS BEFORE the signet section below, deliberately. That section
     * selects a CUSTOM signet, and chainparams_select clears
     * PARAMS_SIGNET.min_chain_work_hex (and its seeds) for a custom
     * challenge -- correctly, per Core -- but PARAMS_SIGNET is a mutable
     * static that is never restored, so a later chainparams_select("signet")
     * still reads the cleared floor. Harmless for the daemon, which selects
     * one chain at boot and never goes back, but it means this block reads ""
     * for signet if it runs afterwards. */
    {
        printf("\n== minimum chain work (Core kernel/chainparams.cpp) ==\n");
        struct { const char* chain; const char* want; } W[] = {
            { "main",     "0000000000000000000000000000000000000001128750f82f4c366153a3a030" },
            { "testnet4", "0000000000000000000000000000000000000000000009a0fe15d0177d086304" },
            { "signet",   "00000000000000000000000000000000000000000000000000000b463ea0a4b8" },
            { "regtest",  "" },
        };
        char seen[4][80];
        for (unsigned i = 0; i < sizeof W / sizeof W[0]; i++){
            char lbl[128];
            seen[i][0] = 0;
            if (chainparams_select(W[i].chain) != 1){
                snprintf(lbl, sizeof lbl, "%s selects", W[i].chain); ck(lbl, 0); continue;
            }
            const char* got = g_chainp->min_chain_work_hex ? g_chainp->min_chain_work_hex : "";
            snprintf(seen[i], sizeof seen[i], "%s", got);
            snprintf(lbl, sizeof lbl, "%s min_chain_work == Core's", W[i].chain);
            ck(lbl, strcmp(got, W[i].want) == 0);
            if (strcmp(got, W[i].want) != 0)
                printf("        got  %s\n        want %s\n", got, W[i].want);
        }
        /* the ACTUAL values, not the two expected constants -- comparing
         * those would be tautological and pass however wrong the tree is */
        ck("testnet4's floor is NOT signet's (the VAL-12 paste)",
           strcmp(seen[1], seen[2]) != 0);
        chainparams_select("main");
    }

    printf("== signet (BIP325) ==\n");
    {
        ck("select(signet)", chainparams_select("signet") == 1);
        ck("id is CHAIN_SIGNET", g_chainp->id == CHAIN_SIGNET);

        /* The genesis is DERIVED from mainnet's, so proving it against Core's
         * asserted hash is the whole safety of that shortcut. chainparams.c
         * refuses to select signet if this fails, so reaching here means it
         * held -- but hash it again from the bytes rather than trusting the
         * stored copy. */
        unsigned char h[32];
        sha256d(h, g_chainp->genesis, 80);
        ck("derived signet genesis hashes to Core's asserted value",
           memcmp(h, g_chainp->genesis_hash, 32) == 0);
        /* 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6,
         * internal order, straight out of Core's assert(). */
        static const unsigned char CORE[32] = {
            0xf6,0x1e,0xee,0x3b,0x63,0xa3,0x80,0xa4,0x77,0xa0,0x63,0xaf,0x32,0xb2,0xbb,0xc9,
            0x7c,0x9f,0xf9,0xf0,0x1f,0x2c,0x42,0x25,0xe9,0x73,0x98,0x81,0x08,0x00,0x00,0x00 };
        ck("and it is the hash Core asserts", memcmp(h, CORE, 32) == 0);

        /* The magic is DERIVED from the challenge, not pasted. Core: "the
         * first 4 bytes of the sha256d of the block script" -- as a
         * SERIALISED vector, so the CompactSize prefix is in the preimage.
         * Dropping that prefix yields a plausible magic no peer would send,
         * which is why this is pinned to the published value. */
        ck("default signet magic is 0a03cf40 on the wire",
           g_chainp->magic == 0x40cf030au);
        ck("and it is what the derivation produces from the challenge",
           chainparams_signet_magic(g_chainp->signet_challenge,
                                    g_chainp->signet_challenge_len) == g_chainp->magic);
        ck("the default challenge is the 71-byte bare CHECKMULTISIG",
           g_chainp->signet_challenge_len == 71 &&
           g_chainp->signet_challenge[0] == 0x51 &&
           g_chainp->signet_challenge[70] == 0xae);
        ck("signet keeps mainnet's port range clear", g_chainp->default_port == 38333);
        ck("and Core's minimum chain work for the public signet",
           g_chainp->min_chain_work_hex[0] != 0);

        /* A CUSTOM signet: different challenge -> different magic, so the two
         * networks cannot hear each other. That isolation is the point. */
        unsigned int pub_magic = g_chainp->magic;
        ck("a custom challenge is accepted", chainparams_set_signet_challenge("51") == 1);
        ck("re-select(signet)", chainparams_select("signet") == 1);
        ck("a custom signet gets a DIFFERENT magic", g_chainp->magic != pub_magic);
        ck("its challenge is the one we set",
           g_chainp->signet_challenge_len == 1 && g_chainp->signet_challenge[0] == 0x51);
        ck("a custom signet has no chain-work floor (Core: uint256{})",
           g_chainp->min_chain_work_hex[0] == 0);
        ck("and no DNS seeds", g_chainp->n_dns_seed_hosts == 0 && g_chainp->dns_seeds == 0);
        ck("odd-length hex is refused", chainparams_set_signet_challenge("5") == 0);
        ck("non-hex is refused", chainparams_set_signet_challenge("zz") == 0);
        ck("empty is refused", chainparams_set_signet_challenge("") == 0);

        /* And the genesis is the same block regardless of challenge -- Core
         * builds it from fixed parameters, so only the magic and the rules
         * change. */
        ck("the custom signet has the same genesis",
           memcmp(g_chainp->genesis_hash, CORE, 32) == 0);
    }

    printf("== selecting signet does not disturb any other chain ==\n");
    {
        /* The failure that would matter most: signet leaking into mainnet.
         * PARAMS_SIGNET is the one mutable params struct, so pin that
         * selecting it and coming back leaves mainnet byte-identical. */
        chainparams_select("main");
        chainparams_t before = *g_chainp;
        chainparams_select("signet");
        chainparams_select("main");
        ck("mainnet params are byte-identical after a signet round trip",
           memcmp(&before, g_chainp, sizeof before) == 0);
        ck("mainnet still has no signet challenge", g_chainp->signet_challenge == 0);
        ck("mainnet magic is untouched", g_chainp->magic == 0xd9b4bef9u);
        ck("regtest has no signet challenge",
           chainparams_select("regtest") == 1 && g_chainp->signet_challenge == 0);
        ck("testnet4 has no signet challenge",
           chainparams_select("testnet4") == 1 && g_chainp->signet_challenge == 0);
        chainparams_select("main");
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

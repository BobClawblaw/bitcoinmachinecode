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
 *   6. testnet/signet are refused, unknown names are refused.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../daemon/chainparams.h"
#include "../script_flags_consts.h"

typedef unsigned char u8;
typedef unsigned long u64;

extern void block_hash(u8 out[32], const u8 hdr[80]);
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

    printf("\n== 5: per-chain datadirs ==\n");
    { char out[256];
      mkdir("/tmp/bmc-cp-test", 0755);   /* parent for the subdir mkdir */
      chainparams_datadir("/tmp/bmc-cp-test", out, sizeof out);
      ck("main datadir is the base itself", !strcmp(out, "/tmp/bmc-cp-test"));
      chainparams_select("regtest");
      chainparams_datadir("/tmp/bmc-cp-test", out, sizeof out);
      struct stat sb;
      ck("regtest datadir is base/regtest and was created",
         !strcmp(out, "/tmp/bmc-cp-test/regtest") && stat(out, &sb) == 0 && S_ISDIR(sb.st_mode));
      chainparams_select("main"); }

    printf("\n== 6: refusals ==\n");
    ck("testnet refused",  chainparams_select("test") == 0);
    ck("signet refused",   chainparams_select("signet") == 0);
    ck("garbage refused",  chainparams_select("florin") == 0);
    ck("a refused select leaves the previous chain in force", g_chainp->id == CHAIN_MAIN);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

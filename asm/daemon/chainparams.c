/* daemon/chainparams.c -- see chainparams.h for the contract.
 *
 * Values cited to Core's kernel/chainparams.cpp (CMainParams/CRegTestParams).
 * The regtest genesis block is NOT transcribed: Core builds it from the SAME
 * CreateGenesisBlock(coinbase) as mainnet with only (nTime, nNonce, nBits)
 * changed -- so it is DERIVED here the same way, by patching those 12 header
 * bytes of the mainnet block, and then the sha256d of the result is asserted
 * against Core's own hashGenesisBlock string before the selection is allowed
 * to succeed. A transcription error cannot boot.
 */
#include <stdio.h>
#include "log_ts.h"   /* timestamped fprintf(stderr), like every other daemon line */
#include <string.h>
#include <sys/stat.h>
#include "chainparams.h"

typedef unsigned char u8;

/* sha256d, bitcoin_hash.asm -- the same hash every block goes through */
extern void sha256d(u8 out[32], const void* p, unsigned long n);

/* the two asm-owned runtime globals (see chainparams.h) */
extern unsigned int net_magic;    /* bitcoin_net.asm */
extern unsigned int sfc_chain;    /* bitcoin_script_flags.asm */

/* The mainnet genesis block, all 285 bytes. Byte-for-byte the archive's
 * record 0 and test_rpc_chain.c's GENESIS_HEX (which the RPC layer diffs
 * against the oracle); hash asserted below anyway. */
static const u8 GENESIS_MAIN[285] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,
    0x67,0x76,0x8f,0x61,0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,
    0x4b,0x1e,0x5e,0x4a,0x29,0xab,0x5f,0x49,0xff,0xff,0x00,0x1d,0x1d,0xac,0x2b,0x7c,
    0x01,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x4d,0x04,0xff,0xff,0x00,0x1d,
    0x01,0x04,0x45,0x54,0x68,0x65,0x20,0x54,0x69,0x6d,0x65,0x73,0x20,0x30,0x33,0x2f,
    0x4a,0x61,0x6e,0x2f,0x32,0x30,0x30,0x39,0x20,0x43,0x68,0x61,0x6e,0x63,0x65,0x6c,
    0x6c,0x6f,0x72,0x20,0x6f,0x6e,0x20,0x62,0x72,0x69,0x6e,0x6b,0x20,0x6f,0x66,0x20,
    0x73,0x65,0x63,0x6f,0x6e,0x64,0x20,0x62,0x61,0x69,0x6c,0x6f,0x75,0x74,0x20,0x66,
    0x6f,0x72,0x20,0x62,0x61,0x6e,0x6b,0x73,0xff,0xff,0xff,0xff,0x01,0x00,0xf2,0x05,
    0x2a,0x01,0x00,0x00,0x00,0x43,0x41,0x04,0x67,0x8a,0xfd,0xb0,0xfe,0x55,0x48,0x27,
    0x19,0x67,0xf1,0xa6,0x71,0x30,0xb7,0x10,0x5c,0xd6,0xa8,0x28,0xe0,0x39,0x09,0xa6,
    0x79,0x62,0xe0,0xea,0x1f,0x61,0xde,0xb6,0x49,0xf6,0xbc,0x3f,0x4c,0xef,0x38,0xc4,
    0xf3,0x55,0x04,0xe5,0x1e,0xc1,0x12,0xde,0x5c,0x38,0x4d,0xf7,0xba,0x0b,0x8d,0x57,
    0x8a,0x4c,0x70,0x2b,0x6b,0xf1,0x1d,0x5f,0xac,0x00,0x00,0x00,0x00
};

/* wire (sha256d) order -- the display hex reversed */
static const u8 GENESIS_MAIN_HASH[32] = {
    0x6f,0xe2,0x8c,0x0a,0xb6,0xf1,0xb3,0x72,0xc1,0xa6,0xa2,0x46,0xae,0x63,0xf7,0x4f,
    0x93,0x1e,0x83,0x65,0xe1,0x5a,0x08,0x9c,0x68,0xd6,0x19,0x00,0x00,0x00,0x00,0x00
};
/* Core: 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206 */
static const u8 GENESIS_REG_HASH[32] = {
    0x06,0x22,0x6e,0x46,0x11,0x1a,0x0b,0x59,0xca,0xaf,0x12,0x60,0x43,0xeb,0x5b,0xbf,
    0x28,0xc3,0x4f,0x3a,0x5e,0x33,0x2a,0x1f,0xc7,0xb2,0xb7,0x3c,0xf1,0x88,0x91,0x0f
};

/* filled by chainparams_select("regtest"): GENESIS_MAIN with the regtest
 * (nTime=1296688602, nBits=0x207fffff, nNonce=2) header fields patched in */
static u8 genesis_reg[285];
static u8 genesis_sig[285];

/* BIP325. The DEFAULT signet challenge, from Core's SigNetParams when
 * -signetchallenge is absent (kernel/chainparams.cpp): a bare 1-of-2
 * CHECKMULTISIG. A custom signet overwrites this buffer. */
#define SIGNET_CHALLENGE_MAX 1024
static u8  signet_challenge[SIGNET_CHALLENGE_MAX] = {
    0x51,0x21,0x03,0xad,0x5e,0x0e,0xda,0xd1,0x8c,0xb1,0xf0,0xfc,0x0d,0x28,0xa3,
    0xd4,0xf1,0xf3,0xe4,0x45,0x64,0x03,0x37,0x48,0x9a,0xbb,0x10,0x40,0x4f,0x2d,
    0x1e,0x08,0x6b,0xe4,0x30,0x21,0x03,0x59,0xef,0x50,0x21,0x96,0x4f,0xe2,0x2d,
    0x6f,0x8e,0x05,0xb2,0x46,0x3c,0x95,0x40,0xce,0x96,0x88,0x3f,0xe3,0xb2,0x78,
    0x76,0x0f,0x04,0x8f,0x51,0x89,0xf2,0xe6,0xc4,0x52,0xae };
static long signet_challenge_len = 71;
static int  signet_challenge_custom = 0;

/* Core asserts this genesis hash for signet; genesis_sig is DERIVED from
 * mainnet's (same coinbase, different nTime/nBits/nNonce -- Core builds it
 * with the same CreateGenesisBlock) and proven against these bytes at
 * selection time, exactly as regtest is. Internal (wire) order. */
static const u8 GENESIS_SIG_HASH[32] = {
    0xf6,0x1e,0xee,0x3b,0x63,0xa3,0x80,0xa4,0x77,0xa0,0x63,0xaf,0x32,0xb2,0xbb,0xc9,
    0x7c,0x9f,0xf9,0xf0,0x1f,0x2c,0x42,0x25,0xe9,0x73,0x98,0x81,0x08,0x00,0x00,0x00 };

/* The testnet4 genesis block, all 261 bytes. Unlike regtest it is NOT a
 * patched mainnet block: Core's CTestNet4Params builds it from its own 2024
 * timestamp message and an anyone-can-try OP_CHECKSIG output. Constructed
 * from Core's CreateGenesisBlock recipe and verified against BOTH of Core's
 * asserts (hashGenesisBlock AND hashMerkleRoot) before being pasted here;
 * re-verified at runtime by chainparams_select and by tests/test_chainparams. */
static const u8 GENESIS_T4[261] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x4e,0x7b,0x2b,0x91,0x28,0xfe,0x02,0x91,0xdb,0x06,0x93,0xaf,
    0x2a,0xe4,0x18,0xb7,0x67,0xe6,0x57,0xcd,0x40,0x7e,0x80,0xcb,0x14,0x34,0x22,0x1e,
    0xae,0xa7,0xa0,0x7a,0x04,0x6f,0x35,0x66,0xff,0xff,0x00,0x1d,0xbb,0x0c,0x78,0x17,
    0x01,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x55,0x04,0xff,0xff,0x00,0x1d,
    0x01,0x04,0x4c,0x4c,0x30,0x33,0x2f,0x4d,0x61,0x79,0x2f,0x32,0x30,0x32,0x34,0x20,
    0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,
    0x30,0x30,0x30,0x30,0x31,0x65,0x62,0x64,0x35,0x38,0x63,0x32,0x34,0x34,0x39,0x37,
    0x30,0x62,0x33,0x61,0x61,0x39,0x64,0x37,0x38,0x33,0x62,0x62,0x30,0x30,0x31,0x30,
    0x31,0x31,0x66,0x62,0x65,0x38,0x65,0x61,0x38,0x65,0x39,0x38,0x65,0x30,0x30,0x65,
    0xff,0xff,0xff,0xff,0x01,0x00,0xf2,0x05,0x2a,0x01,0x00,0x00,0x00,0x23,0x21,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xac,0x00,0x00,0x00,0x00
};
/* Core: 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043 */
static const u8 GENESIS_T4_HASH[32] = {
0x43,0xf0,0x8b,0xda,0xb0,0x50,0xe3,0x5b,0x56,0x7c,0x86,0x4b,0x91,0xf4,0x7f,0x50,
    0xae,0x72,0x5a,0xe2,0xde,0x53,0xbc,0xfb,0xba,0xf2,0x84,0xda,0x00,0x00,0x00,0x00
};

/* DNS seeds, from each chain's chainparams.cpp vSeeds. Bootstrap-only. */
static const char* const SEEDS_MAIN[] = {
    "seed.bitcoin.sipa.be", "dnsseed.bluematt.me", "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch", "seed.btc.petertodd.net",
    "seed.bitcharcoal.com", "seed.bitcoin.wiz.biz",
    "dnsseed.bitcoin.dashjr.org", "seed.bitnodes.io" };
static const char* const SEEDS_T4[] = {
    "seed.testnet4.bitcoin.sprovoost.nl", "seed.testnet4.wiz.biz" };
static const char* const SEEDS_SIGNET[] = {
    "seed.signet.bitcoin.sprovoost.nl", "seed.signet.achownodes.xyz" };

static const chainparams_t PARAMS_MAIN = {
    .id = CHAIN_MAIN, .name = "main",
    .min_chain_work_hex = "0000000000000000000000000000000000000001128750f82f4c366153a3a030",
    .magic = 0xd9b4bef9u,            /* f9 be b4 d9 on the wire            */
    .default_port = 8333, .default_rpc_port = 8332,
    .genesis = GENESIS_MAIN, .genesis_len = 285,
    .genesis_hash = GENESIS_MAIN_HASH,
    .halving_interval = 210000,
    .pow_no_retargeting = 0, .pow_limit_bits = 0x1d00ffffu,
    .p2pkh_version = 0x00, .p2sh_version = 0x05, .wif_version = 0x80,
    .bech32_hrp = "bc",
    .xpub_version = 0x0488B21Eu, .xprv_version = 0x0488ADE4u,
    .dns_seeds = 1,
    .allow_min_difficulty = 0,
    .enforce_bip94 = 0,
    .dns_seed_hosts = SEEDS_MAIN,
    .n_dns_seed_hosts = (int)(sizeof SEEDS_MAIN / sizeof *SEEDS_MAIN),
};

static const chainparams_t PARAMS_REGTEST = {
    .id = CHAIN_REGTEST, .name = "regtest",
    .min_chain_work_hex = "",          /* Core: uint256{} -- no floor on regtest */
    .magic = 0xdab5bffau,            /* fa bf b5 da on the wire            */
    .default_port = 18444, .default_rpc_port = 18443,
    .genesis = genesis_reg, .genesis_len = 285,
    .genesis_hash = GENESIS_REG_HASH,
    .halving_interval = 150,
    .pow_no_retargeting = 1, .pow_limit_bits = 0x207fffffu,
    .p2pkh_version = 0x6f, .p2sh_version = 0xc4, .wif_version = 0xef,
    .bech32_hrp = "bcrt",
    .xpub_version = 0x043587CFu, .xprv_version = 0x04358394u,
    .dns_seeds = 0,
    .allow_min_difficulty = 1,      /* Core regtest: true (moot: no retarget) */
    .enforce_bip94 = 0,
    .dns_seed_hosts = 0,
    .n_dns_seed_hosts = 0,
};

static const chainparams_t PARAMS_TESTNET4 = {
    .id = CHAIN_TESTNET4, .name = "testnet4",
    .min_chain_work_hex = "00000000000000000000000000000000000000000000000000000b463ea0a4b8",
    .magic = 0x283f161cu,            /* 1c 16 3f 28 on the wire            */
    .default_port = 48333, .default_rpc_port = 48332,
    .genesis = GENESIS_T4, .genesis_len = 261,
    .genesis_hash = GENESIS_T4_HASH,
    .halving_interval = 210000,
    .pow_no_retargeting = 0, .pow_limit_bits = 0x1d00ffffu,
    .p2pkh_version = 0x6f, .p2sh_version = 0xc4, .wif_version = 0xef,
    .bech32_hrp = "tb",
    .xpub_version = 0x043587CFu, .xprv_version = 0x04358394u,
    .dns_seeds = 1,
    .allow_min_difficulty = 1,       /* fPowAllowMinDifficultyBlocks       */
    .enforce_bip94 = 1,              /* consensus.enforce_BIP94             */
    .dns_seed_hosts = SEEDS_T4,
    .n_dns_seed_hosts = (int)(sizeof SEEDS_T4 / sizeof *SEEDS_T4),
};

/* NOT const: a custom signet changes the magic, the challenge, the seeds and
 * the chain-work floor at selection time. Every other chain stays const. */
static chainparams_t PARAMS_SIGNET = {
    .id = CHAIN_SIGNET, .name = "signet",
    /* Core sets this only for the DEFAULT signet; a custom one gets uint256{} */
    .min_chain_work_hex = "00000000000000000000000000000000000000000000000000000b463ea0a4b8",
    .magic = 0x40cf030au,            /* 0a 03 cf 40 -- DERIVED, see select  */
    .default_port = 38333, .default_rpc_port = 38332,
    .genesis = genesis_sig, .genesis_len = 285,
    .genesis_hash = GENESIS_SIG_HASH,
    .halving_interval = 210000,
    .pow_no_retargeting = 0, .pow_limit_bits = 0x1e0377aeu,
    .p2pkh_version = 0x6f, .p2sh_version = 0xc4, .wif_version = 0xef,
    .bech32_hrp = "tb",
    .xpub_version = 0x043587CFu, .xprv_version = 0x04358394u,
    .dns_seeds = 1,
    .allow_min_difficulty = 0,       /* Core signet: false                  */
    .enforce_bip94 = 0,              /* Core signet: enforce_BIP94 = false  */
    .dns_seed_hosts = SEEDS_SIGNET,
    .n_dns_seed_hosts = (int)(sizeof SEEDS_SIGNET / sizeof *SEEDS_SIGNET),
    .signet_challenge = signet_challenge,
    .signet_challenge_len = 71,
};

const chainparams_t* g_chainp = &PARAMS_MAIN;

static void put_le32(u8* p, unsigned int v){
    p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24);
}

unsigned int chainparams_signet_magic(const u8* challenge, long len){
    /* Core: "message start is defined as the first 4 bytes of the sha256d of
     * the block script", hashed through a HashWriter as a SERIALISED vector --
     * so the CompactSize length prefix is part of the preimage. Dropping it
     * yields a plausible-looking magic that no signet peer would ever send. */
    u8 buf[9 + SIGNET_CHALLENGE_MAX];
    long n = 0;
    if (len < 0xfd) buf[n++] = (u8)len;
    else if (len <= 0xffff){ buf[n++]=0xfd; buf[n++]=(u8)len; buf[n++]=(u8)(len>>8); }
    else { buf[n++]=0xfe; for (int i=0;i<4;i++) buf[n++]=(u8)(len>>(8*i)); }
    memcpy(buf + n, challenge, (size_t)len); n += len;
    u8 h[32]; sha256d(h, buf, n);
    return (unsigned)h[0] | ((unsigned)h[1]<<8) | ((unsigned)h[2]<<16) | ((unsigned)h[3]<<24);
}

int chainparams_set_signet_challenge(const char* hex){
    if (!hex || !*hex) return 0;
    long n = (long)strlen(hex);
    if (n & 1) return 0;
    n /= 2;
    if (n < 1 || n > SIGNET_CHALLENGE_MAX) return 0;
    for (long i = 0; i < n; i++){
        int v = 0;
        for (int k = 0; k < 2; k++){
            char c = hex[i*2+k]; v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
            else return 0;
        }
        signet_challenge[i] = (u8)v;
    }
    signet_challenge_len = n;
    signet_challenge_custom = 1;
    return 1;
}

int chainparams_select(const char* name){
    if (!name || !*name || !strcmp(name, "main") || !strcmp(name, "mainnet")){
        g_chainp = &PARAMS_MAIN;
        net_magic = PARAMS_MAIN.magic;
        sfc_chain = 0;
        return 1;
    }
    if (!strcmp(name, "regtest")){
        /* derive the regtest genesis (see the file comment) and PROVE it */
        memcpy(genesis_reg, GENESIS_MAIN, sizeof genesis_reg);
        put_le32(genesis_reg + 68, 1296688602u);   /* nTime  */
        put_le32(genesis_reg + 72, 0x207fffffu);   /* nBits  */
        put_le32(genesis_reg + 76, 2u);            /* nNonce */
        u8 h[32]; sha256d(h, genesis_reg, 80);
        if (memcmp(h, GENESIS_REG_HASH, 32) != 0){
            fprintf(stderr, "[chain] FATAL: derived regtest genesis hash does not "
                            "match Core's -- refusing to select regtest\n");
            return 0;
        }
        g_chainp = &PARAMS_REGTEST;
        net_magic = PARAMS_REGTEST.magic;
        sfc_chain = 1;
        return 1;
    }
    if (!strcmp(name, "testnet4")){
        /* prove the pasted block before trusting it, exactly like regtest */
        u8 h[32]; sha256d(h, GENESIS_T4, 80);
        if (memcmp(h, GENESIS_T4_HASH, 32) != 0){
            fprintf(stderr, "[chain] FATAL: testnet4 genesis hash does not "
                            "match Core's -- refusing to select testnet4\n");
            return 0;
        }
        g_chainp = &PARAMS_TESTNET4;
        net_magic = PARAMS_TESTNET4.magic;
        sfc_chain = 2;
        return 1;
    }
    if (!strcmp(name, "signet")){
        /* derive the genesis from mainnet's and PROVE it, exactly like regtest */
        memcpy(genesis_sig, GENESIS_MAIN, sizeof genesis_sig);
        put_le32(genesis_sig + 68, 1598918400u);   /* nTime  */
        put_le32(genesis_sig + 72, 0x1e0377aeu);   /* nBits  */
        put_le32(genesis_sig + 76, 52613770u);     /* nNonce */
        u8 h[32]; sha256d(h, genesis_sig, 80);
        if (memcmp(h, GENESIS_SIG_HASH, 32) != 0){
            fprintf(stderr, "[chain] FATAL: signet genesis hash does not match "
                            "Core's -- refusing to select signet\n");
            return 0;
        }
        PARAMS_SIGNET.signet_challenge_len = signet_challenge_len;
        PARAMS_SIGNET.magic = chainparams_signet_magic(signet_challenge,
                                                       signet_challenge_len);
        if (signet_challenge_custom){
            /* Core gives a custom signet no chain-work floor and no seeds:
             * neither means anything on a network only its operator knows
             * about, and a stale mainnet-scale floor would stall it forever. */
            PARAMS_SIGNET.min_chain_work_hex = "";
            PARAMS_SIGNET.dns_seed_hosts = 0;
            PARAMS_SIGNET.n_dns_seed_hosts = 0;
            PARAMS_SIGNET.dns_seeds = 0;
        }
        g_chainp = &PARAMS_SIGNET;
        net_magic = PARAMS_SIGNET.magic;
        /* NOT 0. The mainnet selector gates on HEIGHT, and signet's heights
         * are small numbers, so mainnet's schedule judges early signet blocks
         * pre-segwit and the node rejects them as "unexpected-witness". Found
         * by running a real sync. Signet has its own arm, with its own heights
         * read from Core. */
        sfc_chain = 3;
        fprintf(stderr, "[chain] signet: %s challenge (%ld bytes), magic %02x %02x %02x %02x\n",
                signet_challenge_custom ? "custom" : "default", signet_challenge_len,
                PARAMS_SIGNET.magic & 0xff, (PARAMS_SIGNET.magic >> 8) & 0xff,
                (PARAMS_SIGNET.magic >> 16) & 0xff, (PARAMS_SIGNET.magic >> 24) & 0xff);
        return 1;
    }
    if (!strcmp(name, "test") || !strcmp(name, "testnet")){
        fprintf(stderr, "[chain] chain=%s is not supported by this node "
                        "(main, signet, testnet4 and regtest are; "
                        "\"test\"/\"testnet\" mean legacy testnet3 -- say "
                        "chain=testnet4); refusing to start with the wrong "
                        "chain's rules\n", name);
        return 0;
    }
    fprintf(stderr, "[chain] unknown chain=%s\n", name);
    return 0;
}

const char* chainparams_datadir(const char* base, char* out, long cap){
    if (g_chainp->id == CHAIN_MAIN)
        snprintf(out, (size_t)cap, "%s", base);
    else {
        snprintf(out, (size_t)cap, "%s/%s", base, g_chainp->name);
        mkdir(out, 0755);   /* EEXIST is the normal case */
    }
    return out;
}

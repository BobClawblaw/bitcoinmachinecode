/* daemon/chainparams.h -- runtime chain selection (mainnet / regtest).
 *
 * One global parameter set, selected ONCE at boot from `chain=` in
 * bitcoin.conf (node_config.c) before any socket, block, or address is
 * touched, and never changed again -- so every reader can use the plain
 * globals without synchronization, exactly like Core's Params() singleton.
 *
 * The default is MAINNET, statically: a process that never calls
 * chainparams_select() (every existing tool, test, and the production
 * daemon's current config) behaves byte-identically to before this file
 * existed. That includes two runtime globals OWNED BY ASSEMBLY and only
 * WRITTEN here:
 *   - net_magic  (bitcoin_net.asm)         wire message-start dword
 *   - sfc_chain  (bitcoin_script_flags.asm) activation-schedule selector
 *
 * What is deliberately NOT chain-selected:
 *   - The block-archive container marker (bitcoin_store.asm's
 *     [len][f9beb4d9] framing, archive_verify's ARCHIVE_MAGIC): that is this
 *     project's own FILE format, not the wire protocol. Chains never share a
 *     datadir (chainparams_datadir appends "/regtest", Core's own layout),
 *     so distinguishing them by container marker would only break every
 *     existing offline tool for no isolation gain.
 *
 * Every numeric value below is read out of Core's kernel/chainparams.cpp
 * (CMainParams / CRegTestParams) -- kept next to a citation comment, and the
 * genesis blocks are verified against Core's own asserted hashes by
 * tests/test_chainparams.c, which hashes the byte arrays with block_hash and
 * compares. Never trust these constants unhashed.
 */
#ifndef CHAINPARAMS_H
#define CHAINPARAMS_H

#define CHAIN_MAIN     0
#define CHAIN_REGTEST  1
#define CHAIN_TESTNET4 2

typedef struct {
    int          id;                 /* CHAIN_* */
    const char*  name;               /* "main" / "regtest" (Core's -chain=) */
    unsigned int magic;              /* wire message-start, as the LE dword */
    int          default_port;       /* P2P listen/dial */
    int          default_rpc_port;
    /* genesis, raw block bytes + its sha256d hash in WIRE (internal) order */
    const unsigned char* genesis;
    long                 genesis_len;
    const unsigned char* genesis_hash;   /* [32] */
    long         halving_interval;   /* nSubsidyHalvingInterval */
    int          pow_no_retargeting; /* fPowNoRetargeting */
    unsigned int pow_limit_bits;     /* powLimit as compact nBits */
    /* address encodings */
    unsigned char p2pkh_version;     /* base58Prefixes[PUBKEY_ADDRESS] */
    unsigned char p2sh_version;      /* base58Prefixes[SCRIPT_ADDRESS] */
    unsigned char wif_version;       /* base58Prefixes[SECRET_KEY] */
    const char*  bech32_hrp;
    /* BIP32 extended-key version bytes. Core uses one pair for mainnet and
     * ANOTHER for every test chain, and its descriptor parser rejects the
     * wrong one outright -- an xpub handed to a regtest node is "not valid".
     * Without these the whole extended-key surface (gethdkeys, addhdkey,
     * listdescriptors' xpub) is silently mainnet-only. */
    unsigned int xpub_version;    /* 0x0488B21E main / 0x043587CF test    */
    unsigned int xprv_version;    /* 0x0488ADE4 main / 0x04358394 test    */
    int          dns_seeds;          /* regtest: none, ever */
    /* testnet4: fPowAllowMinDifficultyBlocks -- a block whose time is more
     * than 2*10min after its parent may use pow_limit_bits (relevant to
     * getblocktemplate; validation accepts each header's own nBits and
     * relies on cumulative work, see reorg.c) */
    int          allow_min_difficulty;
    int          enforce_bip94;      /* testnet4: retarget from the period's
                                        FIRST block (timewarp fix)          */
    /* the chain's DNS seed hostnames (bootstrap-only; see main.c). NULL/0
     * for chains with none (regtest). */
    const char* const* dns_seed_hosts;
    int          n_dns_seed_hosts;
} chainparams_t;

/* The selected chain. Statically CHAIN_MAIN. */
extern const chainparams_t* g_chainp;

/* Select by Core's -chain= name ("main", "regtest" or "testnet4";
 * "test"/"testnet" (ambiguous, testnet3) and "signet" are recognised and
 * REFUSED loudly rather than half-supported). Returns 1 ok,
 * 0 unknown/unsupported. Also writes the two asm globals. Call before any
 * network or block activity; calling twice with the same name is harmless. */
int chainparams_select(const char* name);

/* Core's datadir layout: mainnet lives at the datadir root, every other
 * chain in a subdirectory named after it ("<datadir>/regtest"). Writes the
 * effective path (creating the subdirectory if missing) into out. Returns
 * out for convenience. */
const char* chainparams_datadir(const char* base, char* out, long cap);

#endif

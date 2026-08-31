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
#define CHAIN_SIGNET   3

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
    /* Core consensus.nMinimumChainWork, as its uint256 hex. The floor a
     * header chain must clear before this node will commit work to it --
     * the defence against a peer feeding an enormous low-difficulty chain.
     * Empty/all-zero on regtest, exactly as Core leaves it. */
    const char*  min_chain_work_hex;
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
    /* BIP325. NULL on every chain but signet. The block SIGNATURE stands in
     * for meaningful proof of work here, so a signet whose challenge is not
     * set is not a chain this node can validate at all -- which is why
     * selection fails rather than defaulting to something. */
    const unsigned char* signet_challenge;
    long                 signet_challenge_len;
} chainparams_t;

/* The selected chain. Statically CHAIN_MAIN. */
extern const chainparams_t* g_chainp;

/* Select by Core's -chain= name ("main", "regtest" or "testnet4";
 * "test"/"testnet" (ambiguous, testnet3) is recognised and REFUSED loudly
 * rather than half-supported). Returns 1 ok, 0 unknown/unsupported. Also writes the two asm globals. Call before any
 * network or block activity; calling twice with the same name is harmless. */
int chainparams_select(const char* name);

/* Set a CUSTOM signet challenge (Core's -signetchallenge), as hex. Call
 * BEFORE chainparams_select("signet"); with no call, the default signet's
 * challenge is used. Returns 1 ok, 0 on malformed or over-long hex.
 *
 * The challenge is not cosmetic: the network MAGIC is derived from it
 * (Core: the first 4 bytes of the sha256d of the serialised challenge), so
 * two signets with different challenges cannot even talk to each other --
 * which is exactly the isolation a custom signet wants. Core also drops the
 * minimum-chain-work floor and the DNS seeds for a custom signet, because
 * neither means anything on a network only its operator knows about; this
 * does the same. */
int chainparams_set_signet_challenge(const char* hex);

/* The magic Core derives for a given challenge: first 4 bytes of
 * sha256d(CompactSize(len) || challenge), as the little-endian dword. Exposed
 * because it is worth testing directly against Core's published value rather
 * than only through a successful handshake. */
unsigned int chainparams_signet_magic(const unsigned char* challenge, long len);

/* Core's datadir layout: mainnet lives at the datadir root, every other
 * chain in a subdirectory named after it ("<datadir>/regtest"). Writes the
 * effective path (creating the subdirectory if missing) into out. Returns
 * out for convenience. */
const char* chainparams_datadir(const char* base, char* out, long cap);

#endif

/* daemon/genesis_skip.h -- "is this the genesis block?", in ONE place.
 *
 * Core never writes ANY chain's genesis coinbase to its chainstate: the
 * output is unspendable by consensus, and including it leaves a node one
 * UTXO richer than Core forever -- a difference that surfaces the first time
 * the set is compared against gettxoutsetinfo, which is exactly the parity
 * this project is measured on.
 *
 * The rule lived only in daemon/utxo_live.c (the LIVE writer), so the
 * offline batch builder happily included the genesis coinbase and the two
 * writers disagreed about what the UTXO set is. That is the whole reason
 * this is a header and not a second copy of the constants.
 *
 * Matched by HASH, not by height: the synthetic chains in
 * tests/test_cross_tx_verify.c and tests/test_utxo_checkpoint.c use height 0
 * as an ordinary block whose outputs are later spent, and a bare
 * `height == 0` test silently dropped those (caught by both suites failing,
 * 2026-08-22).
 *
 * Static bytes rather than a chainparams.c link dependency: this is included
 * by tools and tests that never select a chain, and matching all three
 * hashes is chain-agnostic. Each derivation is verified against Core's
 * asserted hash by tests/test_chainparams.c.
 */
#ifndef BMC_GENESIS_SKIP_H
#define BMC_GENESIS_SKIP_H

#include <string.h>

/* mainnet: display 000000000019d668...8ce26f, in wire (sha256d) order */
static const unsigned char BMC_MAINNET_GENESIS[32] = {
    0x6f,0xe2,0x8c,0x0a,0xb6,0xf1,0xb3,0x72,0xc1,0xa6,0xa2,0x46,0xae,0x63,0xf7,0x4f,
    0x93,0x1e,0x83,0x65,0xe1,0x5a,0x08,0x9c,0x68,0xd6,0x19,0x00,0x00,0x00,0x00,0x00 };
/* regtest: display 0f9188f1...466e2206 reversed */
static const unsigned char BMC_REGTEST_GENESIS[32] = {
    0x06,0x22,0x6e,0x46,0x11,0x1a,0x0b,0x59,0xca,0xaf,0x12,0x60,0x43,0xeb,0x5b,0xbf,
    0x28,0xc3,0x4f,0x3a,0x5e,0x33,0x2a,0x1f,0xc7,0xb2,0xb7,0x3c,0xf1,0x88,0x91,0x0f };
/* testnet4: display 00000000da84f2ba...8bf043 reversed */
static const unsigned char BMC_TESTNET4_GENESIS[32] = {
    0x43,0xf0,0x8b,0xda,0xb0,0x50,0xe3,0x5b,0x56,0x7c,0x86,0x4b,0x91,0xf4,0x7f,0x50,
    0xae,0x72,0x5a,0xe2,0xde,0x53,0xbc,0xfb,0xba,0xf2,0x84,0xda,0x00,0x00,0x00,0x00 };

/* height must ALSO be 0: see the note above about synthetic test chains. */
static inline int bmc_is_genesis_block(long height, const unsigned char blk_hash[32]){
    return height == 0 &&
           (memcmp(blk_hash, BMC_MAINNET_GENESIS,  32) == 0 ||
            memcmp(blk_hash, BMC_REGTEST_GENESIS,  32) == 0 ||
            memcmp(blk_hash, BMC_TESTNET4_GENESIS, 32) == 0);
}

#endif /* BMC_GENESIS_SKIP_H */

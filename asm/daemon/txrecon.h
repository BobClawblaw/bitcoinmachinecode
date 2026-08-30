/* daemon/txrecon.h -- BIP330 transaction-reconciliation NEGOTIATION.
 *
 * SCOPE, STATED UP FRONT. This is the `sendtxrcncl` handshake only: version
 * and salt exchange, the rules about who may offer it to whom, and the
 * combined salt both sides derive. It is NOT reconciliation: no sketches, no
 * reqrecon/sketch/reconcildiff, no set difference.
 *
 * That matches Bitcoin Core, whose own Erlay is incomplete --
 * node/txreconciliation.cpp implements exactly four functions (PreRegisterPeer,
 * RegisterPeer, ForgetPeer, IsPeerRegistered) and net_processing.cpp says so
 * in as many words: "While Erlay support is incomplete, it must be enabled
 * explicitly via -txreconciliation."
 *
 * Implementing the negotiation alone is therefore not a half-measure -- it is
 * the whole of what any deployed peer speaks today, and it is differentially
 * testable against a real Core node. The reconciliation rounds have no
 * running implementation anywhere to check against.
 */
#ifndef BMC_TXRECON_H
#define BMC_TXRECON_H

#define TXRECON_VERSION 1u          /* Core's TXRECONCILIATION_VERSION */

/* Result of registering a peer that sent us sendtxrcncl. The values mirror
 * Core's ReconciliationRegisterResult, including which ones are a protocol
 * violation that must drop the connection. */
enum {
    TXRECON_NOT_FOUND          = 0,  /* we never offered: ignore, do not drop */
    TXRECON_SUCCESS            = 1,
    TXRECON_ALREADY_REGISTERED = 2,  /* drop: a second sendtxrcncl */
    TXRECON_PROTOCOL_VIOLATION = 3   /* drop: version 0 */
};

/* The 32-byte combined salt: TaggedHash("Tx Relay Salting") over the two
 * salts in ASCENDING order, as BIP330 requires. Ordering by value rather
 * than by role is what lets both peers derive the same salt without agreeing
 * who is "first". */
void txrecon_combine_salt(unsigned char out32[32], unsigned long long salt1,
                          unsigned long long salt2);

/* May we OFFER reconciliation to this peer? Core's conditions, all of which
 * must hold (net_processing.cpp, the SENDTXRCNCL send site). */
int txrecon_may_offer(int peer_proto_version, int peer_relays_txs,
                      int is_block_relay_only, int is_feeler,
                      int is_addr_fetch, int we_ignore_incoming_txs);

/* Is an INBOUND sendtxrcncl acceptable? 1 yes, 0 means drop the peer.
 * `after_verack` is Core's fSuccessfullyConnected: sendtxrcncl is a
 * pre-verack message and arriving later is a violation. */
int txrecon_may_accept(int we_have_txrecon, int after_verack,
                       int we_reject_incoming_txs, int peer_relays_txs);

/* Register a peer that sent a valid sendtxrcncl. `offered` is whether WE sent
 * one first (Core's PreRegisterPeer having stored our salt); `registered` is
 * whether this peer is already registered. Returns one of the TXRECON_*
 * results, and on SUCCESS writes the combined salt. */
int txrecon_register(int offered, int registered, unsigned int peer_version,
                     unsigned long long local_salt, unsigned long long remote_salt,
                     unsigned char out_salt32[32], unsigned int* negotiated_version);
/* Decide whether to offer reconciliation to a peer whose `version` payload we
 * have, and if so build the 12-byte sendtxrcncl payload (u32 version, u64
 * salt, both little-endian) and report the salt we chose.
 *
 * Parsing lives here rather than in the assembly handshake because the
 * deciding field -- the OPTIONAL fRelay byte at the very end of the version
 * payload -- has to be located past a variable-length user agent. Getting a
 * variable-length parse subtly wrong in assembly is how this tree ended up
 * reading inv counts as a single byte; see daemon/serve_invbounds.c.
 *
 * Returns 1 and fills out12/salt when we should offer, 0 when we should not.
 * `we_ignore_incoming_txs` is -blocksonly. */
int txrecon_build_offer(const unsigned char* version_payload, long len,
                        int is_block_relay_only, int is_feeler, int is_addr_fetch,
                        int we_ignore_incoming_txs,
                        unsigned char out12[12], unsigned long long* salt_out);

/* Parse a received sendtxrcncl payload. 1 on success. */
int txrecon_parse(const unsigned char* payload, long len,
                  unsigned int* version_out, unsigned long long* salt_out);

#endif

/* daemon/relay_policy.h -- Core's tx-relay policy decisions (2026-09-01):
 * -blocksonly, the relay/forcerelay/mempool/download/addr permissions,
 * -inboundrelaypercent, the version message's fRelay bit. Pure decision
 * functions (unit-tested in tests/test_relay_policy.c) plus the small
 * per-connection state the serve loop's C hooks consult. */
#ifndef RELAY_POLICY_H
#define RELAY_POLICY_H

/* connection kinds, as Core distinguishes them for RejectIncomingTxs */
#define RP_CONN_INBOUND     0
#define RP_CONN_OUTBOUND    1   /* full relay leg */
#define RP_CONN_BLOCK_RELAY 2   /* outbound block-relay-only */
#define RP_CONN_FEELER      3

/* -blocksonly (Core: m_opts.ignore_incoming_txs) */
void rp_set_blocksonly(int on);
int  rp_blocksonly(void);

/* Core PeerManagerImpl::RejectIncomingTxs: 1 = this peer may not send us
 * transactions (block-relay-only or feeler connections always; in
 * -blocksonly every peer without the `relay` permission). */
int  rp_reject_incoming_txs(unsigned perms, int conn_kind);

/* The fRelay byte of OUR version message to this peer (Core PushNodeVersion:
 * !RejectIncomingTxs), further cleared for an inbound peer past the
 * -inboundrelaypercent share. */
int  rp_our_frelay(unsigned perms, int conn_kind, int share_exhausted);

/* Core's inbound tx-relay budget: max_full_relay = percent/100 * inbound
 * limit. `relaying_now` counts the inbound peers that negotiated tx relay in
 * both directions; a peer that asked for no relay (fRelay=0) consumes none
 * of the share. 1 = the next inbound peer gets fRelay=0. */
int  rp_inbound_share_exhausted(long relaying_now, long inbound_limit, int percent);

/* fRelay from a peer's version payload: 1 relay, 0 no relay (ABSENT means
 * 1, as the protocol defines), -1 unparseable. */
int  rp_version_frelay(const unsigned char* payload, long len);

/* Core sends `feefilter` unless -blocksonly, and never to a forcerelay peer. */
int  rp_send_feefilter(unsigned perms);

#endif

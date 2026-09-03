/* daemon/tx_submit.c -- worker-side handler for a sendrawtransaction submission.
 *
 * The RPC server runs in the serve PARENT, which owns no peer sockets. It
 * stages a raw tx into the shared node_status_t submission channel and bumps a
 * sequence number; the forked download worker (which owns the outbound peer
 * legs and the live UTXO writer state) picks it up at the top of its loop and
 * calls txsub_accept_and_relay: validate + insert into the mempool, then queue
 * the txid for announcement on every live peer leg.
 *
 * Relay is an `inv` ANNOUNCEMENT, exactly as Core does it: we send the txid
 * and the peer fetches the transaction with `getdata`. That future the old
 * comment here described has arrived -- daemon/tx_relay.c's drain answers
 * getdata(MSG_TX/MSG_WITNESS_TX) out of the shared mempool -- so the reason
 * for the old unsolicited `tx` push is gone.
 *
 * It mattered more than tidiness. An unsolicited transaction is not what a
 * relaying node sends; a peer receiving one can tell it is talking to the
 * node the transaction came FROM, because anything merely passing it along
 * would have announced first and waited to be asked. Pushing it to every leg
 * in the same instant said the same thing a second time. Handing the txid to
 * tx_relay.c's announce queue puts our own transactions on the same
 * staggered, per-leg Poisson schedule as everything else we relay, which is
 * what Core's clearnet behaviour looks like from the outside.
 *
 * Announcement is therefore ASYNCHRONOUS: this function returns once the
 * transaction is in the mempool, and the invs go out on the worker's
 * following rotations as each leg's timer comes due. Core's
 * sendrawtransaction returns at the same point, for the same reason.
 *
 * Kept in its own file, decoupled from the peer sockets, so the accept+relay
 * path is unit-testable over a socketpair (tests/test_tx_submit.c).
 */
#include <stdio.h>
#include <string.h>

typedef unsigned char u8;

extern long tx_accept_validate_reason(void* mp, const u8 txid[32], const u8* tx,
                                      unsigned long len, char* reason, unsigned long rcap);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* scratch, unsigned long scratchcap);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);

/* Announce an own-originated txid on every leg. The real implementation is
 * daemon/tx_relay.c; this weak stub keeps the socketpair unit test linkable
 * without dragging that translation unit in, and lets the test substitute a
 * recording version of its own. */
__attribute__((weak)) void txrelay_announce_own(const u8 txid[32]){ (void)txid; }

/* Validate + mempool-accept the staged tx, and on accept queue its txid for
 * announcement on every live peer leg. Returns 1 on accept, or a negative
 * Core RPC error code on reject (reason filled). peer_fds[i] < 0 entries are
 * skipped. On accept, *relayed_out (if non-NULL) receives the number of live
 * legs the announcement is queued for -- legs it WILL reach as their timers
 * come due, not sockets already written, since nothing goes out from here. */
int txsub_accept_and_relay(void* mp_area, const u8* tx, unsigned long len,
                           const int* peer_fds, int n_fds,
                           char* reason, unsigned long rcap, int* relayed_out){
    if (relayed_out) *relayed_out = 0;
    if (reason && rcap) reason[0] = 0;
    if (!tx || len == 0){ if (reason && rcap) snprintf(reason, rcap, "TX decode failed"); return -22; }

    u8 txid[32];
    static u8 scratch[2000*81 + 8];              /* worker is single-threaded */
    if (!tx_txid(txid, tx, len, scratch, sizeof scratch)){
        if (reason && rcap) snprintf(reason, rcap, "TX decode failed");
        return -22; }

    long r = tx_accept_validate_reason(mp_area, txid, tx, len, reason, rcap);
    if (r != 1) return (int)r;

    int live = 0;
    for (int i = 0; i < n_fds; i++) if (peer_fds[i] >= 0) live++;
    txrelay_announce_own(txid);
    if (relayed_out) *relayed_out = live;
    return 1;
}

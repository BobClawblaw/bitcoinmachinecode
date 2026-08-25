/* daemon/tx_submit.c -- worker-side handler for a sendrawtransaction submission.
 *
 * The RPC server runs in the serve PARENT, which owns no peer sockets. It
 * stages a raw tx into the shared node_status_t submission channel and bumps a
 * sequence number; the forked download worker (which owns the outbound peer
 * legs and the live UTXO writer state) picks it up at the top of its loop and
 * calls txsub_accept_and_relay: validate + insert into the mempool, then push
 * the raw tx to every live peer leg.
 *
 * Relay is an UNSOLICITED `tx` push rather than an `inv`: the worker runs no
 * serve loop to answer a peer's follow-up `getdata`, so announcing via inv
 * would never complete. Pushing the tx directly is what actually propagates it
 * from this process. (A future shared mempool + worker-side getdata responder
 * could switch this to the inv/getdata handshake Core uses.)
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

/* Validate + mempool-accept the staged tx, and on accept relay it to every
 * live peer leg. Returns 1 on accept (relayed), or a negative Core RPC error
 * code on reject (reason filled). peer_fds[i] < 0 entries are skipped. On
 * accept, *relayed_out (if non-NULL) receives the number of legs written to. */
int txsub_accept_and_relay(void* mp_area, const u8* tx, unsigned long len,
                           const int* peer_fds, int n_fds,
                           char* reason, unsigned long rcap, int* relayed_out){
    if (relayed_out) *relayed_out = 0;
    if (reason && rcap) reason[0] = 0;
    if (!tx || len == 0){ if (reason && rcap) snprintf(reason, rcap, "TX decode failed"); return -22; }

    u8 txid[32];
    static u8 scratch[2000*81 + 8];              /* worker is single-threaded */
    if (!tx_txid(txid, tx, len, scratch, sizeof scratch)){
        if (reason && rcap) snprintf(reason, rcap, "TX decode failed"); return -22; }

    long r = tx_accept_validate_reason(mp_area, txid, tx, len, reason, rcap);
    if (r != 1) return (int)r;

    int relayed = 0;
    for (int i = 0; i < n_fds; i++){
        if (peer_fds[i] < 0) continue;
        if (p2p_write(peer_fds[i], "tx", 2, tx, (unsigned)len) > 0) relayed++;
    }
    if (relayed_out) *relayed_out = relayed;
    return 1;
}

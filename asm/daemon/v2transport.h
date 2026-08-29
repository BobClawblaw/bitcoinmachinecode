/* daemon/v2transport.h -- BIP324 v2 transport attached to live sockets.
 *
 * The dispatch itself lives in bitcoin_net.asm (see g_v2_active there): once
 * a socket completes a v2 handshake, p2p_read and p2p_write route through
 * this module for that fd and every existing caller is unchanged. */
#ifndef BMC_V2TRANSPORT_H
#define BMC_V2TRANSPORT_H

#define BMC_NODE_P2P_V2 (1ULL << 11)   /* service bit advertising v2 support */

/* Run the BIP324 handshake on an already-connected socket.
 *   1  = v2 session established; the fd now speaks v2 through p2p_read/write
 *   0  = the peer is v1 (inbound only). Detection peeks rather than reads, so
 *        NOTHING has been taken off the socket and the caller simply carries
 *        on with the v1 path on the same fd.
 *  -1  = the handshake failed; the caller must close the fd
 * `initiator` is 1 for a connection we dialled. An initiator cannot fall back
 * in-band -- it has already put 64 random bytes on the wire, which a v1 peer
 * rejects as a bad magic -- so 0 is never returned for one. */
int bmc_v2_handshake(int fd, int initiator, int timeout_ms);

/* Tear down the session for an fd. Safe on an fd that never had one; must be
 * called before the fd number can be reused, or the next connection to land
 * on that number inherits a dead session. */
void bmc_v2_close(int fd);

/* 1 if this fd is carrying a v2 session. */
int bmc_v2_is_active(int fd);

/* Copy the BIP324 session id for an fd. 1 on success, 0 if the fd has no
 * session. Both peers derive the same 32 bytes, so it is the cheapest way to
 * confirm a handshake agreed with the other side -- Core reports the same
 * value as `session_id` in getpeerinfo. */
int bmc_v2_session_id(int fd, unsigned char out32[32]);

/* How many bytes of decoy garbage to send in a handshake. Randomised per
 * connection; this is only the cap. */
void bmc_v2_set_garbage_max(unsigned max);
#endif

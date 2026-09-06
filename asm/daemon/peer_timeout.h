/* CC-7 / DMN-14: Core -peertimeout -- the time a peer has, from socket open,
 * to complete the version handshake (DEFAULT_PEER_CONNECT_TIMEOUT 60 s). */
#ifndef PEER_TIMEOUT_H
#define PEER_TIMEOUT_H
long peer_handshake_secs(long configured);          /* clamp to [1, 600]; 0/neg -> 60 */
int  peer_handshake_deadline(int fd, long secs);     /* SO_RCVTIMEO + SO_SNDTIMEO; 0 ok */
#endif

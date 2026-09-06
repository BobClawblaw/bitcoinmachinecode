/* daemon/anchors.h -- CC-4 (2026-09-06): block-relay-only outbound legs and
 * Core's anchors.dat.
 *
 * Core keeps 2 outbound connections that send fRelay=0, never announce a
 * transaction and ignore addr gossip: an attacker who owns every full-relay
 * peer still cannot hide a block. On shutdown those two are written to
 * anchors.dat and dialled first on the next start (the file is deleted on
 * read, so a crash loop does not pin the same peers forever). This node had
 * N identical full-relay legs and no anchors. */
#ifndef ANCHORS_H
#define ANCHORS_H
#define LEG_FULL        0
#define LEG_BLOCK_ONLY  1
/* Core net.cpp SerializeFileDB: magic(4) || CompactSize(n) || n x CAddress
 * (V2_DISK: time(4 LE) || services CompactSize || BIP155 net,len,addr || port BE)
 * || sha256d(everything before). Byte-compatible with Core's anchors.dat. */
long anchors_write(const char* path, const char* const* hosts, int n, unsigned magic, unsigned long long services, unsigned now);
long anchors_read(const char* path, char (*hosts)[128], int cap, unsigned magic);   /* deletes the file; -1 on bad file */
/* the fd list the tx announcer and tx poller may use: block-only legs become -1 */
int  legs_relay_fds(const int* fds, const unsigned char* kinds, int n, int* out);
#endif

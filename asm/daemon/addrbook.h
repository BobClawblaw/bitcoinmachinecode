/* daemon/addrbook.h -- the address book, version 2: any BIP155 network.
 *
 * peers2.dat: 16-byte header "BMCADBK2" + u32 count + 4 reserved, then fixed
 * 48-byte records:
 *   [0]     net (BMC_NET_*)      [1]     addr length
 *   [2..33] address bytes        [34..35] port, big-endian (wire form)
 *   [36..43] services u64 LE     [44..47] last_seen u32 LE
 * Dedup key is (net, address, port), as in Core's addrman. The whole book is
 * held in memory (65,536 records = 3 MB) so lookups are O(1) by hash; the
 * file is appended per add and a changed record rewritten in place.
 * FIRST OPEN migrates the legacy 18-byte peers.dat (IPv4 only) into it and
 * leaves the old file untouched; a second open sees peers2.dat and skips.
 * Single-writer discipline is the caller's (the download worker writes; the
 * serve children and the RPC parent open read-only). */
#ifndef BMC_ADDRBOOK_H
#define BMC_ADDRBOOK_H
#include "netaddr.h"

#define AB2_MAX 65536
#define AB2_REC 48
typedef struct {
    bmc_addr_t         a;
    unsigned long long services;
    unsigned           last_seen;
} ab2_rec_t;

typedef struct ab2 ab2_t;
/* open (creating/migrating when rw) the book in `dir` ("." for CWD). NULL on error. */
ab2_t* ab2_open(const char* dir, int rw);
void   ab2_close(ab2_t* b);
long   ab2_count(const ab2_t* b);
long   ab2_count_net(const ab2_t* b, int net);
int    ab2_get(const ab2_t* b, long i, ab2_rec_t* out);        /* 1 / 0 */
long   ab2_find(const ab2_t* b, const bmc_addr_t* a);          /* index or -1 */
/* add or refresh: 1 added, 0 already present (last_seen/services refreshed if
 * newer), -1 error / read-only. When full, the entry with the oldest
 * last_seen is replaced. */
int    ab2_add(ab2_t* b, const bmc_addr_t* a, unsigned long long services, unsigned last_seen);
/* re-read the file if another process grew it (readers call before a scan) */
int    ab2_refresh(ab2_t* b);
/* legacy migration is automatic in ab2_open; exposed for the test */
long   ab2_migrate_legacy(ab2_t* b, const char* legacy_path);
#endif

/* daemon/addrbook.h -- the address book, version 3: any BIP155 network.
 *
 * peers2.dat: 16-byte header "BMCADBK3" + u32 count + 4 reserved, then fixed
 * 56-byte records:
 *   [0]     net (BMC_NET_*)      [1]     addr length
 *   [2..33] address bytes        [34..35] port, big-endian (wire form)
 *   [36..43] services u64 LE     [44..47] last_seen u32 LE
 *   [48..51] source netgroup u32 LE      [52] flags (bit0 AB2_F_TRIED)
 *   [53..55] reserved
 *
 * NET-10 (audit 2026-09-03, scoped in docs/audits/NET-10_ADDRMAN_SCOPE.md).
 * Version 2 evicted the record with the smallest last_seen -- a number the
 * gossiping peer chooses. An attacker's addresses arrive looking fresh and
 * honest ones we have not spoken to recently look stale, so a flood did not
 * merely dilute the book, it preferentially destroyed the once-connected set
 * the dialer draws from. Version 3 stores WHO told us about an address and
 * whether we ever connected to it, which is what the three rules need:
 *   1. a cap on live entries per source netgroup (a single source cannot own
 *      the book however many addresses it sends);
 *   2. a tried entry is never evicted to make room;
 *   3. eviction picks untried-and-terrible first, then untried-oldest, and
 *      only falls back to tried if the book somehow holds nothing else.
 * A v2 file is upgraded in place on first open.
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
#define AB2_REC 56
#define AB2_F_TRIED 1u        /* we have completed a connection to this address */
/* Live entries permitted per source netgroup. Core gives one source group 64
 * of 1024 new-table buckets (6.25%); AB2_MAX/16 is the same share. A source
 * of 0 means "unknown" (our own seeds, the legacy migration, the RPC addnode
 * path) and is never capped. */
#define AB2_SRC_CAP (AB2_MAX/16)
typedef struct {
    bmc_addr_t         a;
    unsigned long long services;
    unsigned           last_seen;
    unsigned           src_group;   /* netgroup of the peer that told us */
    unsigned char      flags;       /* AB2_F_* */
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
/* as ab2_add, but recording which source netgroup supplied the address; the
 * per-source cap applies to it. src_group 0 = unknown, never capped.
 * Returns 1 added, 0 present-or-refused-by-the-cap, -1 error. */
int    ab2_add_from(ab2_t* b, const bmc_addr_t* a, unsigned long long services,
                    unsigned last_seen, unsigned src_group);
/* mark an address as one we have actually connected to: it stops being an
 * eviction candidate and becomes a preferred dial candidate. 1 / 0. */
int    ab2_mark_tried(ab2_t* b, const bmc_addr_t* a);
/* live entries currently attributed to one source netgroup (for the cap and
 * for the tests). */
long   ab2_count_src(const ab2_t* b, unsigned src_group);
/* NET-10 negative control: the per-source cap, overridable so a test can
 * reproduce the pre-fix flood. <= 0 restores AB2_SRC_CAP. */
void   ab2_set_src_cap(long cap);
/* NET-10 tests: shrink the book so eviction is reachable without inserting
 * 65,536 records (eviction rebuilds the hash, so a real full-book flood is
 * ~4e9 operations -- untestable). <= 0 restores AB2_MAX. */
void   ab2_set_capacity(long cap);
/* re-read the file if another process grew it (readers call before a scan) */
int    ab2_refresh(ab2_t* b);
/* legacy migration is automatic in ab2_open; exposed for the test */
long   ab2_migrate_legacy(ab2_t* b, const char* legacy_path);
#endif

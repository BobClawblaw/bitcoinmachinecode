/* daemon/archive_seed.h -- the archive's index is addressed BY HEIGHT: slot h
 * holds block h, and slot 0 therefore holds genesis. Everything downstream
 * assumes it (locator build, catch-up, script-flag heights, the UTXO walk's
 * skip-genesis-coinbase rule, store_read_at itself).
 *
 * A fresh datadir has an empty index, and whichever writer stores the first
 * block decides what lands in slot 0. The parallel downloader starts its span
 * at the archive tip + 1 = 0 and so writes genesis there; the serial leg
 * (node_sync / the leg rotation) appends the first block a PEER sends, which
 * is block 1 -- genesis is not a block any peer relays. The archive is then
 * shifted by one for its whole life: every read of height h returns block
 * h+1, so block h+1's coins are inserted under height h.
 *
 * 2026-09-06: main() seeded genesis only when `g_chainp->id != CHAIN_MAIN`,
 * on the reasoning that the mainnet archive on this box already had genesis
 * from a one-time injection (5f36dee). That is true of THAT archive and of no
 * other: every fresh mainnet sync that did not start with the parallel
 * downloader built a shifted archive. It surfaced as a false `bad-txns-BIP30`
 * -- the next block's coinbase is already in the set, inserted one height
 * early -- the moment the parallel downloader (which writes by height) filled
 * in beside the shifted region.
 *
 * So: seed on EVERY chain, keyed only on the archive being empty.
 *
 * 2026-11-07: "empty" is read from index.dat, not from the handle's tip,
 * which store_init always sets to -1: keyed on the tip, the seed ran on every
 * boot (see archive_seed.c). A cleared record 0, or one naming a later copy
 * of genesis, is pointed at the original copy just before block 1 when that
 * copy is there byte for byte. A non-empty archive leaves the handle
 * reloaded from index.dat (store_reload). */
#ifndef ARCHIVE_SEED_H
#define ARCHIVE_SEED_H
/* 1 = seeded genesis at height 0, 0 = archive not empty (nothing appended;
 * record 0 may have been pointed at the original genesis), -1 = an index
 * read, write or append failed (errno set). */
int archive_seed_genesis_if_empty(void* store_buf, const unsigned char* genesis,
                                  unsigned long genesis_len);
#endif

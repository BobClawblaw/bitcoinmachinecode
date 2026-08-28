/* wallet_scan.h -- the wallet rescan (see wallet_scan.c for why it exists
 * and what the on-disk format is). */
#ifndef WALLET_SCAN_H
#define WALLET_SCAN_H

/* One derived wallet key, by the hash160 that appears in a scriptPubKey.
 * The caller MUST sort the array with wscan_key_cmp before scanning -- the
 * matcher binary-searches it, once per output of every transaction in the
 * chain, and an unsorted array would silently miss matches rather than fail. */
typedef struct {
    unsigned char h160[20];
    unsigned int  keyidx;     /* the <i> in m/84'/0'/0'/<i>/<branch> */
    unsigned char branch;     /* 0 receive, 1 change */
    unsigned char hdkey;      /* WHICH HD key this came from: 0 = the wallet's
                               * own seed, 1..N = a key added by addhdkey.
                               * Without it two HD keys collide on
                               * (keyidx, branch) and a record from one
                               * resolves to the other's address -- the wallet
                               * would then build a spend against the wrong
                               * scriptPubKey. */
} wscan_key;

int wscan_key_cmp(const void* a, const void* b);

/* One wallet event: an output paying us, or an input spending one.
 *
 * A SPEND needs two identities and carrying only one is not enough:
 *   txid/vout  -- the SPENDING transaction and the index of the input's
 *                 outpoint, which is what listsinceblock reports;
 *   prev_txid  -- the txid of the outpoint that was SPENT.
 * Without prev_txid, "is this output still unspent" can only be answered by
 * matching on (vout, key, value), which collides whenever a wallet receives
 * two equal-valued outputs at the same index to the same key -- and a
 * collision there makes coin selection spend an already-spent output, which
 * produces an invalid transaction rather than a wrong number. prev_txid is
 * zero on a receive. */
typedef struct {
    unsigned int  height;
    unsigned char txid[32];   /* WIRE order, as the archive stores it */
    unsigned int  vout;
    unsigned long long value; /* satoshis; for a spend, the value spent */
    unsigned char kind;       /* 0 receive, 1 spend */
    unsigned int  keyidx;
    unsigned char branch;
    unsigned char prev_txid[32];  /* spend only: the outpoint that was spent */
    unsigned char is_coinbase;    /* receive only: the tx was its block's
                                   * first, so the coin needs 100 confirmations
                                   * before it is spendable. Only a format-3
                                   * file carries this; see wscan_flags_known */
    unsigned char hdkey;          /* which HD key owns this output; see
                                   * wscan_key. Only a format-4 file carries
                                   * it, and 0 -- the wallet's own seed -- is
                                   * both the default and what every older
                                   * file means. */
} wscan_rec;

/* 1 when the scan file that produced these records was format 3 or newer and
 * therefore carries a real is_coinbase per record; 0 when it was an older
 * format, where is_coinbase reads 0 for every record because the flag was
 * never stored. A balance that must respect coinbase maturity has to know
 * the difference between "not a coinbase" and "the file cannot say". */
int wscan_flags_known(void);

/* sha256d, supplied by the linking target (bitcoin_hash.o / sha256.o). */
void wscan_sha256d(unsigned char out[32], const void* data, unsigned long len);

/* Walk heights [from, to] and write the record file at out_path.
 *
 * read_block(h, buf, cap) returns the block's length, or < 81 when the block
 * is unavailable -- in which case the scan ABANDONS rather than skipping the
 * height, because a skipped height understates every total derived from the
 * result and the caller cannot tell.
 *
 * own_slots sizes the owned-outpoint set (0 -> 65536). If it fills, the scan
 * fails for the same reason.
 *
 * Returns the record count, or -1 with `err` filled. On failure nothing at
 * out_path is disturbed.
 */
long wscan_run(long from, long to,
               const wscan_key* keys, int nkeys,
               long (*read_block)(long h, unsigned char* buf, long cap),
               unsigned char* blockbuf, long bufcap,
               const char* out_path,
               unsigned long own_slots,
               void (*progress)(long h, long to, void* ctx), void* ctx,
               char* err, unsigned long errcap);

/* Read records back. Returns the count read (0 for an absent, short or
 * magic-less file -- all of which mean "no scan has completed", which is
 * the honest reading). *tip_out gets the highest height the file covers,
 * or -1 when there is no usable file. */
long wscan_read(const char* path, wscan_rec* out, long cap, long* tip_out);

/* Rewrite the whole record file from an array, with the same header-last
 * durability discipline wscan_run uses. Behind importprunedfunds and
 * removeprunedfunds, which edit the record set WITHOUT rescanning the chain.
 * Returns 0, or -1 with `err` filled; on failure `path` is not disturbed. */
int wscan_write(const char* path, const wscan_rec* recs, long n, long tip,
                char* err, unsigned long errcap);

/* The scriptPubKey forms this wallet recognises: P2WPKH, P2PKH, P2SH. Sets
 * *h to the 20-byte hash inside and returns 1, else 0. Exported so callers
 * that decide "is this output ours" outside the scan loop (importprunedfunds)
 * ask the SAME question the scan asks -- a second copy of this would let the
 * two disagree about what the wallet owns. */
int wscan_spk_h160(const unsigned char* spk, unsigned long len,
                   const unsigned char** h);

#endif

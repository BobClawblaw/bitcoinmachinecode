/* utxo_snapshot.h -- Core's assumeutxo snapshot serialization; see the .c. */
#ifndef UTXO_SNAPSHOT_H
#define UTXO_SNAPSHOT_H

/* One coin's serialization (vout | code | amount | compressed script).
 * Returns the byte count, or -1 on an oversized script/buffer. */
long usnap_coin(unsigned int vout, unsigned long height, int coinbase,
                unsigned long long value,
                const unsigned char* spk, unsigned long spklen,
                unsigned char* out, unsigned long cap);

/* The 51-byte file header (magic | version 2 | mainnet magic | base hash |
 * coin count). Returns 51. */
long usnap_header(const unsigned char base_hash_wire[32],
                  unsigned long long coins, unsigned char out[51]);

/* compressor.cpp's CompressAmount, exported for the KATs. */
unsigned long long usnap_compress_amount(unsigned long long n);

#endif

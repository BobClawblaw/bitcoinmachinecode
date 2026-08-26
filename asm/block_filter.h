/* block_filter.h -- BIP158 basic compact block filters (see block_filter.c). */
#ifndef BLOCK_FILTER_H
#define BLOCK_FILTER_H

/* One spent-prevout scriptPubKey (from the block's undo data). */
typedef struct { const unsigned char* script; unsigned long len; } bf_script;

/* Build the BIP158 basic filter for one block. `prevouts` are the spent
 * prevout scripts in any order (the set is hashed and sorted; order cannot
 * matter). Returns the serialized filter length, or -1 on a malformed block
 * or a too-small buffer. */
long bf_basic_build(const unsigned char* block, unsigned long blocklen,
                    const unsigned char block_hash[32],
                    const bf_script* prevouts, unsigned long n_prevouts,
                    unsigned char* out, unsigned long cap);

/* One link of the BIP157 filter-header chain:
 * out = sha256d(sha256d(filter) || prev_header). header(-1) is 32 zeros. */
void bf_header(const unsigned char* filter, unsigned long len,
               const unsigned char prev_header[32], unsigned char out[32]);

#endif

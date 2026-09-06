#include "archive_seed.h"
extern void block_hash(unsigned char out[32], const unsigned char* hdr80);
extern long store_append(void* st, const unsigned char hash[32], const unsigned char* blk, unsigned long len);
/* The store keeps its tip height at +24; -1 means "no blocks at all". */
int archive_seed_genesis_if_empty(void* store_buf, const unsigned char* genesis,
                                  unsigned long genesis_len)
{
    if (*(int*)((char*)store_buf + 24) != -1) return 0;
    unsigned char gh[32];
    block_hash(gh, genesis);
    if (store_append(store_buf, gh, genesis, genesis_len) < 0) return -1;
    return 1;
}

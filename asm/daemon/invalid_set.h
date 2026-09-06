/* daemon/invalid_set.h -- CC-10 (2026-09-06): the operator's invalidated
 * blocks (Core invalidateblock / reconsiderblock). Persisted as raw 32-byte
 * wire-order hashes in <chaindir>/invalid.dat; consulted by the header fetch
 * (a page containing one is refused) and the reorg analyzer (a candidate
 * containing one is refused), so the node stays below the mark until a
 * chain that avoids it is heavier. */
#ifndef INVALID_SET_H
#define INVALID_SET_H
#define INVSET_MAX 64
long invset_load(const char* path);                    /* count, 0 if absent, -1 if unreadable (then empty) */
long invset_save(const char* path);                    /* 0 ok */
int  invset_add(const unsigned char hash[32]);         /* 1 added, 0 already, -1 full */
int  invset_remove(const unsigned char hash[32]);      /* 1 removed, 0 absent */
int  invset_has(const unsigned char hash[32]);
long invset_count(void);
void invset_clear(void);
#endif

/* daemon/banlist.h -- see banlist.c. Core's banlist.json, byte-compatible:
 * the same four keys, the same entry version, the same sweep-on-load. */
#ifndef BANLIST_H
#define BANLIST_H
typedef struct {
    char      subnet[64];
    long long until;      /* unix seconds */
    long long created;
} ban_entry_t;
/* replace banlist.json atomically (tmp + fsync + rename + dir fsync); 0 = ok */
int banlist_save(const ban_entry_t* e, int n);
/* load, dropping already-expired entries; returns how many were handed to add() */
int banlist_load(long long now, int (*add)(const char* subnet, long long until, long long created));
#endif

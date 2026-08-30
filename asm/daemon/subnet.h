/* daemon/subnet.h -- "does this address fall inside that subnet?"
 *
 * ONE implementation, because there were two and one of them was wrong.
 * ctl_ban_covers() in main.c compared dotted-decimal components as STRINGS,
 * which meant:
 *   - any prefix that is not a whole number of octets (/28, /12, /20) was
 *     rejected outright and matched NOTHING, and
 *   - IPv6 was not handled at all.
 * So `setban 2001:db8::/32 add` was accepted, stored, listed by listbanned --
 * and never matched a peer. A ban that silently does nothing is worse than a
 * refused one, because the operator believes the peer is gone.
 *
 * The whitelist work needed correct matching and grew its own copy; two
 * spellings of one rule is how they drift, so both now call this.
 */
#ifndef SUBNET_H
#define SUBNET_H

typedef struct {
    int           family;      /* AF_INET / AF_INET6 */
    unsigned char addr[16];    /* network order, already masked */
    int           bits;
} subnet_t;

/* "addr" or "addr/prefixlen", IPv4 or IPv6; brackets around an IPv6 literal
 * are accepted. No prefix means a full-length (host) match. 1 ok, 0 malformed. */
int subnet_parse(const char* spec, subnet_t* out);

/* 1 if `ip` (printable, optionally bracketed, optionally with an IPv4 :port)
 * lies inside `net`. Families never cross. */
int subnet_covers(const subnet_t* net, const char* ip);

/* Convenience for callers holding the subnet as text (the ban list stores it
 * that way). 0 if the spec does not parse -- a malformed entry matches
 * nothing, which is what the old code did for a DIFFERENT reason. */
int subnet_covers_str(const char* spec, const char* ip);

#endif

/* daemon/netperm.h -- Core's -whitelist peer permissions.
 *
 * Core: NetPermissionFlags (src/net_permissions.h), granted per peer by
 * -whitelist=[<permissions>@]<subnet> and -whitebind. The permission this
 * option is overwhelmingly used for is `noban`: a local wallet, a miner, or a
 * monitoring node must not be disconnected or banned for tripping a
 * misbehaviour heuristic.
 *
 * WHAT THIS NODE HONOURS, AND WHY THE REST IS REFUSED (2026-09-01):
 * noban, relay, forcerelay, mempool, download and addr are enforced --
 * see daemon/relay_policy.c for where each one bites. `bloomfilter` needs
 * BIP37, which this node does not implement, and `out` would apply the
 * entry to the peers we dial, which this node does not do (whitelist is
 * inbound-only here, Core's default direction); both are refused. Accepting those
 * tokens and doing nothing with them is the exact failure this codebase has
 * reproduced repeatedly -- `whitelist=rpc` sat in the live config for weeks
 * doing nothing, and `externalip` and `permitbaremultisig` before it. So an
 * unsupported token is a STARTUP ERROR naming the token, not a warning.
 *
 * A bare `whitelist=<subnet>` (no permissions) means Core's implicit set,
 * which is broader than noban. This node grants noban and says plainly, once,
 * that the rest of the implicit set is not enforced -- silence there would be
 * the same lie in a quieter voice.
 */
#ifndef NETPERM_H
#define NETPERM_H

#define NP_NOBAN      (1u << 0)   /* Core NetPermissionFlags::NoBan (implies download) */
#define NP_RELAY      (1u << 1)   /* Core Relay: accept relayed txs even in -blocksonly (2026-09-01) */
#define NP_FORCERELAY (1u << 2)   /* Core ForceRelay: relay a tx even if already in the mempool    */
#define NP_MEMPOOL    (1u << 3)   /* Core Mempool: may send us `mempool` (we never advertise NODE_BLOOM) */
#define NP_DOWNLOAD   (1u << 4)   /* Core Download: served past -maxuploadtarget (noban implies it)     */
#define NP_ADDR       (1u << 5)   /* Core Addr: unlimited addr gossip / uncached getaddr (see netperm.c) */
/* Core's NetPermissions::ToStrings order: bloomfilter, noban, forcerelay,
 * relay, mempool, download, addr. Fills `out` with up to `cap` static
 * strings, returns the count (getpeerinfo "permissions"). */
int netperm_names(unsigned flags, const char** out, int cap);
/* -whitelistrelay / -whitelistforcerelay: the permissions an entry WITHOUT
 * an explicit perms@ list gets (Core: relay by default, forcerelay off). */
void netperm_set_implicit_defaults(int relay, int forcerelay);

/* Add one -whitelist entry: "[perms@]addr[/prefixlen]", where addr is IPv4 or
 * IPv6. Returns 1 stored, 0 rejected (*err set to a reason for the caller to
 * print). Rejection is meant to stop the node starting. */
int netperm_add(const char* spec, const char** err);

/* Permission flags for a peer address, 0 if it matches no entry. `ip` is the
 * printable form this node already carries for a peer ("1.2.3.4", "::1", or
 * "[::1]"). */
unsigned netperm_for(const char* ip);

/* Entries configured (0 = the option was never given). */
int netperm_count(void);

/* 1 if any entry was given WITHOUT explicit permissions. Core would grant its
 * implicit set there; this node grants only noban, and the caller says so
 * once at boot rather than leaving the operator to assume otherwise. */
int netperm_has_implicit(void);

/* Drop every entry. For tests; the daemon configures once at boot. */
void netperm_reset(void);


/* ---------------------------------------------------------------- whitebind
 * Core -whitebind=[permissions@]<addr>:<port>: bind an ADDITIONAL listener and
 * grant every peer that arrives on it those permissions.
 *
 * The distinction from -whitelist is the whole point: whitelist grants by the
 * PEER's address, whitebind by WHICH SOCKET accepted the connection. This node
 * already establishes one property that way -- a peer accepted on the onion
 * service's loopback target IS an onion peer, because its source address is
 * always 127.0.0.1 and tells you nothing. whitebind is the same shape, and is
 * the only way to grant permissions to a peer whose address you cannot
 * predict (behind NAT, or reaching you over a tunnel).
 *
 * Same permission scope as -whitelist: `noban` is enforced, every other Core
 * token is a startup error naming it. */
#define NETPERM_MAX_BIND 8

/* Parse and store one -whitebind. 1 stored, 0 rejected (*err set). */
int netperm_whitebind_add(const char* spec, const char** err);

int netperm_whitebind_count(void);
/* Listener i: its bind address (printable), port, and granted flags. */
const char* netperm_whitebind_addr(int i);
int         netperm_whitebind_port(int i);
unsigned    netperm_whitebind_flags(int i);

/* Record that a listening fd grants `flags`, then look it up on accept. -1
 * clears. Keyed by fd because that is what the accept loop holds. */
void     netperm_bind_fd(int fd, unsigned flags);
unsigned netperm_for_fd(int fd);

#endif

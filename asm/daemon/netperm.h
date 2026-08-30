/* daemon/netperm.h -- Core's -whitelist peer permissions.
 *
 * Core: NetPermissionFlags (src/net_permissions.h), granted per peer by
 * -whitelist=[<permissions>@]<subnet> and -whitebind. The permission this
 * option is overwhelmingly used for is `noban`: a local wallet, a miner, or a
 * monitoring node must not be disconnected or banned for tripping a
 * misbehaviour heuristic.
 *
 * WHAT THIS NODE HONOURS, AND WHY THE REST IS REFUSED. Only `noban` is
 * enforced here. Every other flag Core defines needs an enforcement point
 * that either does not exist in this node (bloomfilter -- BIP37 is not
 * implemented, BIP157/158 is) or has not been wired yet. Accepting those
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

#define NP_NOBAN      (1u << 0)   /* Core NetPermissionFlags::NoBan   */

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

#endif

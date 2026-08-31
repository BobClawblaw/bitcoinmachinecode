/* daemon/rpc_acl.h -- Core's -rpcallowip / -rpcbind, faithfully.
 *
 * Both were on the unimplemented list, and the note beside them said the RPC
 * surface was "lower urgency now that cookie auth exists and the listener
 * cannot leave loopback". That reads as though loopback-only were a designed
 * safety property. It is not -- it is what you get when -rpcbind is not
 * implemented, and Core supports both options with its OWN guardrail:
 *
 *   - the allow list ALWAYS contains 127.0.0.0/8 and ::1, before any
 *     -rpcallowip entry is added (httpserver.cpp InitHTTPAllowList);
 *   - an invalid -rpcallowip subnet is a startup ERROR, not a warning;
 *   - -rpcbind is IGNORED, with a warning, when no -rpcallowip was given:
 *     "refusing to allow everyone to connect" (httpserver.cpp:225).
 *
 * So implementing them does not weaken the default: with no configuration the
 * server still binds loopback and accepts only loopback. What changes is that
 * an operator who wants remote RPC can now say so, and cannot say half of it.
 */
#ifndef RPC_ACL_H
#define RPC_ACL_H

/* Reset to Core's base list: 127.0.0.0/8 and ::1, always allowed. Call once
 * before adding configured entries. */
void rpc_acl_reset(void);

/* Add one -rpcallowip subnet. 1 stored, 0 malformed (the caller should refuse
 * to start, as Core does -- a typo'd ACL that silently allows less than
 * intended is a support call; one that silently allows MORE is an incident,
 * and refusing avoids having to reason about which it was). */
int rpc_acl_add(const char* spec);

/* 1 if this peer address may talk to the RPC server. */
int rpc_acl_allows(const char* ip);

/* How many -rpcallowip entries were configured (excludes the base loopback
 * entries). Zero means -rpcbind must be ignored, per Core. */
int rpc_acl_configured(void);

#endif

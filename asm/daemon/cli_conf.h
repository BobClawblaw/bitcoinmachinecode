/* daemon/cli_conf.h -- where bitcoin_cli finds the port and the credentials.
 *
 * WHY THIS EXISTS. bitcoin_cli hardcoded port 8332 and the credentials
 * "bitcoin"/"bitcoin", and read neither the config file nor the cookie the
 * daemon writes. Against this node's own live configuration -- RPC on 8331,
 * P2P on 8332, cookie auth -- a bare `bitcoin_cli getblockcount` therefore
 * opened an HTTP POST against the P2P LISTENER and reported
 *
 *     error: malformed HTTP reply
 *
 * which reads as "the RPC server is down" when the server is fine and the
 * client dialled the wrong socket. On the right port it then failed auth and
 * said "malformed JSON-RPC reply", which reads the same way. Two different
 * client-side mistakes, both indistinguishable from a dead server.
 *
 * It was broken for every non-default configuration, not just this one: the
 * port was hardcoded to mainnet's, so regtest, testnet4 and signet nodes were
 * all unreachable without -rpcport.
 */
#ifndef CLI_CONF_H
#define CLI_CONF_H

typedef struct {
    int  port;
    char user[128];
    char pass[256];
    char cookie_path[512];   /* where the cookie was looked for, for errors */
    char chain[16];
    int  from_cookie;        /* credentials came from the cookie file */
} cli_conf_t;

/* Resolve the endpoint the way the daemon would describe it:
 *   1. `chain` from the config file unless overridden.
 *   2. `rpcport` from the config file; otherwise that chain's default.
 *   3. rpcuser/rpcpassword from the config file; otherwise the cookie at
 *      rpccookiefile, else <datadir>/[<chain>/].cookie -- mainnet lives at the
 *      datadir root and every other chain in a subdirectory, exactly as
 *      chainparams_datadir lays it out.
 * `datadir` may be NULL (then only the defaults and overrides apply).
 * Returns 1 if credentials were found, 0 if not (*err set; the caller should
 * say so rather than send "bitcoin"/"bitcoin" and get a 401). */
int cli_conf_resolve(const char* datadir, const char* chain_override,
                     cli_conf_t* out, const char** err);

/* That chain's default RPC port (Core's), or 0 for an unknown name. */
int cli_conf_default_rpcport(const char* chain);

#endif

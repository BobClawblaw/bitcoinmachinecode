/* daemon/torcontrol.h -- create this node's onion service through tor's
 * control port, the way Core's torcontrol.cpp does: PROTOCOLINFO, then
 * AUTHENTICATE with the cookie file it names (or a password), then
 * ADD_ONION with a persisted ED25519-V3 private key so the .onion address
 * is the same across restarts (Core keeps it in onion_v3_private_key; so do
 * we, same name). The virtual port is the chain's default P2P port -- Core:
 * "always the default port to avoid decloaking nodes using other ports" --
 * mapped to a local target address:port.
 * The control connection must stay OPEN: tor removes an ephemeral service
 * when the controller that added it disconnects. */
#ifndef BMC_TORCONTROL_H
#define BMC_TORCONTROL_H
typedef struct {
    int  fd;                      /* the live control connection, or -1 */
    char onion[80];               /* "<56>.onion" once created */
    char err[160];
} torctl_t;
/* Returns 1 with t->onion set and t->fd kept open, 0 on failure (t->err says
 * why). `password` may be NULL (cookie auth via the file PROTOCOLINFO names;
 * `cookie_override` replaces that path when non-NULL, for tests). */
int  torctl_add_onion(torctl_t* t, const char* ctrl_ip, int ctrl_port,
                      const char* password, const char* cookie_override,
                      int virtual_port, const char* target /* "127.0.0.1:port" */,
                      const char* keyfile, int timeout_ms);
void torctl_close(torctl_t* t);
#endif

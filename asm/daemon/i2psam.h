/* daemon/i2psam.h -- I2P transport over the SAM v3.1 bridge (i2pd/java
 * router on 127.0.0.1:7656), the shape Core's i2p.cpp uses.
 *
 * A SAM session is one control socket that must STAY OPEN for the session's
 * life; each stream (outbound CONNECT or inbound ACCEPT) is its own socket
 * that says HELLO, names the session id, and then carries raw data.
 *   session:  HELLO VERSION MIN=3.1 MAX=3.1
 *             SESSION CREATE STYLE=STREAM ID=<id> DESTINATION=<key|TRANSIENT>
 *                     SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4,0 ...
 *   dial:     HELLO; STREAM CONNECT ID=<id> DESTINATION=<b64 dest> SILENT=false
 *   accept:   HELLO; STREAM ACCEPT ID=<id> SILENT=false
 *             -> first line after RESULT=OK is the PEER's destination (b64)
 * A .b32.i2p name is base32(sha256(destination bytes)); the router resolves
 * one with NAMING LOOKUP. I2P uses base64 with '-' and '~' for '+' and '/'.
 * The private key is persisted in i2p_private_key (Core's file name) so the
 * node keeps one address across restarts. */
#ifndef BMC_I2PSAM_H
#define BMC_I2PSAM_H
typedef struct {
    int  ctrl;                 /* the session control socket, kept open */
    char id[32];               /* session id */
    char b32[80];              /* our own <52>.b32.i2p */
    char err[192];
} i2psam_t;
/* create (or resume, from `keyfile`) a STREAM session. 1 ok / 0 err. */
int  i2psam_session(i2psam_t* s, const char* sam_ip, int sam_port,
                    const char* keyfile, int timeout_ms);
void i2psam_close(i2psam_t* s);
/* dial a .b32.i2p name (or a full b64 destination); returns the stream fd. */
int  i2psam_connect(i2psam_t* s, const char* sam_ip, int sam_port,
                    const char* dest_or_b32, int timeout_ms, char* err, long errcap);
/* accept one inbound stream; peer_b32 (>=80) gets the caller's .b32.i2p. */
int  i2psam_accept(i2psam_t* s, const char* sam_ip, int sam_port,
                   char* peer_b32, long cap, int timeout_ms);
/* the .b32.i2p name of a base64 destination (test/utility) */
int  i2psam_dest_to_b32(char* out, long cap, const char* dest_b64);
#endif

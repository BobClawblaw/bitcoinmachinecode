/* daemon/torcontrol.c -- see torcontrol.h. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>
#include "torcontrol.h"
#include "netaddr.h"

extern int tcp_connect_ip(unsigned ip_netorder, unsigned short port_be);

/* read control-protocol reply lines until the final "250 " / "5xx " line;
 * returns the status code (0 on I/O failure). `buf` collects all lines. */
static int read_reply(int fd, char* buf, long cap, int timeout_ms){
    long o = 0; int code = 0;
    for (;;){
        char line[1024]; long l = 0;
        for (;;){
            struct pollfd pf = { fd, POLLIN, 0 };
            if (poll(&pf, 1, timeout_ms) <= 0) return 0;
            char c; long r = read(fd, &c, 1);
            if (r <= 0){ if (r < 0 && errno == EINTR) continue; return 0; }
            if (c == '\n') break;
            if (c != '\r' && l < (long)sizeof line - 1) line[l++] = c;
        }
        line[l] = 0;
        if (o + l + 2 < cap){ memcpy(buf + o, line, (size_t)l); o += l; buf[o++] = '\n'; buf[o] = 0; }
        if (l >= 4 && line[3] == ' '){ code = atoi(line); break; }   /* final line: "250 OK" */
        if (l < 4) return 0;
    }
    return code;
}
static int send_cmd(int fd, const char* cmd, int timeout_ms){
    long n = (long)strlen(cmd);
    struct pollfd pf = { fd, POLLOUT, 0 };
    if (poll(&pf, 1, timeout_ms) <= 0) return 0;
    return write(fd, cmd, (size_t)n) == n;
}
static int hexbyte(unsigned char b, char* o){ static const char* H = "0123456789ABCDEF"; o[0] = H[b >> 4]; o[1] = H[b & 15]; return 2; }
/* find "KEY=" in a reply and copy its (possibly quoted) value */
static int reply_value(const char* reply, const char* key, char* out, long cap){
    const char* p = strstr(reply, key); if (!p) return 0;
    p += strlen(key);
    int q = (*p == '"'); if (q) p++;
    long n = 0;
    while (*p && n < cap - 1 && (q ? *p != '"' : (*p != ' ' && *p != '\n'))) out[n++] = *p++;
    out[n] = 0; return n > 0;
}
/* tor's control protocol quotes the cookie path with C-style escapes; we
 * handle the plain case (no escapes), which is what tor emits for normal
 * paths */
static int read_file(const char* path, unsigned char* out, long cap){
    int fd = open(path, O_RDONLY); if (fd < 0) return -1;
    long n = read(fd, out, (size_t)cap); close(fd); return (int)n;
}

int torctl_add_onion(torctl_t* t, const char* ctrl_ip, int ctrl_port,
                     const char* password, const char* cookie_override,
                     int virtual_port, const char* target,
                     const char* keyfile, int timeout_ms){
    t->fd = -1; t->onion[0] = 0; t->err[0] = 0;
    unsigned ip; if (inet_pton(AF_INET, ctrl_ip, &ip) != 1){ snprintf(t->err, sizeof t->err, "bad control address"); return 0; }
    int fd = tcp_connect_ip(ip, htons((unsigned short)ctrl_port));
    if (fd < 0){ snprintf(t->err, sizeof t->err, "cannot connect to tor control port %s:%d", ctrl_ip, ctrl_port); return 0; }
    static char reply[8192];
    /* 1. PROTOCOLINFO: which auth methods, where the cookie is */
    if (!send_cmd(fd, "PROTOCOLINFO 1\r\n", timeout_ms) || read_reply(fd, reply, sizeof reply, timeout_ms) != 250){
        snprintf(t->err, sizeof t->err, "PROTOCOLINFO failed"); close(fd); return 0; }
    char methods[128] = {0}, cookiefile[512] = {0};
    reply_value(reply, "METHODS=", methods, sizeof methods);
    reply_value(reply, "COOKIEFILE=", cookiefile, sizeof cookiefile);
    /* 2. AUTHENTICATE */
    char cmd[2048];
    if (password && *password && strstr(methods, "HASHEDPASSWORD")){
        snprintf(cmd, sizeof cmd, "AUTHENTICATE \"%s\"\r\n", password);
    } else if (strstr(methods, "COOKIE") || cookie_override){
        const char* path = cookie_override ? cookie_override : cookiefile;
        unsigned char cookie[64]; int n = read_file(path, cookie, sizeof cookie);
        if (n != 32){ snprintf(t->err, sizeof t->err, "cannot read the tor auth cookie %s (%d bytes)", path, n); close(fd); return 0; }
        char hex[65]; for (int i = 0; i < 32; i++) hexbyte(cookie[i], hex + 2*i); hex[64] = 0;
        snprintf(cmd, sizeof cmd, "AUTHENTICATE %s\r\n", hex);
    } else if (strstr(methods, "NULL")){
        snprintf(cmd, sizeof cmd, "AUTHENTICATE\r\n");
    } else { snprintf(t->err, sizeof t->err, "no usable tor auth method (%s)", methods); close(fd); return 0; }
    if (!send_cmd(fd, cmd, timeout_ms) || read_reply(fd, reply, sizeof reply, timeout_ms) != 250){
        snprintf(t->err, sizeof t->err, "tor AUTHENTICATE rejected: %.100s", reply); close(fd); return 0; }
    /* 3. ADD_ONION with the persisted key, or NEW:ED25519-V3 the first time */
    char key[1024] = {0};
    { int n = read_file(keyfile, (unsigned char*)key, sizeof key - 1);
      if (n > 0){ key[n] = 0; char* nl = strchr(key, '\n'); if (nl) *nl = 0; } else key[0] = 0; }
    snprintf(cmd, sizeof cmd, "ADD_ONION %s Port=%d,%s\r\n", key[0] ? key : "NEW:ED25519-V3", virtual_port, target);
    if (!send_cmd(fd, cmd, timeout_ms) || read_reply(fd, reply, sizeof reply, timeout_ms) != 250){
        snprintf(t->err, sizeof t->err, "ADD_ONION failed: %.100s", reply); close(fd); return 0; }
    char sid[80] = {0}, priv[1024] = {0};
    reply_value(reply, "ServiceID=", sid, sizeof sid);
    reply_value(reply, "PrivateKey=", priv, sizeof priv);
    if (strlen(sid) != 56){ snprintf(t->err, sizeof t->err, "ADD_ONION returned no v3 ServiceID"); close(fd); return 0; }
    snprintf(t->onion, sizeof t->onion, "%s.onion", sid);
    /* the address must parse as a valid v3 onion (checksum) -- a controller
     * that hands us garbage must not be announced */
    bmc_addr_t a;
    if (!bmc_addr_from_string(&a, t->onion) || a.net != BMC_NET_TORV3){
        snprintf(t->err, sizeof t->err, "ADD_ONION ServiceID is not a valid v3 onion: %s", t->onion); t->onion[0] = 0; close(fd); return 0; }
    if (!key[0] && priv[0]){
        int kf = open(keyfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (kf >= 0){ (void)!write(kf, priv, strlen(priv)); (void)!write(kf, "\n", 1); close(kf); }
    }
    t->fd = fd;
    return 1;
}
void torctl_close(torctl_t* t){ if (t->fd >= 0) close(t->fd); t->fd = -1; }

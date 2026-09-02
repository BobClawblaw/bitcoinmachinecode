/* daemon/i2psam.c -- see i2psam.h. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>
#include "i2psam.h"
#include "../base32.h"

extern int  tcp_connect_ip(unsigned ip_netorder, unsigned short port_be);
extern void sha256_full(unsigned char* out, const void* msg, long len);   /* sha256.asm */

/* I2P's base64 alphabet: standard, with '-' for '+' and '~' for '/' */
static int b64val(char c){
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '~' || c == '/') return 63;
    return -1;
}
static long i2p_b64decode(unsigned char* out, long cap, const char* s){
    long o = 0; unsigned acc = 0; int bits = 0;
    for (; *s && *s != '='; s++){
        int v = b64val(*s); if (v < 0) return -1;
        acc = (acc << 6) | (unsigned)v; bits += 6;
        if (bits >= 8){ bits -= 8; if (o >= cap) return -1; out[o++] = (unsigned char)((acc >> bits) & 0xff); }
    }
    return o;
}
int i2psam_dest_to_b32(char* out, long cap, const char* dest_b64){
    static unsigned char raw[4096];
    long n = i2p_b64decode(raw, sizeof raw, dest_b64);
    if (n < 387 || cap < 62) return 0;
    unsigned char h[32]; sha256_full(h, raw, n);
    long l = base32_encode(out, h, 32);
    memcpy(out + l, ".b32.i2p", 9);
    return 1;
}
static int send_line(int fd, const char* s, int timeout_ms){
    long n = (long)strlen(s);
    struct pollfd pf = { fd, POLLOUT, 0 };
    if (poll(&pf, 1, timeout_ms) <= 0) return 0;
    return write(fd, s, (size_t)n) == n;
}
/* SAM replies are one '\n'-terminated line */
static int read_line(int fd, char* b, long cap, int timeout_ms){
    long n = 0;
    for (;;){
        struct pollfd pf = { fd, POLLIN, 0 };
        if (poll(&pf, 1, timeout_ms) <= 0) return 0;
        char c; long r = read(fd, &c, 1);
        if (r <= 0){ if (r < 0 && errno == EINTR) continue; return 0; }
        if (c == '\n') break;
        if (n < cap - 1) b[n++] = c;
    }
    b[n] = 0; return 1;
}
static int reply_val(const char* line, const char* key, char* out, long cap){
    const char* p = strstr(line, key); if (!p) return 0;
    p += strlen(key);
    int q = (*p == '"'); if (q) p++;
    long n = 0;
    while (*p && n < cap - 1 && (q ? *p != '"' : *p != ' ')) out[n++] = *p++;
    out[n] = 0; return n > 0;
}
static int hello(int fd, int timeout_ms){
    char l[512];
    if (!send_line(fd, "HELLO VERSION MIN=3.1 MAX=3.1\n", timeout_ms)) return 0;
    if (!read_line(fd, l, sizeof l, timeout_ms)) return 0;
    return strstr(l, "RESULT=OK") != NULL;
}
static int sam_open(const char* ip, int port, int timeout_ms){
    unsigned a; if (inet_pton(AF_INET, ip, &a) != 1) return -1;
    int fd = tcp_connect_ip(a, htons((unsigned short)port));
    if (fd < 0) return -1;
    if (!hello(fd, timeout_ms)){ close(fd); return -1; }
    return fd;
}
int i2psam_session(i2psam_t* s, const char* sam_ip, int sam_port, const char* keyfile, int timeout_ms){
    memset(s, 0, sizeof *s); s->ctrl = -1;
    int fd = sam_open(sam_ip, sam_port, timeout_ms);
    if (fd < 0){ snprintf(s->err, sizeof s->err, "cannot reach the SAM bridge at %s:%d", sam_ip, sam_port); return 0; }
    static char key[4096]; key[0] = 0;
    { int kf = open(keyfile, O_RDONLY);
      if (kf >= 0){ long n = read(kf, key, sizeof key - 1); close(kf); if (n > 0){ key[n] = 0; char* nl = strchr(key, '\n'); if (nl) *nl = 0; } else key[0] = 0; } }
    snprintf(s->id, sizeof s->id, "bmc-%d", (int)getpid());
    static char cmd[8192];
    snprintf(cmd, sizeof cmd,
             "SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s SIGNATURE_TYPE=7 "
             "i2cp.leaseSetEncType=4,0 inbound.quantity=3 outbound.quantity=3\n",
             s->id, key[0] ? key : "TRANSIENT");
    static char line[8192];
    if (!send_line(fd, cmd, timeout_ms) || !read_line(fd, line, sizeof line, timeout_ms)){
        snprintf(s->err, sizeof s->err, "SESSION CREATE: no reply"); close(fd); return 0; }
    if (!strstr(line, "RESULT=OK")){
        snprintf(s->err, sizeof s->err, "SESSION CREATE: %.150s", line); close(fd); return 0; }
    static char dest[4096];
    if (!reply_val(line, "DESTINATION=", dest, sizeof dest)){
        /* resuming from a key: the router echoes no DESTINATION, so use ours */
        snprintf(dest, sizeof dest, "%s", key);
    } else if (!key[0]){
        int kf = open(keyfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (kf >= 0){ (void)!write(kf, dest, strlen(dest)); (void)!write(kf, "\n", 1); close(kf); }
    }
    if (!i2psam_dest_to_b32(s->b32, sizeof s->b32, dest)){
        snprintf(s->err, sizeof s->err, "cannot derive our .b32.i2p from the destination"); close(fd); return 0; }
    s->ctrl = fd;
    return 1;
}
void i2psam_close(i2psam_t* s){ if (s->ctrl >= 0) close(s->ctrl); s->ctrl = -1; }
int i2psam_connect(i2psam_t* s, const char* sam_ip, int sam_port, const char* dest_or_b32,
                   int timeout_ms, char* err, long errcap){
    if (err && errcap) err[0] = 0;
    int fd = sam_open(sam_ip, sam_port, timeout_ms);
    if (fd < 0){ if (err) snprintf(err, errcap, "SAM unreachable"); return -1; }
    static char cmd[8192], line[8192];
    snprintf(cmd, sizeof cmd, "STREAM CONNECT ID=%s DESTINATION=%s SILENT=false\n", s->id, dest_or_b32);
    if (!send_line(fd, cmd, timeout_ms) || !read_line(fd, line, sizeof line, timeout_ms)){
        if (err) snprintf(err, errcap, "STREAM CONNECT: no reply");
        close(fd); return -1; }
    if (!strstr(line, "RESULT=OK")){
        if (err) snprintf(err, errcap, "%.150s", line);
        close(fd); return -1; }
    return fd;
}
int i2psam_accept(i2psam_t* s, const char* sam_ip, int sam_port, char* peer_b32, long cap, int timeout_ms){
    int fd = sam_open(sam_ip, sam_port, timeout_ms);
    if (fd < 0) return -1;
    static char cmd[512], line[8192];
    snprintf(cmd, sizeof cmd, "STREAM ACCEPT ID=%s SILENT=false\n", s->id);
    if (!send_line(fd, cmd, timeout_ms) || !read_line(fd, line, sizeof line, timeout_ms)){ close(fd); return -1; }
    if (!strstr(line, "RESULT=OK")){ close(fd); return -1; }
    /* the NEXT line, when a peer arrives, is that peer's destination */
    if (!read_line(fd, line, sizeof line, timeout_ms)){ close(fd); return -1; }
    if (peer_b32 && cap) { peer_b32[0] = 0; i2psam_dest_to_b32(peer_b32, cap, line); }
    return fd;
}

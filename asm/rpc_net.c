/* rpc_net.c -- JSON-RPC 2.0 framing + HTTP POST transport.
 */
#include "rpc_net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>

/* ---------------- base64 (RFC 4648) for HTTP Basic auth ---------------- */
static void base64_encode(const char* in, size_t n, char* out) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned a = (unsigned char)in[i];
        unsigned b = (i + 1 < n) ? (unsigned char)in[i+1] : 0;
        unsigned c = (i + 2 < n) ? (unsigned char)in[i+2] : 0;
        out[o++] = tbl[a >> 2];
        out[o++] = tbl[((a & 3) << 4) | (b >> 4)];
        out[o++] = (i + 1 < n) ? tbl[((b & 15) << 2) | (c >> 6)] : '=';
        out[o++] = (i + 2 < n) ? tbl[c & 63] : '=';
    }
    out[o] = 0;
}

/* ---------------- rpc_request_build ---------------- */
rj_val* rpc_request_build(const char* method, rj_val* params, long id) {
    rj_val* req = rj_obj();
    rj_obj_set(req, "jsonrpc", rj_str("2.0"));
    rj_obj_set(req, "id", rj_numf("%ld", id));
    rj_obj_set(req, "method", rj_str(method));
    rj_obj_set(req, "params", params ? params : rj_arr());
    return req;
}

/* ---------------- rpc_reply_parse ---------------- */
int rpc_reply_parse(const char* body, size_t len, rpc_reply* r) {
    memset(r, 0, sizeof(*r));
    rj_val* doc = rj_parse(body, len);
    if (!doc || doc->typ != RJ_OBJ) { if (doc) rj_free(doc); return 0; }
    rj_val* id = rj_obj_get(doc, "id");
    if (id && id->typ == RJ_NUM) { r->has_id = 1; r->id = strtol(id->str, NULL, 10); }
    rj_val* err = rj_obj_get(doc, "error");
    if (err && !(err->typ == RJ_NULL)) {
        r->is_error = 1;
        rj_val* code = rj_obj_get(err, "code");
        if (code && code->typ == RJ_NUM) r->error_code = strtol(code->str, NULL, 10);
        rj_val* msg = rj_obj_get(err, "message");
        if (msg && msg->typ == RJ_STR) r->error_message = strdup(msg->str);
    }
    rj_val* res = rj_obj_get(doc, "result");
    /* result field is present when error is null (Core omits result on error). */
    r->result = NULL;
    if (!r->is_error && res) {
        /* deep-copy the result subtree so the caller owns it independently */
        char tmp[65536];
        long w = rj_write(tmp, sizeof tmp, res, 0);
        if (w > 0 && w < (long)sizeof tmp) r->result = rj_parse(tmp, (size_t)w);
    }
    rj_free(doc);
    return 1;
}

void rpc_reply_free(rpc_reply* r) {
    if (r->result) rj_free(r->result);
    free(r->error_message);
    memset(r, 0, sizeof(*r));
}

/* ---------------- rpc_http_post ---------------- */
static int sock_connect_loopback(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    /* client-side timeouts (2026-08-31): a stuck server used to hang the CLI
     * forever -- a timeout-less bitcoin_cli deadlocked a whole diagnostic
     * sweep. 10 s to connect, 60 s per read/write. */
    { struct timeval tv = { 60, 0 };
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv); }
    { int fl = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, fl | O_NONBLOCK);
      int cr = connect(fd, (struct sockaddr*)&a, sizeof a);
      if (cr < 0 && errno == EINPROGRESS){
          struct pollfd pf = { fd, POLLOUT, 0 };
          if (poll(&pf, 1, 10000) <= 0){ close(fd); return -1; }
          int se = 0; socklen_t sl = sizeof se;
          if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &se, &sl) != 0 || se != 0){ close(fd); return -1; }
      } else if (cr < 0){ close(fd); return -1; }
      fcntl(fd, F_SETFL, fl); }
    return fd;
}

static long sock_read_all(int fd, char* out, long cap) {
    long total = 0;
    while (total < cap) {
        long n = read(fd, out + total, (size_t)(cap - total));
        if (n < 0) return total ? total : -1;
        if (n == 0) break;
        total += n;
    }
    return total;
}

long rpc_http_post(int port, const char* user, const char* pass,
                   const char* body, long bodylen,
                   char* out, long outcap, char* errmsg, size_t errcap) {
    int fd = sock_connect_loopback(port);
    if (fd < 0) {
        if (errmsg && errcap) snprintf(errmsg, errcap, "couldn't connect to server (port %d)", port);
        return -1;
    }
    /* Authorization: Basic base64(user:pass) */
    size_t ul = strlen(user), pl = strlen(pass);
    char* cred = malloc(ul + pl + 2);
    if (!cred) { close(fd); return -1; }
    memcpy(cred, user, ul);
    cred[ul] = ':';
    memcpy(cred + ul + 1, pass, pl);
    cred[ul + pl + 1] = 0;
    size_t b64len = ((ul + pl + 1 + 2) / 3) * 4;
    char* b64 = malloc(b64len + 1);
    if (!b64) { free(cred); close(fd); return -1; }
    base64_encode(cred, ul + pl + 1, b64);
    free(cred);

    char head[512];
    int hl = snprintf(head, sizeof head,
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "\r\n", port, b64, bodylen);
    free(b64);
    if (write(fd, head, (size_t)hl) != hl) { close(fd); return -1; }
    if (write(fd, body, (size_t)bodylen) != bodylen) { close(fd); return -1; }

    char* resp = malloc(outcap + 1);
    if (!resp) { close(fd); return -1; }
    long total = sock_read_all(fd, resp, outcap);
    close(fd);
    if (total < 0) { free(resp); if (errmsg && errcap) snprintf(errmsg, errcap, "read error"); return -1; }
    resp[total] = 0;

    /* A reply that is not HTTP at all almost always means the client dialled
     * a non-HTTP service -- on this node, typically the P2P listener, whose
     * port sits one below the RPC port in the shipped config. Saying
     * "malformed HTTP reply" there sends the operator to look at the daemon,
     * which is fine; the port is the problem. */
    if (total > 0 && strncmp(resp, "HTTP/", 5) != 0){
        free(resp);
        if (errmsg && errcap)
            snprintf(errmsg, errcap,
                     "port %d answered but did not speak HTTP -- is that the "
                     "P2P port rather than the RPC port?", port);
        return -1;
    }
    /* 401 is an authentication failure, not a malformed anything. */
    if (total > 12 && !strncmp(resp + 9, "401", 3)){
        free(resp);
        if (errmsg && errcap)
            snprintf(errmsg, errcap,
                     "authentication failed (HTTP 401) on port %d -- wrong "
                     "rpcuser/rpcpassword, or the cookie was not read", port);
        return -1;
    }

    /* Split headers/body at \r\n\r\n */
    char* sep = strstr(resp, "\r\n\r\n");
    if (!sep) { free(resp); if (errmsg && errcap) snprintf(errmsg, errcap, "malformed HTTP reply"); return -1; }
    char* b = sep + 4;
    long blen = total - (long)(b - resp);
    /* Honor Content-Length if present, else use remainder. */
    char* cl = strstr(resp, "Content-Length:");
    if (cl && cl < sep) {
        long clv = strtol(cl + 15, NULL, 10);
        if (clv >= 0 && clv < blen) blen = clv;
    }
    if (blen > outcap) blen = outcap;
    memcpy(out, b, (size_t)blen);
    out[blen] = 0;
    free(resp);
    return blen;
}

/* ---------------- http_request_parse ---------------- */
int http_request_parse(const char* buf, size_t len,
                       const char** method, size_t* method_len,
                       const char** path, size_t* path_len,
                       const char** body, size_t* body_len) {
    /* find \r\n\r\n */
    const char* hdrend = NULL;
    for (size_t i = 0; i + 3 < len; i++)
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') { hdrend = buf + i; break; }
    if (!hdrend) return 0;
    const char* line_end = memchr(buf, '\r', (size_t)(hdrend - buf));
    if (!line_end) return 0;
    /* request line: METHOD SP PATH SP HTTP/x.y */
    const char* sp1 = memchr(buf, ' ', (size_t)(line_end - buf));
    if (!sp1) return 0;
    const char* sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - (sp1 + 1)));
    if (!sp2) return 0;
    if (method) *method = buf;
    if (method_len) *method_len = (size_t)(sp1 - buf);
    if (path) *path = sp1 + 1;
    if (path_len) *path_len = (size_t)(sp2 - (sp1 + 1));
    if (body) *body = hdrend + 4;
    if (body_len) *body_len = len - (size_t)((hdrend + 4) - buf);
    return 1;
}

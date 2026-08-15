/* rpc_server.c -- HTTP JSON-RPC 2.0 server endpoint (daemon side).
 *
 * See rpc_server.h for the Core-behavior contract. This module owns the
 * sockets + threading; request rendering flows through the shared
 * rpc_dispatch() so the server can never diverge from the client.
 */
#include "rpc_server.h"
#include "rpc_net.h"
#include "rpc_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ---- JSON-RPC error codes (Core src/rpc/protocol.h) ---- */
#define RPC_INVALID_REQUEST  -32600
#define RPC_METHOD_NOT_FOUND -32601
#define RPC_PARSE_ERROR      -32700

/* ---- HTTP status codes (Core src/rpc/protocol.h) ---- */
#define HTTP_OK                200
#define HTTP_NO_CONTENT        204
#define HTTP_BAD_REQUEST       400
#define HTTP_UNAUTHORIZED      401
#define HTTP_NOT_FOUND         404
#define HTTP_BAD_METHOD        405
#define HTTP_INTERNAL_SERVER_ERROR 500

#define WWW_AUTH_HEADER "Basic realm=\"jsonrpc\""

/* ---- server state (single instance) ---- */
static int  g_listen_fd = -1;
static volatile int g_run = 0;
static pthread_t    g_thread;
static const rpc_wallet* g_wallet;
static const char* g_user;
static const char* g_pass;

/* ---------------- base64 decode (RFC 4648) for Basic auth ---------------- */
static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static unsigned char* base64_decode(const char* in, size_t inlen, size_t* outlen) {
    size_t out_cap = (inlen / 4) * 3 + 3;
    unsigned char* out = malloc(out_cap + 1);
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i + 1 < inlen; i += 4) {
        int a = b64val(in[i]), b = i+1 < inlen ? b64val(in[i+1]) : -1;
        int c = i+2 < inlen ? b64val(in[i+2]) : -1;
        int d = i+3 < inlen ? b64val(in[i+3]) : -1;
        if (a < 0 || b < 0) { free(out); return NULL; }
        out[o++] = (unsigned char)((a << 2) | (b >> 4));
        if (c >= 0) out[o++] = (unsigned char)(((b & 15) << 4) | (c >> 2));
        if (d >= 0) out[o++] = (unsigned char)(((c & 3) << 6) | d);
    }
    out[o] = 0;
    *outlen = o;
    return out;
}

/* Find a header value (case-insensitive) within the raw header text. Returns a
 * pointer to the value (after ':'), NULL if absent. */
static const char* find_header(const char* headers, size_t hlen,
                               const char* name, size_t namelen) {
    const char* p = headers;
    const char* end = headers + hlen;
    while (p < end) {
        const char* le = memchr(p, '\r', (size_t)(end - p));
        if (!le) break;
        size_t linelen = (size_t)(le - p);
        if (linelen >= namelen + 2 && strncasecmp(p, name, namelen) == 0 && p[namelen] == ':') {
            const char* v = p + namelen + 1;
            while (v < le && (*v == ' ' || *v == '\t')) v++;
            return v;
        }
        p = le + 2;
    }
    return NULL;
}

/* Verify Authorization: Basic <user:pass> against the configured credentials. */
static int auth_ok(const char* headers, size_t hlen,
                   const char* user, const char* pass) {
    const char* auth = find_header(headers, hlen, "Authorization", 13);
    if (!auth) return 0;
    if (strncmp(auth, "Basic ", 6) != 0) return 0;
    const char* cred64 = auth + 6;
    const char* q = cred64;
    while (q < headers + hlen && *q != '\r' && *q != '\n') q++;
    size_t credlen = (size_t)(q - cred64);
    size_t declen = 0;
    unsigned char* decoded = base64_decode(cred64, credlen, &declen);
    if (!decoded) return 0;
    unsigned char* colon = memchr(decoded, ':', declen);
    int ok = 0;
    if (colon) {
        size_t ulen = (size_t)(colon - decoded);
        size_t plen = declen - ulen - 1;
        size_t eu = strlen(user), ep = strlen(pass);
        if (ulen == eu && plen == ep &&
            memcmp(decoded, user, eu) == 0 && memcmp(colon + 1, pass, ep) == 0)
            ok = 1;
    }
    free(decoded);
    return ok;
}

/* Deep-copy an rj_val via the serializer round-trip. */
static rj_val* rj_dup(const rj_val* v) {
    char tmp[65536];
    long w = rj_write(tmp, sizeof tmp, v, 0);
    if (w <= 0 || w >= (long)sizeof tmp) return NULL;
    return rj_parse(tmp, (size_t)w);
}

/* Build a JSON-RPC reply per Core JSONRPCReplyObj. `result` is consumed on
 * success. `id` echoed (deep-copied) only when include_id. */
static rj_val* build_reply(rj_val* result, int is_error, long error_code,
                           const char* error_msg, int v2,
                           const rj_val* id, int include_id) {
    rj_val* obj = rj_obj();
    if (v2) rj_obj_set(obj, "jsonrpc", rj_str("2.0"));
    if (is_error) {
        rj_val* err = rj_obj();
        rj_obj_set(err, "code", rj_numf("%ld", error_code));
        rj_obj_set(err, "message", rj_str(error_msg ? error_msg : ""));
        if (!v2) rj_obj_set(obj, "result", rj_null());
        rj_obj_set(obj, "error", err);
    } else {
        rj_obj_set(obj, "result", result ? result : rj_null());
        if (!v2) rj_obj_set(obj, "error", rj_null());
    }
    if (include_id) {
        if (id) rj_obj_set(obj, "id", rj_dup(id));
        else    rj_obj_set(obj, "id", rj_null());
    }
    return obj;
}

/* Snap JSON-RPC version: V2 when jsonrpc=="2.0". Sets *invalid_version for a
 * non-string or unsupported version string. */
static int request_is_v2(const rj_val* req, int* invalid_version) {
    *invalid_version = 0;
    rj_val* jv = rj_obj_get(req, "jsonrpc");
    if (!jv || jv->typ == RJ_NULL) return 0;
    if (jv->typ != RJ_STR) { *invalid_version = 1; return 0; }
    if (!strcmp(jv->str, "2.0")) return 1;
    if (!strcmp(jv->str, "1.0")) return 0;
    *invalid_version = 1;
    return 0;
}

static int parse_method(const rj_val* req, const char** method,
                        const rj_val** params, long* ec, const char** em) {
    rj_val* m = rj_obj_get(req, "method");
    if (!m || m->typ == RJ_NULL) { *ec = RPC_INVALID_REQUEST; *em = "Missing method"; return 0; }
    if (m->typ != RJ_STR) { *ec = RPC_INVALID_REQUEST; *em = "Method must be a string"; return 0; }
    *method = m->str;
    *params = rj_obj_get(req, "params");
    return 1;
}

static const char* status_text(int s) {
    switch (s) {
        case HTTP_OK: return "OK";
        case HTTP_NO_CONTENT: return "No Content";
        case HTTP_BAD_REQUEST: return "Bad Request";
        case HTTP_UNAUTHORIZED: return "Unauthorized";
        case HTTP_NOT_FOUND: return "Not Found";
        case HTTP_BAD_METHOD: return "Method Not Allowed";
        default: return "Internal Server Error";
    }
}

/* Dispatch a parsed JSON-RPC request object and write the exact HTTP reply. */
static void handle_request(int cfd, const char* body, size_t blen) {
    rj_val* req = rj_parse(body, blen);
    int status = HTTP_OK;
    int is_v2_notification = 0;
    rj_val* reply = NULL;

    if (!req) {
        /* non-parseable body: version unknown -> V1 reply, HTTP 500 */
        reply = build_reply(NULL, 1, RPC_PARSE_ERROR, "Parse error", /*v2*/0, NULL, 1);
        status = HTTP_INTERNAL_SERVER_ERROR;
    } else if (req->typ != RJ_OBJ) {
        /* parseable but not an object (e.g. array/string): Core throws
         * RPC_PARSE_ERROR "Top-level object parse error" -> HTTP 500 */
        reply = build_reply(NULL, 1, RPC_PARSE_ERROR, "Top-level object parse error", /*v2*/0, NULL, 1);
        status = HTTP_INTERNAL_SERVER_ERROR;
        rj_free(req); req = NULL;
    } else {
        int invalid_version = 0;
        int v2 = request_is_v2(req, &invalid_version);
        rj_val* id = rj_obj_get(req, "id");
        int has_id = (id != NULL);

        if (invalid_version) {
            reply = build_reply(NULL, 1, RPC_INVALID_REQUEST,
                                "JSON-RPC version not supported", /*v2*/0, id, has_id);
            status = HTTP_BAD_REQUEST;
        } else {
            const char* method = NULL; const rj_val* params = NULL;
            long ec = 0; const char* em = NULL;
            if (!parse_method(req, &method, &params, &ec, &em)) {
                reply = build_reply(NULL, 1, ec, em, /*v2*/0, id, has_id);
                status = HTTP_BAD_REQUEST; /* -32600 -> 400 */
            } else {
                rj_val* result = NULL; long dec = 0; const char* dem = NULL;
                int ok = rpc_dispatch(method, params, g_wallet, &result, &dec, &dem);
                if (ok) {
                    /* V2 notifications: no id -> 204 no body */
                    if (v2 && !has_id) is_v2_notification = 1;
                    reply = build_reply(result, 0, 0, NULL, v2, id, has_id);
                    status = HTTP_OK;
                } else {
                    if (v2) {
                        reply = build_reply(NULL, 1, dec, dem, 1, id, has_id);
                        status = HTTP_OK; /* V2 catches errors as HTTP 200 */
                    } else {
                        reply = build_reply(NULL, 1, dec, dem, 0, id, has_id);
                        if (dec == RPC_METHOD_NOT_FOUND) status = HTTP_NOT_FOUND;
                        else if (dec == RPC_INVALID_REQUEST) status = HTTP_BAD_REQUEST;
                        else status = HTTP_INTERNAL_SERVER_ERROR;
                    }
                }
            }
        }
        rj_free(req); req = NULL;
    }

    if (is_v2_notification && reply) { rj_free(reply); reply = NULL; status = HTTP_NO_CONTENT; }

    char bodybuf[262144];
    long bodylen = 0;
    if (reply) {
        bodylen = rj_write(bodybuf, sizeof bodybuf, reply, 0);
        rj_free(reply);
        if (bodylen < 0) bodylen = 0;
    }

    char hdr[192];
    int hl = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %ld\r\n"
        "\r\n",
        status, status_text(status), bodylen);
    write(cfd, hdr, (size_t)hl);
    if (bodylen > 0) write(cfd, bodybuf, (size_t)bodylen);
    close(cfd);
}

/* Serve one connection: read the full request, authenticate, dispatch. */
static void service_conn(int cfd) {
    char buf[262144];
    size_t got = 0;
    while (1) {
        ssize_t n = read(cfd, buf + got, sizeof buf - 1 - got);
        if (n <= 0) break;
        got += (size_t)n;
        if (got + 1 >= sizeof buf) break;
        /* stop once headers + full Content-Length body are present */
        const char* hdrend = NULL;
        for (size_t i = 0; i + 3 < got; i++)
            if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') { hdrend = buf + i; break; }
        if (hdrend) {
            size_t hdrlen = (size_t)(hdrend - buf);
            const char* clv = find_header(buf, hdrlen, "Content-Length", 14);
            long nv = -1;
            if (clv) nv = strtol(clv, NULL, 10);
            if (nv >= 0 && (long)(got - (hdrlen + 4)) >= nv) break;
            if (nv < 0) break;
        }
    }
    if (got == 0) { close(cfd); return; }
    buf[got] = 0;

    /* parse HTTP request line + headers */
    const char *m, *path, *body; size_t mlen, plen, blen;
    if (!http_request_parse(buf, (size_t)got, &m, &mlen, &path, &plen, &body, &blen)) {
        const char* e = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        write(cfd, e, strlen(e)); close(cfd); return;
    }
    (void)path; (void)plen;

    /* only POST (Core exact text + 405) */
    if (mlen != 4 || memcmp(m, "POST", 4) != 0) {
        const char* txt = "JSONRPC server handles only POST requests";
        char resp[256];
        int rl = snprintf(resp, sizeof resp,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %zu\r\n\r\n%s", strlen(txt), txt);
        write(cfd, resp, (size_t)rl); close(cfd); return;
    }

    /* auth (Core: 401 + WWW-Authenticate when missing/incorrect) */
    const char* hdrend = NULL;
    for (size_t i = 0; i + 3 < got; i++)
        if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') { hdrend = buf + i; break; }
    int authorized = 0;
    if (hdrend) {
        size_t hdrlen = (size_t)(hdrend - buf);
        authorized = auth_ok(buf, hdrlen, g_user ? g_user : "", g_pass ? g_pass : "");
    }
    if (!authorized) {
        char resp[256];
        int rl = snprintf(resp, sizeof resp,
            "HTTP/1.1 401 Unauthorized\r\n"
            "WWW-Authenticate: %s\r\n"
            "Content-Length: 0\r\n\r\n", WWW_AUTH_HEADER);
        write(cfd, resp, (size_t)rl); close(cfd); return;
    }

    handle_request(cfd, body, blen);
}

static void* server_thread(void* arg) {
    (void)arg;
    while (g_run) {
        struct sockaddr_in cli; socklen_t cl = sizeof cli;
        int c = accept(g_listen_fd, (struct sockaddr*)&cli, &cl);
        if (c < 0) continue;
        service_conn(c);
    }
    return NULL;
}

int rpc_server_start(const rpc_server_cfg* cfg, int* actual_port,
                     char* errmsg, size_t errcap) {
    g_user = cfg->user;
    g_pass = cfg->pass;
    g_wallet = cfg->wallet;

    /* never die from a peer closing a socket mid-write (SIGPIPE) */
    signal(SIGPIPE, SIG_IGN);

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        if (errmsg && errcap) snprintf(errmsg, errcap, "socket() failed");
        return -1;
    }
    int one = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)cfg->port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(g_listen_fd, (struct sockaddr*)&a, sizeof a) < 0) {
        if (errmsg && errcap) snprintf(errmsg, errcap, "bind() failed on port %d", cfg->port);
        close(g_listen_fd); g_listen_fd = -1;
        return -1;
    }
    if (listen(g_listen_fd, 16) < 0) {
        if (errmsg && errcap) snprintf(errmsg, errcap, "listen() failed");
        close(g_listen_fd); g_listen_fd = -1;
        return -1;
    }
    socklen_t al = sizeof a;
    getsockname(g_listen_fd, (struct sockaddr*)&a, &al);
    if (actual_port) *actual_port = ntohs(a.sin_port);

    g_run = 1;
    if (pthread_create(&g_thread, NULL, server_thread, NULL) != 0) {
        if (errmsg && errcap) snprintf(errmsg, errcap, "pthread_create failed");
        close(g_listen_fd); g_listen_fd = -1;
        return -1;
    }
    return 0;
}

void rpc_server_stop(void) {
    if (!g_run) return;
    g_run = 0;
    shutdown(g_listen_fd, SHUT_RDWR);
    close(g_listen_fd);
    g_listen_fd = -1;
    pthread_join(g_thread, NULL);
}

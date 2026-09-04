/* rpc_server.c -- HTTP JSON-RPC 2.0 server endpoint (daemon side).
 *
 * See rpc_server.h for the Core-behavior contract. This module owns the
 * sockets + threading; request rendering flows through the shared
 * rpc_dispatch() so the server can never diverge from the client.
 */
#include "rpc_server.h"
#include "crypto_hkdf.h"   /* hmac_sha256, shared with BIP324 */
#include "rpc_net.h"
#include "rpc_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include "bmc_thread.h"
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

/* DMN-6 (audit 2026-09-03): let a forked child drop the RPC listener.
 *
 * Every inbound serve child inherits it across fork(). After the parent exits
 * -- `bitcoin-cli stop` outside systemd, or a crash -- the socket stays bound
 * by those children, so the NEXT instance's rpc_server_start fails with
 * "bind() failed". That failure is deliberately non-fatal, so the new node
 * comes up with no RPC and no cookie: unstoppable by `stop`, and invisible to
 * monitoring, until the last old child happens to die.
 *
 * The child has no business serving RPC, so it closes the descriptor
 * outright. Called immediately after fork, beside the other listener closes. */
void rpc_server_close_listener_in_child(void){
    if (g_listen_fd >= 0){ close(g_listen_fd); g_listen_fd = -1; }
}
static volatile int g_run = 0;
static pthread_t    g_thread;
static const rpc_wallet* g_wallet;
static int (*g_allows)(const char*);
static const char* g_user;
static const char* g_pass;

/* ---- -rpcthreads / -rpcworkqueue / -rpcservertimeout (2026-09-01) ---- */
static int g_threads = 16, g_workqueue = 64, g_timeout_s = 30;

/* ---- RPC-4 (audit 2026-09-03): a TOTAL deadline for reading one request ----
 *
 * -rpcservertimeout is a PER-ACTIVITY timeout (SO_RCVTIMEO), in Core as here,
 * and that part is faithful. What is not faithful is where the reading
 * happens: Core reads requests non-blockingly on the libevent thread and hands
 * only COMPLETE requests to the -rpcthreads pool, so a slow sender costs
 * memory (bounded by MAX_SIZE), not a thread. Here service_conn does the
 * reading, on a pool worker, BEFORE authentication -- so a client that sends
 * one byte every g_timeout_s - 1 seconds resets the timeout forever and holds
 * a worker with no credentials at all. Sixteen such sockets (the default
 * rpcthreads) take the whole pool, the next 64 connections queue unanswered,
 * everything after that gets 503, and the operator's own `bitcoin-cli stop`
 * queues behind them.
 *
 * Restructuring onto a non-blocking accept-thread reader is the real fix and
 * is a larger change than this audit item warrants. A total wall-clock budget
 * for the pre-dispatch read closes the unbounded hold, which is the part that
 * makes this reachable by an unauthenticated client: a request that has not
 * arrived within the budget gets 408 and the worker is freed. The budget is
 * deliberately several times the per-activity timeout so that a legitimate
 * client on a slow link is unaffected -- RPC_REQ_MAX is a few hundred KB, and
 * a real client sends that in one burst. */
#define RPC_REQ_DEADLINE_DEFAULT 60
static long g_req_deadline_s = RPC_REQ_DEADLINE_DEFAULT;
#define RPC_QUEUE_CAP 4096
static int g_q[RPC_QUEUE_CAP]; static int g_q_head, g_q_tail, g_q_n;
static pthread_mutex_t g_q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_q_cond = PTHREAD_COND_INITIALIZER;
static pthread_t g_workers[256]; static int g_n_workers;

/* ---- -rpcwhitelist / -rpcwhitelistdefault ---- */
#define RPC_WL_MAX 16
static struct { char user[64]; char methods[448]; } g_wl[RPC_WL_MAX];
static int g_wl_n; static int g_wl_default = -1;
int rpc_whitelist_add(const char* spec){
    if (!spec) return 0;
    const char* c = strchr(spec, ':');
    if (!c || c == spec || g_wl_n >= RPC_WL_MAX || (size_t)(c - spec) >= 64 || strlen(c + 1) >= 448) return 0;
    memcpy(g_wl[g_wl_n].user, spec, (size_t)(c - spec)); g_wl[g_wl_n].user[c - spec] = 0;
    snprintf(g_wl[g_wl_n].methods, sizeof g_wl[g_wl_n].methods, "%s", c + 1);
    g_wl_n++;
    return 1;
}
void rpc_whitelist_set_default(int d){ g_wl_default = d; }
void rpc_whitelist_clear(void){ g_wl_n = 0; g_wl_default = -1; }
static int wl_entry_has(const char* list, const char* method){
    size_t ml = strlen(method);
    for (const char* p = list; p && *p; ){
        const char* e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n == ml && !memcmp(p, method, ml)) return 1;
        p = e ? e + 1 : NULL;
    }
    return 0;
}
int rpc_whitelist_allows(const char* user, const char* method){
    if (g_wl_n == 0) return 1;
    int seen = 0;
    for (int i = 0; i < g_wl_n; i++){
        if (strcmp(g_wl[i].user, user ? user : "")) continue;
        seen = 1;
        if (!wl_entry_has(g_wl[i].methods, method)) return 0;   /* entries intersect */
    }
    if (seen) return 1;
    /* no whitelist for this user: Core denies unless rpcwhitelistdefault=0 */
    return g_wl_default == 0;
}

/* ---- -rpccookieperms ---- */
static int g_cookie_perms = 0;
void rpc_cookie_set_perms(int p){ g_cookie_perms = p < 0 ? 0 : (p > 2 ? 2 : p); }

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
        /* ---- The LAST header line has no '\r' inside `hlen` ----
         *
         * Callers pass hlen = hdrend - buf, where hdrend points AT the '\r'
         * of the terminating CRLFCRLF -- which is the final header line's own
         * terminator. So memchr found nothing for that line and this loop used
         * to `break`, making the last header invisible.
         *
         * Two live consequences, both found while building the RPC-4 slow
         * client test. (1) Content-Length is the last header in the request
         * this server's own make_post builds, so it was never found, nv stayed
         * -1, and the read loop stopped WITHOUT waiting for the body: any
         * client that writes headers and body in separate segments -- which is
         * ordinary, and unavoidable once the body exceeds one segment -- got
         * "Parse error". It only ever worked because a small request arrives in
         * one read(). (2) An Authorization header sent last was invisible to
         * auth_ok, so a correctly credentialed client got 401.
         *
         * Treat end-of-buffer as a line end instead of giving up on the line. */
        const char* le = memchr(p, '\r', (size_t)(end - p));
        if (!le) le = end;
        size_t linelen = (size_t)(le - p);
        if (linelen >= namelen + 2 && strncasecmp(p, name, namelen) == 0 && p[namelen] == ':') {
            const char* v = p + namelen + 1;
            while (v < le && (*v == ' ' || *v == '\t')) v++;
            return v;
        }
        if (le == end) break;
        p = le + 2;
    }
    return NULL;
}

/* ---- RPC cookie authentication (Core's default) --------------------------
 * A password in the config file is a long-lived shared secret that every
 * client needs a copy of. Core's default instead writes a fresh random
 * credential to <datadir>/.cookie at 0600 on every start and deletes it on
 * exit, so a local client reads it from the filesystem and nothing durable
 * has to be distributed. This node had no such option: the plaintext
 * password was the ONLY way in.
 *
 * Format is Core's exactly -- "__cookie__:<64 hex>" with no trailing newline
 * -- so bitcoin-cli and any Core-compatible tooling authenticate unchanged. */
/* ---- rpcauth: hashed credentials, so no plaintext password in the config ---
 * Core's format, unchanged: -rpcauth=<user>:<salt>$<hmac-sha256-hex>, where
 * the HMAC is keyed by the SALT over the PASSWORD. Repeatable. Generated by
 * Core's share/rpcauth/rpcauth.py, so an operator's existing entries work
 * here verbatim.
 *
 * This is the last piece that made rpcuser/rpcpassword mandatory. Cookie auth
 * already removed the need for a shared secret between a local client and the
 * node; rpcauth removes the plaintext from the config file for the cases where
 * a fixed credential is genuinely wanted. */
#define RPC_MAX_AUTH 8
static struct { char user[64]; char salt[64]; char hash[65]; } g_rpcauth[RPC_MAX_AUTH];
static int g_n_rpcauth;

/* HMAC-SHA256 now lives in crypto_hkdf.c: BIP324's handshake needs the same
 * primitive, and two copies of a keyed hash is the shape that ends with one
 * of them quietly diverging. */

/* Register one -rpcauth value. 1 on success, 0 if malformed (which is
 * REPORTED by the caller, never silently dropped -- an operator who mistypes
 * a credential must not end up with a node that quietly accepts nothing). */
int rpc_auth_add(const char* spec){
    if (!spec || g_n_rpcauth >= RPC_MAX_AUTH) return 0;
    const char* colon = strchr(spec, ':');
    if (!colon) return 0;
    const char* dollar = strchr(colon + 1, '$');
    if (!dollar) return 0;
    size_t ul = (size_t)(colon - spec);
    size_t sl = (size_t)(dollar - colon - 1);
    size_t hl = strlen(dollar + 1);
    if (!ul || ul >= sizeof g_rpcauth[0].user) return 0;
    if (!sl || sl >= sizeof g_rpcauth[0].salt) return 0;
    if (hl != 64) return 0;                       /* sha256 hex, exactly */
    memcpy(g_rpcauth[g_n_rpcauth].user, spec, ul);      g_rpcauth[g_n_rpcauth].user[ul] = 0;
    memcpy(g_rpcauth[g_n_rpcauth].salt, colon + 1, sl); g_rpcauth[g_n_rpcauth].salt[sl] = 0;
    memcpy(g_rpcauth[g_n_rpcauth].hash, dollar + 1, 64); g_rpcauth[g_n_rpcauth].hash[64] = 0;
    g_n_rpcauth++;
    return 1;
}
int rpc_auth_count(void){ return g_n_rpcauth; }
void rpc_auth_clear(void){ g_n_rpcauth = 0; }

#define RPC_COOKIE_USER "__cookie__"
static char g_cookie_pass[65];          /* 64 hex + NUL; empty = no cookie */
static char g_cookie_path[512];

/* Compare in time independent of WHERE the mismatch is. The previous
 * comparison returned early on a length mismatch and used memcmp, so both
 * the length and a matching prefix were observable. The listener is
 * loopback-only, which makes this low severity, not a non-issue. */
static int ct_eq(const unsigned char* a, size_t alen,
                 const char* b, size_t blen) {
    unsigned diff = (unsigned)(alen ^ blen);
    size_t n = alen < blen ? alen : blen;
    for (size_t i = 0; i < n; i++) diff |= (unsigned)(a[i] ^ (unsigned char)b[i]);
    /* fold the tail of the longer side in so the loop count depends only on
     * the shorter length, never on where the bytes stop matching */
    for (size_t i = n; i < alen; i++) diff |= (unsigned)a[i];
    for (size_t i = n; i < blen; i++) diff |= (unsigned)(unsigned char)b[i];
    return diff == 0;
}

/* Write <path> with a fresh credential at 0600. 1 on success. */
int rpc_cookie_write(const char* path) {
    if (!path || !*path) return 0;
    unsigned char r[32];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t got = read(fd, r, sizeof r);
    close(fd);
    if (got != (ssize_t)sizeof r) return 0;
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { g_cookie_pass[i*2] = H[r[i] >> 4]; g_cookie_pass[i*2+1] = H[r[i] & 15]; }
    g_cookie_pass[64] = 0;
    /* O_EXCL would refuse to start after an unclean shutdown left a stale
     * cookie, so replace it -- but create at 0600 from the outset rather
     * than chmod'ing afterwards, which would leave a readable window. */
    unlink(path);
    int cf = open(path, O_WRONLY | O_CREAT | O_TRUNC, g_cookie_perms == 2 ? 0644 : (g_cookie_perms == 1 ? 0640 : 0600));
    if (cf < 0) { g_cookie_pass[0] = 0; return 0; }
    char line[128];
    int n = snprintf(line, sizeof line, "%s:%s", RPC_COOKIE_USER, g_cookie_pass);
    int ok = (write(cf, line, (size_t)n) == n);
    close(cf);
    if (!ok) { unlink(path); g_cookie_pass[0] = 0; return 0; }
    snprintf(g_cookie_path, sizeof g_cookie_path, "%s", path);
    return 1;
}

void rpc_cookie_remove(void) {
    if (g_cookie_path[0]) unlink(g_cookie_path);
    g_cookie_path[0] = 0;
    memset(g_cookie_pass, 0, sizeof g_cookie_pass);
}

/* Verify Authorization: Basic <user:pass> against the configured credentials. */
/* RPC-2 (audit 2026-09-03): THREAD-LOCAL, not process-global.
 *
 * The old comment -- "one connection at a time per worker" -- described the
 * invariant this needs, and the variable did not have it. Since the 16-thread
 * RPC pool landed on 2026-09-01, up to 16 workers run service_conn ->
 * auth_ok -> the wl_forbidden copy concurrently, with nothing between the
 * write here and the read there but a return. Thread A authenticating as
 * `alice` (whitelist: getblockcount) while thread B authenticates as `admin`
 * could copy B's name, or the empty string B cleared it to, and evaluate A's
 * whitelist for the wrong principal -- in either direction.
 *
 * __thread makes the stated invariant real: each worker gets its own, and the
 * write and the read are the same thread's. Threading an out-parameter
 * through auth_ok's four call sites would do the same thing with more
 * surface; this is the smaller change and the comment now matches the code. */
static __thread char g_last_auth_user[64];
static int auth_ok(const char* headers, size_t hlen,
                   const char* user, const char* pass) {
    g_last_auth_user[0] = 0;
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
        /* the configured user/pass, and -- when one was emitted -- the
         * cookie. Both arms run so acceptance does not leak which matched. */
        int by_pass   = ct_eq(decoded, ulen, user, strlen(user)) &
                        ct_eq(colon + 1, plen, pass, strlen(pass));
        int by_cookie = g_cookie_pass[0] &&
                        (ct_eq(decoded, ulen, RPC_COOKIE_USER, strlen(RPC_COOKIE_USER)) &
                         ct_eq(colon + 1, plen, g_cookie_pass, strlen(g_cookie_pass)));
        /* an empty configured password must never authenticate an empty one */
        if (!*pass) by_pass = 0;
        /* -rpcauth entries: HMAC-SHA256(salt, password) compared to the
         * stored hex. Every entry is checked so acceptance does not leak
         * which one matched, same reason both arms above always run. */
        int by_auth = 0;
        for (int i = 0; i < g_n_rpcauth; i++){
            unsigned char mac[32]; char hex[65];
            hmac_sha256(mac, (const unsigned char*)g_rpcauth[i].salt, strlen(g_rpcauth[i].salt),
                        colon + 1, plen);
            static const char* H = "0123456789abcdef";
            for (int b = 0; b < 32; b++){ hex[b*2] = H[mac[b] >> 4]; hex[b*2+1] = H[mac[b] & 15]; }
            hex[64] = 0;
            by_auth |= ct_eq(decoded, ulen, g_rpcauth[i].user, strlen(g_rpcauth[i].user)) &
                       ct_eq((const unsigned char*)hex, 64, g_rpcauth[i].hash, 64);
        }
        ok = (by_pass | by_cookie | by_auth);
        if (ok){ size_t n = ulen < sizeof g_last_auth_user - 1 ? ulen : sizeof g_last_auth_user - 1;
                 memcpy(g_last_auth_user, decoded, n); g_last_auth_user[n] = 0; }
    }
    free(decoded);
    return ok;
}


/* Test hook: auth_ok is static because nothing outside this file should be
 * making authentication decisions. tests/test_core_parity.c needs to assert
 * that the cookie is accepted and a wrong one is not, which is exactly an
 * authentication decision -- so it gets a named door rather than the header
 * being widened for everyone. */
int rpc_auth_ok_for_test(const char* hdrs, unsigned long hlen,
                         const char* user, const char* pass){
    return auth_ok(hdrs, (size_t)hlen, user, pass);
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

/* write all of [p, p+n) or fail: a short write on a reply is a corrupt
 * reply, which was silently possible for the header before 2026-09-02 */
static int write_all(int fd, const void* p, size_t n){
    const unsigned char* b = (const unsigned char*)p;
    while (n){ ssize_t w = write(fd, b, n); if (w <= 0) return -1; b += w; n -= (size_t)w; }
    return 0;
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
static int wl_forbidden(const char* user, const char* body, size_t blen){
    /* -rpcwhitelist: Core answers HTTP 403 with an empty body when the
     * authenticated user may not call the method. Checked on the raw body
     * before parsing so a forbidden call never reaches the dispatcher. */
    if (g_wl_n == 0) return 0;
    rj_val* req = rj_parse(body, blen);
    if (!req) return 0;
    int forbid = 0;
    if (req->typ == RJ_OBJ){
        rj_val* m = rj_obj_get(req, "method");
        if (m && m->typ == RJ_STR && m->str && !rpc_whitelist_allows(user, m->str)) forbid = 1;
    }
    rj_free(req);
    return forbid;
}
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
                /* A V2 NOTIFICATION (no id) gets no response whatever the
                 * method did. This flag used to be set only on the success
                 * path, so a notification whose method FAILED was answered
                 * with a full error body -- a spec violation that stayed
                 * invisible while the only method the tests notified with
                 * always succeeded. Core decides the same way, after
                 * execution and regardless of outcome (httprpc.cpp: "Even
                 * though we do execute notifications, we do not respond to
                 * them"). */
                if (v2 && !has_id) is_v2_notification = 1;
                if (ok) {
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

    /* Body is sized to the value: getblock/getrawtransaction on a real block
     * is many MB. A fixed buffer + rj_write's returned length used as the
     * write() size was an out-of-bounds read that leaked process memory to the
     * client (and produced invalid JSON past the buffer). */
    char* respbody = NULL;
    long bodylen = 0;
    if (reply) {
        respbody = rj_write_alloc(reply, 0, &bodylen);
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
    if (write_all(cfd, hdr, (size_t)hl) != 0) {
        /* RPC-1 (audit 2026-09-03): this used to `return` -- leaking BOTH the
         * client descriptor and respbody, which for getblock verbosity 2 is
         * many megabytes. Every other exit in this function frees and closes.
         *
         * Reachable by any authenticated client: send a request and reset the
         * connection, or simply never read a large reply so the 30s
         * SO_SNDTIMEO fires. Loop that and the process runs out of
         * descriptors -- at which point the RPC listener AND the P2P inbound
         * listener in the same process both stop accepting. */
        free(respbody);
        close(cfd);
        return;
    }
    for (long off = 0; respbody && off < bodylen; ) {   /* full write, handles short writes */
        ssize_t wr = write(cfd, respbody + off, (size_t)(bodylen - off));
        if (wr <= 0) break;
        off += wr;
    }
    free(respbody);
    close(cfd);
}

/* Serve one connection: read the full request, authenticate, dispatch.
 *
 * REQUEST BUFFER (2026-08-25): was a fixed 256KB stack array, which silently
 * truncated anything larger -- submitblock's hex payload alone can be ~8MB
 * (a 4MB-weight block). Now a heap buffer growing on demand up to
 * RPC_REQ_MAX; oversize requests are dropped (connection closed) rather
 * than half-parsed. The header-end scan resumes where the last read left
 * off instead of rescanning from byte 0 (quadratic at MB sizes). */
#define RPC_REQ_MAX (9u<<20)     /* 8MB hex block + JSON + headers, with margin */

/* ---- getblocktemplate longpoll (BIP22) -------------------------------------
 * The accept loop is deliberately SERIAL (one request at a time; the wallet
 * and chain handlers are not concurrent-safe), so a longpoll request cannot
 * simply block inside its handler -- it would stall every other RPC. Instead
 * a request whose body carries a "longpollid" is handed to a detached waiter
 * thread that (a) polls the CHAIN TIP through a shared-state-free primitive
 * -- a direct pread of index.dat's last 48-byte record, whose first 32 bytes
 * are the tip hash -- and (b) only after the tip differs from the
 * longpollid's embedded prev-hash (or a 60s cap; Core also wakes on
 * substantial mempool change -- divergence, documented here) re-enters the
 * SERIAL execution path by taking the same mutex the accept loop holds
 * around every handler. Handlers therefore never run concurrently. */
static pthread_mutex_t g_exec_lock = PTHREAD_MUTEX_INITIALIZER;
#define LP_MAX_WAIT_S  60
#define LP_POLL_MS     250

static int lp_tip_hash(unsigned char out[32]){
    int fd = open("index.dat", O_RDONLY);
    if (fd < 0) return 0;
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz < 48){ close(fd); return 0; }
    off_t last = (sz / 48 - 1) * 48;
    int ok = pread(fd, out, 32, last) == 32;
    close(fd);
    return ok;
}

typedef struct { int cfd; char* buf; size_t body_off, blen; unsigned char prev[32]; int have_prev; } lp_req_t;

static void* lp_waiter(void* arg){
    lp_req_t* r = (lp_req_t*)arg;
    if (r->have_prev){
        for (int waited = 0; waited < LP_MAX_WAIT_S * 1000; waited += LP_POLL_MS){
            unsigned char cur[32];
            if (lp_tip_hash(cur) && memcmp(cur, r->prev, 32) != 0) break;   /* tip moved */
            struct timespec ts = {0, LP_POLL_MS * 1000000L};
            nanosleep(&ts, NULL);
        }
    }
    pthread_mutex_lock(&g_exec_lock);
    handle_request(r->cfd, r->buf + r->body_off, r->blen);
    pthread_mutex_unlock(&g_exec_lock);
    free(r->buf); free(r);
    return NULL;
}

/* extract the 64-hex prev-tip embedded in the request's longpollid ("<tip
 * display hex><counter>"); wire order out. 0 if absent/malformed (the waiter
 * then answers immediately, which is also what Core does for an unknown id). */
static int lp_extract_prev(const char* body, size_t blen, unsigned char out[32]){
    const char* k = NULL;
    for (size_t i = 0; i + 12 <= blen; i++)
        if (!memcmp(body + i, "\"longpollid\"", 12)){ k = body + i + 12; break; }
    if (!k) return 0;
    const char* end = body + blen;
    while (k < end && (*k == ':' || *k == ' ' || *k == '\t')) k++;
    if (k >= end || *k != '"') return 0;
    k++;
    if ((size_t)(end - k) < 64) return 0;
    for (int b = 0; b < 32; b++){
        unsigned hi, lo;
        char c1 = k[b*2], c2 = k[b*2+1];
        hi = (c1 >= '0' && c1 <= '9') ? (unsigned)(c1-'0') : (c1 >= 'a' && c1 <= 'f') ? (unsigned)(c1-'a'+10) : 99;
        lo = (c2 >= '0' && c2 <= '9') ? (unsigned)(c2-'0') : (c2 >= 'a' && c2 <= 'f') ? (unsigned)(c2-'a'+10) : 99;
        if (hi > 15 || lo > 15) return 0;
        out[31-b] = (unsigned char)((hi<<4)|lo);   /* display -> wire */
    }
    return 1;
}

static void service_conn(int cfd) {
    { struct timeval tv = { g_timeout_s, 0 };            /* -rpcservertimeout */
      setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
      setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv); }
    /* RPC-4: the whole request must arrive within this budget, however much
     * activity keeps the per-read timeout alive. */
    struct timespec t_start; clock_gettime(CLOCK_MONOTONIC, &t_start);
    size_t cap = 262144;
    char* buf = malloc(cap);
    if (!buf) { close(cfd); return; }
    size_t got = 0, scanned = 0;
    const char* hdrend = NULL;
    while (1) {
        if (got + 1 >= cap) {
            if (cap >= RPC_REQ_MAX) { free(buf); close(cfd); return; }
            size_t ncap = cap * 2; if (ncap > RPC_REQ_MAX) ncap = RPC_REQ_MAX;
            size_t hoff = hdrend ? (size_t)(hdrend - buf) : 0;
            char* nb = realloc(buf, ncap);
            if (!nb) { free(buf); close(cfd); return; }
            if (hdrend) hdrend = nb + hoff;   /* pointer survives realloc */
            buf = nb; cap = ncap;
        }
        /* RPC-4: enforce the total budget, and never block past it. The
         * per-read timeout is shrunk to whatever remains, so a read that
         * begins just under the deadline cannot overshoot it by another
         * g_timeout_s seconds. */
        if (g_req_deadline_s > 0){
            struct timespec now_ts; clock_gettime(CLOCK_MONOTONIC, &now_ts);
            long elapsed = (long)(now_ts.tv_sec - t_start.tv_sec);
            long left = g_req_deadline_s - elapsed;
            if (left <= 0){
                const char* e = "HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n";
                (void)write_all(cfd, e, strlen(e));
                free(buf); close(cfd); return;
            }
            if (left < g_timeout_s){
                struct timeval tv = { left, 0 };
                setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            }
        }
        ssize_t n = read(cfd, buf + got, cap - 1 - got);
        if (n <= 0) break;
        got += (size_t)n;
        /* stop once headers + full Content-Length body are present */
        if (!hdrend) {
            size_t start = scanned > 3 ? scanned - 3 : 0;
            for (size_t i = start; i + 3 < got; i++)
                if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') { hdrend = buf + i; break; }
            scanned = got;
        }
        if (hdrend) {
            size_t hdrlen = (size_t)(hdrend - buf);
            const char* clv = find_header(buf, hdrlen, "Content-Length", 14);
            long nv = -1;
            if (clv) nv = strtol(clv, NULL, 10);
            if (nv >= 0 && (long)(got - (hdrlen + 4)) >= nv) break;
            if (nv < 0) break;
        }
    }
    if (got == 0) { free(buf); close(cfd); return; }
    buf[got] = 0;

    /* parse HTTP request line + headers */
    const char *m, *path, *body; size_t mlen, plen, blen;
    if (!http_request_parse(buf, (size_t)got, &m, &mlen, &path, &plen, &body, &blen)) {
        const char* e = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        (void)write_all(cfd, e, strlen(e)); free(buf); close(cfd); return;
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
        (void)write_all(cfd, resp, (size_t)rl); free(buf); close(cfd); return;
    }

    /* auth (Core: 401 + WWW-Authenticate when missing/incorrect).
     * hdrend was already located during the read loop above. */
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
        (void)write_all(cfd, resp, (size_t)rl); free(buf); close(cfd); return;
    }

    { char user[64]; snprintf(user, sizeof user, "%s", g_last_auth_user);
      if (wl_forbidden(user, body, blen)){
          const char* e = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
          (void)write_all(cfd, e, strlen(e)); free(buf); close(cfd); return;
      } }
    /* longpoll: a getblocktemplate carrying a longpollid waits OFF-THREAD
     * (see the block comment above lp_waiter) */
    { int is_lp = 0;
      for (size_t i = 0; !is_lp && i + 12 <= blen; i++)
          if (!memcmp(body + i, "\"longpollid\"", 12)) is_lp = 1;
      if (is_lp){
          int has_gbt = 0;
          for (size_t i = 0; !has_gbt && i + 16 <= blen; i++)
              if (!memcmp(body + i, "getblocktemplate", 16)) has_gbt = 1;
          if (has_gbt){
              lp_req_t* r = malloc(sizeof *r);
              if (r){
                  r->cfd = cfd; r->buf = buf; r->body_off = (size_t)(body - buf); r->blen = blen;
                  r->have_prev = lp_extract_prev(body, blen, r->prev);
                  pthread_t th;
                  if (bmc_pthread_create(&th, lp_waiter, r) == 0){
                      pthread_detach(th);
                      return;                        /* r owns buf + cfd now */
                  }
                  free(r);                           /* fall through: serial */
              }
          }
      } }
    pthread_mutex_lock(&g_exec_lock);
    handle_request(cfd, body, blen);
    pthread_mutex_unlock(&g_exec_lock);
    free(buf);
}

static void* server_thread(void* arg) {
    (void)arg;
    while (g_run) {
        struct sockaddr_in cli; socklen_t cl = sizeof cli;
        int c = accept(g_listen_fd, (struct sockaddr*)&cli, &cl);
        if (c < 0) {
            /* RPC-1: `continue` with no pause spun a core whenever accept
             * kept failing -- and the failure that matters is EMFILE/ENFILE,
             * where the condition persists until a descriptor is released, so
             * the spin is unbounded. Back off briefly on the
             * out-of-descriptors cases (and log once, since a silently
             * degraded RPC listener is how this stays unnoticed); other
             * errors are transient per-connection and retry immediately. */
            if (errno == EMFILE || errno == ENFILE) {
                static int said = 0;
                if (!said++)
                    fprintf(stderr, "[rpc] accept: out of file descriptors (%s) -- "
                                    "backing off; the RPC listener is degraded\n",
                            strerror(errno));
                struct timespec ts = { 0, 50 * 1000 * 1000 };   /* 50 ms */
                nanosleep(&ts, NULL);
            }
            continue;
        }
        /* Core InitHTTPAllowList: the ACL is checked on every connection, not
         * inferred from the bind address. A node bound to 0.0.0.0 with a
         * narrow allow list must still refuse everyone else. */
        if (g_allows){
            char ip[64] = {0};
            inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof ip);
            if (!g_allows(ip)){
                fprintf(stderr, "[rpc] refused connection from %s "
                                "(not in -rpcallowip)\n", ip);
                close(c);
                continue;
            }
        }
        /* -rpcworkqueue: hand the connection to the pool; past the queue
         * depth Core answers 503 "Work queue depth exceeded" */
        pthread_mutex_lock(&g_q_lock);
        if (g_q_n >= g_workqueue || g_q_n >= RPC_QUEUE_CAP){
            pthread_mutex_unlock(&g_q_lock);
            const char* e = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 25\r\n\r\nWork queue depth exceeded";
            (void)write_all(c, e, strlen(e)); close(c);
            continue;
        }
        g_q[g_q_tail] = c; g_q_tail = (g_q_tail + 1) % RPC_QUEUE_CAP; g_q_n++;
        pthread_cond_signal(&g_q_cond);
        pthread_mutex_unlock(&g_q_lock);
    }
    return NULL;
}
static void* worker_thread(void* arg){
    (void)arg;
    for (;;){
        pthread_mutex_lock(&g_q_lock);
        while (g_q_n == 0 && g_run) pthread_cond_wait(&g_q_cond, &g_q_lock);
        if (g_q_n == 0 && !g_run){ pthread_mutex_unlock(&g_q_lock); return NULL; }
        int c = g_q[g_q_head]; g_q_head = (g_q_head + 1) % RPC_QUEUE_CAP; g_q_n--;
        pthread_mutex_unlock(&g_q_lock);
        service_conn(c);
    }
}

int rpc_server_start(const rpc_server_cfg* cfg, int* actual_port,
                     char* errmsg, size_t errcap) {
    g_user = cfg->user;
    g_pass = cfg->pass;
    g_wallet = cfg->wallet;
    g_allows = cfg->allows;

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
    /* Core -rpcbind. Loopback unless an address is configured AND the caller
     * satisfied Core's rule that -rpcbind without -rpcallowip is ignored. */
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (cfg->bind_addr && cfg->bind_addr[0]){
        if (inet_pton(AF_INET, cfg->bind_addr, &a.sin_addr) != 1){
            snprintf(errmsg, errcap, "rpcbind=%s is not a valid IPv4 address",
                     cfg->bind_addr);
            close(g_listen_fd); g_listen_fd = -1; return -1;
        }
    }
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

    g_threads   = cfg->threads   > 0 ? (cfg->threads > 256 ? 256 : cfg->threads) : 16;
    g_workqueue = cfg->workqueue > 0 ? (cfg->workqueue > RPC_QUEUE_CAP ? RPC_QUEUE_CAP : cfg->workqueue) : 64;
    g_timeout_s = cfg->timeout_s > 0 ? cfg->timeout_s : 30;
    /* RPC-4: the total-read budget. Env-overridable so an operator on a
     * pathological link can raise it, or set it to 0 to restore the old
     * unbounded behaviour deliberately rather than by accident. */
    { const char* e = getenv("BMC_RPC_REQ_DEADLINE_SECS");
      long v = -1;
      if (e && *e) v = strtol(e, NULL, 10);
      if (v >= 0){
          /* An explicit value wins outright, including one below
           * -rpcservertimeout (which then means a single stalled read can end
           * the request) and 0, which restores the old unbounded behaviour
           * deliberately rather than by accident. */
          g_req_deadline_s = v;
      } else {
          /* Default: never shorter than the per-read timeout, or a request
           * that legitimately blocks once would be cut off mid-flight. */
          g_req_deadline_s = RPC_REQ_DEADLINE_DEFAULT;
          if (g_req_deadline_s < g_timeout_s) g_req_deadline_s = g_timeout_s;
      } }
    g_q_head = g_q_tail = g_q_n = 0;
    g_run = 1;
    g_n_workers = 0;
    for (int i = 0; i < g_threads; i++)
        if (bmc_pthread_create(&g_workers[g_n_workers], worker_thread, NULL) == 0) g_n_workers++;
    if (g_n_workers == 0 || bmc_pthread_create(&g_thread, server_thread, NULL) != 0) {
        if (errmsg && errcap) snprintf(errmsg, errcap, "pthread_create failed");
        g_run = 0; pthread_cond_broadcast(&g_q_cond);
        for (int i = 0; i < g_n_workers; i++) pthread_join(g_workers[i], NULL);
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
    pthread_mutex_lock(&g_q_lock); pthread_cond_broadcast(&g_q_cond); pthread_mutex_unlock(&g_q_lock);
    for (int i = 0; i < g_n_workers; i++) pthread_join(g_workers[i], NULL);
    g_n_workers = 0;
    /* connections still queued are closed unanswered (Core does the same on shutdown) */
    while (g_q_n > 0){ close(g_q[g_q_head]); g_q_head = (g_q_head + 1) % RPC_QUEUE_CAP; g_q_n--; }
}

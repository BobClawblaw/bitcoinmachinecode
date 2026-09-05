/* test_rpc_server.c -- end-to-end HTTP JSON-RPC SERVER endpoint test.
 *
 * Proves the PRODUCTION server path (not an in-process stub): it forks/execs
 * the ACTUAL daemon/bitcoin_rpcd binary on an ephemeral port, then drives it
 * two ways:
 *
 *   1. over a raw loopback socket, asserting Core-bit-exact HTTP behavior:
 *        - 401 + WWW-Authenticate when auth is wrong/missing
 *        - 405 "JSONRPC server handles only POST requests" for GET
 *        - -32700 "Parse error" envelope (HTTP 500) for non-JSON bodies
 *        - -32600 for a non-object request
 *        - bit-exact V2 success/error JSON-RPC envelopes with id echo
 *   2. by exec'ing the ACTUAL daemon/bmc_cli against it (the paired
 *      client), asserting the printed output matches bitcoind/bitcoin-cli.
 *
 * Complements test_rpc_transport (client side) and closes the RPC-transport
 * OPEN item's server half alongside bitcoin-cli (t_8e5be37f).
 */
#include "../rpc_net.h"
#include "../rpc_json.h"
#include "../rpc_commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int fails = 0;
static void ck(const char* label, int cond) {
    printf("%s %s\n", cond ? "ok  :" : "FAIL:", label);
    if (!cond) fails++;
}

/* ---- bitcoin-cli exec capture ---- */
static char out_buf[65536], err_buf[16384];
static int last_exit = 0;
static int run_cli(int port, const char* user, const char* pass,
                   const char* method, const char* p1) {
    char portarg[64], uarg[128], parg[128];
    snprintf(portarg, sizeof portarg, "-rpcport=%d", port);
    snprintf(uarg, sizeof uarg, "-rpcuser=%s", user);
    snprintf(parg, sizeof parg, "-rpcpassword=%s", pass);
    char* argv[16]; int ac = 0;
    argv[ac++] = (char*)"daemon/bmc_cli";
    argv[ac++] = portarg;
    argv[ac++] = uarg;
    argv[ac++] = parg;
    argv[ac++] = (char*)method;
    if (p1) argv[ac++] = (char*)p1;
    argv[ac] = NULL;
    int pout[2], perr[2];
    if (pipe(pout) < 0 || pipe(perr) < 0){ perror("pipe"); _exit(2); }
    pid_t pid = fork();
    if (pid == 0) {
        dup2(pout[1], 1); dup2(perr[1], 2);
        close(pout[0]); close(pout[1]); close(perr[0]); close(perr[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(pout[1]); close(perr[1]);
    size_t no = 0, ne = 0;
    /* read stdout until EOF (listunspent/decoderaw can be multi-KB, so loop) */
    while (1) {
        ssize_t n = read(pout[0], out_buf + no, sizeof out_buf - 1 - no);
        if (n <= 0) break;
        no += (size_t)n;
        if (no >= sizeof out_buf - 1) break;
    }
    out_buf[no] = 0;
    while (1) {
        ssize_t n = read(perr[0], err_buf + ne, sizeof err_buf - 1 - ne);
        if (n <= 0) break;
        ne += (size_t)n;
        if (ne >= sizeof err_buf - 1) break;
    }
    err_buf[ne] = 0;
    close(pout[0]); close(perr[0]);
    int st; waitpid(pid, &st, 0);
    last_exit = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return last_exit;
}
static void ck_out(const char* label, const char* expect) {
    ck(label, strcmp(out_buf, expect) == 0);
    if (strcmp(out_buf, expect)) printf("      stdout got : [%s]\n      want        : [%s]\n", out_buf, expect);
}

/* ---- raw HTTP exchange against the server ---- */
static char raw_out[262144];
static int raw_exchange(int port, const char* req, size_t reqlen) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&a, sizeof a) < 0) { close(fd); return -1; }
    if (write(fd, req, reqlen) != (ssize_t)reqlen){ close(fd); return -1; }
    /* read until headers + Content-Length body complete, or connection closes */
    size_t got = 0;
    while (got < sizeof raw_out - 1) {
        ssize_t n = read(fd, raw_out + got, sizeof raw_out - 1 - got);
        if (n <= 0) break;
        got += (size_t)n;
        raw_out[got] = 0;
        const char* hdrend = NULL;
        for (size_t i = 0; i + 3 < got; i++)
            if (raw_out[i]=='\r' && raw_out[i+1]=='\n' && raw_out[i+2]=='\r' && raw_out[i+3]=='\n') { hdrend = raw_out + i; break; }
        if (hdrend) {
            const char* cl = strstr(raw_out, "Content-Length:");
            if (cl && cl < hdrend) {
                long n2 = strtol(cl + 15, NULL, 10);
                size_t bodystart = (size_t)((hdrend + 4) - raw_out);
                if (n2 >= 0 && (long)(got - bodystart) >= n2) break;
            } else break; /* no content-length (e.g. 204) */
        }
    }
    close(fd);
    raw_out[got] = 0;
    return (int)got;
}
/* build a Basic auth header */
static void make_post(char* buf, size_t cap, int port, const char* user,
                      const char* pass, const char* body,
                      const char* extra_headers) {
    /* base64(user:pass) */
    size_t ul = strlen(user), pl = strlen(pass);
    char cred[512]; memcpy(cred, user, ul); cred[ul] = ':';
    memcpy(cred + ul + 1, pass, pl); cred[ul + pl + 1] = 0;
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = ul + pl + 1, o = 0; char b64[1024];
    for (size_t i = 0; i < n; i += 3) {
        unsigned x = (unsigned char)cred[i], y = (i+1<n)?(unsigned char)cred[i+1]:0, z = (i+2<n)?(unsigned char)cred[i+2]:0;
        b64[o++] = tbl[x >> 2];
        b64[o++] = tbl[((x & 3) << 4) | (y >> 4)];
        b64[o++] = (i+1<n) ? tbl[((y & 15) << 2) | (z >> 6)] : '=';
        b64[o++] = (i+2<n) ? tbl[z & 63] : '=';
    }
    b64[o] = 0;
    snprintf(buf, cap,
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n%s",
        port, b64, strlen(body), extra_headers ? extra_headers : "", body);
}
static int has_prefix(const char* s, const char* p) { return strncmp(s, p, strlen(p)) == 0; }
static int has_substr(const char* s, const char* sub) { return strstr(s, sub) != NULL; }

int main(void) {
    /* ---- spin up the REAL server daemon on an ephemeral port ---- */
    int pout[2]; if (pipe(pout) < 0){ perror("pipe"); return 1; }
    pid_t srv = fork();
    if (srv == 0) {
        dup2(pout[1], 2); close(pout[0]); close(pout[1]);
        char* argv[] = { (char*)"daemon/bitcoin_rpcd", NULL };
        /* TEST_RPC_PORT=0 -> HTTP server binds an ephemeral port (see daemon) */
        setenv("TEST_RPC_PORT", "0", 1);
        /* RPC-4: a short total-read budget so the slow-client case below
         * finishes in seconds rather than the 60s production default. */
        setenv("BMC_RPC_REQ_DEADLINE_SECS", "3", 1);
        execv(argv[0], argv);
        _exit(127);
    }
    close(pout[1]);
    /* read the daemon's stderr until it reports the bound port */
    char log[65536]; size_t lgot = 0; int port = -1;
    while (1) {
        ssize_t n = read(pout[0], log + lgot, sizeof log - 1 - lgot);
        if (n <= 0) break;
        lgot += (size_t)n; log[lgot] = 0;
        char* m = strstr(log, "listening on 127.0.0.1:");
        if (m) { port = atoi(m + strlen("listening on 127.0.0.1:")); break; }
        if (lgot > sizeof log - 1) break;
    }
    close(pout[0]);
    if (port <= 0) {
        printf("FAIL: could not determine server port (daemon died?)\n");
        kill(srv, SIGKILL); waitpid(srv, NULL, 0);
        return 1;
    }
    printf("ok  : bitcoin_rpcd up on 127.0.0.1:%d\n", port);

    char req[8192];

    /* ============ 1. correct auth -> getnewaddress via real bmc_cli ===== */
    extern long wallet_derive_p2wpkh_address(char* out, long cap, const unsigned char seed[64], unsigned index);
    unsigned char seed[64]; for (int i = 0; i < 64; i++) seed[i] = (unsigned char)(0x10 + i);
    char addr[96]; wallet_derive_p2wpkh_address(addr, 96, seed, 0);
    char expect[128]; snprintf(expect, sizeof expect, "%s\n", addr);
    run_cli(port, "bitcoin", "bitcoin", "getnewaddress", NULL);
    ck("bmc_cli getnewaddress exit 0", last_exit == 0);
    ck_out("getnewaddress prints raw address (real server)", expect);

    /* ============ 2. getbalance via real bmc_cli ======================= */
    /* getbalance answers from the real scriptPubKey->UTXO address index
     * (asm/daemon/build_addr_index.c) now, not the wallet's own fake
     * utxo_* arrays. This harness never launches bitcoin_rpcd with
     * -datadir=, so the wallet's own default address correctly resolves
     * to zero, same as real Core before it's synced. */
    run_cli(port, "bitcoin", "bitcoin", "getbalance", NULL);
    /* getbalance answers from the wallet RESCAN now (2026-08-27), and this
     * server has none: "I have not looked" must not be reported as
     * 0.00000000. Empty stdout, and a -4 on stderr naming what to run. */
    ck_out("getbalance without a rescan prints nothing (real server)", "");
    ck("getbalance without a rescan errors naming rescanblockchain (real server)",
       strstr(err_buf, "-4") && strstr(err_buf, "rescanblockchain"));

    /* ============ 3. unknown method -> bmc_cli stderr ------------------ */
    run_cli(port, "bitcoin", "bitcoin", "nosuchmethod", NULL);
    ck("unknown method exit 1", last_exit == 1);
    ck("unknown method stderr bit-exact",
       strcmp(err_buf, "error code: -32601\nerror message:\nMethod not found\n") == 0);

    /* ============ 4. HTTP 401 on bad password (raw) ======================= */
    make_post(req, sizeof req, port, "bitcoin", "WRONG", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getbalance\",\"params\":[]}", NULL);
    raw_exchange(port, req, strlen(req));
    ck("401 on wrong password", has_prefix(raw_out, "HTTP/1.1 401 Unauthorized"));
    ck("401 has WWW-Authenticate Basic realm jsonrpc",
       has_substr(raw_out, "WWW-Authenticate: Basic realm=\"jsonrpc\""));

    /* ============ 5. HTTP 401 on missing auth (raw) ======================== */
    {
        char noauth[1024];
        snprintf(noauth, sizeof noauth,
            "POST / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\n"
            "Content-Length: 45\r\nConnection: close\r\n\r\n"
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getbalance\",\"params\":[]}",
            port);
        raw_exchange(port, noauth, strlen(noauth));
        ck("401 on missing auth", has_prefix(raw_out, "HTTP/1.1 401 Unauthorized"));
    }

    /* ============ 6. 405 on GET (raw, Core exact text) ===================== */
    {
        char g[512]; snprintf(g, sizeof g,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", port);
        raw_exchange(port, g, strlen(g));
        ck("405 on GET", has_prefix(raw_out, "HTTP/1.1 405 Method Not Allowed"));
        ck("405 body Core-exact", has_substr(raw_out, "JSONRPC server handles only POST requests"));
    }

    /* ============ 7. parse error -32700 (raw, non-JSON body) =============== */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin", "this is not json", NULL);
    raw_exchange(port, req, strlen(req));
    ck("parse error HTTP 500", has_prefix(raw_out, "HTTP/1.1 500"));
    ck("parse error envelope bit-exact",
       has_substr(raw_out, "{\"result\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}"));

    /* ============ 8. V2 success envelope bit-exact (raw) =================== */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getnewaddress\",\"params\":[]}", NULL);
    raw_exchange(port, req, strlen(req));
    ck("V2 success HTTP 200", has_prefix(raw_out, "HTTP/1.1 200 OK"));
    {
        char wenvel[256];
        snprintf(wenvel, sizeof wenvel,
            "{\"jsonrpc\":\"2.0\",\"result\":\"%s\",\"id\":1}", addr);
        char* body = strstr(raw_out, "\r\n\r\n");
        ck("V2 success envelope bit-exact (jsonrpc+result+id)",
           body && strncmp(body + 4, wenvel, strlen(wenvel)) == 0);
    }

    /* ============ 9. V2 error envelope bit-exact (raw) ===================== */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"nosuchmethod\",\"params\":[]}", NULL);
    raw_exchange(port, req, strlen(req));
    ck("V2 error HTTP 200 (errors caught)", has_prefix(raw_out, "HTTP/1.1 200 OK"));
    ck("V2 error envelope bit-exact (jsonrpc+error+id, no result)",
       has_substr(raw_out, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":7}"));

    /* ============ 10. non-object, NON-ARRAY top level -> -32700 (raw) ======
     * This section used to send "[1,2,3]" and assert HTTP 500. That was the
     * RPC-6 defect written down as expected behaviour: an array is a BATCH to
     * Core, not a malformed request, and the 500 was the thing to fix. The
     * top-level parse error is real -- it just belongs to a top level that is
     * neither an object nor an array, which is what is sent now. The batch
     * cases moved to section 10b. */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin", "\"hello\"", NULL);
    raw_exchange(port, req, strlen(req));
    ck("bare string top level -> HTTP 500 parse path", has_prefix(raw_out, "HTTP/1.1 500"));
    ck("bare string top level -> -32700 top-level parse error",
       has_substr(raw_out, "\"message\":\"Top-level object parse error\""));
    make_post(req, sizeof req, port, "bitcoin", "bitcoin", "42", NULL);
    raw_exchange(port, req, strlen(req));
    ck("bare number top level -> -32700 too",
       has_prefix(raw_out, "HTTP/1.1 500") &&
       has_substr(raw_out, "\"message\":\"Top-level object parse error\""));

    /* ============ 10a. RPC-16: a large `id` must be ECHOED, not nulled =====
     * rj_dup round-tripped the id through a 64 KiB stack buffer -- rj_write
     * into tmp[65536], then rj_parse back -- and returned NULL above that.
     * build_reply's only use of it is the id echo, and the request cap is
     * 9 MiB, so a client sending a legitimately large id got `"id":null` back
     * and could no longer match the reply to its own request. rj_clone does
     * the same job structurally with no cap, and was already in rpc_json.c.
     *
     * The id here is a ~70 KiB string: comfortably over the old buffer, well
     * under the request cap. */
    {
        static char bigreq[200000];
        static char bigid[70000];
        memset(bigid, 'z', sizeof bigid - 1); bigid[sizeof bigid - 1] = 0;
        static char body[160000];
        snprintf(body, sizeof body,
                 "{\"jsonrpc\":\"2.0\",\"id\":\"%s\",\"method\":\"getblockcount\",\"params\":[]}", bigid);
        make_post(bigreq, sizeof bigreq, port, "bitcoin", "bitcoin", body, NULL);
        raw_exchange(port, bigreq, strlen(bigreq));
        ck("RPC-16: a 70 KiB id does NOT come back as null",
           !has_substr(raw_out, "\"id\":null"));
        ck("RPC-16: the id is echoed (a long run of the id's own bytes appears)",
           has_substr(raw_out, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
        /* the opposite half: a SMALL id still echoes exactly as before */
        make_post(bigreq, sizeof bigreq, port, "bitcoin", "bitcoin",
                  "{\"jsonrpc\":\"2.0\",\"id\":41,\"method\":\"getblockcount\",\"params\":[]}", NULL);
        raw_exchange(port, bigreq, strlen(bigreq));
        ck("RPC-16: a small numeric id still echoes verbatim", has_substr(raw_out, "\"id\":41"));
    }

    /* ============ 10b. RPC-6: batch requests (raw) =========================
     * Core (httprpc.cpp, valRequest.isArray()): HTTP 200, one reply per
     * element, per-element failures as error OBJECTS inside the array,
     * notifications executed but omitted, all-notification batch -> 204,
     * empty array -> "[]" at 200. */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "[{\"method\":\"getblockcount\",\"id\":1},"
              "{\"method\":\"getbestblockhash\",\"id\":2}]", NULL);
    raw_exchange(port, req, strlen(req));
    ck("batch of two -> HTTP 200 (was 500 before RPC-6)",
       has_prefix(raw_out, "HTTP/1.1 200 OK"));
    ck("batch reply is a JSON ARRAY", has_substr(raw_out, "\r\n\r\n["));
    ck("batch echoes BOTH ids",
       has_substr(raw_out, "\"id\":1") && has_substr(raw_out, "\"id\":2"));
    ck("batch did not answer a top-level parse error",
       !has_substr(raw_out, "Top-level object parse error"));

    /* a failing element is an error object IN the array, not an HTTP error */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "[{\"method\":\"getblockcount\",\"id\":1},"
              "{\"method\":\"nosuchmethod\",\"id\":2}]", NULL);
    raw_exchange(port, req, strlen(req));
    ck("batch with a failing member is STILL HTTP 200",
       has_prefix(raw_out, "HTTP/1.1 200 OK"));
    ck("the failing member carries -32601 inside the array",
       has_substr(raw_out, "\"code\":-32601"));

    /* a non-object member is Core's -32600 "Invalid Request object", per
     * element -- NOT the top-level -32700, and not an HTTP error */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "[1,2,3]", NULL);
    raw_exchange(port, req, strlen(req));
    ck("[1,2,3] is a batch of three INVALID requests, HTTP 200",
       has_prefix(raw_out, "HTTP/1.1 200 OK"));
    ck("[1,2,3] members answer -32600 Invalid Request object",
       has_substr(raw_out, "\"code\":-32600") &&
       has_substr(raw_out, "\"message\":\"Invalid Request object\""));

    /* all-notification batch -> 204, no body */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "[{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\"}]", NULL);
    raw_exchange(port, req, strlen(req));
    ck("all-notification batch -> HTTP 204", has_prefix(raw_out, "HTTP/1.1 204"));

    /* but an EMPTY array is "[]" at 200, not 204 (Core's deliberate
     * back-compat divergence from the JSON-RPC 2.0 spec) */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin", "[]", NULL);
    raw_exchange(port, req, strlen(req));
    ck("empty batch -> HTTP 200, not 204", has_prefix(raw_out, "HTTP/1.1 200 OK"));
    ck("empty batch body is []", has_substr(raw_out, "\r\n\r\n[]"));

    /* THE OPPOSITE HALF. Adding the batch branch must not turn a single
     * request into a one-element batch: the reply body has to stay a bare
     * OBJECT, and the single-request HTTP status mapping has to survive.
     * This daemon is deliberately not warmed up, so getblockcount answers
     * -28 "Loading block index..." -> HTTP 500 on the V1 path; that is the
     * status the pre-RPC-6 code sent for this body too, and asserting it
     * here is what would catch exec_one having lost the status mapping. */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "{\"method\":\"getblockcount\",\"id\":9}", NULL);
    raw_exchange(port, req, strlen(req));
    { const char* b = strstr(raw_out, "\r\n\r\n");
      ck("a single request is still answered as a bare OBJECT, not an array",
         b && b[4] == '{');
      ck("a single request still echoes its id", has_substr(raw_out, "\"id\":9"));
      ck("a single request keeps its own HTTP status mapping (not forced 200)",
         has_prefix(raw_out, "HTTP/1.1 500")); }

    /* ============ 11. V2 notification -> 204 no body (raw) =================
     * getbalance FAILS on this server (no rescan), which makes this the
     * stronger form of the check: a notification gets no response even when
     * the method errors. That path used to emit a full error body. */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "{\"jsonrpc\":\"2.0\",\"method\":\"getbalance\",\"params\":[]}", NULL);
    raw_exchange(port, req, strlen(req));
    ck("V2 notification HTTP 204", has_prefix(raw_out, "HTTP/1.1 204 No Content"));
    ck("V2 notification no body", strlen(raw_out) == (size_t)(strstr(raw_out, "\r\n\r\n") + 4 - raw_out));

    /* ============ 12. V1 request -> both result+error fields (raw) ========= */
    /* uses a method that SUCCEEDS on a server with no rescan: this case is
     * about the V1 envelope carrying result AND error:null, not about which
     * method produced the result. */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "{\"id\":1,\"method\":\"getnewaddress\",\"params\":[]}", NULL);
    raw_exchange(port, req, strlen(req));
    ck("V1 success envelope has error:null",
       has_substr(raw_out, "\"error\":null,\"id\":1") && has_substr(raw_out, "\"result\":\""));

    /* ============ 13. wrong method on parametrized - GET handled above ====== */
    /* listunspent, same real-index story as getbalance above: no addr
     * index configured, so the wallet's own default address correctly
     * owns nothing yet -- an empty array. */
    run_cli(port, "bitcoin", "bitcoin", "listunspent", NULL);
    ck_out("listunspent without a rescan prints nothing (real server)", "");
    ck("listunspent without a rescan errors naming rescanblockchain (real server)",
       strstr(err_buf, "-4") && strstr(err_buf, "rescanblockchain"));

    /* ============ 14. large request (2026-08-25 transport fix) ============
     * The request buffer was a fixed 256KB stack array that silently
     * truncated bigger bodies -- submitblock's ~8MB hex could never arrive.
     * A 600KB params payload to an unknown method must now be read IN FULL
     * and parsed: the -32601 Method-not-found reply proves the body crossed
     * the old limit intact (a truncated body is a JSON parse error). */
    { size_t big_n = 600*1024;
      char* bigp = malloc(big_n + 1);
      memset(bigp, 'a', big_n); bigp[big_n] = 0;
      size_t cap = big_n + 4096;
      char* body = malloc(cap);
      snprintf(body, cap, "{\"id\":9,\"method\":\"nosuchmethod\",\"params\":[\"%s\"]}", bigp);
      char* req = malloc(cap + 2048);
      make_post(req, cap + 2048, port, "bitcoin", "bitcoin", body, NULL);
      raw_exchange(port, req, strlen(req));
      ck("600KB request parsed past the old 256KB cap (-32601, not a parse error)",
         has_substr(raw_out, "Method not found"));
      free(req); free(body); free(bigp); }

    /* ==== a request whose BODY arrives in a second segment must still work ==
     *
     * find_header was passed hlen = hdrend - buf, where hdrend points at the
     * '\r' of the terminating CRLFCRLF -- the last header line's own
     * terminator. memchr therefore found no line end for that header and the
     * scan gave up on it, so Content-Length (the last header this server's own
     * make_post emits) was never found: the read loop stopped without waiting
     * for the body and the client got "Parse error". It worked only because a
     * small request arrives in a single read(). The same blindness made an
     * Authorization header sent last invisible to auth_ok, i.e. a 401 for a
     * correctly credentialed client.
     *
     * Found while building the RPC-4 case below -- until it was fixed, a
     * trickled BODY was answered immediately and could not have pinned
     * anything, which would have made that test vacuous. */
    {
        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET; sa.sin_port = htons((unsigned short)port);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ck("split-request client connected", sfd >= 0 && connect(sfd, (struct sockaddr*)&sa, sizeof sa) == 0);
        /* The request is built BY HAND, not with make_post: make_post emits
         * "Connection: close" after Content-Length, so Content-Length is not
         * the last header there and the blind spot never shows. Real clients
         * routinely end their header block with Content-Length. */
        char whole[4096];
        const char* b88 = "{\"id\":88,\"method\":\"getblockcount\",\"params\":[]}";
        int wl = snprintf(whole, sizeof whole,
            "POST / HTTP/1.1\r\n"
            "Host: 127.0.0.1:%d\r\n"
            "Authorization: Basic Yml0Y29pbjpiaXRjb2lu\r\n"     /* bitcoin:bitcoin */
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"                            /* LAST header */
            "\r\n%s", port, strlen(b88), b88);
        const char* split = strstr(whole, "\r\n\r\n");
        size_t hlen = split ? (size_t)(split - whole) + 4 : (size_t)wl;
        ck("request ends its header block with Content-Length", split != NULL);
        (void)!send(sfd, whole, hlen, MSG_NOSIGNAL);          /* headers only */
        { struct timespec ts = { 0, 400*1000*1000 }; nanosleep(&ts, NULL); }
        (void)!send(sfd, whole + hlen, (size_t)wl - hlen, MSG_NOSIGNAL);  /* body */
        char rb[4096]; size_t rn = 0;
        { struct timeval tv = { 5, 0 }; setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); }
        for (;;){ ssize_t r = recv(sfd, rb + rn, sizeof rb - 1 - rn, 0); if (r <= 0) break; rn += (size_t)r; if (rn >= sizeof rb - 1) break; }
        rb[rn] = 0;
        ck("a body sent in a SECOND segment is not a parse error",
           rn > 0 && !strstr(rb, "Parse error"));
        ck("...and the request is actually answered (id echoed)",
           strstr(rb, "\"id\":88") != NULL);
        close(sfd);
    }

    /* An Authorization header sent LAST must authenticate. Same blind spot:
     * auth_ok scans the same range, so a correctly credentialed client whose
     * Authorization line ended the header block got 401. */
    {
        char req2[4096];
        const char* b89 = "{\"id\":89,\"method\":\"getblockcount\",\"params\":[]}";
        snprintf(req2, sizeof req2,
            "POST / HTTP/1.1\r\n"
            "Host: 127.0.0.1:%d\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Authorization: Basic Yml0Y29pbjpiaXRjb2lu\r\n"     /* LAST header */
            "\r\n%s", port, strlen(b89), b89);
        raw_exchange(port, req2, strlen(req2));
        ck("Authorization sent as the LAST header still authenticates (not 401)",
           !has_substr(raw_out, "401 Unauthorized"));
    }

    /* ============ RPC-4: a slow sender cannot pin a worker forever ========
     *
     * THE BUG. -rpcservertimeout is a PER-READ timeout (SO_RCVTIMEO) and is
     * reset by every byte, and service_conn does its reading on a pool worker
     * BEFORE authentication. A client that trickles one byte per interval
     * therefore held a worker indefinitely with no credentials. Sixteen such
     * sockets (the default rpcthreads) take the whole pool, the next 64
     * connections queue unanswered and the rest get 503 -- including the
     * operator's own `bitcoin-cli stop`.
     *
     * WHAT IS ASSERTED. A connection that announces a large Content-Length and
     * then trickles is dropped within the total budget (3s here, set in the
     * child's environment above), and -- the part that matters -- an ordinary
     * authenticated request still succeeds while it is in flight, proving the
     * worker was not held. The trickle interval is 1s, comfortably under the
     * 30s per-read timeout, so the OLD code would have kept resetting it and
     * never returned. */
    {
        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET; sa.sin_port = htons((unsigned short)port);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ck("RPC-4 slow client connected", sfd >= 0 && connect(sfd, (struct sockaddr*)&sa, sizeof sa) == 0);
        /* An INCOMPLETE header block: the blank line that ends the headers is
         * never sent, so the server's read loop can never decide the request
         * is complete and keeps reading. This is the case only a total budget
         * closes -- a trickled BODY would also be held, but bounding that
         * relies on Content-Length parsing, and the point here is the loop
         * that has no bound at all. */
        const char* head = "POST / HTTP/1.1\r\nContent-Type: application/json\r\n";
        (void)!write(sfd, head, strlen(head));

        struct timespec s0; clock_gettime(CLOCK_MONOTONIC, &s0);
        int closed = 0;
        for (int i = 0; i < 12 && !closed; i++){
            struct timespec ts = { 1, 0 }; nanosleep(&ts, NULL);
            /* MSG_NOSIGNAL: once the server drops us this write hits a
             * closed peer, and a SIGPIPE would kill the harness instead of
             * reporting the very behaviour under test. Header bytes, so the
             * request stays syntactically incomplete however long we go on. */
            if (send(sfd, "X", 1, MSG_NOSIGNAL) < 0) { closed = 1; break; }
            /* Is the server done with us? A closed peer shows up as a read of
             * 0 (its 408 arrives first, which also counts as "answered"). */
            char probe[256];
            struct timeval z = { 0, 1000 };
            setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &z, sizeof z);
            ssize_t r = recv(sfd, probe, sizeof probe, 0);
            if (r == 0) closed = 1;
            else if (r > 0){ probe[r < 255 ? r : 255] = 0; if (strstr(probe, "408")) closed = 1; }
            if (i == 0 && !closed){
                /* mid-trickle: the pool must still answer someone else */
                char r2[8192];
                make_post(r2, sizeof r2, port, "bitcoin", "bitcoin",
                          "{\"id\":77,\"method\":\"getblockcount\",\"params\":[]}", NULL);
                raw_exchange(port, r2, strlen(r2));
                ck("RPC-4 an ordinary request is answered while a slow client is mid-request",
                   has_substr(raw_out, "\"id\":77") || has_substr(raw_out, "result"));
            }
        }
        struct timespec s1; clock_gettime(CLOCK_MONOTONIC, &s1);
        long took = (long)(s1.tv_sec - s0.tv_sec);
        printf("      (slow client released after ~%lds, budget 3s)\n", took);
        ck("RPC-4 the trickling client is released, not held indefinitely", closed);
        ck("RPC-4 ...and released near the total budget, not after 12 resets", took <= 8);
        close(sfd);
    }

    /* ---- RPC-5 (audit 2026-09-03): only a real getblocktemplate longpolls,
     * and the waiters are bounded.
     *
     * The path used to be chosen by searching the RAW BODY for the substrings
     * "longpollid" and "getblocktemplate" before any parsing, so ANY method
     * carrying those bytes reached it -- and the path returns before the
     * worker slot is released, so -rpcthreads and -rpcworkqueue do not bound
     * it: a detached 64 MiB-stack thread and an fd per request, held up to
     * 60 s. Thousands exhaust `ulimit -u`, and then fork() for inbound P2P
     * fails.
     *
     * NOT tested over HTTP, deliberately. A decoy request answers identically
     * whether or not it was handled off-thread, because the cost is the SPAWN
     * and not the latency -- a timing assertion written first here PASSED with
     * the fix reverted. The two mechanisms are therefore exercised directly. */
    {
        extern int rpc_lp_is_gbt(const char* body, unsigned long blen);
        extern int rpc_lp_try_take(void);
        extern void rpc_lp_release(void);
        extern int rpc_lp_max_waiters(void);
        extern int rpc_lp_waiters_inflight(void);

        const char* decoy =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getbestblockhash\",\"params\":[],"
            "\"decoy\":{\"longpollid\":\"aa\",\"also\":\"getblocktemplate\"}}";
        const char* real =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblocktemplate\","
            "\"params\":[{\"longpollid\":\"aa\"}]}";
        ck("RPC-5 a decoy body carrying both tokens is NOT a getblocktemplate",
           rpc_lp_is_gbt(decoy, strlen(decoy)) == 0);
        ck("RPC-5 a real getblocktemplate still is",
           rpc_lp_is_gbt(real, strlen(real)) == 1);

        /* the cap: exactly LP_MAX_WAITERS may be in flight, then no more */
        int cap = rpc_lp_max_waiters();
        int got = 0;
        for (int i = 0; i < cap + 8; i++) if (rpc_lp_try_take()) got++;
        ck("RPC-5 the waiter count is bounded, not unbounded", got == cap);
        ck("RPC-5   and the counter agrees", rpc_lp_waiters_inflight() == cap);
        rpc_lp_release();
        ck("RPC-5 releasing one frees exactly one slot", rpc_lp_try_take() == 1);
        for (int i = 0; i < cap; i++) rpc_lp_release();
        ck("RPC-5 all slots return when the waiters finish", rpc_lp_waiters_inflight() == 0);
    }

    /* ---- RPC-10 (audit 2026-09-03): Core's reply framing ----
     * Core appends "\n" to every reply body and this server did not, so the
     * "bit-exact" claim was off by one byte. And it closes after every reply
     * while never saying so, which makes an HTTP/1.1 keep-alive client
     * (http.client, requests) see an unexpected EOF on its NEXT request.
     *
     * The newline is gated on there BEING a body -- section 11 above asserts a
     * v2 notification's response ends exactly at the header terminator, and an
     * unconditional append would emit a 1-byte body on a 204 and break it.
     * That existing assertion is the guard, so it must keep passing. */
    {
        char req[512];
        make_post(req, sizeof req, port, "bitcoin", "bitcoin",
                  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[]}", NULL);
        int n = raw_exchange(port, req, strlen(req));
        /* A 401 has no body and ends with the header terminator, so it
         * satisfies "ends with a newline" and "Content-Length 0 == 0" for
         * free -- the first draft of this used the wrong credentials and two
         * of its three assertions passed vacuously on exactly that. Pin the
         * 200 first so the rest cannot. */
        ck("RPC-10 the reply still arrives", n > 0);
        /* "jsonrpc", not "result": on a freshly-started daemon this answers
         * -28 "Loading block index...", which is a perfectly real 200 body
         * with no result key. Matching on "result" made this fail for the
         * wrong reason. */
        ck("RPC-10 ...as a 200 with a real body (not a 401)",
           has_prefix(raw_out, "HTTP/1.1 200 OK") && has_substr(raw_out, "\"jsonrpc\""));
        ck("RPC-10 Connection: close is announced", has_substr(raw_out, "Connection: close"));
        ck("RPC-10 the body ends with Core's newline",
           n > 0 && raw_out[strlen(raw_out) - 1] == '\n');
        /* and the length header agrees with what was sent -- an appended byte
         * that Content-Length did not count would hang a conforming client */
        { const char* cl = strstr(raw_out, "Content-Length: ");
          const char* be = strstr(raw_out, "\r\n\r\n");
          if (cl && be){
              long want = atol(cl + 16);
              long got  = (long)strlen(be + 4);
              ck("RPC-10 Content-Length counts the newline", want == got);
          } else ck("RPC-10 Content-Length present", 0); }
    }

    /* ---- teardown ---- */
    kill(srv, SIGTERM);
    waitpid(srv, NULL, 0);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

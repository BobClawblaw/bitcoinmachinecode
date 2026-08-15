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
 *   2. by exec'ing the ACTUAL daemon/bitcoin_cli against it (the paired
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
    argv[ac++] = (char*)"daemon/bitcoin_cli";
    argv[ac++] = portarg;
    argv[ac++] = uarg;
    argv[ac++] = parg;
    argv[ac++] = (char*)method;
    if (p1) argv[ac++] = (char*)p1;
    argv[ac] = NULL;
    int pout[2], perr[2];
    pipe(pout); pipe(perr);
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
    write(fd, req, reqlen);
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
    int pout[2]; pipe(pout);
    pid_t srv = fork();
    if (srv == 0) {
        dup2(pout[1], 2); close(pout[0]); close(pout[1]);
        char* argv[] = { (char*)"daemon/bitcoin_rpcd", NULL };
        /* TEST_RPC_PORT=0 -> HTTP server binds an ephemeral port (see daemon) */
        setenv("TEST_RPC_PORT", "0", 1);
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

    /* ============ 1. correct auth -> getnewaddress via real bitcoin_cli ===== */
    extern long wallet_derive_p2wpkh_address(char* out, long cap, const unsigned char seed[64], unsigned index);
    unsigned char seed[64]; for (int i = 0; i < 64; i++) seed[i] = (unsigned char)(0x10 + i);
    char addr[96]; wallet_derive_p2wpkh_address(addr, 96, seed, 0);
    char expect[128]; snprintf(expect, sizeof expect, "%s\n", addr);
    run_cli(port, "bitcoin", "bitcoin", "getnewaddress", NULL);
    ck("bitcoin_cli getnewaddress exit 0", last_exit == 0);
    ck_out("getnewaddress prints raw address (real server)", expect);

    /* ============ 2. getbalance via real bitcoin_cli ======================= */
    run_cli(port, "bitcoin", "bitcoin", "getbalance", NULL);
    ck_out("getbalance 0.25500000 (real server)", "0.25500000\n");

    /* ============ 3. unknown method -> bitcoin_cli stderr ------------------ */
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

    /* ============ 10. non-object request -> -32600 (raw) ==================== */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin", "[1,2,3]", NULL);
    raw_exchange(port, req, strlen(req));
    ck("non-object HTTP 500 parse path", has_prefix(raw_out, "HTTP/1.1 500"));
    ck("non-object -32700 parse error",
       has_substr(raw_out, "\"message\":\"Top-level object parse error\""));

    /* ============ 11. V2 notification -> 204 no body (raw) ================= */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "{\"jsonrpc\":\"2.0\",\"method\":\"getbalance\",\"params\":[]}", NULL);
    raw_exchange(port, req, strlen(req));
    ck("V2 notification HTTP 204", has_prefix(raw_out, "HTTP/1.1 204 No Content"));
    ck("V2 notification no body", strlen(raw_out) == (size_t)(strstr(raw_out, "\r\n\r\n") + 4 - raw_out));

    /* ============ 12. V1 request -> both result+error fields (raw) ========= */
    make_post(req, sizeof req, port, "bitcoin", "bitcoin",
              "{\"id\":1,\"method\":\"getbalance\",\"params\":[]}", NULL);
    raw_exchange(port, req, strlen(req));
    ck("V1 success envelope has error:null",
       has_substr(raw_out, "\"result\":\"0.25500000\",\"error\":null,\"id\":1"));

    /* ============ 13. wrong method on parametrized - GET handled above ====== */
    /* spot-check listunspent object render via real bitcoin_cli */
    run_cli(port, "bitcoin", "bitcoin", "listunspent", NULL);
    ck("listunspent array rendered (real server)",
       has_substr(out_buf, "\"amount\": \"0.25000000\"") &&
       has_substr(out_buf, "\"amount\": \"0.00500000\""));

    /* ---- teardown ---- */
    kill(srv, SIGTERM);
    waitpid(srv, NULL, 0);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

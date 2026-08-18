/* test_rpc_transport.c -- end-to-end bitcoin-cli network layer test.
 *
 * Proves the REAL JSON-RPC transport path: a minimal loopback HTTP/1.1
 * JSON-RPC responder (pthread) dispatches requests through the shared
 * rpc_dispatch() render path, and the ACTUAL daemon/bitcoin_cli client binary
 * is exec'd against it over a real local socket. Asserts:
 *   1. the client sends a byte-exact JSON-RPC 2.0 framed HTTP request,
 *   2. the reply the client prints is the bit-exact Core rendering
 *      (string results raw; objects/arrays via write(2)),
 *   3. RPC errors produce bitcoin-cli's exact stderr + non-zero exit,
 *   4. transport/auth failures produce bitcoin-cli's error line.
 *
 * This is the client-side of the RPC-transport OPEN item; the production HTTP
 * server endpoint (which also dispatches through rpc_dispatch) is the child
 * card t_0ca5d72e.
 */
#include "../rpc_net.h"
#include "../rpc_commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/wait.h>

/* wallet-core command layer (asm/wallet_core.c) */
extern long wallet_derive_p2wpkh_address(char* out, long cap, const unsigned char seed[64], unsigned index);
extern long wallet_derive_p2wpkh_change(char* out, long cap, const unsigned char seed[64], unsigned index);

static int fails = 0;
static void ck(const char* label, int cond) {
    printf("%s %s\n", cond ? "ok  :" : "FAIL:", label);
    if (!cond) fails++;
}
static int last_req_exit = 0;

/* ---- server state ---- */
static int srv_port;
static int srv_fd;
static volatile int srv_run = 1;
static pthread_t srv_thr;

/* wallet state shared by the render path */
static unsigned char seed[64];
static unsigned char utxo_txid[2][32];
static unsigned long  utxo_idx[2]     = {0, 1};
static unsigned long long utxo_val[2] = {25000000ULL, 500000ULL}; /* 0.25 + 0.005 */
static const char* utxo_script[2] = {
    "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", /* P2PKH */
    "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", /* P2PKH */
};
static rpc_wallet wallet = { seed, utxo_txid, utxo_idx, utxo_val,
                             (const unsigned char* const*)utxo_script, 2 };

/* capture the most recent client request for wire-framing assertions */
static char last_req[65536];
static size_t last_req_len = 0;

/* Split a reply body: returns the JSON (after HTTP body). */
static void service_conn(int cfd) {
    char buf[65536];
    size_t got = 0;
    /* Read until we have the full HTTP headers + Content-Length body (TCP may
     * split the request across segments, so loop instead of assuming one read
     * delivers everything). */
    while (1) {
        ssize_t n = read(cfd, buf + got, sizeof buf - 1 - got);
        if (n <= 0) break;
        got += (size_t)n;
        if (got + 1 >= sizeof buf) break;
        /* if we have headers with a Content-Length and the body is complete, stop */
        char* hdrend = NULL;
        for (size_t i = 0; i + 3 < got; i++)
            if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') { hdrend = buf + i; break; }
        if (hdrend) {
            char* cl = strstr(buf, "Content-Length:");
            long clv = cl ? strtol(cl + 15, NULL, 10) : -1;
            if (clv >= 0 && (long)(got - (size_t)((hdrend + 4) - buf)) >= clv) break;
            if (clv < 0) break; /* no content-length; rely on full-data heuristic */
        }
    }
    buf[got] = 0;
    if (got == 0) { close(cfd); return; }
    /* parse HTTP request */
    const char *method, *path, *body; size_t mlen, plen, blen;
    if (!http_request_parse(buf, (size_t)got, &method, &mlen, &path, &plen, &body, &blen)) {
        const char* e400 = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        write(cfd, e400, strlen(e400)); close(cfd); return;
    }
    /* capture the request line + body for wire assertions */
    {
        /* store the JSON body as the "last request" */
        size_t copy = blen < sizeof last_req ? blen : sizeof last_req - 1;
        memcpy(last_req, body, copy); last_req[copy] = 0; last_req_len = copy;
    }
    (void)mlen; (void)path; (void)plen;

    /* parse JSON-RPC request */
    rj_val* req = rj_parse(body, blen);
    const char* reply_body;
    char reply_buf[65536];
    if (!req || req->typ != RJ_OBJ) {
        reply_body = "{\"result\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}";
    } else {
        rj_val* m = rj_obj_get(req, "method");
        rj_val* pid = rj_obj_get(req, "id");
        const char* meth = (m && m->typ == RJ_STR) ? m->str : "";
        rj_val* params = rj_obj_get(req, "params");
        rj_val* result = NULL; long ec = 0; const char* em = NULL;
        int ok = rpc_dispatch(meth, params, &wallet, &result, &ec, &em);
        if (ok) {
            rj_val* resp = rj_obj();
            rj_obj_set(resp, "result", result);
            rj_obj_set(resp, "error", rj_null());
            if (pid) rj_obj_set(resp, "id", rj_str(pid->str));
            else     rj_obj_set(resp, "id", rj_null());
            rj_write(reply_buf, sizeof reply_buf, resp, 0);
            rj_free(resp);
            reply_body = reply_buf;
        } else {
            rj_val* err = rj_obj();
            rj_obj_set(err, "code", rj_numf("%ld", ec));
            rj_obj_set(err, "message", rj_str(em ? em : ""));
            rj_val* resp = rj_obj();
            rj_obj_set(resp, "result", rj_null());
            rj_obj_set(resp, "error", err);
            if (pid) rj_obj_set(resp, "id", rj_str(pid->str));
            else     rj_obj_set(resp, "id", rj_null());
            rj_write(reply_buf, sizeof reply_buf, resp, 0);
            rj_free(resp);
            reply_body = reply_buf;
        }
        rj_free(req);
    }
    char hdr[128];
    int hl = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %ld\r\n\r\n",
        (long)strlen(reply_body));
    write(cfd, hdr, (size_t)hl);
    write(cfd, reply_body, strlen(reply_body));
    close(cfd);
}

static void* srv_thread(void* arg) {
    (void)arg;
    while (srv_run) {
        struct sockaddr_in cli; socklen_t cl = sizeof cli;
        int c = accept(srv_fd, (struct sockaddr*)&cli, &cl);
        if (c < 0) continue;
        service_conn(c);
    }
    return NULL;
}

static void start_server(void) {
    srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = 0; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(srv_fd, (struct sockaddr*)&a, sizeof a);
    listen(srv_fd, 8);
    socklen_t al = sizeof a; getsockname(srv_fd, (struct sockaddr*)&a, &al);
    srv_port = ntohs(a.sin_port);
    pthread_create(&srv_thr, NULL, srv_thread, NULL);
}
static void stop_server(void) {
    srv_run = 0;
    /* wake any blocked accept so the loop can observe srv_run==0 and exit;
     * shutdown() unblocks a blocking accept more reliably than close() from
     * another thread. */
    shutdown(srv_fd, SHUT_RDWR);
    close(srv_fd);
    pthread_detach(srv_thr); /* don't join: the accept may be mid-return; the
                              * test process is exiting immediately anyway. */
}

/* Run the real bitcoin_cli binary; capture stdout/stderr/exit. */
static char out_buf[65536], err_buf[16384];
static int run_cli(const char* portarg, ...) {
    /* build argv: bitcoin_cli <portarg> method params... */
    char* argv[32]; int ac = 0;
    argv[ac++] = (char*)"daemon/bitcoin_cli";
    argv[ac++] = (char*)portarg;
    /* consume varargs as method + params */
    va_list ap; va_start(ap, portarg);
    const char* m;
    while ((m = va_arg(ap, const char*))) argv[ac++] = (char*)m;
    va_end(ap);
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
    ssize_t n1 = read(pout[0], out_buf, sizeof out_buf - 1); out_buf[n1 < 0 ? 0 : n1] = 0;
    ssize_t n2 = read(perr[0], err_buf, sizeof err_buf - 1); err_buf[n2 < 0 ? 0 : n2] = 0;
    close(pout[0]); close(perr[0]);
    int st; waitpid(pid, &st, 0);
    last_req_exit = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void ck_out(const char* label, const char* expect) {
    ck(label, strcmp(out_buf, expect) == 0);
    if (strcmp(out_buf, expect) != 0) {
        printf("      stdout got : [%s]\n      want        : [%s]\n", out_buf, expect);
    }
}
static void ck_err(const char* label, const char* expect) {
    ck(label, strcmp(err_buf, expect) == 0);
    if (strcmp(err_buf, expect) != 0) {
        printf("      stderr got : [%s]\n      want        : [%s]\n", err_buf, expect);
    }
}

int main(int argc, char** argv) {
    char portarg[64];
    if (argc >= 2) snprintf(portarg, sizeof portarg, "-rpcport=%s", argv[1]);
    else {
        /* derive ephemeral port ourselves: start server, build portarg */
        for (int i = 0; i < 64; i++) seed[i] = (unsigned char)(0x10 + i);
        for (int i = 0; i < 32; i++) { utxo_txid[0][i] = (unsigned char)(0xa0 + i); utxo_txid[1][i] = (unsigned char)(0x50 + i); }
        start_server();
        snprintf(portarg, sizeof portarg, "-rpcport=%d", srv_port);
    }

    /* ---------- 1. getnewaddress: string result rendered raw ---------- */
    {
        /* expected address derived from seed idx0 receive */
        char addr[96]; wallet_derive_p2wpkh_address(addr, 96, seed, 0);
        char portfixed[64]; snprintf(portfixed, sizeof portfixed, "-rpcport=%d", srv_port);
        int rc = run_cli(portfixed, "getnewaddress", NULL);
        ck("getnewaddress exit 0", rc == 0);
        char expect[128]; snprintf(expect, sizeof expect, "%s\n", addr);
        ck_out("getnewaddress prints raw address", expect);
    }

    /* ---------- 2. getrawchangeaddress ---------- */
    {
        char addr[96]; wallet_derive_p2wpkh_change(addr, 96, seed, 0);
        char portfixed[64]; snprintf(portfixed, sizeof portfixed, "-rpcport=%d", srv_port);
        run_cli(portfixed, "getrawchangeaddress", NULL);
        char expect[128]; snprintf(expect, sizeof expect, "%s\n", addr);
        ck_out("getrawchangeaddress prints raw address", expect);
    }

    /* ---------- 3. getbalance: string result, Core amount ---------- */
    /* getbalance now answers from the real scriptPubKey->UTXO address
     * index (asm/daemon/build_addr_index.c), not the wallet's own fake
     * utxo_* arrays -- see rpc_commands_set_addr_index's doc comment.
     * This harness's in-process rpc_dispatch never calls that setter, so
     * it's exactly a fresh/unconfigured server: the wallet's own default
     * address (correctly) resolves to zero balance, same as real Core
     * before it's synced. */
    {
        char portfixed[64]; snprintf(portfixed, sizeof portfixed, "-rpcport=%d", srv_port);
        run_cli(portfixed, "getbalance", NULL);
        ck_out("getbalance (no addr index configured)", "0.00000000\n");
    }

    /* ---------- 4. wire framing: request body captured on the socket ---------- */
    {
        char portfixed[64]; snprintf(portfixed, sizeof portfixed, "-rpcport=%d", srv_port);
        run_cli(portfixed, "getnewaddress", NULL);
        const char* want = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getnewaddress\",\"params\":[]}";
        ck("wire request is byte-exact JSON-RPC 2.0 framed", strcmp(last_req, want) == 0);
        if (strcmp(last_req, want)) printf("      got : [%s]\n      want: [%s]\n", last_req, want);
    }

    /* ---------- 5. validateaddress: object -> pretty write(2) ---------- */
    {
        char portfixed[64]; snprintf(portfixed, sizeof portfixed, "-rpcport=%d", srv_port);
        run_cli(portfixed, "validateaddress", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", NULL);
        const char* want =
            "{\n"
            "  \"isvalid\": true,\n"
            "  \"address\": \"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH\",\n"
            "  \"scriptPubKey\": \"76a914751e76e8199196d454941c45d1b3a323f1433bd688ac\",\n"
            "  \"isscript\": false,\n"
            "  \"iswitness\": false,\n"
            "  \"ischange\": false\n"
            "}\n";
        ck_out("validateaddress pretty write(2)", want);
    }

    /* ---------- 6. listunspent: array of objects ---------- */
    /* Same real-index story as getbalance above: no addr index configured
     * in this harness, so the wallet's own default address (correctly)
     * owns nothing yet -- an empty array, same as real Core pre-sync. */
    {
        char portfixed[64]; snprintf(portfixed, sizeof portfixed, "-rpcport=%d", srv_port);
        run_cli(portfixed, "listunspent", NULL);
        ck_out("listunspent (no addr index configured)", "[]\n");
    }

    /* ---------- 7. gettxout: real Core semantics (any confirmed outpoint via
     * the LSM UTXO store, not the wallet's own outputs -- see rpc_commands_
     * set_utxo_store's doc comment). This harness's in-process rpc_dispatch
     * never calls that setter, so it's exactly a fresh/unconfigured server
     * with no chain data loaded: every outpoint (wallet's own included)
     * correctly comes back null, same as real Core before it's synced. ---- */
    {
        char portfixed[64]; snprintf(portfixed, sizeof portfixed, "-rpcport=%d", srv_port);
        char tx0[65]; { char* d="0123456789abcdef"; for(int i=0;i<32;i++){tx0[i*2]=d[utxo_txid[0][i]>>4];tx0[i*2+1]=d[utxo_txid[0][i]&15];} tx0[64]=0; }
        /* exec: gettxout <txid> 0 -- wallet's own outpoint, but no UTXO store
         * configured in this harness, so still null (not an error) */
        run_cli(portfixed, "gettxout", tx0, "0", NULL);
        ck("gettxout (no store configured) exit 0", last_req_exit == 0);
        ck_out("gettxout (no store configured) prints nothing (null result)", "");
        /* unknown txid -> null -> bitcoin-cli prints nothing */
        run_cli(portfixed, "gettxout", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0", NULL);
        ck("gettxout unknown exit 0", last_req_exit == 0);
        ck_out("gettxout unknown prints nothing (null result)", "");
    }

    /* ---------- 8. unknown method -> JSON-RPC error -> bitcoin-cli stderr ---- */
    {
        char portfixed[64]; snprintf(portfixed, sizeof portfixed, "-rpcport=%d", srv_port);
        int rc = run_cli(portfixed, "nosuchmethod", NULL);
        ck("unknown method exit 1", rc == 1);
        ck_err("unknown method stderr", "error code: -32601\nerror message:\nMethod not found\n");
    }

    /* ---------- 9. transport failure (dead port) -> bitcoin-cli error ----- */
    {
        char bad[64]; snprintf(bad, sizeof bad, "-rpcport=%d", srv_port + 1000);
        int rc = run_cli(bad, "getnewaddress", NULL);
        ck("connect-fail exit 1", rc == 1);
        ck("connect-fail error contains couldn't connect", strstr(err_buf, "couldn't connect to server") != NULL);
    }

    /* ---------- 10. decoderawtransaction (object render) ---------- */
    {
        char portfixed[64]; snprintf(portfixed, sizeof portfixed, "-rpcport=%d", srv_port);
        /* minimal legacy tx: version 1, 1 input(P2PKH outpoint, empty sig, seq ffffffff),
         * 1 output 100000 sats to P2PKH, locktime 0 */
        run_cli(portfixed, "decoderawtransaction",
            "0100000001"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  /* prev txid (raw, display-reversed shown) */
            "00000000"
            "00"
            "ffffffff"
            "01"
            "a086010000000000"
            "1976a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
            "00000000", NULL);
        ck("decoderawtransaction exit 0", last_req_exit == 0);
        ck("decode has vin/vout", strstr(out_buf, "\"vin\"") != NULL && strstr(out_buf, "\"vout\"") != NULL);
        ck("decode value 0.001", strstr(out_buf, "\"value\": 0.00100000") != NULL);
        ck("decode address present", strstr(out_buf, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") != NULL);
    }

    stop_server();
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}

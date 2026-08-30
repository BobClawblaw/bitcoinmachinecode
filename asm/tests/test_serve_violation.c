/* tests/test_serve_violation.c -- the serve loop reports protocol violations
 * (audit 2026-08-29 finding 7).
 *
 * peer_misbehaving() shipped with a 100-point threshold, a shared ban list and
 * /32 auto-ban, and ZERO call sites -- machinery that looked like a defence
 * and did nothing. This test exists to make sure the first real caller stays
 * connected: it drives the actual asm serve loop, sends an oversized message
 * announcement, and asserts the callback fired with the right reason.
 *
 * The negative half matters just as much: a WELL-FORMED message must not
 * trigger it. A hook that fires on every disconnect would look identical in
 * a log and would ban honest peers.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>

extern int  node_accept_handshake(int fd);
extern int  node_handshake(int fd);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern unsigned int net_magic;
extern void (*g_serve_violation_hook)(const char*);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static int g_fired = 0;
static char g_reason[128];
static void on_violation(const char* r){
    g_fired = 1;
    snprintf(g_reason, sizeof g_reason, "%s", r ? r : "");
}

/* Run one server child; the client sends `announced` as a message length.
 * Returns the child's exit code: 70 = hook fired, 71 = it did not.
 * `cmd` selects the message type and `body`/`blen` an explicit payload. */
static const char* g_cmd = "inv";
static const unsigned char* g_body = 0;
static unsigned g_blen = 0;
static const char* g_want_reason = "oversized message announcement";

static int run_case(unsigned announced, int send_payload){
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr*)&a, sizeof a)) { close(ls); return -1; }
    socklen_t al = sizeof a; getsockname(ls, (struct sockaddr*)&a, &al);
    listen(ls, 2);

    pid_t pid = fork();
    if (pid == 0){
        int c = accept(ls, 0, 0);
        if (c < 0) _exit(3);
        if (node_accept_handshake(c) != 1) _exit(4);
        g_fired = 0;
        g_serve_violation_hook = on_violation;
        /* The oversize check happens on the header, before the loop reaches
         * the store, so zeroed buffers are enough for this path. */
        static unsigned char st[4096], idx[4096], out[4096];
        node_serve_loop(c, -1, st, idx, out, (long)sizeof out);
        _exit(g_fired ? (strcmp(g_reason, g_want_reason) ? 72 : 70) : 71);
    }
    int fd = tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if (fd < 0){ close(ls); return -1; }
    struct timeval tv = {8, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (node_handshake(fd) != 1){ close(fd); close(ls); return -2; }

    unsigned char h[24];
    memcpy(h, &net_magic, 4);
    memset(h + 4, 0, 12); memcpy(h + 4, g_cmd, strlen(g_cmd));
    h[16] = (unsigned char)announced;         h[17] = (unsigned char)(announced >> 8);
    h[18] = (unsigned char)(announced >> 16); h[19] = (unsigned char)(announced >> 24);
    memset(h + 20, 0, 4);
    ssize_t w = write(fd, h, 24); (void)w;
    if (g_body && g_blen){ w = write(fd, g_body, g_blen); }
    else if (send_payload && announced){
        unsigned char* p = calloc(1, announced);
        if (p){ w = write(fd, p, announced); free(p); }
    }
    shutdown(fd, SHUT_WR);
    int st = 0; waitpid(pid, &st, 0);
    close(fd); close(ls);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -3;
}

int main(void){
    printf("== an oversized announcement is reported as misbehaviour ==\n");
    { int rc = run_case(0xFFFFFFFFu, 0);
      ck("the serve loop called the violation hook", rc == 70);
      if (rc == 72) printf("        it fired, but with the wrong reason string\n");
      if (rc == 71) printf("        the loop dropped the peer WITHOUT reporting it\n"); }

    printf("== a well-formed message does NOT report a violation ==\n");
    /* If the hook fired on ordinary disconnects it would ban honest peers,
     * and the positive test above could not tell the difference. */
    { int rc = run_case(0, 0);
      ck("an empty, valid `inv` is not misbehaviour", rc == 71); }

    { int rc = run_case(32, 1);
      ck("a small valid payload is not misbehaviour", rc == 71); }

    printf("== an inv vector above MAX_INV_SZ is reported ==\n");
    /* Core scores this ("inv message size = %u"). Here it also replaces a
     * single-byte count read that misparsed any vector above 252 entries. */
    { g_want_reason = "inv/getdata vector above MAX_INV_SZ";
      unsigned char hdr[3];
      hdr[0] = 0xfd; hdr[1] = 0x51; hdr[2] = 0xc3;   /* 50001, canonical */
      g_body = hdr; g_blen = 3;
      int rc = run_case(3, 0);
      ck("50001 entries reports a violation", rc == 70);
      if (rc == 72) printf("        fired with the wrong reason\n");
      if (rc == 71) printf("        the loop dropped it WITHOUT reporting\n");
      g_body = 0; g_blen = 0; }

    printf("== a legal inv is NOT a violation ==\n");
    /* The bound must not fire on ordinary traffic; an inv of one block is the
     * commonest message this node receives. */
    { g_want_reason = "inv/getdata vector above MAX_INV_SZ";
      static unsigned char one[37];
      one[0] = 1; one[1] = 2;                      /* count 1, type MSG_BLOCK */
      g_body = one; g_blen = 37;
      ck("a 1-entry inv reports nothing", run_case(37, 0) == 71);
      g_body = 0; g_blen = 0; }
    { g_want_reason = "inv/getdata vector above MAX_INV_SZ";
      static unsigned char big[3 + 300 * 36];
      big[0] = 0xfd; big[1] = 300 & 0xff; big[2] = 300 >> 8;
      for (int i = 0; i < 300; i++) big[3 + i * 36] = 2;   /* MSG_BLOCK */
      g_body = big; g_blen = sizeof big;
      ck("a 300-entry inv reports nothing (used to misparse above 252)",
         run_case((unsigned)sizeof big, 0) == 71);
      g_body = 0; g_blen = 0; }
    g_want_reason = "oversized message announcement";
    g_cmd = "inv";

    printf("== the boundary ==\n");
    { int rc = run_case(4000001u, 0);
      ck("one byte over the limit reports", rc == 70); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

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
 * Returns the child's exit code: 70 = hook fired, 71 = it did not. */
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
        _exit(g_fired ? (strcmp(g_reason, "oversized message announcement") ? 72 : 70) : 71);
    }
    int fd = tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if (fd < 0){ close(ls); return -1; }
    struct timeval tv = {8, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (node_handshake(fd) != 1){ close(fd); close(ls); return -2; }

    unsigned char h[24];
    memcpy(h, &net_magic, 4);
    memset(h + 4, 0, 12); memcpy(h + 4, "inv", 3);
    h[16] = (unsigned char)announced;         h[17] = (unsigned char)(announced >> 8);
    h[18] = (unsigned char)(announced >> 16); h[19] = (unsigned char)(announced >> 24);
    memset(h + 20, 0, 4);
    ssize_t w = write(fd, h, 24); (void)w;
    if (send_payload && announced){
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

    printf("== the boundary ==\n");
    { int rc = run_case(4000001u, 0);
      ck("one byte over the limit reports", rc == 70); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

/* tests/test_v2transport.c -- BIP324 bound to real sockets.
 *
 * The point of this test is that NOTHING here calls the BIP324 code directly.
 * Both sides speak p2p_write and p2p_read -- the same two functions every
 * other file in the node uses -- and the encryption happens underneath them.
 * If the fd-keyed dispatch in bitcoin_net.asm were wrong, these messages
 * would either fail to arrive or arrive in plaintext, and both are checked.
 *
 * Two processes over a socketpair, because the handshake blocks on both
 * sides at once and a single process would deadlock against itself.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "../daemon/v2transport.h"

extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern int  p2p_read(int fd, char cmd_out[12], void* payload, unsigned cap, unsigned* plen_out);
extern unsigned char g_v2_active[];
extern unsigned int net_magic;

/* a payload that must never appear in cleartext on a v2 socket */
static const unsigned char MARKER[8] = { 0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE };

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* the responder half, run in a child process */
static int responder(int fd, int expect_v2){
    int hs = bmc_v2_handshake(fd, 0, 5000);
    if (expect_v2 && hs != 1) return 10;
    if (!expect_v2 && hs != 0) return 11;
    if (!expect_v2) return 0;                 /* v1 case handled by the parent */

    char cmd[12]; unsigned char buf[4096]; unsigned plen;
    for (int i = 0; i < 5; i++){
        int r = p2p_read(fd, cmd, buf, sizeof buf, &plen);
        if (r != 1) return 20 + i;
        if (strncmp(cmd, "ping", 4)) return 30 + i;
        if (plen != 8) return 40 + i;
        if (p2p_write(fd, "pong", 4, buf, 8) <= 0) return 50 + i;
    }
    /* one large message back, to exercise a payload past a single read */
    unsigned char* big = malloc(200000);
    for (int i = 0; i < 200000; i++) big[i] = (unsigned char)(i * 7);
    if (p2p_write(fd, "block", 5, big, 200000) <= 0){ free(big); return 60; }
    free(big);

    /* Finally: read the parent's next message as RAW BYTES rather than through
     * p2p_read, and confirm it is not a v1 frame. Without this the test would
     * pass just as happily if both sides had quietly fallen back to plaintext
     * v1 -- they would still understand each other perfectly. */
    unsigned char raw[512];
    ssize_t n = recv(fd, raw, sizeof raw, 0);
    if (n < 24) return 70;
    unsigned int magic;
    memcpy(&magic, raw, 4);
    if (magic == net_magic) return 71;             /* a v1 header: not encrypted */
    for (ssize_t i = 0; i + 8 <= n; i++)
        if (!memcmp(raw + i, MARKER, 8)) return 72; /* payload in the clear */
    return 0;
}

int main(void){
    printf("== v1 is untouched when no fd is registered ==\n");
    { int sv[2];
      socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
      ck("no fd starts out flagged for v2", g_v2_active[sv[0]] == 0 && g_v2_active[sv[1]] == 0);
      unsigned char pl[8] = {1,2,3,4,5,6,7,8};
      long w = p2p_write(sv[0], "ping", 4, pl, 8);
      ck("p2p_write still returns 24 + plen", w == 32);
      char cmd[12]; unsigned char buf[64]; unsigned plen;
      int r = p2p_read(sv[1], cmd, buf, sizeof buf, &plen);
      ck("p2p_read still reads a v1 frame", r == 1 && !strncmp(cmd, "ping", 4) && plen == 8);
      ck("  payload intact", !memcmp(buf, pl, 8));
      close(sv[0]); close(sv[1]); }

    /* Positive control for the wire check further down. That check asserts a
     * v2 socket carries no network magic and no cleartext payload -- which
     * would also hold if the check simply never found anything. Here the same
     * two things are looked for on a genuine v1 socket, where they MUST be
     * present. */
    { int sv[2];
      socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
      p2p_write(sv[0], "ping", 4, MARKER, 8);
      unsigned char raw[256];
      ssize_t n = recv(sv[1], raw, sizeof raw, 0);
      unsigned int magic = 0;
      if (n >= 4) memcpy(&magic, raw, 4);
      ck("on a v1 socket the network magic IS at offset 0", n >= 24 && magic == net_magic);
      int found = 0;
      for (ssize_t i = 0; n >= 8 && i + 8 <= n; i++) if (!memcmp(raw + i, MARKER, 8)) found = 1;
      ck("  and the payload IS visible in the clear", found);
      close(sv[0]); close(sv[1]); }

    printf("== a v2 session carries traffic through p2p_read/p2p_write ==\n");
    { int sv[2];
      if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0){ printf("  FAIL socketpair\n"); return 1; }
      pid_t pid = fork();
      if (pid == 0){ close(sv[0]); _exit(responder(sv[1], 1)); }
      close(sv[1]);
      int fd = sv[0];

      ck("initiator handshake completes", bmc_v2_handshake(fd, 1, 5000) == 1);
      ck("  and the fd is now flagged for v2", bmc_v2_is_active(fd) && g_v2_active[fd] == 1);

      int ok = 1, shape_ok = 1;
      unsigned char pl[8] = {9,8,7,6,5,4,3,2};
      char cmd[12]; unsigned char buf[4096]; unsigned plen;
      for (int i = 0; i < 5; i++){
          /* the write hook must keep v1's 24+plen return, which reorg.c
           * compares against 24 -- a v2 packet for a small payload is
           * shorter than that on the wire */
          if (p2p_write(fd, "ping", 4, pl, 8) != 32) { shape_ok = 0; ok = 0; break; }
          if (p2p_read(fd, cmd, buf, sizeof buf, &plen) != 1) { ok = 0; break; }
          if (strncmp(cmd, "pong", 4) || plen != 8 || memcmp(buf, pl, 8)) { ok = 0; break; }
      }
      ck("five ping/pong round trips over the encrypted session", ok);
      ck("  every write returned v1's 24+plen shape", shape_ok);

      unsigned char* big = malloc(300000);
      int r = p2p_read(fd, cmd, big, 300000, &plen);
      ck("a 200 KB message arrives whole", r == 1 && !strncmp(cmd, "block", 5) && plen == 200000);
      { int good = 1;
        for (int i = 0; i < 200000; i++) if (big[i] != (unsigned char)(i * 7)) { good = 0; break; }
        ck("  and its bytes are correct", good); }
      free(big);

      /* the child now reads raw bytes and checks they are not a v1 frame */
      ck("a distinctive payload can be sent for the wire check",
         p2p_write(fd, "ping", 4, MARKER, 8) == 32);

      bmc_v2_close(fd);
      ck("closing clears the flag so the fd number is safe to reuse",
         g_v2_active[fd] == 0 && !bmc_v2_is_active(fd));
      close(fd);
      int st = 0; waitpid(pid, &st, 0);
      int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
      char l[140]; snprintf(l, sizeof l, "the responder side agreed throughout (exit %d)", code);
      ck(l, code == 0);
      if (code == 71) printf("        the wire carried a v1 magic -- both sides fell back to plaintext\n");
      if (code == 72) printf("        the payload appeared in cleartext on the wire\n");
      ck("  the wire carried no v1 magic and no cleartext payload",
         code != 71 && code != 72); }

    printf("== an inbound v1 peer is detected and left on the v1 path ==\n");
    /* The responder must not eat the bytes a v1 peer already sent. */
    { int sv[2];
      socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
      pid_t pid = fork();
      if (pid == 0){
          close(sv[0]);
          /* speak plain v1 at it */
          unsigned char v[86]; memset(v, 0, sizeof v); v[0] = 9;
          _exit(p2p_write(sv[1], "version", 7, v, sizeof v) > 0 ? 0 : 1);
      }
      close(sv[1]);
      int fd = sv[0];
      int hs = bmc_v2_handshake(fd, 0, 3000);
      ck("the handshake reports v1 rather than failing", hs == 0);
      ck("  and the fd was never flagged for v2", g_v2_active[fd] == 0);

      /* THE POINT OF THE FALLBACK: the peer's version message must still be
       * on the socket. Detection has to peek rather than read, or those bytes
       * vanish with the discarded transport -- the peer then waits forever for
       * a reply to a version we ate, and the connection dies on a timeout with
       * nothing in the log to explain it. An earlier cut of this did exactly
       * that, and asserting only `hs == 0` did not notice. */
      char cmd[12]; unsigned char buf[256]; unsigned plen;
      int r = p2p_read(fd, cmd, buf, sizeof buf, &plen);
      ck("  the peer's version message is still readable on the v1 path",
         r == 1 && !strncmp(cmd, "version", 7) && plen == 86);
      close(fd);
      int st = 0; waitpid(pid, &st, 0);
      ck("  the v1 peer wrote its version message", WIFEXITED(st) && WEXITSTATUS(st) == 0); }

    printf("== an initiator does not silently fall back ==\n");
    /* It has already put 64 random bytes on the wire; a v1 peer would reject
     * them as a bad magic. Falling back in place would be wrong, so a failed
     * outbound attempt must report failure and let the caller redial. */
    { int sv[2];
      socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
      pid_t pid = fork();
      if (pid == 0){ close(sv[0]); close(sv[1]); _exit(0); }   /* peer hangs up */
      close(sv[1]);
      int hs = bmc_v2_handshake(sv[0], 1, 1500);
      ck("a peer that hangs up gives -1, not a fallback", hs == -1);
      ck("  and leaves no session behind", g_v2_active[sv[0]] == 0);
      close(sv[0]);
      int st; waitpid(pid, &st, 0); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}

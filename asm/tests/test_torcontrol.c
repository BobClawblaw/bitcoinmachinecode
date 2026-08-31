/* tests/test_torcontrol.c -- the tor control client against a FAKE tor that
 * speaks the control protocol and records what it was told:
 *   PROTOCOLINFO -> AUTHENTICATE <hex of the cookie file> -> ADD_ONION
 *   NEW:ED25519-V3 Port=<default port>,127.0.0.1:<listen port>
 * on first run, and ADD_ONION ED25519-V3:<the persisted key> on the next,
 * the ServiceID validated as a v3 onion (Core's example address), the key
 * file written 0600, and failures (bad cookie, ADD_ONION 5xx) reported
 * rather than announced. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include "../daemon/torcontrol.h"
#include "test_tmpdir.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static const char* SID = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd";
static int rdline(int fd, char* b, int cap){ int n = 0; char c; while (n < cap - 1 && read(fd, &c, 1) == 1){ if (c == '\n') break; if (c != '\r') b[n++] = c; } b[n] = 0; return n; }
/* mode 0: cookie ok, new key; 1: reject auth; 2: ADD_ONION fails; 3: bogus ServiceID */
static void fake_tor(int ls, int mode, int report, const char* cookiehex){
    int c = accept(ls, 0, 0); if (c < 0) _exit(1);
    char l[2048]; char msg[4096];
    rdline(c, l, sizeof l); (void)!write(report, l, strlen(l)); (void)!write(report, "\n", 1);
    snprintf(msg, sizeof msg, "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/run/tor/control.authcookie\"\r\n250-VERSION Tor=\"0.4.9.11\"\r\n250 OK\r\n");
    (void)!write(c, msg, strlen(msg));
    rdline(c, l, sizeof l); (void)!write(report, l, strlen(l)); (void)!write(report, "\n", 1);
    if (mode == 1 || strcmp(l + 13, cookiehex)){ (void)!write(c, "515 Authentication failed: Wrong length on authentication cookie.\r\n", 67); _exit(0); }
    (void)!write(c, "250 OK\r\n", 8);
    rdline(c, l, sizeof l); (void)!write(report, l, strlen(l)); (void)!write(report, "\n", 1);
    if (mode == 2){ (void)!write(c, "512 Bad arguments to ADD_ONION: Unrecognized key type\r\n", 55); _exit(0); }
    if (!strncmp(l, "ADD_ONION NEW:", 14))
        snprintf(msg, sizeof msg, "250-ServiceID=%s\r\n250-PrivateKey=ED25519-V3:FAKEKEYBASE64==\r\n250 OK\r\n", mode == 3 ? "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrya" : SID);
    else
        snprintf(msg, sizeof msg, "250-ServiceID=%s\r\n250 OK\r\n", SID);   /* tor omits PrivateKey when the key was supplied */
    (void)!write(c, msg, strlen(msg));
    /* stay connected until the client closes (the service lives that long) */
    rdline(c, l, sizeof l); close(c); _exit(0);
}
static int listen_lo(int* port){
    int ls = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); bind(ls, (struct sockaddr*)&a, sizeof a);
    socklen_t al = sizeof a; getsockname(ls, (struct sockaddr*)&a, &al); listen(ls, 2); *port = ntohs(a.sin_port); return ls;
}
static int run(int mode, torctl_t* t, char* wire){
    int port, rp[2]; (void)!pipe(rp); int ls = listen_lo(&port);
    pid_t pid = fork(); if (pid == 0){ close(rp[0]); fake_tor(ls, mode, rp[1], "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"); }
    close(rp[1]); close(ls);
    int r = torctl_add_onion(t, "127.0.0.1", port, NULL, "cookie.bin", 8333, "127.0.0.1:18444", "onion_v3_private_key", 2000);
    torctl_close(t); int st; waitpid(pid, &st, 0);
    int wl = 0, n; while ((n = (int)read(rp[0], wire + wl, 4096 - wl)) > 0) wl += n; wire[wl] = 0; close(rp[0]);
    return r;
}
int main(void){
    tt_isolate(); signal(SIGPIPE, SIG_IGN);
    { unsigned char ck32[32]; for (int i = 0; i < 16; i++){ ck32[i] = "\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"[i]; ck32[16+i] = ck32[i]; }
      int f = open("cookie.bin", O_WRONLY|O_CREAT|O_TRUNC, 0600); (void)!write(f, ck32, 32); close(f); }
    unlink("onion_v3_private_key");
    torctl_t t; char wire[4096];
    printf("== first run: cookie auth, NEW key, service created, key persisted ==\n");
    int r = run(0, &t, wire);
    ck("succeeded", r == 1);
    ck("PROTOCOLINFO first", !strncmp(wire, "PROTOCOLINFO 1\n", 15));
    ck("AUTHENTICATE with the hex of the 32-byte cookie", strstr(wire, "AUTHENTICATE AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899\n") != NULL);
    ck("ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:18444 (virtual port = chain default, Core's rule)", strstr(wire, "ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:18444\n") != NULL);
    { char want[80]; snprintf(want, sizeof want, "%s.onion", SID); ck("onion address = ServiceID + .onion, validated as v3", !strcmp(t.onion, want)); }
    { struct stat st; ck("private key persisted in onion_v3_private_key, mode 0600", stat("onion_v3_private_key", &st) == 0 && (st.st_mode & 0777) == 0600);
      char k[256] = {0}; int f = open("onion_v3_private_key", O_RDONLY); (void)!read(f, k, 255); close(f);
      ck("key file holds tor's PrivateKey verbatim", !strncmp(k, "ED25519-V3:FAKEKEYBASE64==", 26)); }
    printf("\n== second run: the persisted key is REUSED (same address across restarts) ==\n");
    r = run(0, &t, wire);
    ck("succeeded", r == 1);
    ck("ADD_ONION ED25519-V3:<persisted key> Port=...", strstr(wire, "ADD_ONION ED25519-V3:FAKEKEYBASE64== Port=8333,127.0.0.1:18444\n") != NULL);
    printf("\n== failures are reported, never announced ==\n");
    unlink("onion_v3_private_key");
    r = run(1, &t, wire); ck("auth rejected -> 0 with a reason", r == 0 && strstr(t.err, "AUTHENTICATE") != NULL && t.onion[0] == 0);
    r = run(2, &t, wire); ck("ADD_ONION 512 -> 0 with the reply in the reason", r == 0 && strstr(t.err, "ADD_ONION") != NULL);
    r = run(3, &t, wire); ck("a ServiceID that fails the v3 checksum is refused", r == 0 && strstr(t.err, "not a valid v3 onion") != NULL);
    ck("no key file left behind by the failed runs", access("onion_v3_private_key", F_OK) != 0);
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}

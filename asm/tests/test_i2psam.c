/* tests/test_i2psam.c -- the SAM v3.1 client against a FAKE bridge that
 * records every command, so the wire format is pinned to Core's i2p.cpp
 * rather than to whatever this client emits:
 *   HELLO VERSION MIN=3.1 MAX=3.1
 *   SESSION CREATE STYLE=STREAM ID=<id> DESTINATION=TRANSIENT|<key>
 *           SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4,0 ...
 *   STREAM CONNECT ID=<id> DESTINATION=<dest> SILENT=false
 *   STREAM ACCEPT  ID=<id> SILENT=false     (next line = peer destination)
 * Every stream is its OWN socket that says HELLO first -- getting that wrong
 * is the classic SAM mistake (the control socket must stay open and idle).
 * The destination and its .b32.i2p come from the REAL i2pd router on this
 * box (DEST GENERATE SIGNATURE_TYPE=7), so the base64 alphabet ('-' and '~'
 * for '+' and '/') and the base32(sha256(dest)) derivation are checked
 * against the router's own answer, not against our own arithmetic. */
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
#include "../daemon/i2psam.h"
#include "test_tmpdir.h"
#include "i2p_vec.h"                 /* REAL_DEST_B64 / REAL_B32, from the local router */
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static int rdn(int fd, char* b, int n){ int g = 0; while (g < n){ int r = (int)read(fd, b + g, (size_t)(n - g)); if (r <= 0) break; g += r; } return g; }
static int rdline(int fd, char* b, int cap){ int n = 0; char c; while (n < cap - 1 && read(fd, &c, 1) == 1){ if (c == '\n') break; b[n++] = c; } b[n] = 0; return n; }
/* mode 0 ok / 1 session refused / 2 connect refused (CANT_REACH_PEER).
 * One CHILD per connection: a SAM session socket stays OPEN and idle for the
 * session's life, so a single-threaded server that read it after replying
 * would never accept the stream sockets that follow. */
static void serve_conn(int c, int mode, int report){
    char l[8192];
    if (rdline(c, l, sizeof l) <= 0) return;
    (void)!write(report, l, strlen(l)); (void)!write(report, "\n", 1);
    (void)!write(c, "HELLO REPLY RESULT=OK VERSION=3.1\n", strlen("HELLO REPLY RESULT=OK VERSION=3.1\n"));
    if (rdline(c, l, sizeof l) <= 0) return;
    (void)!write(report, l, strlen(l)); (void)!write(report, "\n", 1);
    if (!strncmp(l, "SESSION CREATE", 14)){
        if (mode == 1){ (void)!write(c, "SESSION STATUS RESULT=DUPLICATED_ID\n", strlen("SESSION STATUS RESULT=DUPLICATED_ID\n")); return; }
        char msg[8192];
        if (strstr(l, "DESTINATION=TRANSIENT")) snprintf(msg, sizeof msg, "SESSION STATUS RESULT=OK DESTINATION=%s\n", REAL_DEST_B64);
        else                                    snprintf(msg, sizeof msg, "SESSION STATUS RESULT=OK\n");
        (void)!write(c, msg, strlen(msg));
        rdline(c, l, sizeof l);            /* hold it open until the client closes */
        return;
    }
    if (!strncmp(l, "STREAM CONNECT", 14)){
        if (mode == 2){ (void)!write(c, "STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE=\"unreachable\"\n", strlen("STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE=\"unreachable\"\n")); return; }
        (void)!write(c, "STREAM STATUS RESULT=OK\n", strlen("STREAM STATUS RESULT=OK\n"));
        char b[64] = {0}; int n = (int)read(c, b, 63);
        if (n > 0){ (void)!write(c, ">", strlen(">")); (void)!write(c, b, (size_t)n); }
        return;
    }
    if (!strncmp(l, "STREAM ACCEPT", 13)){
        (void)!write(c, "STREAM STATUS RESULT=OK\n", strlen("STREAM STATUS RESULT=OK\n"));
        char msg[8192]; snprintf(msg, sizeof msg, "%s\n", REAL_DEST_B64);
        (void)!write(c, msg, strlen(msg));
        (void)!write(c, "inbound-data", strlen("inbound-data"));
        return;
    }
}
static void fake_sam(int ls, int mode, int report){
    for (int conn = 0; conn < 6; conn++){
        int c = accept(ls, 0, 0); if (c < 0) break;
        pid_t k = fork();
        if (k == 0){ close(ls); serve_conn(c, mode, report); close(c); _exit(0); }
        close(c);
    }
    _exit(0);
}
static int listen_lo(int* port){
    int ls = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); bind(ls, (struct sockaddr*)&a, sizeof a);
    socklen_t al = sizeof a; getsockname(ls, (struct sockaddr*)&a, &al); listen(ls, 4); *port = ntohs(a.sin_port); return ls;
}
int main(void){
    tt_isolate(); signal(SIGPIPE, SIG_IGN);
    printf("== the .b32.i2p derivation, against the local i2pd router's own answer ==\n");
    { char b32[80];
      ck("base64(I2P alphabet) + sha256 + base32 == the router's b32 for its destination",
         i2psam_dest_to_b32(b32, sizeof b32, REAL_DEST_B64) && !strcmp(b32, REAL_B32)); }
    ck("a truncated destination is rejected", !i2psam_dest_to_b32((char[80]){0}, 80, "AAAA"));

    printf("\n== session: HELLO then SESSION CREATE, Core's parameters ==\n");
    int port, rp[2]; (void)!pipe(rp); int ls = listen_lo(&port);
    pid_t pid = fork(); if (pid == 0){ close(rp[0]); fake_sam(ls, 0, rp[1]); }
    close(rp[1]);
    i2psam_t s;
    int r = i2psam_session(&s, "127.0.0.1", port, "i2p_private_key", 3000);
    ck("session created", r == 1);
    ck("our address is the router's b32 for the destination it gave us", !strcmp(s.b32, REAL_B32));
    { struct stat st; ck("destination persisted in i2p_private_key, mode 0600",
                         stat("i2p_private_key", &st) == 0 && (st.st_mode & 0777) == 0600); }
    char err[192]; int fd = i2psam_connect(&s, "127.0.0.1", port, REAL_B32, 3000, err, sizeof err);
    ck("STREAM CONNECT returned a stream", fd >= 0);
    if (fd >= 0){ (void)!write(fd, "hello", 5); char b[16] = {0}; int n = rdn(fd, b, 6);
                  ck("the stream carries data (echo)", n == 6 && !strcmp(b, ">hello")); close(fd); }
    char peer[80] = {0};
    int afd = i2psam_accept(&s, "127.0.0.1", port, peer, sizeof peer, 3000);
    ck("STREAM ACCEPT returned a stream", afd >= 0);
    ck("the caller's destination is decoded to its .b32.i2p", !strcmp(peer, REAL_B32));
    if (afd >= 0){ char b[16] = {0}; int n = rdn(afd, b, 12); ck("inbound data arrives after the destination line", n == 12 && !strcmp(b, "inbound-data")); close(afd); }
    i2psam_close(&s);
    int st; kill(pid, SIGKILL); waitpid(pid, &st, 0);
    char wire[16384]; int wl = 0, n; while ((n = (int)read(rp[0], wire + wl, (size_t)(16000 - wl))) > 0) wl += n; wire[wl] = 0; close(rp[0]); close(ls);
    printf("\n== the recorded wire, against Core's i2p.cpp ==\n");
    { int hellos = 0; for (const char* p = wire; (p = strstr(p, "HELLO VERSION MIN=3.1 MAX=3.1")); p += 4) hellos++;
      ck("every socket (session, connect, accept) begins with HELLO VERSION MIN=3.1 MAX=3.1", hellos == 3); }
    ck("SESSION CREATE STYLE=STREAM ... SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4,0",
       strstr(wire, "SESSION CREATE STYLE=STREAM ID=") && strstr(wire, "DESTINATION=TRANSIENT")
       && strstr(wire, "SIGNATURE_TYPE=7") && strstr(wire, "i2cp.leaseSetEncType=4,0"));
    ck("STREAM CONNECT ID=<id> DESTINATION=<dest> SILENT=false", strstr(wire, "STREAM CONNECT ID=") && strstr(wire, "SILENT=false"));
    ck("STREAM ACCEPT ID=<id> SILENT=false", strstr(wire, "STREAM ACCEPT ID=") != NULL);

    printf("\n== a resumed session sends the PERSISTED key, not TRANSIENT ==\n");
    (void)!pipe(rp); ls = listen_lo(&port);
    pid = fork(); if (pid == 0){ close(rp[0]); fake_sam(ls, 0, rp[1]); }
    close(rp[1]);
    r = i2psam_session(&s, "127.0.0.1", port, "i2p_private_key", 3000);
    ck("session created from the key file", r == 1);
    ck("same address as the first run (persistent identity)", !strcmp(s.b32, REAL_B32));
    i2psam_close(&s); kill(pid, SIGKILL); waitpid(pid, &st, 0);
    wl = 0; while ((n = (int)read(rp[0], wire + wl, (size_t)(16000 - wl))) > 0) wl += n; wire[wl] = 0; close(rp[0]); close(ls);
    ck("SESSION CREATE carried the destination, not TRANSIENT", strstr(wire, "DESTINATION=TRANSIENT") == NULL && strstr(wire, REAL_DEST_B64) != NULL);

    printf("\n== failures are reported ==\n");
    (void)!pipe(rp); ls = listen_lo(&port);
    pid = fork(); if (pid == 0){ close(rp[0]); fake_sam(ls, 1, rp[1]); }
    close(rp[1]); unlink("i2p_private_key");
    r = i2psam_session(&s, "127.0.0.1", port, "i2p_private_key", 3000);
    if (r != 0 || !strstr(s.err, "DUPLICATED_ID")) printf("    [diag] r=%d err=\"%s\"\n", r, s.err);
    ck("SESSION CREATE refusal -> 0 with the router's reason", r == 0 && strstr(s.err, "DUPLICATED_ID") != NULL);
    ck("no key file written by a failed session", access("i2p_private_key", F_OK) != 0);
    kill(pid, SIGKILL); waitpid(pid, &st, 0); close(rp[0]); close(ls);
    { i2psam_t s2; memset(&s2, 0, sizeof s2); strcpy(s2.id, "x");
      char e[192]; int f = i2psam_connect(&s2, "127.0.0.1", 1, REAL_B32, 300, e, sizeof e);
      ck("connect with no reachable bridge -> -1", f == -1); }
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}

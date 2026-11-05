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
#include "../crypto_hkdf.h"
#include "test_tmpdir.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static const char* SID = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd";
static int rdline(int fd, char* b, int cap){ int n = 0; char c; while (n < cap - 1 && read(fd, &c, 1) == 1){ if (c == '\n') break; if (c != '\r') b[n++] = c; } b[n] = 0; return n; }
/* mode 0: SAFECOOKIE ok, new key; 1: reject auth; 2: ADD_ONION fails;
 * 3: bogus ServiceID; 4: a control port that does NOT know the cookie
 * (wrong SERVERHASH); 5: METHODS=COOKIE only (plain cookie); 6: METHODS=
 * NULL,SAFECOOKIE (Core prefers NULL) */
static const unsigned char COOKIE[32] = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
                                          0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99 };
static void hex32(const unsigned char* b, char* o){ for (int i = 0; i < 32; i++) sprintf(o + 2*i, "%02X", b[i]); o[64] = 0; }
static int unhex(const char* h, unsigned char* out, int n){
    for (int i = 0; i < n; i++){ unsigned v; if (sscanf(h + 2*i, "%2x", &v) != 1) return 0; out[i] = (unsigned char)v; } return 1; }
static void sc_hmac(unsigned char out[32], const char* key, const unsigned char* cn, const unsigned char* sn){
    unsigned char m[96]; memcpy(m, COOKIE, 32); memcpy(m + 32, cn, 32); memcpy(m + 64, sn, 32);
    hmac_sha256(out, (const unsigned char*)key, strlen(key), m, 96);
}
static void rep(int report, const char* l){ (void)!write(report, l, strlen(l)); (void)!write(report, "\n", 1); }
static void fake_tor(int ls, int mode, int report){
    int c = accept(ls, 0, 0); if (c < 0) _exit(1);
    char l[2048]; char msg[4096];
    rdline(c, l, sizeof l); rep(report, l);
    const char* methods = mode == 5 ? "COOKIE" : mode == 6 ? "NULL,SAFECOOKIE" : "COOKIE,SAFECOOKIE";
    snprintf(msg, sizeof msg, "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=%s COOKIEFILE=\"/run/tor/control.authcookie\"\r\n250-VERSION Tor=\"0.4.9.11\"\r\n250 OK\r\n", methods);
    (void)!write(c, msg, strlen(msg));
    if (rdline(c, l, sizeof l) <= 0) _exit(0);
    rep(report, l);
    if (mode == 6){
        if (strcmp(l, "AUTHENTICATE")){ (void)!write(c, "515 Authentication failed\r\n", 27); _exit(0); }
    } else {
        unsigned char cn[32], sn[32], sh[32], want[32];
        if (strncmp(l, "AUTHCHALLENGE SAFECOOKIE ", 25) || strlen(l) != 25 + 64 || !unhex(l + 25, cn, 32)){
            (void)!write(c, "515 Authentication failed\r\n", 27); _exit(0); }
        for (int i = 0; i < 32; i++) sn[i] = (unsigned char)(0x40 + i);
        sc_hmac(sh, "Tor safe cookie authentication server-to-controller hash", cn, sn);
        if (mode == 4) sh[7] ^= 1;                       /* it does not know the cookie */
        char shx[65], snx[65]; hex32(sh, shx); hex32(sn, snx);
        snprintf(msg, sizeof msg, "250 AUTHCHALLENGE SERVERHASH=%s SERVERNONCE=%s\r\n", shx, snx);
        (void)!write(c, msg, strlen(msg));
        if (rdline(c, l, sizeof l) <= 0) _exit(0);
        rep(report, l);
        sc_hmac(want, "Tor safe cookie authentication controller-to-server hash", cn, sn);
        char wx[65]; hex32(want, wx);
        if (mode == 1 || strncmp(l, "AUTHENTICATE ", 13) || strcmp(l + 13, wx)){
            (void)!write(c, "515 Authentication failed: Safe cookie response did not match expected value.\r\n", 80); _exit(0); }
    }
    (void)!write(c, "250 OK\r\n", 8);
    rdline(c, l, sizeof l); rep(report, l);
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
    pid_t pid = fork(); if (pid == 0){ close(rp[0]); fake_tor(ls, mode, rp[1]); }
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
    printf("== first run: SAFECOOKIE auth, NEW key, service created, key persisted ==\n");
    int r = run(0, &t, wire);
    ck("succeeded", r == 1);
    if (r != 1) printf("      err: %s\n      wire:\n%s\n", t.err, wire);
    ck("PROTOCOLINFO first", !strncmp(wire, "PROTOCOLINFO 1\n", 15));
    /* HST-5 (audit 2026-10-23): Core's SAFECOOKIE, never the plain cookie */
    ck("HST-5: AUTHCHALLENGE SAFECOOKIE <client nonce>, as Core does", strstr(wire, "\nAUTHCHALLENGE SAFECOOKIE ") != NULL);
    ck("HST-5: the raw cookie never goes on the wire", strstr(wire, "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899") == NULL);
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
    printf("\n== HST-5: what a control port that does not know the cookie gets ==\n");
    r = run(4, &t, wire);
    ck("HST-5: a wrong SERVERHASH is refused before we answer", r == 0 && strstr(t.err, "SERVERHASH") != NULL);
    ck("HST-5: ...no AUTHENTICATE was sent at all", strstr(wire, "\nAUTHENTICATE") == NULL);
    r = run(5, &t, wire);
    ck("HST-5: METHODS=COOKIE only: refused, as Core (no plain cookie auth)", r == 0 && strstr(t.err, "no supported") != NULL);
    ck("HST-5: ...and the cookie bytes were not sent", strstr(wire, "AABBCCDDEEFF00112233445566778899") == NULL && strstr(wire, "AUTHENTICATE") == NULL);
    r = run(6, &t, wire);
    ck("HST-5: NULL offered with SAFECOOKIE: Core's order, NULL first", r == 1 && strstr(wire, "\nAUTHENTICATE\n") != NULL);
    unlink("onion_v3_private_key");
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}

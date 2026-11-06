/* test_sd_watchdog.c -- daemon/sd_watchdog.c (2026-11-06).
 *
 * The serve parent feeds systemd's watchdog only while the download worker's
 * progress stamp moves. This checks:
 *   1. the ping rule: nothing while off or before the first stamp; the first
 *      ping at once; no ping while the stamp stands still, however long; a
 *      moved stamp pings once a quarter of the timeout has passed.
 *   2. WATCHDOG_USEC parsing: microseconds to milliseconds, junk is "off".
 *   3. sdw_init: off without NOTIFY_SOCKET or WATCHDOG_USEC, off when
 *      WATCHDOG_PID names another process, and on otherwise -- with the three
 *      variables removed from the environment so no child inherits them.
 *   4. the datagram itself, "WATCHDOG=1", on a socket this test binds (a path
 *      socket, then an abstract one, as systemd uses): sent when the stamp
 *      moves, and NOT sent while it stands still.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include "sd_watchdog.h"

static int g_checks, g_fails;
static void ck(const char* name, int cond){
    g_checks++;
    if (cond) printf("  ok  %s\n", name);
    else { g_fails++; printf("  FAIL %s\n", name); }
}

#ifdef __linux__
/* bind a datagram socket at `path` ('@' = abstract), with a short receive timeout */
static int bind_sock(const char* path){
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un a; memset(&a, 0, sizeof a); a.sun_family = AF_UNIX;
    size_t n = strlen(path); memcpy(a.sun_path, path, n);
    if (a.sun_path[0] == '@') a.sun_path[0] = 0; else unlink(path);
    if (bind(fd, (struct sockaddr*)&a, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n)) != 0){ perror("bind"); exit(1); }
    struct timeval tv = {0, 200000}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return fd;
}
/* 1 = exactly "WATCHDOG=1" arrived, 0 = nothing within the timeout, -1 = something else */
static int got_ping(int fd){
    char b[64]; ssize_t r = recv(fd, b, sizeof b - 1, 0);
    if (r < 0) return 0;
    b[r] = 0;
    return strcmp(b, "WATCHDOG=1") == 0 ? 1 : -1;
}
static void set_env(const char* sock, const char* usec, long pid){
    char p[32]; snprintf(p, sizeof p, "%ld", pid);
    setenv("NOTIFY_SOCKET", sock, 1); setenv("WATCHDOG_USEC", usec, 1); setenv("WATCHDOG_PID", p, 1);
}
#endif

int main(void){
    printf("== the ping rule ==\n");
    const long long T = 600000;                                   /* WatchdogSec=10min */
    ck("off: no ping",                              !sdw_should_ping(1000, 500, -1, -1, 0));
    ck("no stamp yet: no ping",                     !sdw_should_ping(1000, 0, -1, -1, T));
    ck("first stamp: ping at once",                  sdw_should_ping(1000, 500, -1, -1, T));
    ck("stamp unchanged a moment later: no ping",   !sdw_should_ping(2000, 500, 1000, 500, T));
    ck("stamp unchanged a whole timeout later: no ping", !sdw_should_ping(1000 + 2*T, 500, 1000, 500, T));
    ck("stamp moved, under T/4 since the last ping: no ping", !sdw_should_ping(1000 + T/4 - 1, 900, 1000, 500, T));
    ck("stamp moved, T/4 since the last ping: ping", sdw_should_ping(1000 + T/4, 900, 1000, 500, T));

    printf("\n== WATCHDOG_USEC ==\n");
    ck("600000000 us = 600000 ms", sdw_parse_usec("600000000") == 600000);
    ck("unset = off",              sdw_parse_usec(NULL) == 0);
    ck("empty = off",              sdw_parse_usec("") == 0);
    ck("0 = off",                  sdw_parse_usec("0") == 0);
    ck("trailing junk = off",      sdw_parse_usec("600s") == 0);
    ck("not a number = off",       sdw_parse_usec("ten") == 0);

#ifndef __linux__
    printf("\n== macOS: no systemd, the watchdog stays off ==\n");
    setenv("NOTIFY_SOCKET", "/tmp/x", 1); setenv("WATCHDOG_USEC", "4000000", 1);
    ck("sdw_init is off even with the variables set", sdw_init() == 0);
#else
    printf("\n== sdw_init's environment ==\n");
    char path[108];
    snprintf(path, sizeof path, "%s/bmc-sdw-%d.sock", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
    unsetenv("NOTIFY_SOCKET"); unsetenv("WATCHDOG_USEC"); unsetenv("WATCHDOG_PID");
    ck("no NOTIFY_SOCKET: off", sdw_init() == 0);
    set_env(path, "4000000", (long)getpid() + 1);
    ck("WATCHDOG_PID names another process: off", sdw_init() == 0);
    set_env(path, "4000000", (long)getpid()); unsetenv("WATCHDOG_USEC");
    ck("no WATCHDOG_USEC: off", sdw_init() == 0);

    int fd = bind_sock(path);
    set_env(path, "4000000", (long)getpid());
    ck("WatchdogSec=4s for this pid: on, 4000 ms", sdw_init() == 4000);
    ck("the environment is cleared for children",
       !getenv("NOTIFY_SOCKET") && !getenv("WATCHDOG_USEC") && !getenv("WATCHDOG_PID"));

    printf("\n== the datagram (path socket) ==\n");
    sdw_tick(10000, 9000);
    ck("first stamp: WATCHDOG=1 sent", got_ping(fd) == 1);
    sdw_tick(12000, 9000);
    ck("stamp unchanged: nothing sent", got_ping(fd) == 0);
    sdw_tick(10500, 10400);
    ck("stamp moved but under T/4 (1 s) since: nothing sent", got_ping(fd) == 0);
    sdw_tick(11000, 10900);
    ck("stamp moved, T/4 since: WATCHDOG=1 sent", got_ping(fd) == 1);
    sdw_tick(60000, 10900);
    ck("a minute with the same stamp: nothing sent", got_ping(fd) == 0);
    ck("two pings counted", sdw_pings() == 2);
    close(fd); unlink(path);

    printf("\n== the datagram (abstract socket, as systemd's) ==\n");
    char abs[64]; snprintf(abs, sizeof abs, "@bmc-sdw-test-%d", (int)getpid());
    fd = bind_sock(abs);
    set_env(abs, "8000000", (long)getpid());
    ck("re-armed on an abstract socket: 8000 ms", sdw_init() == 8000);
    sdw_tick(100000, 99000);
    ck("moved stamp: WATCHDOG=1 sent", got_ping(fd) == 1);
    close(fd);
#endif

    printf("\n%s (%d checks, %d failures)\n", g_fails == 0 ? "ALL PASS" : "SOME FAILED", g_checks, g_fails);
    return g_fails ? 1 : 0;
}

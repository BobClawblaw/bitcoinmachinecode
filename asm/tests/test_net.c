/* test_net.c -- 100% AI-generated harness for the assembly bitcoin_net.asm
 * socket + P2P framing primitives.
 *
 * Uses an AF_UNIX SOCK_STREAM socketpair (created here in C, as transport
 * scaffolding) so the machine-code write/read/frame logic is exercised over a
 * real socket deterministically, with no external network dependency.
 * A separate manual program (live_handshake.c) connects to the live network.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef unsigned char u8;

extern long fd_write_all(int fd, const void *buf, size_t n);
extern long fd_read_full (int fd, void *buf, size_t n);
extern long p2p_frame(u8 *out, const char *cmd, unsigned cmdlen,
                      const void *payload, unsigned plen);
extern long p2p_write(int fd, const char *cmd, unsigned cmdlen,
                      const void *payload, unsigned plen);
extern int  p2p_read(int fd, char cmd_out[12], void *payload,
                     unsigned cap, unsigned *plen_out);

static int failures = 0;
static void cki(const char *lbl, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", lbl, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", lbl, got, exp); failures++; }
}

int main(void){
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0){
        printf("FAIL socketpair\n"); return 1;
    }
    /* defensive receive timeout so a framing bug fails fast instead of hanging */
    struct timeval tv2; tv2.tv_sec=4; tv2.tv_usec=0;
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));

    /* ---- fd_write_all / fd_read_full round-trip ---- */
    const char *msg = "hello bitcoin machine code 0123456789";
    size_t mlen = strlen(msg)+1;
    cki("fd_write_all", fd_write_all(sv[0], msg, mlen), (long)mlen);
    u8 buf[256];
    long got = fd_read_full(sv[1], buf, mlen);
    cki("fd_read_full returns full len", got, (long)mlen);
    cki("fd_read_full bytes match", memcmp(buf, msg, mlen), 0);
    /* EOF is only observable after the write side is shut down */
    shutdown(sv[0], SHUT_WR);
    cki("fd_read_full eof returns 0", fd_read_full(sv[1], buf, 5), 0);
    /* re-open a fresh pair for the framing tests below */
    close(sv[0]); close(sv[1]);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0){
        printf("FAIL socketpair 2 errno=%d\n", errno); return 1;
    }
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));

    /* ---- p2p_frame builds a correct frame (checksum = sha256d[0:4]) ---- */
    const char *cmd = "verack";
    const char *pl = "";                    /* empty payload */
    u8 frame[128];
    long fsz = p2p_frame(frame, cmd, strlen(cmd), pl, 0);
    cki("p2p_frame len = 24", fsz, 24);
    printf("  frame[0:16]="); for(int i=0;i<16;i++) printf("%02x", frame[i]); printf("\n");
    /* magic */
    cki("magic ok", frame[0]==0xf9 && frame[1]==0xbe && frame[2]==0xb4 && frame[3]==0xd9, 1);
    /* command field */
    cki("cmd field", memcmp((const char*)frame+4, "verack", 6), 0);
    /* length = 0 */
    unsigned ln; memcpy(&ln, frame+16, 4);
    cki("len field 0", (long)ln, 0);

    /* ---- p2p_write on one end -> p2p_read on the other ---- */
    const char *pl2 = "00010203payloadbytes";
    size_t plen2 = strlen(pl2);
    long sent = p2p_write(sv[0], "version", 7, pl2, plen2);
    cki("p2p_write total", sent, (long)(24+plen2));

    char cmd2[12];
    u8 pl2_out[128];
    unsigned plen2_out = 0;
    int r = p2p_read(sv[1], cmd2, pl2_out, sizeof(pl2_out), &plen2_out);
    cki("p2p_read returns 1", r, 1);
    cki("p2p_read cmd == version", strncmp(cmd2, "version", 7), 0);
    cki("p2p_read plen", (long)plen2_out, (long)plen2);
    cki("p2p_read payload match", memcmp(pl2_out, pl2, plen2), 0);

    /* ---- truncated-payload drain path: announce len > cap ---- */
    const char *big = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    p2p_write(sv[0], "headers", 7, big, 62);
    u8 small[8];
    unsigned outlen = 0;
    r = p2p_read(sv[1], cmd2, small, 8, &outlen);
    cki("p2p_read trunc returns -2", r, -2);
    cki("p2p_read trunc reports announced len", (long)outlen, 62);
    /* the rest of the 62-byte payload was drained, so the next message reads fine:
       send another and confirm alignment is preserved */
    p2p_write(sv[0], "ping", 4, "abcd", 4);
    u8 after[16]; unsigned alen=0;
    r = p2p_read(sv[1], cmd2, after, sizeof(after), &alen);
    cki("post-drain alignment: ping ok", r, 1);
    cki("post-drain cmd == ping", strncmp(cmd2, "ping", 4), 0);
    cki("post-drain payload match", memcmp(after, "abcd", 4), 0);

    close(sv[0]); close(sv[1]);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}

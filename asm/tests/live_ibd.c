/* live_ibd.c -- MANUAL/live. Drive the ASSEMBLY full-initial-block-download
 * (bitcoind.asm node_handshake + node_ibd) against a LIVE public Bitcoin seed,
 * downloading and persisting REAL mainnet blocks, validating each with asm
 * cons_verify. This is the "download + store a real MULTI-BLOCK chain" test
 * that the PLAN lists as the residual honest gap -- previously node_ibd was
 * proven only against a synthetic fake_peer on loopback (test_ibd_full).
 *
 * Usage: live_ibd <ipv4-or-seed-name> [max_blocks]
 *
 * KNOWN RESULT (2026-08-15): node_ibd's HEADERS phase does not terminate in
 * practical time against a live seed. node_handshake succeeds and
 * node_ibd_headers steadily fetches header pages (genesis-locator crawl), but
 * a live seed never returns a "short page" or empty page to signal tip, so the
 * naive crawl runs unbounded rather than reaching phase-2 (block bodies). This
 * is a STRATEGY limitation of the genesis-start IBD, not a hang: the recent-tip
 * strategy (live_blocks / node_ibd_blocks_x, the ingest card domain) already
 * downloads+validates real block bodies live.
 *
 * ROBUSTNESS FIXES LANDED so node_ibd can never HANG indefinitely:
 *   - tcp_connect_ip now sets SO_RCVTIMEO (10s): a stalled/idle peer causes a
 *     blocking p2p_read to FAIL FAST (EAGAIN -> .fail) instead of hanging.
 *   - node_fetch_headers drains at most 64 non-headers messages.
 *   - node_ibd_headers caps the page crawl at 4096 pages.
 * Repro of pre-fix hang (no longer possible with these bounds):
 *   timeout 20 ./tests/live_ibd <seed-ipv4>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern int  node_handshake(int fd);              /* outbound/initiator */
extern long node_ibd(int fd, void* st, void* hst, void* buf, long buflen);
extern long hst_init(void* st);
extern long store_init(void* st);
extern long hst_count(void* st);

#define PORT_BE ((unsigned short)htons(8333))

int main(int argc, char** argv){
    setbuf(stdout, NULL);
    const char* ipstr = argc>1 ? argv[1] : "seed.bitcoin.sipa.be";
    unsigned ip; inet_pton(AF_INET, ipstr, &ip);
    if(ip==0){
        /* resolve hostname via getaddrinfo into an ipv4 we can pass LE */
        struct addrinfo hints, *res=NULL;
        memset(&hints,0,sizeof hints); hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
        if(getaddrinfo(ipstr, NULL, &hints, &res)!=0 || !res){
            printf("resolve fail: %s\n", ipstr); return 2;
        }
        struct sockaddr_in* sa=(struct sockaddr_in*)res->ai_addr;
        ip = sa->sin_addr.s_addr;              /* already network order */
        freeaddrinfo(res);
    }
    int fd = tcp_connect_ip(ip, PORT_BE);
    if(fd<0){ printf("connect fail fd=%d\n", fd); return 2; }
    printf("PASS connect %s\n", ipstr);

    /* FIX (2026-08-15): bound the blocking p2p_read so a dropped getdata
     * (ancient block bodies, which real seeds refuse to serve) FAILS FAST
     * instead of hanging forever. node_ibd's p2p_read is a plain blocking
     * read with no socket timeout; without this, node_ibd hangs indefinitely
     * waiting for a `block` that never arrives. SO_RCVTIMEO is the established
     * repo convention (see test_net.c/test_serve.c). */
    struct timeval rcv_tv; rcv_tv.tv_sec=5; rcv_tv.tv_usec=0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv_tv, sizeof rcv_tv);

    if(!node_handshake(fd)){ printf("FAIL node_handshake (live peer negotiation)\n"); close(fd); return 1; }
    printf("PASS node_handshake vs live peer\n");

    static unsigned char stb[270000], hstb[8192];
    if(store_init(stb)!=1){ printf("FAIL store_init\n"); return 1; }
    if(hst_init(hstb)!=1){ printf("FAIL hst_init\n"); return 1; }

    static unsigned char* buf = NULL; buf = malloc(1<<23);  /* 8MB workspace */
    printf("running asm node_ibd against live peer...\n");
    long nblk = node_ibd(fd, stb, hstb, buf, 1<<23);
    printf("node_ibd returned %ld blocks\n", nblk);
    printf("header store count = %ld\n", hst_count(hstb));
    close(fd);
    if(nblk>0){
        printf("RESULT: asm full-IBD downloaded+validated+stored %ld REAL mainnet blocks from a live seed\n", nblk);
        return 0;
    }
    printf("RESULT: live IBD did not complete over the wire\n");
    return 1;
}

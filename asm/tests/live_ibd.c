/* live_ibd.c -- MANUAL/live. Drive the ASSEMBLY full-initial-block-download
 * (bitcoind.asm node_handshake + node_ibd) against a LIVE public Bitcoin seed,
 * downloading and persisting REAL mainnet blocks, validating each with asm
 * cons_verify. This is the "download + store a real MULTI-BLOCK chain" test
 * that the PLAN lists as the residual honest gap -- previously node_ibd was
 * proven only against a synthetic fake_peer on loopback (test_ibd_full).
 *
 * Usage: live_ibd <ipv4-or-seed-name> [max_blocks]
 *
 * KNOWN RESULT (2026-08-15): node_ibd HANGS against a live public seed.
 * node_handshake succeeds, but node_ibd requests block bodies from locator=0
 * (genesis) -- ANCIENT blocks -- and real full nodes "tend to drop requests
 * for ancient blocks" (see live_blocks.c). node_ibd's p2p_read has NO network
 * timeout (plain blocking read), so a dropped getdata -> indefinite hang.
 * This is the PLAN "download + store a real MULTI-BLOCK chain" gap surfaced:
 * node_ibd is proven only against a cooperative synthetic fake_peer.
 * Reproduces with: timeout 20 ./tests/live_ibd <seed-ipv4>  (exit 124 = hang).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
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

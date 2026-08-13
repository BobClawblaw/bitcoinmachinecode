/* live_handshake.c -- PROVES the assembly bitcoin_net.asm works against the
 * LIVE Bitcoin P2P network: connects to a seed, sends `version`, and expects
 * the peer to reply `version` + `verack` -- all framing/tcp in machine code.
 *
 * DNS name -> IP is resolved with libc getaddrinfo (the OS resolver), which is
 * the documented delegation; the socket, connect, write, read, frame, checksum
 * are pure assembly.
 *
 * This is a MANUAL live-network check (not part of `make test`, which stays
 * offline/deterministic).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>

/* bitcoin_net's tcp_connect_ip takes the port in big-endian (htons order). */
#define PORT_BE ((unsigned short)htons(8333))

extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char *cmd, unsigned cmdlen,
                      const void *payload, unsigned plen);
extern int  p2p_read(int fd, char cmd_out[12], void *payload,
                     unsigned cap, unsigned *plen_out);
extern void fd_close(int fd);

static int failures = 0;
static void cki(const char *lbl, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", lbl, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", lbl, got, exp); failures++; }
}

static void put_u16be(unsigned char* p, unsigned v){ p[0]=v>>8; p[1]=v&0xff; }
static void put_u32le(unsigned char* p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_u64le(unsigned char* p, unsigned long long v){ for(int i=0;i<8;i++){p[i]=v&0xff; v>>=8;} }

int main(void){
    const char *dns = "seed.bitcoin.sipa.be";
    struct addrinfo hints, *res=NULL;
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    if (getaddrinfo(dns, NULL, &hints, &res)!=0){
        printf("FAIL getaddrinfo\n"); return 1;
    }
    unsigned ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    printf("%s -> %s\n", dns, inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr));
    freeaddrinfo(res);

    int fd = tcp_connect_ip(ip, PORT_BE);
    if (fd < 0){ printf("FAIL tcp_connect_ip fd=%d\n", fd); return 1; }
    printf("PASS tcp_connect_ip fd=%d\n", fd);

    /* ---- build a version message payload (modern layout, matches P2P oracle) ---- */
    unsigned char v[102];
    int o=0;
    put_u32le(v+o,70016); o+=4;               /* version */
    put_u64le(v+o,1);       o+=8;              /* services */
    put_u64le(v+o,(unsigned long long)time(NULL)); o+=8;  /* timestamp */
    put_u64le(v+o,1);       o+=8;              /* addr_recv services */
    /* addr_recv ip 16 zero */ o+=16;
    put_u16be((unsigned char*)v+o,8333); o+=2; /* addr_recv port */
    put_u64le(v+o,1);       o+=8;              /* addr_from services */
    /* addr_from ip 16 zero */ o+=16;
    put_u16be((unsigned char*)v+o,0);  o+=2;   /* addr_from port */
    put_u64le(v+o,0x1111111111111111ULL); o+=8;/* nonce */
    const char *ua="/Satoshi:0.18.0/";
    v[o]=strlen(ua); o+=1; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
    put_u32le(v+o,0); o+=4;                    /* start_height */
    v[o]=1; o+=1;                              /* relay */
    printf("version payload len = %d (oracle had 102)\n", o);

    long sent = p2p_write(fd, "version", 7, v, o);
    printf("p2p_write version: sent %ld\n", sent);
    cki("p2p_write version > 0", sent > 0, 1);

    unsigned char rbuf[4096];
    char cmd[12];
    unsigned plen=0;
    int got_version=0, got_verack=0;
    for (int i=0;i<12;i++){
        int r = p2p_read(fd, cmd, rbuf, sizeof(rbuf), &plen);
        if (r <= 0) break;
        cmd[11]=0;
        printf("  got '%s' (%u bytes)\n", cmd, plen);
        if (strncmp(cmd,"version",7)==0) got_version=1;
        if (strncmp(cmd,"verack",6)==0) { got_verack=1; break; }
    }
    cki("got version from peer", got_version, 1);
    cki("got verack from peer", got_verack, 1);

    fd_close(fd);
    printf("\n%s (%d failures)\n", failures?"LIVE TEST FAILED":"LIVE HANDSHAKE OK", failures);
    return failures?1:0;
}

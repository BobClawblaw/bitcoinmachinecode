/* test_bitcoind.c -- 100% AI-generated harness for the assembly bitcoind.asm:
 * node_make_version (byte-exact version payload) and node_handshake over a
 * loopback fake peer.
 */
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>

/* version_gen.h -- GENERATED from asm/version.inc (single source of truth).
   The byte-exactness assertions below reference these derived constants so a
   version/UA bump cannot silently desync this test from node_make_version. */
#include "../version_gen.h"

extern long node_make_version(unsigned char* out);
extern int  node_handshake(int fd);
extern unsigned char g_peer_version_payload[256];
extern long g_peer_version_len;
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern int  p2p_read(int fd, char cmd_out[12], void* pl, unsigned cap, unsigned* len_out);
extern long fd_read_full(int fd, void* buf, long n);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static int g_saw_wtxidrelay = 0;   /* set by fake_peer: BIP339 msg seen before verack */
static int g_saw_sendaddrv2 = 0;   /* set by fake_peer: BIP155 offer seen before verack */

static void fake_peer(int cfd){
    char cmd[12]; unsigned char rbuf[1024]; unsigned plen=0;
    /* read client version */
    if (p2p_read(cfd, cmd, rbuf, sizeof rbuf, &plen) <= 0) return;
    /* send peer version (102B) + verack */
    /* REALISTIC 102-byte version (UA "/Satoshi:27.1.0/"). The original fake
     * sent 86 bytes (empty UA) -- short enough to fit under the frame overlap
     * that broke the capture against every real peer (real versions are
     * 102-125B and trampled node_handshake's cmd buffer). Real-sized payload
     * or the test proves nothing. */
    unsigned char v[102];
    unsigned char* p=v;
    p[0]=0x80;p[1]=0x11;p[2]=0x01;p[3]=0x00;                 /* version */
    memset(p+4,0,8); p[4]=9;                                  /* services=NETWORK|WITNESS */
    memset(p+12,0,8);                                         /* ts=0 */
    memset(p+20,0,26); memset(p+46,0,26);                     /* addrs */
    memset(p+72,0,8); v[72]=0x99;                             /* nonce */
    v[80]=16; memcpy(v+81, "/Satoshi:27.1.0/", 16);          /* UA */
    memset(p+97,0,4+1);                                       /* start_height, relay */
    p2p_write(cfd, "version", 7, v, 102);
    p2p_write(cfd, "verack", 6, "", 0);
    /* read the client's post-version messages: BIP339 wtxidrelay must
     * arrive BEFORE its verack */
    for (int i=0;i<8;i++){
        if (p2p_read(cfd, cmd, rbuf, sizeof rbuf, &plen) <= 0) break;
        cmd[11]=0;
        if (strncmp(cmd,"wtxidrelay",10)==0) g_saw_wtxidrelay = 1;
        if (strncmp(cmd,"sendaddrv2",10)==0) g_saw_sendaddrv2 = 1;
        if (strncmp(cmd,"verack",6)==0) break;
    }
}

int main(void){
    /* --- node_make_version byte-exactness --- */
    unsigned char v[130]; unsigned char vb[160]; memset(v,0xEE,sizeof v); memset(vb,0xEE,sizeof vb);
    long n = node_make_version(vb);
    cki("version len", n, 81 + NODE_UA_STRING_LEN + 5);
    cki("version field", vb[0]==0x80&&vb[1]==0x11&&vb[2]==0x01&&vb[3]==0x00, 1);
    cki("services=9 (NETWORK|WITNESS)", vb[4]==9, 1);
    unsigned long long ts; memcpy(&ts,vb+12,8); cki("timestamp", (long)ts, 1700000000);
    unsigned short pr; memcpy(&pr,vb+44,2); cki("addr_recv port 0x8d20", pr, 0x8d20);
    memcpy(&pr,vb+70,2); cki("addr_from port 0x8d20", pr, 0x8d20);
    unsigned long long nn; memcpy(&nn,vb+72,8); cki("nonce", nn, 0x1122334455667788ULL);
    cki("UA len", vb[80], NODE_UA_STRING_LEN);
    cki("UA bytes", memcmp(vb+81, NODE_UA_STRING, NODE_UA_STRING_LEN)==0, 1);
    unsigned sh; memcpy(&sh, vb+81+NODE_UA_STRING_LEN, 4); cki("start_height=0", sh, 0);
    cki("relay=1", vb[81+NODE_UA_STRING_LEN+4], 1);
    g_saw_wtxidrelay = 0;   /* reset before the live handshake below */
    g_saw_sendaddrv2 = 0;

    /* --- node_handshake over loopback --- */
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls,1);
    pid_t pid=fork();
    if(pid==0){ int c=accept(ls,0,0); fake_peer(c); close(c);
                /* bit 0: no wtxidrelay seen; bit 1: no sendaddrv2 seen */
                _exit((g_saw_wtxidrelay ? 0 : 1) | (g_saw_sendaddrv2 ? 0 : 2)); }
    int fd = tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);  /* sin_port is already BE */
    cki("connect", fd>=0, 1);
    int r = node_handshake(fd);
    cki("node_handshake ok", r, 1);
    /* the wtxidrelay assertion is checked via the child's exit status
     * below (the flag is set in the forked fake_peer, not this process) */
    /* --- the handshake must CAPTURE the peer's version payload (getpeerinfo
     * and the [dl] outbound log line both parse it) --- */
    cki("captured peer version len", g_peer_version_len, 102);
    unsigned pproto=0; memcpy(&pproto, g_peer_version_payload, 4);
    cki("captured proto", pproto, 0x00011180u);
    unsigned long long psvc=0; memcpy(&psvc, g_peer_version_payload+4, 8);
    cki("captured services", (long)psvc, 9);
    cki("captured nonce byte", g_peer_version_payload[72], 0x99);
    cki("captured UA len", g_peer_version_payload[80], 16);
    cki("captured UA bytes", memcmp(g_peer_version_payload+81, "/Satoshi:27.1.0/", 16)==0, 1);
    close(fd);
    { int st=0; waitpid(pid,&st,0);
      cki("BIP339: wtxidrelay sent after version, before verack (child saw it)",
          WIFEXITED(st) && (WEXITSTATUS(st) & 1)==0, 1);
      cki("BIP155: sendaddrv2 offered after version, before verack (peer is 70016)",
          WIFEXITED(st) && (WEXITSTATUS(st) & 2)==0, 1); }
    close(ls);

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}

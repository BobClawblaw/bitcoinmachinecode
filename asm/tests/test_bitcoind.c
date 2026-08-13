/* test_bitcoind.c -- 100% AI-generated harness for the assembly bitcoind.asm:
 * node_make_version (byte-exact version payload) and node_handshake over a
 * loopback fake peer.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>

extern long node_make_version(unsigned char* out);
extern int  node_handshake(int fd);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern int  p2p_read(int fd, char cmd_out[12], void* pl, unsigned cap, unsigned* len_out);
extern long fd_read_full(int fd, void* buf, long n);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }

static void fake_peer(int cfd){
    char cmd[12]; unsigned char rbuf[1024]; unsigned plen=0;
    /* read client version */
    if (p2p_read(cfd, cmd, rbuf, sizeof rbuf, &plen) <= 0) return;
    /* send peer version (102B) + verack */
    unsigned char v[102];
    unsigned char* p=v;
    p[0]=0x80;p[1]=0x11;p[2]=0x01;p[3]=0x00;                 /* version */
    memset(p+4,0,8); p[4]=1;                                  /* services=1 */
    memset(p+12,0,8);                                         /* ts=0 */
    memset(p+20,0,26); memset(p+46,0,26);                     /* addrs */
    memset(p+72,0,8); v[72]=0x99;                             /* nonce */
    v[80]=0;                                                  /* empty UA */
    memset(p+81,0,4+1);                                       /* start_height, relay */
    p2p_write(cfd, "version", 7, v, 86);
    p2p_write(cfd, "verack", 6, "", 0);
    /* read client verack */
    for (int i=0;i<8;i++){
        if (p2p_read(cfd, cmd, rbuf, sizeof rbuf, &plen) <= 0) break;
        cmd[11]=0;
        if (strncmp(cmd,"verack",6)==0) break;
    }
}

int main(void){
    /* --- node_make_version byte-exactness --- */
    unsigned char v[130]; unsigned char vb[160]; memset(v,0xEE,sizeof v); memset(vb,0xEE,sizeof vb);
    long n = node_make_version(vb);
    cki("version len 128", n, 128);
    cki("version field", vb[0]==0x80&&vb[1]==0x11&&vb[2]==0x01&&vb[3]==0x00, 1);
    cki("services=1", vb[4]==1, 1);
    unsigned long long ts; memcpy(&ts,vb+12,8); cki("timestamp", (long)ts, 1700000000);
    unsigned short pr; memcpy(&pr,vb+44,2); cki("addr_recv port 0x8d20", pr, 0x8d20);
    memcpy(&pr,vb+70,2); cki("addr_from port 0x8d20", pr, 0x8d20);
    unsigned long long nn; memcpy(&nn,vb+72,8); cki("nonce", nn, 0x1122334455667788ULL);
    cki("UA len=42", vb[80], 42);
    cki("UA bytes", memcmp(vb+81,"Bitcoind-AssemlbyCode (BobClawblaw) vx.x.x",42)==0, 1);
    unsigned sh; memcpy(&sh,vb+123,4); cki("start_height=0", sh, 0);
    cki("relay=1", vb[127], 1);

    /* --- node_handshake over loopback --- */
    int ls=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls,1);
    pid_t pid=fork();
    if(pid==0){ int c=accept(ls,0,0); fake_peer(c); close(c); _exit(0); }
    int fd = tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);  /* sin_port is already BE */
    cki("connect", fd>=0, 1);
    int r = node_handshake(fd);
    cki("node_handshake ok", r, 1);
    close(fd); waitpid(pid,0,0); close(ls);

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}

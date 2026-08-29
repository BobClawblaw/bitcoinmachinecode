/* tests/live_v2_core.c -- dial a REAL Bitcoin Core over BIP324.
 *
 * Not part of `make test`: it needs a Core binary and a running node, which
 * the gate cannot assume. Everything else in the suite checks this node
 * against published vectors, which pins the mathematics; only this checks
 * that the protocol actually interoperates.
 *
 * The strongest line it prints is the session id: both peers derive the same
 * 32 bytes independently, and Core reports its own as `session_id` in
 * getpeerinfo. If those two strings match, every layer -- ElligatorSwift,
 * the ECDH, the HKDF labels, the garbage terminators -- agreed exactly.
 *
 * Driven by scripts/live_v2_core_check.sh.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdlib.h>
#include "daemon/v2transport.h"
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char*, void*, unsigned, unsigned*);
extern unsigned int net_magic;

int main(int argc, char** argv){
    int port = argc > 1 ? atoi(argv[1]) : 19444;
    net_magic = 0xdab5bffau;                   /* regtest */

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd,(struct sockaddr*)&sa,sizeof sa)){ printf("FAIL connect\n"); return 1; }
    struct timeval tv = {8,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);

    int v2 = bmc_v2_handshake(fd, 1, 8000);
    printf("bmc_v2_handshake -> %d %s\n", v2,
           v2==1?"(v2 session with real Core)":v2==0?"(peer is v1)":"(failed)");
    if (v2 != 1) return 1;
    { unsigned char sid[32];
      if (bmc_v2_session_id(fd, sid)){
          printf("our session_id: ");
          for (int i=0;i<32;i++) printf("%02x", sid[i]);
          printf("\n");
      } }

    /* now speak the ordinary protocol through the encrypted session */
    unsigned char v[86]; memset(v,0,sizeof v);
    v[0]=0x60; v[1]=0xea; /* proto 70016 */
unsigned long long svc = 9ULL | BMC_NODE_P2P_V2;
    memcpy(v+4,&svc,8);
    if (p2p_write(fd,"version",7,v,sizeof v) <= 0){ printf("FAIL version write\n"); return 1; }

    char cmd[13]; unsigned char buf[65536]; unsigned plen;
    int saw_version=0, saw_verack=0;
    for (int i=0;i<8 && !(saw_version&&saw_verack);i++){
        memset(cmd,0,sizeof cmd);
        int r = p2p_read(fd,cmd,buf,sizeof buf,&plen);
        if (r != 1){ printf("read rc=%d after %d msgs\n", r, i); break; }
        printf("  <- %-12.12s (%u bytes)\n", cmd, plen);
        if(!strncmp(cmd,"version",7)){ saw_version=1; p2p_write(fd,"verack",6,"",0); }
        if(!strncmp(cmd,"verack",6))  saw_verack=1;
    }
    printf("%s: version=%d verack=%d over BIP324\n",
           (saw_version&&saw_verack)?"PASS":"FAIL", saw_version, saw_verack);
    if (getenv("HOLD")) sleep(atoi(getenv("HOLD")));
    bmc_v2_close(fd); close(fd);
    return (saw_version&&saw_verack)?0:1;
}

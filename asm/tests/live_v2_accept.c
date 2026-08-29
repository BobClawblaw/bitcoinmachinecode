/* tests/live_v2_accept.c -- accept a connection from a REAL Bitcoin Core.
 *
 * The responder side, which is also the one that has to tell a v1 peer from a
 * v2 one WITHOUT consuming the v1 peer's first message. Run against Core with
 * v2 enabled it must report a v2 session; run against Core with v2 disabled
 * it must report "peer chose v1" and still read the version message that
 * follows.
 *
 * Not part of `make test` -- see tests/live_v2_core.c. Driven by
 * scripts/live_v2_core_check.sh.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "daemon/v2transport.h"
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char*, void*, unsigned, unsigned*);
extern unsigned int net_magic;

int main(int argc, char** argv){
    int port = argc > 1 ? atoi(argv[1]) : 19555;
    net_magic = 0xdab5bffau;                       /* regtest */
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int on = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    inet_pton(AF_INET,"127.0.0.1",&sa.sin_addr);
    if (bind(ls,(struct sockaddr*)&sa,sizeof sa) || listen(ls,4)){ printf("FAIL bind\n"); return 1; }
    printf("listening on 127.0.0.1:%d\n", port); fflush(stdout);

    int fd = accept(ls, 0, 0);
    if (fd < 0){ printf("FAIL accept\n"); return 1; }
    struct timeval tv = {10,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);

    int v2 = bmc_v2_handshake(fd, 0, 10000);
    printf("bmc_v2_handshake(responder) -> %d %s\n", v2,
           v2==1?"(v2 from real Core)":v2==0?"(peer chose v1)":"(failed)");
    if (v2 == 1){ unsigned char sid[32]; bmc_v2_session_id(fd, sid);
        printf("our session_id: "); for(int i=0;i<32;i++) printf("%02x", sid[i]); printf("\n"); }
    fflush(stdout);
    if (v2 < 0) return 1;

    char cmd[13]; unsigned char buf[65536]; unsigned plen;
    int saw_version = 0;
    for (int i=0;i<6 && !saw_version;i++){
        memset(cmd,0,sizeof cmd);
        int r = p2p_read(fd,cmd,buf,sizeof buf,&plen);
        if (r != 1){ printf("read rc=%d\n", r); break; }
        printf("  <- %-12.12s (%u bytes)\n", cmd, plen);
        if(!strncmp(cmd,"version",7)) saw_version = 1;
    }
    printf("%s: peer version received over %s\n", saw_version?"PASS":"FAIL", v2==1?"BIP324":"v1");
    if (getenv("HOLD")) sleep(atoi(getenv("HOLD")));
    bmc_v2_close(fd); close(fd); close(ls);
    return saw_version?0:1;
}

/* hs_cap_probe -- run the REAL node_handshake against real peers and dump
 * g_peer_version_len + parsed fields right after, exactly as the worker does. */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
extern long node_handshake(int fd);
extern int  tcp_connect_ip(unsigned be_ip, unsigned short be_port);
extern unsigned char g_peer_version_payload[256];
extern long g_peer_version_len;
int main(int argc, char** argv){
    for (int a = 1; a < argc; a++){
        struct in_addr ia; if (!inet_aton(argv[a], &ia)) continue;
        g_peer_version_len = -12345;   /* sentinel: did the handshake write it at all? */
        int fd = tcp_connect_ip(ia.s_addr, htons(8333));
        if (fd < 0){ printf("%-16s connect fail\n", argv[a]); continue; }
        struct timeval tv = {6,0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        long r = node_handshake(fd);
        printf("%-16s hs=%ld len=%ld", argv[a], r, g_peer_version_len);
        if (g_peer_version_len >= 80 && g_peer_version_len <= 256){
            unsigned proto; memcpy(&proto, g_peer_version_payload, 4);
            printf(" proto=%u ua=\"%.*s\"", proto, g_peer_version_payload[80], (char*)g_peer_version_payload+81);
        }
        printf("\n");
        close(fd);
    }
    return 0;
}

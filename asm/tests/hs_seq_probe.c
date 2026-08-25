/* hs_seq_probe -- dial real peers, do the version exchange with raw p2p
 * framing, print the exact message sequence (cmd + announced payload len)
 * until verack/timeout. Diagnostic for the peer-dependent blank capture. */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
extern long node_make_version(unsigned char* out);
extern long p2p_write(int fd, const char* cmd, long cmdlen, const void* payload, long plen);
extern long p2p_read(int fd, char* cmd_out, void* payload, long cap, unsigned* plen_out);
extern int  tcp_connect_ip(unsigned be_ip, unsigned short be_port);
int main(int argc, char** argv){
    for (int a = 1; a < argc; a++){
        struct in_addr ia; if (!inet_aton(argv[a], &ia)) continue;
        int fd = tcp_connect_ip(ia.s_addr, htons(8333));
        if (fd < 0){ printf("%s: connect fail\n", argv[a]); continue; }
        struct timeval tv = {6,0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        unsigned char v[160]; long n = node_make_version(v);
        p2p_write(fd, "version", 7, v, n);
        printf("%s:", argv[a]);
        for (int i = 0; i < 12; i++){
            char cmd[13]; unsigned char pl[2048]; unsigned plen = 0;
            long r = p2p_read(fd, cmd, pl, sizeof pl, &plen);
            if (r <= 0){ printf(" [read=%ld]", r); break; }
            cmd[12] = 0;
            printf(" %s(%u)", cmd, plen);
            if (!strncmp(cmd, "verack", 6)) break;
        }
        printf("\n");
        close(fd);
    }
    return 0;
}

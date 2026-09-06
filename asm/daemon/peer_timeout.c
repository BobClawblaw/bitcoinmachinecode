#include <sys/socket.h>
#include <sys/time.h>
#include "peer_timeout.h"
long peer_handshake_secs(long configured){
    if (configured <= 0) return 60;
    if (configured > 600) return 600;
    return configured;
}
int peer_handshake_deadline(int fd, long secs){
    if (fd < 0) return -1;
    struct timeval tv; tv.tv_sec = (time_t)peer_handshake_secs(secs); tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) != 0) return -1;
    return 0;
}

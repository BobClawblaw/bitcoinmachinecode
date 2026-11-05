/* daemon/hdr_tree_read.c -- the fork tree's read-only lookup, for the RPC
 * process (see hdr_tree.h). Separate from hdr_tree.c, which owns the table
 * and runs in the download worker: this file needs only libc, so every link
 * set that carries rpc_chain.o can carry it. */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "hdr_tree.h"
int hdrtree_file_lookup(const unsigned char hash[32], unsigned char hdr80[80], long* height,
                        unsigned char work[16], unsigned* ntx){
    int fd = open(HDRTREE_FILE, O_RDONLY); if (fd < 0) return 0;
    unsigned char buf[HDRTREE_REC * 64]; int found = 0; long carry = 0;
    for (;;){
        ssize_t n = read(fd, buf + carry, sizeof buf - (size_t)carry);
        if (n <= 0) break;
        long have = carry + n, whole = have - have % HDRTREE_REC;
        for (long o = 0; o < whole; o += HDRTREE_REC){
            const unsigned char* r = buf + o;
            if (memcmp(r, hash, 32)) continue;
            unsigned flags; memcpy(&flags, r + HDRTREE_OFF_FLAGS, 4);
            if (!(flags & HDRTREE_HAVE_HDR)) continue;
            if (hdr80) memcpy(hdr80, r + HDRTREE_OFF_HDR, 80);
            if (height) memcpy(height, r + HDRTREE_OFF_HEIGHT, 8);
            if (work) memcpy(work, r + HDRTREE_OFF_WORK, 16);
            if (ntx) memcpy(ntx, r + HDRTREE_OFF_NTX, 4);
            found = 1;
        }
        carry = have - whole;          /* a record still being appended: keep its start for the next read */
        if (carry) memmove(buf, buf + whole, (size_t)carry);
    }
    close(fd);
    return found;
}

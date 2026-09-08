/* daemon/addr_hist.c -- reader of the address history index (addr_hist_fmt.h).
 * mmap'd read-only, remapped when a rebuild has replaced the file (rename). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "addr_hist_fmt.h"
static const uint8_t* g_map = 0; static size_t g_len = 0; static ino_t g_ino = 0; static ah_header g_hdr;
static int ah_open(void){
    struct stat sb;
    if (stat(AH_FILE, &sb) != 0){ if (g_map){ munmap((void*)g_map, g_len); g_map = 0; } return 0; }
    if (g_map && sb.st_ino == g_ino && (size_t)sb.st_size == g_len) return 1;
    if (g_map){ munmap((void*)g_map, g_len); g_map = 0; }
    int fd = open(AH_FILE, O_RDONLY); if (fd < 0) return 0;
    void* m = mmap(0, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd, 0); close(fd);
    if (m == MAP_FAILED) return 0;
    if ((size_t)sb.st_size < AH_HDR_BYTES){ munmap(m, (size_t)sb.st_size); return 0; }
    memcpy(&g_hdr, m, sizeof g_hdr);
    if (g_hdr.magic != AH_MAGIC || g_hdr.version != AH_VERSION || g_hdr.body_off + g_hdr.body_len > (uint64_t)sb.st_size
        || g_hdr.sparse_off + g_hdr.sparse_n * AH_SPARSE_BYTES > (uint64_t)sb.st_size){ munmap(m, (size_t)sb.st_size); return 0; }
    g_map = m; g_len = (size_t)sb.st_size; g_ino = sb.st_ino;
    return 1;
}
int  ah_available(void){ return ah_open(); }
long ah_to_height(void){ return ah_open() ? (long)g_hdr.to_height : -1; }
long ah_lookup(uint8_t type, const uint8_t hash[32], const ah_event** events){
    *events = 0;
    if (!ah_open()) return -1;
    if (g_hdr.sparse_n == 0) return 0;
    /* the last sparse entry whose key <= target */
    const uint8_t* sp = g_map + g_hdr.sparse_off;
    uint64_t lo = 0, hi = g_hdr.sparse_n;
    while (lo < hi){
        uint64_t mid = (lo + hi) / 2; const uint8_t* e = sp + mid * AH_SPARSE_BYTES;
        if (ah_key_cmp(e[0], e + 1, type, hash) <= 0) lo = mid + 1; else hi = mid;
    }
    if (lo == 0) return 0;                                   /* target below the first key */
    uint64_t off; memcpy(&off, sp + (lo - 1) * AH_SPARSE_BYTES + 33, 8);
    const uint8_t* p = g_map + g_hdr.body_off + off; const uint8_t* end = g_map + g_hdr.body_off + g_hdr.body_len;
    for (int k = 0; k < AH_SPARSE_STRIDE && p + AH_GROUP_HDR <= end; k++){
        ah_group_hdr gh; memcpy(&gh, p, AH_GROUP_HDR);
        int c = ah_key_cmp(gh.type, gh.hash, type, hash);
        if (c == 0){ *events = (const ah_event*)(p + AH_GROUP_HDR); return (long)gh.n; }
        if (c > 0) return 0;
        p += AH_GROUP_HDR + (size_t)gh.n * AH_EVENT_BYTES;
    }
    return 0;
}
/* test seam: forget the mapping */
void ah_reset_for_test(void){ if (g_map){ munmap((void*)g_map, g_len); g_map = 0; } g_len = 0; g_ino = 0; }

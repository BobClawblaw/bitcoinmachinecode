#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "anchors.h"
#include "netaddr.h"
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
static long put_cs(unsigned char* o, unsigned long long v){
    if (v < 253){ o[0] = (unsigned char)v; return 1; }
    if (v <= 0xffff){ o[0] = 253; o[1] = (unsigned char)v; o[2] = (unsigned char)(v >> 8); return 3; }
    o[0] = 254; for (int i = 0; i < 4; i++) o[1+i] = (unsigned char)(v >> (8*i)); return 5;
}
static long get_cs(const unsigned char* p, long len, unsigned long long* v){
    if (len < 1) return 0;
    if (p[0] < 253){ *v = p[0]; return 1; }
    if (p[0] == 253){ if (len < 3) return 0; *v = p[1] | (p[2] << 8); return 3; }
    if (p[0] == 254){ if (len < 5) return 0; *v = 0; for (int i = 0; i < 4; i++) *v |= (unsigned long long)p[1+i] << (8*i); return 5; }
    return 0;
}
long anchors_write(const char* path, const char* const* hosts, int n, unsigned magic, unsigned long long services, unsigned now){
    unsigned char buf[4 + 5 + 64 * 128 + 32]; long o = 0, wrote = 0;
    for (int i = 0; i < 4; i++) buf[o++] = (unsigned char)(magic >> (8*i));
    long cpos = o; o += 1;                                     /* count patched below (n <= 64 fits one byte) */
    for (int i = 0; i < n && wrote < 64; i++){
        bmc_addr_t a; if (!bmc_addr_from_string_port(&a, hosts[i], 0)) continue;
        long l = bmc_addr_encode_v2(buf + o, (long)sizeof buf - o - 32, &a, services, now);
        if (l <= 0) continue;
        o += l; wrote++;
    }
    put_cs(buf + cpos, (unsigned long long)wrote);
    sha256d(buf + o, buf, (unsigned long)o); o += 32;
    char tmp[512]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE* f = fopen(tmp, "wb"); if (!f) return -1;
    long ok = fwrite(buf, 1, (size_t)o, f) == (size_t)o; fclose(f);
    if (!ok || rename(tmp, path) != 0){ unlink(tmp); return -1; }
    return wrote;
}
long anchors_read(const char* path, char (*hosts)[128], int cap, unsigned magic){
    FILE* f = fopen(path, "rb"); if (!f) return 0;
    unsigned char buf[4 + 5 + 64 * 128 + 32]; long len = (long)fread(buf, 1, sizeof buf, f); fclose(f);
    unlink(path);                                              /* Core: read once, then gone */
    if (len < 4 + 1 + 32) return -1;
    unsigned m = buf[0] | (buf[1] << 8) | (buf[2] << 16) | ((unsigned)buf[3] << 24);
    if (m != magic) return -1;
    unsigned char h[32]; sha256d(h, buf, (unsigned long)(len - 32));
    if (memcmp(h, buf + len - 32, 32) != 0) return -1;
    unsigned long long n = 0; long o = 4; long c = get_cs(buf + o, len - 32 - o, &n); if (!c) return -1; o += c;
    long got = 0;
    for (unsigned long long i = 0; i < n && got < cap; i++){
        bmc_addr_t a; unsigned long long sv; unsigned t; long used = 0;
        if (bmc_addr_decode_v2(&a, &sv, &t, buf + o, len - 32 - o, &used) <= 0 || used <= 0) return -1;
        o += used;
        if (bmc_addr_to_string_port(hosts[got], 128, &a) <= 0) continue;
        got++;
    }
    return got;
}
int legs_relay_fds(const int* fds, const unsigned char* kinds, int n, int* out){
    int k = 0;
    for (int i = 0; i < n; i++){ out[i] = (kinds[i] == LEG_BLOCK_ONLY) ? -1 : fds[i]; if (out[i] >= 0) k++; }
    return k;
}

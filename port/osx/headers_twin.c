/* ============================================================================
 * headers_twin.c -- header chain store for the macOS/AArch64 port.
 * Functional twin of asm/bitcoin_headers.asm (branch bmc_osx).
 *
 * hst struct: +0 fd (i64), +8 count (u64).
 * File "headers.dat": 112-byte records = header[80] || hash[32].
 *
 *   long hst_init(void *hst);          1 ok / -1 err
 *   long hst_reload(void *hst);        1 ok / -1 err
 *   long hst_append(void *hst, const u8 hdr[80], const u8 hash[32]);
 *   long hst_count(void *hst)
{
    return *(long *)((u8 *)hst + 8);
}

long hst_get_at(void *hst, u64 height, void *out112);  1 / 0 (oor) / -1
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

typedef uint64_t u64;
typedef int64_t i64;
typedef unsigned char u8;

long hst_init(void *hst)
{
    u8 *H = (u8 *)hst;
    int fd = open("headers.dat", O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;
    *(i64 *)(H + 0) = fd;
    *(u64 *)(H + 8) = 0;
    return 1;
}

long hst_reload(void *hst)
{
    u8 *H = (u8 *)hst;
    int fd = (int)*(i64 *)(H + 0);
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz < 0) return -1;
    *(u64 *)(H + 8) = (u64)sz / 112;
    return 1;
}

long hst_append(void *hst, const void *hdr, const void *hash)
{
    u8 *H = (u8 *)hst;
    int fd = (int)*(i64 *)(H + 0);
    u64 count = *(u64 *)(H + 8);
    off_t off = (off_t)(count * 112);
    if (lseek(fd, off, SEEK_SET) < 0) return -1;
    u8 rec[112];
    memcpy(rec, hdr, 80);
    memcpy(rec + 80, hash, 32);
    if (write(fd, rec, 112) != 112) return -1;
    count += 1;
    *(u64 *)(H + 8) = count;
    return (long)count;                  /* x86 returns the new count */
}

long hst_count(void *hst)
{
    return *(long *)((u8 *)hst + 8);
}

long hst_get_at(void *hst, u64 height, void *out112)
{
    u8 *H = (u8 *)hst;
    int fd = (int)*(i64 *)(H + 0);
    if (height >= *(u64 *)(H + 8)) return 0;
    if (pread(fd, out112, 112, (off_t)(height * 112)) != 112) return -1;
    return 1;
}

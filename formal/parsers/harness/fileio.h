/* formal/parsers/harness/fileio.h -- one in-memory "file" for the on-disk
 * loaders: contents and size are nondeterministic (size <= FP_FSZ), so every
 * byte the loader reads is attacker-chosen (a corrupt or planted file). The
 * stdio / POSIX calls the loaders use are modelled over it; each may also
 * fail. Environment model, trusted: a read returns at most what is left. */
#ifndef FP_FILEIO_H
#define FP_FILEIO_H
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef FP_FSZ
#define FP_FSZ 64
#endif
static unsigned char* g_f; static size_t g_fsz; static size_t g_fpos; static int g_fopen_n;
static FILE g_fobj;
static void fio_init(void){ g_fsz = nondet_size(); ASSUME(g_fsz <= FP_FSZ); g_f = nd_buf(g_fsz); g_fpos = 0; }
FILE* fopen(const char* p, const char* m){ (void)p; (void)m; if (nondet_int()) return 0; g_fpos = 0; g_fopen_n++; return &g_fobj; }
int fclose(FILE* f){ CHECK(f == &g_fobj, "fclose of the open file"); g_fopen_n--; return 0; }
int fseek(FILE* f, long off, int wh){ (void)f; if (nondet_int()) return -1;
    if (wh == SEEK_END) g_fpos = g_fsz; else if (wh == SEEK_SET){ ASSUME(off >= 0); g_fpos = (size_t)off; } return 0; }
long ftell(FILE* f){ (void)f; return (long)g_fpos; }
void rewind(FILE* f){ (void)f; g_fpos = 0; }
size_t fread(void* b, size_t sz, size_t n, FILE* f){
    (void)f; CHECK(sz == 0 || n <= SIZE_MAX / sz, "fread size product fits");
    size_t want = sz * n; CHECK(__CPROVER_w_ok(b, want), "fread buffer writable");
    size_t left = g_fpos <= g_fsz ? g_fsz - g_fpos : 0;
    size_t got = want <= left ? want : left;
    if (nondet_int()) { size_t s = nondet_size(); ASSUME(s <= got); got = s; }   /* short read */
    if (sz) got -= got % sz;
    memcpy(b, g_f + g_fpos, got); g_fpos += got; return sz ? got / sz : 0;
}
#endif

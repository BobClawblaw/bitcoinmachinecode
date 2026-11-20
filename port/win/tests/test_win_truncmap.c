/* test_win_truncmap.c -- ftruncate of a file that is (or was) mapped:
 * after munmap it must shrink like any file; while still mapped (Linux
 * allows it: pages past EOF fault), the new size must at least be what
 * fstat and a fresh mapping see. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok  : " __VA_ARGS__); else { printf("FAIL: " __VA_ARGS__); fails++; } \
			   printf("\n"); } while (0)

static long fsize(int fd)
{
	struct stat st;
	return fstat(fd, &st) ? -1 : (long)st.st_size;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	const char *p = "truncmap.dat";
	unlink(p);
	int fd = open(p, O_RDWR | O_CREAT, 0644);
	CHECK(ftruncate(fd, 8 << 20) == 0, "grow to 8 MB");
	char *m = mmap(0, 8 << 20, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(m != MAP_FAILED, "map it");
	memset(m, 0xab, 8 << 20);
	CHECK(munmap(m, 8 << 20) == 0, "unmap");
	close(fd);
	fd = open(p, O_RDWR);
	CHECK(ftruncate(fd, 1 << 20) == 0, "after munmap: shrink to 1 MB");
	CHECK(fsize(fd) == 1 << 20, "...fstat says 1 MB (%ld)", fsize(fd));

	m = mmap(0, 1 << 20, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(m != MAP_FAILED, "map 1 MB");
	CHECK(ftruncate(fd, 4096) == 0, "while mapped: shrink to 4 KB");
	/* Windows keeps the physical size while a view lives; the cut range is
	 * zeroed instead (winsys truncate_handle) */
	CHECK(fsize(fd) == 4096 || fsize(fd) == 1 << 20, "...fstat says 4 KB, or 1 MB with the tail zeroed (%ld)",
	      fsize(fd));
	CHECK(ftruncate(fd, 2 << 20) == 0, "while mapped: grow to 2 MB");
	char *m2 = mmap(0, 2 << 20, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(m2 != MAP_FAILED, "a second mapping of 2 MB");
	if (m2 != MAP_FAILED)
		CHECK(m2[(2 << 20) - 1] == 0 && m2[8192] == 0, "...past the old 4 KB EOF it reads zero (%d, %d)",
		      m2[(2 << 20) - 1], m2[8192]);
	munmap(m, 1 << 20);
	if (m2 != MAP_FAILED)
		munmap(m2, 2 << 20);
	close(fd);
	unlink(p);
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", fails);
	return fails != 0;
}

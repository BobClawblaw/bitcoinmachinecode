/* test_win_bigmap.c -- map a large file read-only, MAP_SHARED, whole (the
 * LSM's run cache does this with multi-GB run files), and touch its ends.
 * Usage: test_win_bigmap <file> (default: a 5 GB sparse file it makes) */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	const char *p = argc > 1 ? argv[1] : "bigmap.dat";
	if (argc < 2) {
		int w = open(p, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (w < 0 || ftruncate(w, 5LL << 30) != 0 || pwrite(w, "Z", 1, (5LL << 30) - 1) != 1) {
			printf("setup failed: %s\n", strerror(errno));
			return 2;
		}
		close(w);
	}
	int fd = open(p, O_RDONLY);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) != 0) {
		printf("open/fstat failed: %s\n", strerror(errno));
		return 2;
	}
	printf("size %lld\n", (long long)st.st_size);
	void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED) {
		printf("FAIL: mmap of %lld bytes: %s\n", (long long)st.st_size, strerror(errno));
		return 1;
	}
	int r = madvise(m, (size_t)st.st_size, MADV_RANDOM);
	const unsigned char *b = m;
	printf("mapped at %p, madvise %d; first byte %u, last byte %u\n", m, r, b[0], b[st.st_size - 1]);
	munmap(m, (size_t)st.st_size);
	close(fd);
	if (argc < 2)
		unlink(p);
	printf("ALL TESTS PASSED\n");
	return 0;
}

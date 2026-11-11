/* test_win_exitmaps.c -- how long a forked child holding big mappings takes
 * to be reaped after it exits: anonymous MAP_SHARED, file MAP_SHARED with
 * dirty pages, and mlock'ed memory (the daemon's worker holds all three). */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

static long long ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000LL + t.tv_nsec / 1000000; }

static long long run(int kind, size_t len)
{
	int fd = -1;
	if (kind == 1) {
		fd = open("exitmaps.dat", O_RDWR | O_CREAT | O_TRUNC, 0644);
		ftruncate(fd, (off_t)len);
	}
	char *m = mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED | (kind == 1 ? 0 : MAP_ANONYMOUS), fd, 0);
	if (m == MAP_FAILED) { printf("mmap failed\n"); return -1; }
	if (kind == 2)
		mlock(m, len);
	for (size_t i = 0; i < len; i += 4096)
		m[i] = 1;
	int p[2];
	pipe(p);
	pid_t c = fork();
	if (c == 0) {
		for (size_t i = 0; i < len; i += 4096)
			m[i] = 2;
		write(p[1], "x", 1);
		_exit(0);
	}
	char x;
	read(p[0], &x, 1);
	long long t0 = ms();
	waitpid(c, NULL, 0);
	long long dt = ms() - t0;
	munmap(m, len);
	if (fd >= 0) { close(fd); unlink("exitmaps.dat"); }
	close(p[0]); close(p[1]);
	return dt;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	const char *names[3] = { "anon shared", "file shared", "mlocked anon" };
	for (int k = 0; k < 3; k++)
		for (size_t mb = 64; mb <= 1024; mb *= 4)
			printf("%-13s %5zu MB: reaped %lld ms after its last write\n", names[k], mb, run(k, mb << 20));
	return 0;
}

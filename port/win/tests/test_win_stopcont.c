/* test_win_stopcont.c -- SIGSTOP / SIGCONT of a forked child: while stopped
 * it makes no progress; after SIGCONT it runs on; when it then exits, its
 * parent reaps it promptly. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

static long long ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000LL + t.tv_nsec / 1000000; }
static int fails;
static void ck(const char *l, int c) { printf("%s: %s\n", c ? "ok  " : "FAIL", l); fails += !c; }

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	volatile long *ctr = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pid_t c = fork();
	if (c == 0) {
		long long t0 = ms();
		while (ms() - t0 < 1500)
			(*ctr)++;
		_exit(7);
	}
	usleep(200000);
	ck("SIGSTOP accepted", kill(c, SIGSTOP) == 0);
	usleep(50000);
	long a = *ctr;
	usleep(300000);
	long b = *ctr;
	ck("no progress while stopped", a == b);
	ck("SIGCONT accepted", kill(c, SIGCONT) == 0);
	usleep(100000);
	ck("progress after SIGCONT", *ctr != b);
	long long t0 = ms();
	int st = 0;
	waitpid(c, &st, 0);
	long long dt = ms() - t0;
	printf("  reaped %lld ms after SIGCONT+100ms\n", dt);
	ck("exit status 7", WIFEXITED(st) && WEXITSTATUS(st) == 7);
	ck("reaped within 3 s (the child's own time left is ~1.5 s)", dt < 3000);
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", fails);
	return fails != 0;
}

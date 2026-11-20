/* test_win_segvpipe.c -- a forked child's SIGSEGV handler writes to a pipe
 * its parent reads (daemon/crash_trace.c's report path), then dies of the
 * signal: the parent gets the bytes and a WIFSIGNALED SIGSEGV status. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static int g_fd;
static void on_segv(int sig)
{
	(void)!write(g_fd, "report\n", 7);
	signal(sig, SIG_DFL);
	raise(sig);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int pp[2];
	pipe(pp);
	pid_t c = fork();
	if (c == 0) {
		close(pp[0]);
		g_fd = pp[1];
		signal(SIGSEGV, on_segv);
		*(volatile int *)0x10 = 1;
		_exit(3);
	}
	close(pp[1]);
	char b[64];
	ssize_t n = read(pp[0], b, sizeof b - 1);
	b[n > 0 ? n : 0] = 0;
	int st = 0;
	waitpid(c, &st, 0);
	printf("read %zd \"%s\" status 0x%x\n", n, n > 0 ? "report" : "", st);
	int ok = n == 7 && WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV;
	printf(ok ? "\nALL TESTS PASSED\n" : "\n1 FAILURE(S)\n");
	return !ok;
}

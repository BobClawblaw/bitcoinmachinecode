/* test_win_fork.c -- the bmc_win process layer: fork, wait, shared memory,
 * fds and sockets across fork, the socket broker, signals between
 * processes, PDEATHSIG, posix_spawn/system/popen/execl.
 * Usage: test_win_fork [path-of-this-binary]   (argv[1] "child-exit" etc.
 * are its own re-exec modes). */
#define _GNU_SOURCE
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok  : " __VA_ARGS__); else { printf("FAIL: " __VA_ARGS__); fails++; } \
			   printf("\n"); fflush(stdout); } while (0)

static volatile sig_atomic_t got_term, got_chld;
static void on_term(int s) { (void)s; got_term = 1; }
static void on_chld(int s) { (void)s; got_chld = 1; }

static void msleep(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "exit7"))
		return 7;
	setvbuf(stdout, NULL, _IONBF, 0);

	/* 1. fork + exit status */
	pid_t p = fork();
	if (p == 0)
		_exit(42);
	int st = 0;
	pid_t w = waitpid(p, &st, 0);
	CHECK(p > 0 && w == p && WIFEXITED(st) && WEXITSTATUS(st) == 42, "fork/waitpid exit status 42 (pid %d st 0x%x)", p, st);
	CHECK(waitpid(-1, &st, WNOHANG) == -1 && errno == ECHILD, "no children left: ECHILD");

	/* 2. MAP_SHARED anonymous memory is shared; private memory is copied */
	volatile int *shm = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	static int priv = 1;
	*shm = 0;
	p = fork();
	if (p == 0) {
		*shm = 1234;
		priv = 99;
		_exit(0);
	}
	waitpid(p, &st, 0);
	CHECK(*shm == 1234 && priv == 1, "MAP_SHARED shared (%d), private memory copy-on-write (%d)", *shm, priv);

	/* 3. a pipe across fork, and getppid */
	int pp[2];
	pipe(pp);
	pid_t me = getpid();
	p = fork();
	if (p == 0) {
		close(pp[0]);
		char b[64];
		int n = snprintf(b, sizeof b, "ppid-ok=%d", getppid() == me);
		write(pp[1], b, (size_t)n);
		_exit(0);
	}
	close(pp[1]);
	char buf[128] = { 0 };
	ssize_t n = read(pp[0], buf, sizeof buf - 1);
	close(pp[0]);
	waitpid(p, &st, 0);
	CHECK(n > 0 && !strcmp(buf, "ppid-ok=1"), "pipe across fork, getppid in child ('%s')", buf);

	/* 4. a socketpair across fork: the child talks without Winsock */
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
	p = fork();
	if (p == 0) {
		close(sv[0]);
		char b[16] = { 0 };
		ssize_t k = read(sv[1], b, 4);
		if (k == 4 && !memcmp(b, "ping", 4))
			write(sv[1], "pong", 4);
		_exit(0);
	}
	close(sv[1]);
	write(sv[0], "ping", 4);
	memset(buf, 0, sizeof buf);
	n = read(sv[0], buf, 4);
	close(sv[0]);
	waitpid(p, &st, 0);
	CHECK(n == 4 && !memcmp(buf, "pong", 4), "socket data both ways across fork");

	/* 5. a child makes its own socket and connects (the broker), and resolves a name */
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t sl = sizeof sa;
	bind(ls, (struct sockaddr *)&sa, sizeof sa);
	listen(ls, 4);
	getsockname(ls, (struct sockaddr *)&sa, &sl);
	p = fork();
	if (p == 0) {
		int c = socket(AF_INET, SOCK_STREAM, 0);
		int ok = c >= 0 && connect(c, (struct sockaddr *)&sa, sizeof sa) == 0;
		struct sockaddr_in peer;
		socklen_t pl = sizeof peer;
		ok = ok && getpeername(c, (struct sockaddr *)&peer, &pl) == 0 && peer.sin_port == sa.sin_port;
		struct addrinfo *ai = NULL, hints = { 0 };
		hints.ai_family = AF_INET;
		int g = getaddrinfo("localhost", NULL, &hints, &ai);
		if (ai)
			freeaddrinfo(ai);
		char b[8];
		int m = snprintf(b, sizeof b, "%d%d", ok, g == 0);
		write(c, b, (size_t)m);
		close(c);
		_exit(0);
	}
	int as = accept(ls, NULL, NULL);
	memset(buf, 0, sizeof buf);
	n = read(as, buf, 8);
	close(as);
	close(ls);
	waitpid(p, &st, 0);
	CHECK(n == 2 && buf[0] == '1', "child socket()+connect()+getpeername() via the root ('%s')", buf);
	CHECK(n == 2 && buf[1] == '1', "child getaddrinfo via the root");

	/* 6. kill(child, SIGTERM) runs the child's handler; SIGCHLD reaches us */
	signal(SIGCHLD, on_chld);
	pipe(pp);
	p = fork();
	if (p == 0) {
		close(pp[0]);
		signal(SIGTERM, on_term);
		write(pp[1], "r", 1);
		for (int i = 0; i < 500 && !got_term; i++)
			msleep(10);
		_exit(got_term ? 3 : 4);
	}
	close(pp[1]);
	read(pp[0], buf, 1);
	close(pp[0]);
	kill(p, SIGTERM);
	waitpid(p, &st, 0);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 3, "SIGTERM handler ran in the child (st 0x%x)", st);
	for (int i = 0; i < 100 && !got_chld; i++)
		msleep(10);
	CHECK(got_chld, "SIGCHLD delivered to the parent");

	/* 7. a child killed by a default-action signal reports WIFSIGNALED */
	p = fork();
	if (p == 0) {
		for (;;)
			msleep(100);
	}
	msleep(50);
	kill(p, SIGKILL);
	waitpid(p, &st, 0);
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "SIGKILL: WIFSIGNALED, WTERMSIG 9 (st 0x%x)", st);

	/* 8. PR_SET_PDEATHSIG: a grandchild learns its parent died */
	pipe(pp);
	p = fork();
	if (p == 0) {
		pid_t g = fork();
		if (g == 0) {
			signal(SIGTERM, on_term);
			prctl(PR_SET_PDEATHSIG, SIGTERM);
			write(pp[1], "g", 1);
			for (int i = 0; i < 500 && !got_term; i++)
				msleep(10);
			write(pp[1], got_term ? "T" : "x", 1);
			_exit(0);
		}
		char c;
		read(pp[0], &c, 1);
		_exit(0);                      /* the grandchild's parent dies */
	}
	close(pp[1]);
	waitpid(p, &st, 0);
	memset(buf, 0, sizeof buf);
	n = read(pp[0], buf, 1);
	close(pp[0]);
	CHECK(n == 1 && buf[0] == 'T', "PR_SET_PDEATHSIG delivered when the parent exits ('%s')", buf);

	/* 9. system / popen / execl */
	int rc = system("exit 5");
	CHECK(WIFEXITED(rc) && WEXITSTATUS(rc) == 5, "system(\"exit 5\") -> 5 (rc 0x%x)", rc);
	FILE *f = popen("echo hello-from-cmd", "r");
	memset(buf, 0, sizeof buf);
	if (f) {
		fgets(buf, sizeof buf, f);
		pclose(f);
	}
	CHECK(!strncmp(buf, "hello-from-cmd", 14), "popen reads the command's output ('%.20s')", buf);
	if (argc > 1) {
		p = fork();
		if (p == 0) {
			execl(argv[1], "test_win_fork", "exit7", (char *)0);
			_exit(127);
		}
		waitpid(p, &st, 0);
		CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 7, "fork+execl of a bmc binary exits 7 (st 0x%x)", st);
	}

	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", fails);
	return fails != 0;
}

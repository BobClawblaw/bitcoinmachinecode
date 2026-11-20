/* test_win_uxdgram.c -- AF_UNIX SOCK_DGRAM (winsys: mailslots) behaves as
 * on Linux: path and abstract binds, one message per send with its
 * boundaries kept, truncation of a long message, EADDRINUSE on a bound name
 * or an existing file, ENOENT/ECONNREFUSED for a missing receiver,
 * O_NONBLOCK and SO_RCVTIMEO (EAGAIN), connect + write/read, poll's POLLIN,
 * SO_TYPE, and a datagram from a forked child. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void ck(const char *l, int c) { printf("%s: %s\n", c ? "ok  " : "FAIL", l); fails += !c; }

static socklen_t mkaddr(struct sockaddr_un *a, const char *path)
{
	memset(a, 0, sizeof *a);
	a->sun_family = AF_UNIX;
	size_t n = strlen(path);
	memcpy(a->sun_path, path, n);
	if (path[0] == '@')
		a->sun_path[0] = 0;
	return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n);
}

static long long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char path[64], abs_[64];
	snprintf(path, sizeof path, "uxdgram_%d.sock", (int)getpid());
	snprintf(abs_, sizeof abs_, "@bmc_uxdgram_test_%d", (int)getpid());
	unlink(path);
	struct sockaddr_un a, b;
	socklen_t al = mkaddr(&a, path), bl = mkaddr(&b, abs_);

	int s = socket(AF_UNIX, SOCK_DGRAM, 0);
	ck("socket(AF_UNIX, SOCK_DGRAM)", s >= 0);
	int ty = 0;
	socklen_t tl = sizeof ty;
	ck("SO_TYPE is SOCK_DGRAM", getsockopt(s, SOL_SOCKET, SO_TYPE, &ty, &tl) == 0 && ty == SOCK_DGRAM);
	int c = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	errno = 0;
	ck("send to a path that does not exist: ENOENT",
	   sendto(c, "x", 1, 0, (struct sockaddr *)&a, al) < 0 && errno == ENOENT);
	ck("bind a path", bind(s, (struct sockaddr *)&a, al) == 0);
	struct stat st;
	ck("...which creates its file", stat(path, &st) == 0);
	int s2 = socket(AF_UNIX, SOCK_DGRAM, 0);
	errno = 0;
	ck("a second bind of the path: EADDRINUSE", bind(s2, (struct sockaddr *)&a, al) < 0 && errno == EADDRINUSE);
	close(s2);

	ck("send \"one\"", sendto(c, "one", 3, 0, (struct sockaddr *)&a, al) == 3);
	ck("send \"two!\"", sendto(c, "two!", 4, 0, (struct sockaddr *)&a, al) == 4);
	char buf[256];
	struct sockaddr_un from;
	socklen_t fl = sizeof from;
	ssize_t r = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
	ck("one message per recv, boundaries kept: \"one\"", r == 3 && !memcmp(buf, "one", 3));
	ck("...from an unnamed AF_UNIX peer", fl == sizeof(sa_family_t) && from.sun_family == AF_UNIX);
	r = recv(s, buf, sizeof buf, 0);
	ck("then \"two!\"", r == 4 && !memcmp(buf, "two!", 4));

	char big[1000];
	memset(big, 'b', sizeof big);
	ck("send 1000 bytes", sendto(c, big, sizeof big, 0, (struct sockaddr *)&a, al) == 1000);
	ck("send \"after\"", sendto(c, "after", 5, 0, (struct sockaddr *)&a, al) == 5);
	r = recv(s, buf, 10, 0);
	ck("a 10-byte read of it: truncated to 10", r == 10 && buf[9] == 'b');
	r = recv(s, buf, sizeof buf, 0);
	ck("...and the rest dropped: the next read is \"after\"", r == 5 && !memcmp(buf, "after", 5));

	errno = 0;
	ck("empty, MSG_DONTWAIT: EAGAIN", recv(s, buf, sizeof buf, MSG_DONTWAIT) < 0 && errno == EAGAIN);
	struct timeval tv = {0, 150000};
	ck("SO_RCVTIMEO 150 ms", setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0);
	long long t0 = now_ms();
	errno = 0;
	r = recv(s, buf, sizeof buf, 0);
	long long dt = now_ms() - t0;
	ck("...an empty recv waits it out: EAGAIN", r < 0 && errno == EAGAIN);
	ck("...after about 150 ms", dt >= 120 && dt < 2000);

	struct pollfd p = {s, POLLIN, 0};
	ck("poll: not readable when empty", poll(&p, 1, 0) == 0);
	sendto(c, "p", 1, 0, (struct sockaddr *)&a, al);
	p.revents = 0;
	ck("poll: POLLIN with a message waiting", poll(&p, 1, 1000) == 1 && (p.revents & POLLIN));
	recv(s, buf, sizeof buf, 0);

	int ab = socket(AF_UNIX, SOCK_DGRAM, 0);
	ck("bind an abstract name", bind(ab, (struct sockaddr *)&b, bl) == 0);
	int cc = socket(AF_UNIX, SOCK_DGRAM, 0);
	ck("connect to it", connect(cc, (struct sockaddr *)&b, bl) == 0);
	ck("write() on the connected socket", write(cc, "abs", 3) == 3);
	r = read(ab, buf, sizeof buf);
	ck("read() gets it", r == 3 && !memcmp(buf, "abs", 3));
	errno = 0;
	ck("sendto with an address on a connected socket: EISCONN",
	   sendto(cc, "x", 1, 0, (struct sockaddr *)&a, al) < 0 && errno == EISCONN);

	pid_t k = fork();
	if (k == 0) {
		int x = socket(AF_UNIX, SOCK_DGRAM, 0);
		_exit(sendto(x, "child", 5, 0, (struct sockaddr *)&a, al) == 5 ? 0 : 1);
	}
	int stt = -1;
	waitpid(k, &stt, 0);
	r = recv(s, buf, sizeof buf, 0);
	ck("a forked child's datagram arrives", WIFEXITED(stt) && WEXITSTATUS(stt) == 0 && r == 5 &&
						    !memcmp(buf, "child", 5));

	close(s);
	errno = 0;
	ck("closed, the file left: ECONNREFUSED",
	   sendto(c, "x", 1, 0, (struct sockaddr *)&a, al) < 0 && errno == ECONNREFUSED);
	ck("unlink the socket file", unlink(path) == 0);
	close(ab);
	errno = 0;
	ck("abstract name gone with its socket: ECONNREFUSED",
	   sendto(c, "x", 1, 0, (struct sockaddr *)&b, bl) < 0 && errno == ECONNREFUSED);
	close(c);
	close(cc);
	printf(fails ? "%d FAILED\n" : "ALL TESTS PASSED\n", fails);
	return fails != 0;
}

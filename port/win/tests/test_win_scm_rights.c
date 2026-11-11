/* test_win_scm_rights.c -- the dial-helper shape (daemon/main.c): a forked
 * child connects, then hands the CONNECTED socket to its parent over a
 * socketpair with SCM_RIGHTS (plus a struct in the data), and the parent
 * talks to the far end on it. */
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/wait.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok  : " __VA_ARGS__); else { printf("FAIL: " __VA_ARGS__); fails++; } \
			   printf("\n"); } while (0)

typedef struct { int ok; char why[32]; } result;

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	/* the far end */
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t sl = sizeof sa;
	bind(ls, (struct sockaddr *)&sa, sizeof sa);
	getsockname(ls, (struct sockaddr *)&sa, &sl);
	listen(ls, 4);

	int sp[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0, "socketpair");
	pid_t p = fork();
	if (p == 0) {                         /* the dial helper */
		close(sp[0]);
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		result r = { 0, "" };
		if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0) {
			r.ok = 1;
			strcpy(r.why, "connected");
		}
		struct iovec iov = { &r, sizeof r };
		char cbuf[CMSG_SPACE(sizeof(int))];
		memset(cbuf, 0, sizeof cbuf);
		struct msghdr mh;
		memset(&mh, 0, sizeof mh);
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		mh.msg_control = cbuf;
		mh.msg_controllen = sizeof cbuf;
		struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type = SCM_RIGHTS;
		cm->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cm), &fd, sizeof fd);
		ssize_t s = sendmsg(sp[1], &mh, 0);
		struct pollfd hp = { sp[1], POLLIN, 0 };
		poll(&hp, 1, 5000);              /* until the parent has it */
		_exit(s == (ssize_t)sizeof r ? 0 : 3);
	}
	close(sp[1]);
	int far = accept(ls, NULL, NULL);
	result r;
	memset(&r, 0, sizeof r);
	struct iovec iov = { &r, sizeof r };
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct msghdr mh;
	memset(&mh, 0, sizeof mh);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof cbuf;
	ssize_t n = recvmsg(sp[0], &mh, 0);
	int got = -1;
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm))
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS)
			memcpy(&got, CMSG_DATA(cm), sizeof(int));
	CHECK(n == (ssize_t)sizeof r && r.ok, "the struct arrived (%zd bytes, ok=%d '%s')", n, r.ok, r.why);
	CHECK(got >= 0, "an fd arrived with it (%d)", got);
	write(sp[0], "x", 1);                /* the helper may go */
	if (got >= 0) {
		CHECK(write(got, "ping", 4) == 4, "the parent writes on the passed socket");
		char b[8] = { 0 };
		CHECK(read(far, b, 4) == 4 && !memcmp(b, "ping", 4), "the far end reads it ('%s')", b);
		CHECK(write(far, "pong", 4) == 4, "the far end answers");
		memset(b, 0, sizeof b);
		CHECK(read(got, b, 4) == 4 && !memcmp(b, "pong", 4), "the parent reads the answer ('%s')", b);
		struct sockaddr_in peer;
		socklen_t pl = sizeof peer;
		CHECK(getpeername(got, (struct sockaddr *)&peer, &pl) == 0 && peer.sin_port == sa.sin_port,
		      "getpeername on the passed socket names the far end");
		struct tcp_info ti;
		socklen_t tl = sizeof ti;
		CHECK(getsockopt(got, IPPROTO_TCP, TCP_INFO, &ti, &tl) == 0 && ti.tcpi_state == 1 &&
		      ti.tcpi_last_data_recv < 5000, "TCP_INFO: established, data heard %u ms ago", ti.tcpi_last_data_recv);
	}
	int st;
	waitpid(p, &st, 0);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the helper exited cleanly (0x%x)", st);
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", fails);
	return fails != 0;
}

/* test_win_tcpinfo.c -- TCP_INFO's tcpi_last_data_recv counts data that has
 * ARRIVED, read or not: a leg the peer just wrote to reports it as recent
 * before anyone reads it (the daemon's pass-silence judgement). */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static int fails;
static void ck(const char *l, int c) { printf("%s: %s\n", c ? "ok  " : "FAIL", l); fails += !c; }

static unsigned last_recv(int fd)
{
	struct tcp_info ti;
	socklen_t l = sizeof ti;
	memset(&ti, 0, sizeof ti);
	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &l) != 0)
		return ~0u;
	return ti.tcpi_last_data_recv;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int l = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind(l, (struct sockaddr *)&a, sizeof a);
	listen(l, 4);
	socklen_t al = sizeof a;
	getsockname(l, (struct sockaddr *)&a, &al);
	int c = socket(AF_INET, SOCK_STREAM, 0);
	connect(c, (struct sockaddr *)&a, sizeof a);
	int s = accept(l, NULL, NULL);
	usleep(800000);
	unsigned q = last_recv(c);
	printf("  quiet 0.8 s: last_data_recv %u ms\n", q);
	ck("a quiet leg reports its silence (>= 700 ms)", q != ~0u && q >= 700);
	write(s, "x", 1);
	usleep(20000);
	unsigned r = last_recv(c);
	printf("  20 ms after the peer wrote (unread): last_data_recv %u ms\n", r);
	ck("unread data that just arrived counts as recent (< 300 ms)", r < 300);
	char b;
	read(c, &b, 1);
	usleep(400000);
	r = last_recv(c);
	printf("  400 ms after the read: last_data_recv %u ms\n", r);
	ck("...and ages from there", r >= 350 && r < 2000);
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", fails);
	return fails != 0;
}

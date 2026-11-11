/* test_win_closeunread.c -- a server writes a reply and closes while the
 * client's bytes are still unread on its side (an HTTP server refusing a
 * request it never read). The client must still get the reply: Linux sends
 * it ahead of the reset its unread data causes. */
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

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
	write(c, "POST / HTTP/1.1\r\nX-Slow: aaaa", 29);
	usleep(100000);
	const char *e = "HTTP/1.1 503 Service Unavailable\r\n\r\nToo many";
	write(s, e, strlen(e));
	close(s);
	usleep(20000);
	ssize_t more = send(c, "b", 1, MSG_NOSIGNAL);   /* the client goes on sending (a dribbler) */
	usleep(100000);
	printf("  the client's later send: %zd\n", more);
	struct pollfd p = { c, POLLIN, 0 };
	int pr = poll(&p, 1, 2000);
	char buf[256];
	ssize_t k = recv(c, buf, sizeof buf - 1, MSG_DONTWAIT);
	buf[k > 0 ? k : 0] = 0;
	printf("poll %d revents 0x%x recv %zd: %s\n", pr, p.revents, k, buf);
	int ok = k > 0 && strstr(buf, "503");
	printf(ok ? "\nALL TESTS PASSED\n" : "\n1 FAILURE(S)\n");
	return !ok;
}

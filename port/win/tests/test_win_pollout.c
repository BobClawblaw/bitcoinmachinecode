/* test_win_pollout.c -- POLLOUT on a stream socket whose peer does not read:
 * once a non-blocking write says EAGAIN, poll must not report POLLOUT (a
 * service loop that writes only on POLLOUT would otherwise block in send),
 * and once the peer reads enough, POLLOUT comes back. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static int fails;
static void ck(const char *l, int c) { printf("%s: %s\n", c ? "ok  " : "FAIL", l); fails += !c; }

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL) | O_NONBLOCK);
	static char buf[200];
	long total = 0;
	int polls_ok_then_eagain = 0;
	for (int i = 0; i < 200000; i++) {
		struct pollfd p = { sv[1], POLLOUT, 0 };
		int pr = poll(&p, 1, 0);
		ssize_t w = write(sv[1], buf, sizeof buf);
		if (w < 0) {
			if (pr == 1 && (p.revents & POLLOUT))
				polls_ok_then_eagain++;
			if (polls_ok_then_eagain > 3)
				break;
			continue;
		}
		total += w;
	}
	printf("  wrote %ld bytes before the channel filled\n", total);
	struct pollfd p = { sv[1], POLLOUT, 0 };
	int pr = poll(&p, 1, 0);
	printf("  full: poll -> %d revents 0x%x; POLLOUT then EAGAIN %d time(s)\n", pr, p.revents, polls_ok_then_eagain);
	ck("a full channel does not report POLLOUT", pr == 0 || !(p.revents & POLLOUT));
	static char drain[1 << 20];
	long got = 0;
	fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
	for (ssize_t r; (r = read(sv[0], drain, sizeof drain)) > 0;)
		got += r;
	usleep(50000);
	pr = poll(&p, 1, 100);
	ck("after the peer drained it, POLLOUT is back", pr == 1 && (p.revents & POLLOUT));
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", fails);
	return fails != 0;
}

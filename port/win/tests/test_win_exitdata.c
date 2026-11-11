/* test_win_exitdata.c -- a forked child writes to a socketpair and exits at
 * once; the parent reads only afterwards. The bytes must still be there
 * (Linux keeps them; an abortive close at the child's exit would reset the
 * connection and discard them). Also with recvmsg + MSG_DONTWAIT, as the
 * daemon's dial helper result is read. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int fails = 0;
	for (int round = 0; round < 2; round++) {
		int sp[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
		pid_t p = fork();
		if (p == 0) {
			close(sp[0]);
			char msg[300];
			memset(msg, 'a' + round, sizeof msg);
			write(sp[1], msg, sizeof msg);
			_exit(0);
		}
		close(sp[1]);
		int st;
		waitpid(p, &st, 0);
		usleep(200000);
		char b[400];
		ssize_t n;
		if (round == 0) {
			n = read(sp[0], b, sizeof b);
		} else {
			struct iovec iov = { b, 300 };
			struct msghdr mh;
			memset(&mh, 0, sizeof mh);
			mh.msg_iov = &iov;
			mh.msg_iovlen = 1;
			n = recvmsg(sp[0], &mh, MSG_DONTWAIT);
		}
		int ok = n == 300 && b[0] == 'a' + round && b[299] == 'a' + round;
		printf("%s: round %d (%s) got %zd errno %d\n", ok ? "ok  " : "FAIL", round,
		       round ? "recvmsg DONTWAIT" : "read", n, n < 0 ? errno : 0);
		fails += !ok;
		close(sp[0]);
	}
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", fails);
	return fails != 0;
}

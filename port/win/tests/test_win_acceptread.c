/* test_win_acceptread.c -- a forked child accepts (through the root's
 * broker) and READS what the parent sent before and after the accept. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in aa;
	memset(&aa, 0, sizeof aa);
	aa.sin_family = AF_INET;
	aa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind(ls, (struct sockaddr *)&aa, sizeof aa);
	socklen_t al = sizeof aa;
	getsockname(ls, (struct sockaddr *)&aa, &al);
	listen(ls, 2);
	pid_t pid = fork();
	if (pid == 0) {
		int c = accept(ls, 0, 0);
		char b[16] = { 0 };
		ssize_t n = read(c, b, 5);
		printf("child: accept %d, read %zd '%s' errno %d\n", c, n, n > 0 ? b : "", n < 0 ? errno : 0);
		if (n == 5)
			write(c, "ok", 2);
		close(c);
		_exit(n == 5 ? 0 : 1);
	}
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(fd, (struct sockaddr *)&aa, sizeof aa))
		printf("connect failed %d\n", errno);
	write(fd, "hello", 5);
	char r[4] = { 0 };
	ssize_t n = read(fd, r, 2);
	printf("parent: reply %zd '%s'\n", n, n > 0 ? r : "");
	int st;
	waitpid(pid, &st, 0);
	printf("child status 0x%x\n", st);
	return !(n == 2 && st == 0);
}

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
static int try_connect(struct sockaddr_in *sa, int timeo)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (timeo) {
		struct timeval tv = { 10, 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	}
	int r = connect(fd, (struct sockaddr *)sa, sizeof *sa);
	printf("  connect(timeo=%d) -> %d errno %d (%s)\n", timeo, r, r ? errno : 0, r ? strerror(errno) : "");
	close(fd);
	return r;
}
int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t sl = sizeof sa;
	bind(ls, (struct sockaddr *)&sa, sizeof sa);
	getsockname(ls, (struct sockaddr *)&sa, &sl);
	listen(ls, 8);
	printf("before fork:\n");
	try_connect(&sa, 0);
	try_connect(&sa, 1);
	pid_t p = fork();
	if (p == 0) {
		for (int i = 0; i < 4; i++) {
			int c = accept(ls, 0, 0);
			close(c);
		}
		_exit(0);
	}
	try_connect(&sa, 1);              /* at once: the child is already in accept */
	printf("after fork:\n");
	try_connect(&sa, 0);
	try_connect(&sa, 1);
	kill(p, 9);
	int st;
	waitpid(p, &st, 0);
	(void)argc;
	(void)argv;
	return 0;
}

/* test_win_asmconnect.c -- bitcoin_net.asm's tcp_connect_ip (SO_RCVTIMEO and
 * SO_SNDTIMEO set, connect through winsys) after a fork, then a read that
 * must WAIT for the peer's late reply rather than fail at once.
 * port-link: bitcoin_net.asm bitcoin_hash.asm sha256.asm */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
extern int tcp_connect_ip(unsigned ip, unsigned short port);
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
		sleep(1);
		write(c, "x", 1);
		sleep(1);
		close(c);
		_exit(0);
	}
	int fd = tcp_connect_ip(htonl(INADDR_LOOPBACK), aa.sin_port);
	printf("tcp_connect_ip -> %d\n", fd);
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	char b = 0;
	ssize_t n = read(fd, &b, 1);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
	printf("read -> %zd '%c' errno %d after %ld ms (want 1 'x' after ~1000)\n", n, n > 0 ? b : '-', n < 0 ? errno : 0, ms);
	int st;
	waitpid(pid, &st, 0);
	return !(n == 1 && b == 'x');
}

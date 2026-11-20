#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t sl = sizeof sa;
	bind(ls, (struct sockaddr *)&sa, sizeof sa);
	listen(ls, 4);
	getsockname(ls, (struct sockaddr *)&sa, &sl);
	printf("listening on port %d\n", ntohs(sa.sin_port));
	pid_t p = fork();
	if (p == 0) {
		int c = socket(AF_INET, SOCK_STREAM, 0);
		printf("child: socket -> %d (errno %d)\n", c, errno);
		int r = connect(c, (struct sockaddr *)&sa, sizeof sa);
		printf("child: connect -> %d (errno %d)\n", r, errno);
		struct sockaddr_in peer = { 0 }, me = { 0 };
		socklen_t pl = sizeof peer, ml = sizeof me;
		r = getpeername(c, (struct sockaddr *)&peer, &pl);
		printf("child: getpeername -> %d (errno %d) fam %d port %d len %d\n", r, errno, peer.sin_family, ntohs(peer.sin_port), (int)pl);
		r = getsockname(c, (struct sockaddr *)&me, &ml);
		printf("child: getsockname -> %d (errno %d) fam %d port %d\n", r, errno, me.sin_family, ntohs(me.sin_port));
		int one = 1;
		r = setsockopt(c, IPPROTO_TCP, 1, &one, sizeof one);
		printf("child: setsockopt TCP_NODELAY -> %d (errno %d)\n", r, errno);
		close(c);
		_exit(0);
	}
	int as = accept(ls, NULL, NULL);
	int st;
	waitpid(p, &st, 0);
	close(as);
	return 0;
}

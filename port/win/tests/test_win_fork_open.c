#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char cwd[512];
	getcwd(cwd, sizeof cwd);
	printf("parent cwd %s\n", cwd);
	pid_t p = fork();
	if (p == 0) {
		char c2[512] = "";
		getcwd(c2, sizeof c2);
		int fd = open("fork_open_rel.tmp", O_WRONLY | O_CREAT | O_TRUNC, 0644);
		printf("child: cwd %s rel open -> %d errno %d (%s)\n", c2, fd, fd < 0 ? errno : 0, fd < 0 ? strerror(errno) : "");
		char abs[600];
		snprintf(abs, sizeof abs, "%s/fork_open_abs.tmp", cwd);
		fd = open(abs, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		printf("child: abs open %s -> %d errno %d\n", abs, fd, fd < 0 ? errno : 0);
		_exit(0);
	}
	int st;
	waitpid(p, &st, 0);
	unlink("fork_open_rel.tmp");
	unlink("fork_open_abs.tmp");
	return 0;
}

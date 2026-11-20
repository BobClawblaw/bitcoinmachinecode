/* test_win_logpump.c -- node_config.c's log_sink_open(printtoconsole=1) shape
 * run in a forked child whose fd 2 is a pipe: open, pipe, dup(2), a NESTED
 * fork (the pump), dup2 onto 2. The exit code names the step that failed. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static int sink(const char *path)
{
	int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
	if (fd < 0)
		return 10;
	int pfd[2];
	if (pipe(pfd) != 0)
		return 11;
	int console = dup(2);
	if (console < 0)
		return 12;
	pid_t p = fork();
	if (p < 0)
		return 13;
	if (p == 0) {
		close(pfd[1]);
		close(2);
		for (int k = 3; k < 256; k++)
			if (k != pfd[0] && k != fd && k != console)
				close(k);
		char buf[512];
		ssize_t n;
		while ((n = read(pfd[0], buf, sizeof buf)) > 0) {
			write(fd, buf, (size_t)n);
			write(console, buf, (size_t)n);
		}
		_exit(0);
	}
	close(pfd[0]);
	close(console);
	close(fd);
	if (dup2(pfd[1], 2) < 0)
		return 14;
	close(pfd[1]);
	return 0;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	unlink("logpump.log");
	int pp[2];
	pipe(pp);
	pid_t c = fork();
	if (c == 0) {
		close(pp[0]);
		dup2(pp[1], 2);
		close(pp[1]);
		int r = sink("logpump.log");
		if (r)
			_exit(r);
		fprintf(stderr, "to-both\n");
		fflush(stderr);
		_exit(0);
	}
	close(pp[1]);
	char cons[64] = "";
	ssize_t n, t = 0;
	while (t < 63 && (n = read(pp[0], cons + t, (size_t)(63 - t))) > 0)
		t += n;
	int st = 0;
	waitpid(c, &st, 0);
	FILE *f = fopen("logpump.log", "r");
	char line[64] = "";
	if (f) {
		if (!fgets(line, sizeof line, f))
			line[0] = 0;
		fclose(f);
	}
	printf("child exit %d, file '%.20s', console '%.20s'\n", WEXITSTATUS(st), line, cons);
	int ok = WEXITSTATUS(st) == 0 && !strncmp(line, "to-both", 7) && !strncmp(cons, "to-both", 7);
	printf(ok ? "ALL TESTS PASSED\n" : "FAILED\n");
	return !ok;
}

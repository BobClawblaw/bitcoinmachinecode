#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
static char proc_state(int pid)
{
	char p[64];
	snprintf(p, sizeof p, "/proc/%d/stat", pid);
	FILE *f = fopen(p, "r");
	if (!f)
		return '0';
	char buf[512];
	size_t n = fread(buf, 1, sizeof buf - 1, f);
	fclose(f);
	buf[n] = 0;
	char *rp = strrchr(buf, ')');
	return (rp && rp[1] == ' ') ? rp[2] : '?';
}
int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	for (int round = 0; round < 3; round++) {
		pid_t p = fork();
		if (p == 0)
			_exit(0);
		struct timespec ts = { 0, 50 * 1000 * 1000 };
		nanosleep(&ts, 0);
		printf("round %d: before reap %c", round, proc_state(p));
		int st;
		waitpid(p, &st, WNOHANG);
		printf(", after reap %c\n", proc_state(p));
	}
	return 0;
}

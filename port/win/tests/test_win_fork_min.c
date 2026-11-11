#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("before fork\n");
	pid_t p = fork();
	if (p == 0) {
		write(1, "child\n", 6);
		_exit(42);
	}
	printf("parent: fork -> %d\n", p);
	int st = 0;
	pid_t w = waitpid(p, &st, 0);
	printf("waitpid -> %d st=0x%x\n", w, st);
	return 0;
}

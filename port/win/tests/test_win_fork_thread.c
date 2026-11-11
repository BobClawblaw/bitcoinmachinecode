#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
static void *worker(void *arg)
{
	write(*(int *)arg, "L", 1);
	return (void *)7;
}
int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int pp[2];
	pipe(pp);
	pid_t p = fork();
	if (p == 0) {
		pthread_t th;
		int r = pthread_create(&th, NULL, worker, &pp[1]);
		if (r)
			_exit(8);
		char c = 0;
		if (read(pp[0], &c, 1) != 1 || c != 'L')
			_exit(7);
		void *res = 0;
		pthread_join(th, &res);
		_exit(res == (void *)7 ? 0 : 6);
	}
	int st = 0;
	waitpid(p, &st, 0);
	printf("child exit 0x%x (want 0)\n", st);
	return st != 0;
}

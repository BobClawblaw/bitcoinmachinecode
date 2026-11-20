/* test_win_procpid.c -- /proc of other processes, as the daemon's datadir
 * lock scan reads it: /proc lists a forked child's pid; /proc/<child>/fd
 * lists the fd whose open file description it shares with us; readlink and
 * stat through it name our file; kcmp(KCMP_FILE) says same description; a
 * separately opened description of the same file is not listed. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static int fails;
static void ck(const char *l, int c) { printf("%s: %s\n", c ? "ok  " : "FAIL", l); fails += !c; }

static int dir_has(const char *dir, const char *name)
{
	DIR *d = opendir(dir);
	if (!d)
		return -1;
	struct dirent *e;
	int hit = 0;
	while ((e = readdir(d)))
		if (!strcmp(e->d_name, name))
			hit = 1;
	closedir(d);
	return hit;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int lk = open("procpid.lock", O_RDWR | O_CREAT, 0644);
	int other = open("procpid.other", O_RDWR | O_CREAT, 0644);
	int sync[2];
	pipe(sync);
	pid_t c = fork();
	if (c == 0) {
		close(other);
		int sep = open("procpid.other", O_RDONLY);   /* its own description */
		(void)sep;
		char x;
		read(sync[0], &x, 1);
		_exit(0);
	}
	usleep(200000);
	char cs[16], fds[16], p[64], want[512], got[512];
	snprintf(cs, sizeof cs, "%d", (int)c);
	snprintf(fds, sizeof fds, "%d", lk);
	ck("/proc lists the child's pid", dir_has("/proc", cs) == 1);
	snprintf(p, sizeof p, "/proc/%d/fd", (int)c);
	ck("/proc/<child>/fd lists the shared lock fd", dir_has(p, fds) == 1);
	snprintf(fds, sizeof fds, "%d", other);
	ck("...but not a file the child opened on its own", dir_has(p, fds) == 0);
	snprintf(p, sizeof p, "/proc/self/fd/%d", lk);
	ssize_t wl = readlink(p, want, sizeof want - 1);
	snprintf(p, sizeof p, "/proc/%d/fd/%d", (int)c, lk);
	ssize_t gl = readlink(p, got, sizeof got - 1);
	ck("readlink through the child names the same file", wl > 0 && wl == gl && !memcmp(want, got, (size_t)wl));
	struct stat a, b;
	ck("stat through the child is the same inode", fstat(lk, &a) == 0 && stat(p, &b) == 0 && a.st_ino == b.st_ino);
	ck("kcmp(KCMP_FILE): the same description", syscall(SYS_kcmp, getpid(), c, 0, lk, lk) == 0);
	ck("kcmp(KCMP_FILE): different files differ", syscall(SYS_kcmp, getpid(), c, 0, lk, other) > 0);
	write(sync[1], "x", 1);
	waitpid(c, NULL, 0);
	close(lk);
	close(other);
	unlink("procpid.lock");
	unlink("procpid.other");
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", fails);
	return fails != 0;
}

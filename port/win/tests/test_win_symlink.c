/* test_win_symlink.c -- symlinks (WSL-style reparse points, no privilege
 * needed) and hard links: symlink/readlink, lstat sees the link and stat
 * its target, open follows a link at the last component, O_NOFOLLOW gives
 * ELOOP, O_CREAT|O_EXCL refuses a link (even a dangling one), a self-loop
 * gives ELOOP, unlink and rename act on the link, realpath resolves it,
 * readdir reports DT_LNK, and link() makes a second name for a file. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int fails;
static void ck(const char *l, int c) { printf("%s: %s\n", c ? "ok  " : "FAIL", l); fails += !c; }

static int dtype_of(const char *dir, const char *name)
{
	DIR *d = opendir(dir);
	if (!d)
		return -1;
	struct dirent *e;
	int t = -2;
	while ((e = readdir(d)))
		if (!strcmp(e->d_name, name))
			t = e->d_type;
	closedir(d);
	return t;
}

static int slurp(const char *p, char *buf, size_t cap)
{
	int fd = open(p, O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	return (int)n;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char cwd[PATH_MAX];
	if (!getcwd(cwd, sizeof cwd))
		return 2;
	const char *D = "symlink.d";
	unlink("symlink.d/sub/rel"); unlink("symlink.d/abs"); unlink("symlink.d/lnk"); unlink("symlink.d/lnk2");
	unlink("symlink.d/dang"); unlink("symlink.d/loop"); unlink("symlink.d/hard"); unlink("symlink.d/t.txt");
	rmdir("symlink.d/sub"); rmdir(D);
	ck("mkdir", mkdir(D, 0755) == 0 && mkdir("symlink.d/sub", 0755) == 0);
	int fd = open("symlink.d/t.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ck("target written", fd >= 0 && write(fd, "hello", 5) == 5 && close(fd) == 0);

	ck("symlink", symlink("t.txt", "symlink.d/lnk") == 0);
	ck("symlink over an existing name: EEXIST", symlink("t.txt", "symlink.d/lnk") == -1 && errno == EEXIST);
	char buf[256];
	ssize_t n = readlink("symlink.d/lnk", buf, sizeof buf);
	ck("readlink gives the target verbatim", n == 5 && !memcmp(buf, "t.txt", 5));
	ck("readlink truncates to the buffer", readlink("symlink.d/lnk", buf, 3) == 3 && !memcmp(buf, "t.t", 3));
	ck("readlink of a regular file: EINVAL", readlink("symlink.d/t.txt", buf, sizeof buf) == -1 && errno == EINVAL);
	ck("readlink of nothing: ENOENT", readlink("symlink.d/none", buf, sizeof buf) == -1 && errno == ENOENT);

	struct stat ls, ss, ts;
	ck("lstat sees a link", lstat("symlink.d/lnk", &ls) == 0 && S_ISLNK(ls.st_mode) && ls.st_size == 5);
	ck("stat sees the target", stat("symlink.d/lnk", &ss) == 0 && S_ISREG(ss.st_mode) && ss.st_size == 5 &&
	   stat("symlink.d/t.txt", &ts) == 0 && ss.st_ino == ts.st_ino);
	ck("open follows it", slurp("symlink.d/lnk", buf, sizeof buf) == 5 && !strcmp(buf, "hello"));
	ck("access follows it", access("symlink.d/lnk", R_OK) == 0);
	errno = 0;
	ck("O_NOFOLLOW: ELOOP", open("symlink.d/lnk", O_RDONLY | O_NOFOLLOW) == -1 && errno == ELOOP);
	errno = 0;
	ck("O_CREAT|O_EXCL on a link: EEXIST",
	   open("symlink.d/lnk", O_WRONLY | O_CREAT | O_EXCL, 0644) == -1 && errno == EEXIST);
	ck("readdir: DT_LNK", dtype_of(D, "lnk") == DT_LNK && dtype_of(D, "t.txt") == DT_REG);

	ck("a dangling link", symlink("no-such-dir/x", "symlink.d/dang") == 0);
	errno = 0;
	ck("stat through it: ENOENT", stat("symlink.d/dang", &ss) == -1 && errno == ENOENT);
	errno = 0;
	ck("access through it: ENOENT", access("symlink.d/dang", F_OK) == -1 && errno == ENOENT);
	ck("lstat still sees it", lstat("symlink.d/dang", &ls) == 0 && S_ISLNK(ls.st_mode));
	errno = 0;
	ck("O_CREAT|O_EXCL on a dangling link: EEXIST",
	   open("symlink.d/dang", O_WRONLY | O_CREAT | O_EXCL, 0644) == -1 && errno == EEXIST);

	ck("a link to itself", symlink("loop", "symlink.d/loop") == 0);
	errno = 0;
	ck("open of it: ELOOP", open("symlink.d/loop", O_RDONLY) == -1 && errno == ELOOP);

	ck("a relative target in another dir", symlink("../t.txt", "symlink.d/sub/rel") == 0 &&
	   slurp("symlink.d/sub/rel", buf, sizeof buf) == 5);
	char abs[PATH_MAX + 32];
	snprintf(abs, sizeof abs, "%s/symlink.d/t.txt", cwd);
	ck("an absolute target", symlink(abs, "symlink.d/abs") == 0 && slurp("symlink.d/abs", buf, sizeof buf) == 5);
	char rp[PATH_MAX], rt[PATH_MAX];
	ck("realpath resolves through it", realpath("symlink.d/sub/rel", rp) && realpath("symlink.d/t.txt", rt) &&
	   !strcmp(rp, rt));

	ck("rename moves the link", rename("symlink.d/lnk", "symlink.d/lnk2") == 0 &&
	   lstat("symlink.d/lnk2", &ls) == 0 && S_ISLNK(ls.st_mode) && lstat("symlink.d/lnk", &ls) == -1);
	ck("unlink removes the link, not the target", unlink("symlink.d/lnk2") == 0 &&
	   lstat("symlink.d/lnk2", &ls) == -1 && stat("symlink.d/t.txt", &ts) == 0);

	ck("link makes a second name", link("symlink.d/t.txt", "symlink.d/hard") == 0 &&
	   stat("symlink.d/hard", &ss) == 0 && stat("symlink.d/t.txt", &ts) == 0 &&
	   ss.st_ino == ts.st_ino && ts.st_nlink == 2);
	errno = 0;
	ck("link over an existing name: EEXIST", link("symlink.d/t.txt", "symlink.d/hard") == -1 && errno == EEXIST);

	unlink("symlink.d/sub/rel"); unlink("symlink.d/abs"); unlink("symlink.d/dang"); unlink("symlink.d/loop");
	unlink("symlink.d/hard"); unlink("symlink.d/t.txt"); rmdir("symlink.d/sub");
	ck("cleanup", rmdir(D) == 0);
	printf(fails ? "%d FAILED\n" : "ALL TESTS PASSED\n", fails);
	return fails != 0;
}

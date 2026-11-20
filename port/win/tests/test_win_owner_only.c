/* test_win_owner_only.c -- mode bits that give group and other nothing make
 * the file owner-only on Windows too.
 *
 * Linux enforces mode bits; Windows enforces the DACL. A file created 0600
 * (the I2P key, the wallet's .pass file, the RPC cookie) kept its
 * directory's inherited DACL while stat() said 0600. Now such a file gets a
 * protected DACL (this user and SYSTEM, full access, nothing inherited).
 * The DACL is read back with icacls, run through the shell: "(I)" marks an
 * inherited ACE and "(F)" full access, in every display language.
 *
 * Checked: open(O_CREAT, 0600) creates it owner-only; 0644 keeps the
 * inherited DACL; chmod and fchmod to 0600 put the owner-only DACL on;
 * chmod back to 0644 restores inheritance; mkdir 0700 makes an owner-only
 * directory whose new files inherit only its ACEs; an O_TRUNC that has to
 * replace a mapped 0600 file keeps it 0600 and owner-only. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

static int fails;
static void ck(const char *l, int c) { printf("%s: %s\n", c ? "ok  " : "FAIL", l); fails += !c; }

typedef struct { int aces, inherited, full, ok; } acl_view;

/* icacls <path>: one ACE per line ("NAME:(flags)(rights)"); the last line is
 * the summary. Only the lines that name the path or follow it hold ACEs. */
static acl_view acl_of(const char *path)
{
	acl_view v = { 0, 0, 0, 0 };
	char cmd[PATH_MAX + 32];
	snprintf(cmd, sizeof cmd, "icacls '%s' 2>&1", path);
	FILE *p = popen(cmd, "r");
	if (!p)
		return v;
	char line[1024];
	while (fgets(line, sizeof line, p)) {
		if (!strstr(line, ":("))
			continue;                          /* the summary or a blank line */
		v.aces++;
		if (strstr(line, "(I)"))
			v.inherited++;
		if (strstr(line, "(F)"))
			v.full++;
	}
	v.ok = pclose(p) == 0 && v.aces > 0;
	return v;
}

static int owner_only(acl_view v) { return v.ok && v.inherited == 0 && v.full == v.aces; }

static unsigned mode_of(const char *p)
{
	struct stat st;
	return stat(p, &st) == 0 ? (unsigned)(st.st_mode & 07777) : 0xFFFFu;
}

static int mk(const char *p, unsigned mode)
{
	int fd = open(p, O_CREAT | O_EXCL | O_WRONLY, mode);
	if (fd < 0)
		return -1;
	int r = write(fd, "secret\n", 7) == 7 ? 0 : -1;
	close(fd);
	return r;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char dir[] = "/tmp/bmc_win_oo_XXXXXX";
	if (!mkdtemp(dir)) {
		printf("FAIL: mkdtemp: %s\n", strerror(errno));
		return 1;
	}
	if (chdir(dir) != 0) {
		printf("FAIL: chdir: %s\n", strerror(errno));
		return 1;
	}
	char base[PATH_MAX];
	if (!getcwd(base, sizeof base)) {
		printf("FAIL: getcwd\n");
		return 1;
	}
	umask(022);
	char p[PATH_MAX + 64];
#define AT(name) (snprintf(p, sizeof p, "%s/%s", base, name), p)

	/* the directory's own DACL is the inherited baseline */
	acl_view parent = acl_of(base);
	ck("icacls reads the test directory", parent.ok);

	ck("open(O_CREAT, 0600) succeeds", mk("key", 0600) == 0);
	ck("  stat says 0600", mode_of("key") == 0600);
	acl_view key = acl_of(AT("key"));
	printf("      key: %d ACE(s), %d inherited, %d full\n", key.aces, key.inherited, key.full);
	ck("  its DACL is owner-only: nothing inherited, every ACE full access", owner_only(key));
	ck("  at most two ACEs (this user and SYSTEM)", key.aces >= 1 && key.aces <= 2);

	ck("open(O_CREAT, 0644) succeeds", mk("plain", 0644) == 0);
	acl_view plain = acl_of(AT("plain"));
	ck("  its DACL is the inherited one", plain.ok && plain.inherited > 0);

	ck("chmod 0600 succeeds", chmod("plain", 0600) == 0);
	ck("  stat says 0600", mode_of("plain") == 0600);
	ck("  the DACL is now owner-only", owner_only(acl_of(AT("plain"))));
	ck("chmod 0644 succeeds", chmod("plain", 0644) == 0);
	acl_view back = acl_of(AT("plain"));
	ck("  inheritance is back", back.ok && back.inherited > 0);

	ck("open(O_CREAT, 0644) for fchmod", mk("viafd", 0644) == 0);
	int fd = open("viafd", O_RDWR);
	ck("fchmod 0600 succeeds", fd >= 0 && fchmod(fd, 0600) == 0);
	if (fd >= 0)
		close(fd);
	ck("  the DACL is now owner-only", owner_only(acl_of(AT("viafd"))));

	ck("mkdir 0700 succeeds", mkdir("private", 0700) == 0);
	acl_view pd = acl_of(AT("private"));
	ck("  the directory is owner-only", owner_only(pd));
	ck("a 0644 file inside it", mk("private/inner", 0644) == 0);
	acl_view in = acl_of(AT("private/inner"));
	ck("  holds only what it inherited from the directory",
	   in.ok && in.inherited == in.aces && in.aces == pd.aces && in.full == in.aces);

	/* O_TRUNC of a file a mapping still holds is done by replacing the file
	 * (ws_fd.c): the replacement must keep the bits and the DACL */
	ck("open(O_CREAT, 0600) for the mapped case", mk("mapped", 0600) == 0);
	int mf = open("mapped", O_RDONLY);
	void *view = mf >= 0 ? mmap(NULL, 7, PROT_READ, MAP_SHARED, mf, 0) : MAP_FAILED;
	ck("  mapped", view != MAP_FAILED);
	int tf = open("mapped", O_WRONLY | O_TRUNC);
	ck("  open(O_TRUNC) while mapped succeeds", tf >= 0);
	if (tf >= 0)
		close(tf);
	ck("  stat still says 0600", mode_of("mapped") == 0600);
	ck("  still owner-only", owner_only(acl_of(AT("mapped"))));
	if (view != MAP_FAILED)
		munmap(view, 7);
	if (mf >= 0)
		close(mf);

	unlink("key");
	unlink("plain");
	unlink("viafd");
	unlink("mapped");
	unlink("private/inner");
	rmdir("private");
	if (chdir("/tmp") == 0)
		rmdir(dir);
	printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
	return fails ? 1 : 0;
}

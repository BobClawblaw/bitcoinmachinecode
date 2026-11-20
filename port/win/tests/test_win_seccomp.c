/* test_win_seccomp.c -- seccomp filter mode: SECCOMP_RET_TRAP delivers
 * SIGSYS with the arguments in the ucontext and the handler's RAX as the
 * result; RET_ERRNO answers an errno; the filter and the handler carry over
 * fork (a MAP_SHARED counter sees the child's trapped calls). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static volatile int *shared;

static void on_sys(int sig, siginfo_t *si, void *ctx)
{
	(void)sig;
	ucontext_t *uc = ctx;
	if (si->si_syscall == SYS_fsync) {
		__atomic_add_fetch(shared, 1, __ATOMIC_SEQ_CST);
		uc->uc_mcontext.gregs[REG_RAX] = uc->uc_mcontext.gregs[REG_RDI] == 99 ? -EIO : 0;
	}
}

static int fails;
static void ck(const char *l, int c) { printf("%s: %s\n", c ? "ok  " : "FAIL", l); fails += !c; }

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	shared = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = on_sys;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSYS, &sa, 0);
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fsync, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_unlink, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog pr = { (unsigned short)(sizeof f / sizeof f[0]), f };
	ck("PR_SET_NO_NEW_PRIVS", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	ck("PR_SET_SECCOMP filter installs", prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &pr) == 0);
	int fd = open("seccomp.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
	{
		char lp[64], b[8] = { 0 };
		write(fd, "hello", 5);
		snprintf(lp, sizeof lp, "/proc/self/fd/%d", fd);
		int r = open(lp, O_RDONLY);
		ck("open(/proc/self/fd/N) reopens the file", r >= 0 && read(r, b, 5) == 5 && !memcmp(b, "hello", 5));
		close(r);
	}
	ck("a trapped fsync returns the handler's 0", fsync(fd) == 0 && *shared == 1);
	errno = 0;
	ck("the handler's -EIO is the call's error", syscall(SYS_fsync, 99) == -1 && errno == EIO);
	errno = 0;
	ck("RET_ERRNO: unlink answers EPERM", unlink("seccomp.tmp") == -1 && errno == EPERM);
	pid_t p = fork();
	if (p == 0)
		_exit(fsync(fd) == 0 && fsync(fd) == 0 ? 0 : 1);
	int st = 0;
	waitpid(p, &st, 0);
	ck("a forked child's fsyncs trap too (shared counter)", WIFEXITED(st) && WEXITSTATUS(st) == 0 && *shared == 4);
	close(fd);
	syscall(SYS_unlinkat, AT_FDCWD, "seccomp.tmp", 0) ;  /* still EPERM'd: unlinkat is allowed here */
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", fails);
	return fails != 0;
}

/* syscall_arch.h -- bmc_win override of musl's arch/x86_64/syscall_arch.h.
 * Windows has no Linux syscall instruction: every musl syscall goes to the
 * Win32 emulation in port/win/winsys (MS ABI, Linux x86_64 numbers, returns
 * -errno exactly like the kernel). */
#define __SYSCALL_LL_E(x) (x)
#define __SYSCALL_LL_O(x) (x)

__attribute__((ms_abi)) long __bmc_win_syscall(long n, long a1, long a2, long a3,
                                              long a4, long a5, long a6);

static __inline long __syscall0(long n)
{ return __bmc_win_syscall(n, 0, 0, 0, 0, 0, 0); }
static __inline long __syscall1(long n, long a1)
{ return __bmc_win_syscall(n, a1, 0, 0, 0, 0, 0); }
static __inline long __syscall2(long n, long a1, long a2)
{ return __bmc_win_syscall(n, a1, a2, 0, 0, 0, 0); }
static __inline long __syscall3(long n, long a1, long a2, long a3)
{ return __bmc_win_syscall(n, a1, a2, a3, 0, 0, 0); }
static __inline long __syscall4(long n, long a1, long a2, long a3, long a4)
{ return __bmc_win_syscall(n, a1, a2, a3, a4, 0, 0); }
static __inline long __syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{ return __bmc_win_syscall(n, a1, a2, a3, a4, a5, 0); }
static __inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{ return __bmc_win_syscall(n, a1, a2, a3, a4, a5, a6); }

/* no vDSO on Windows: clock_gettime goes through the emulation */
#define IPC_64 0

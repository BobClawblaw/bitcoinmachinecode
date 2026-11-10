/* pthread_arch.h -- bmc_win override of musl's arch/x86_64/pthread_arch.h.
 * Windows reserves %fs/%gs, so the thread pointer lives in a native
 * (gs-relative, PE TLS directory) thread-local set by port/win/rt. */
extern __thread uintptr_t __bmc_win_tp;
static inline uintptr_t __get_tp()
{
	return __bmc_win_tp;
}

#define MC_PC gregs[REG_RIP]

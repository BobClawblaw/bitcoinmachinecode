/* malloc.h -- musl's, plus glibc's mallinfo2 (bmc_win; rt/malloc.c). */
#include_next <malloc.h>
#ifndef BMC_WIN_MALLINFO2
#define BMC_WIN_MALLINFO2
#include <stddef.h>
struct mallinfo2 {
	size_t arena, ordblks, smblks, hblks, hblkhd, usmblks, fsmblks, uordblks, fordblks, keepcost;
};
struct mallinfo2 mallinfo2(void);
#endif

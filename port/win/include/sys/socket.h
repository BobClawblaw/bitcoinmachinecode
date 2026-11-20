/* sys/socket.h -- musl's, plus what glibc's brings in (bmc_win).
 * glibc's <sys/socket.h> includes <sys/types.h>, which (by default) defines
 * struct timeval and fd_set via <sys/select.h>; bmc code that includes only
 * <sys/socket.h> uses them. */
#include_next <sys/socket.h>
#include <sys/select.h>

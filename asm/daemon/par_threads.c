#include <unistd.h>
#include "par_threads.h"
static int g_par = 0;
void par_set(int par){ g_par = par; }
int  par_get(void){ return g_par; }
int  par_script_threads(void){
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN); if (ncpu < 1) ncpu = 1;
    long t = g_par;
    if (t <= 0) t += ncpu;      /* 0 -> every core, -n -> leave n cores free */
    if (t < 1) t = 1;           /* a node always has one script-checking thread */
    return (int)t;
}

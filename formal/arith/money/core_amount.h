/* Bitcoin Core v31.1 money rules, transcribed for the harnesses. Each line
 * cites the Core source it comes from (src/ relative). Types are Core's:
 * CAmount is int64_t, nHeight is int. */
#ifndef CORE_AMOUNT_H
#define CORE_AMOUNT_H
#include <stdint.h>
typedef int64_t CAmount;                                   /* consensus/amount.h */
#define CORE_COIN      ((CAmount)100000000)                /* consensus/amount.h COIN */
#define CORE_MAX_MONEY ((CAmount)21000000 * CORE_COIN)     /* consensus/amount.h MAX_MONEY */
static inline int core_MoneyRange(CAmount v){              /* consensus/amount.h MoneyRange */
    return v >= 0 && v <= CORE_MAX_MONEY;
}
/* validation.cpp GetBlockSubsidy */
static inline CAmount core_GetBlockSubsidy(int nHeight, int nSubsidyHalvingInterval){
    int halvings = nHeight / nSubsidyHalvingInterval;
    if (halvings >= 64)
        return 0;
    CAmount nSubsidy = 50 * CORE_COIN;
    nSubsidy >>= halvings;
    return nSubsidy;
}
#endif

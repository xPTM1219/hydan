/*
 * $Id$
 * Created: 05/20/2004
 *
 * xvr (c) 2004
 * xvr@xvr.net
 */

#include "hdn_math.h"

/*
 * return n!
 */
uint64_t hdn_math_factorial (uint32_t n)
{
    /*
     * return value is only accurate if n <= 22.
     * on 32 bits, n <= 13
     */
    assert (n <= 22);

    if (n == 0) return 1;

    return n * hdn_math_factorial (n-1);
}

/*
 * xor two streams of size n together
 */
void hdn_math_xor (void *dest, void *src, int n)
{
    int i;

    for (i = 0; i < n; i++)
        *((uint8_t *)dest + i) ^= *((uint8_t *)src + i);
}

/*
 * calculates how many bits we can get out of n reorderable items
 */
uint32_t hdn_math_numbits_if_reordered (uint32_t n)
{
    uint32_t l = 0;

    if (!n)
        return 0;

    /*
     * calculate log(n!) iteratively, since n! can be a prohibitively
     * large number and i don't want to use bignum...
     * Reminder for the high-school challenged:
     *    log (a * b) == log (a) + log (b)
     * For an approximate solution, there is also:
     *    n! =~ sqrt (2*Pi*n) * (n/e)^n
     */
    do {
        l += hdn_math_log2 (n);
    } while (--n);

    return l;
}

uint32_t hdn_math_log2 (uint64_t n)
{
    uint32_t i = sizeof (n) * 8;

    while (--i)
    {
        if ((n >> i) & 1)
            return i;
    }

    return 0;
}


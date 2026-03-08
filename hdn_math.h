/*
 * $Id$
 * Created: 05/20/2004
 *
 * xvr (c) 2004
 * xvr@xvr.net
 */

#ifndef _HDN_MATH_H_
#define _HDN_MATH_H_

#include "hydan.h"

/*
 * y'all know what ! does ..
 */
uint64_t hdn_math_factorial (uint32_t n);

/*
 * xors b onto a
 */
void hdn_math_xor (void *a, void *b, int len);

/*
 * returns the number of bits we can obtain if we reordered 'n' items.
 * it is preferrable to use this function as opposed to log2(fact(n))
 * because fact(n) can be a huuge number, and i don't want to use
 * bignum.  this function calculates this value iteratively.
 */
uint32_t hdn_math_numbits_if_reordered (uint32_t n);

/*
 * log 2..
 */
uint32_t hdn_math_log2 (uint64_t n);

#endif

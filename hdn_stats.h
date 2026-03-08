/*
 * $Id: hdn_stats.h,v 1.4 2003/01/19 02:02:21 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#ifndef _HDN_STATS_H_
#define _HDN_STATS_H_

#include "hydan.h"

/*
 * count the number of embeddable bits in data and store it in num.
 */
void hdn_stats_embeddable_bits (hdn_data_t *data, uint32_t *num);


/*
 * use to print out detailed stats to stdout
 */
int hdn_stats_main (int argc, char **argv);

#endif

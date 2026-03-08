/*
 * $Id: hdn_common.h,v 1.8 2004/04/29 21:12:56 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#ifndef _HDN_COMMON_H_
#define _HDN_COMMON_H_

#include "hydan.h"

/*
 * returns the next address to embed/decode from in the code sections.
 * NULL if none left.
 */
hdn_disassembly_data_t *hdn_disassemble_all (hdn_sections_t *s,
                                             uint32_t *max_insns);

#endif

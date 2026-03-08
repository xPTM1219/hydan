/*
 * $Id: hdn_insns_reord.h,v 1.1 2004/04/30 05:27:15 xvr Exp $
 * Created: 04/29/2004
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#ifndef _HDN_INSNS_REORD_H_
#define _HDN_INSNS_REORD_H_

#include "hydan.h"

/*
 * looks at all the instructions and tags the ones that can be
 * reordered.
 */
void hdn_reord_insns_tag_valid (hdn_disassembly_data_t *dis,
                                uint32_t num_insns);

/*
 * looks for all the instructions that have been jumped to.  these
 * cannot be reordered [well, they can be, but then i have to fix the
 * respective address -- fix this later XXX]
 */
void hdn_reord_insns_mark_jumped_to (hdn_sections_header_t *sh,
                                     hdn_disassembly_data_t *dis,
                                     uint32_t max_insn);
/*
 * takes care of embedding as many bits of data from source [starting
 * from bit position], into adjacent + consecutive instructions
 * starting at dis[curr_elt].  Returns the number of functions that
 * were embedded into.
 */
uint32_t hdn_reord_insns (hdn_disassembly_data_t *dis,
                          uint32_t curr_elt,
                          uint32_t num_elts,
                          uint8_t *source,
                          uint32_t bit);

/*
 * Pass in an array of all the instructions, returns the number of
 * bits that can be reordered using the block at curr_insn.
 */
uint32_t hdn_reord_insns_is_possible (hdn_disassembly_data_t *dis,
                                      uint32_t curr_insn,
                                      uint32_t max_insn);

#endif

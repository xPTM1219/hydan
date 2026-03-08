/*
 * $Id: hdn_insns.h,v 1.9 2003/12/09 18:23:36 xvr Exp $
 * Created: 08/23/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */


#ifndef _HDN_INSNS_H_
#define _HSN_INSNS_H_

#include "hydan.h"

/*
 * looks at all the instructions and tags the ones that can be
 * substituted.
 */
void hdn_subst_insns_tag_valid (hdn_disassembly_data_t *dis,
                                uint32_t num_insns);

/*
 * tells us if the current instruction is valid for use in our stego
 * or not.  Returns the number of bits that can be encoded into that
 * particular instruction.
 */
uint32_t hdn_subst_insns_is_possible (hdn_disassembly_data_t *data,
                                      uint32_t num_elts, uint32_t elt);

/*
 * returns the value encoded in the current instruction, and stores
 * its number of bits into numbits (numbits can be null if that info
 * is not needed)
 */
uint32_t hdn_subst_insns_val (x86_insn_t *insn, uint8_t *host, int *numbits);

/*
 * same as above, except it returns the description of the instruction
 * set, NULL if not found.
 */
char *hdn_subst_insns_desc (x86_insn_t *insn, uint8_t *host, char **insn_dsc);


/*
 * encodes the instruction
 * returns the number of bits encoded
 */
uint32_t hdn_subst_insns (x86_insn_t *insn, uint8_t *host_loc,
                          uint8_t *source_loc, int bit_offset);

/*
 * returns 1 if the instruction flips imm to its negative value (like
 * add/sub) and the imm is negative.
 * XXX only used for stats.. kinda gross to export this functions.
 */
uint32_t hdn_subst_insns_is_neg (x86_insn_t *insn, uint8_t *host);

#endif

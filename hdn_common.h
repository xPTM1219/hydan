/*
 * $Id: hdn_common.h,v 1.8 2004/04/29 21:12:56 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 *
 * Shared disassembly helpers: linear-sweep decoding of code sections
 * via Zydis, and translation of Zydis output into our legacy
 * x86_insn_t view (see hydan.h).
 */

#ifndef _HDN_COMMON_H_
#define _HDN_COMMON_H_

#include "hydan.h"

/*
 * disassembles every code section in the list (32-bit compat mode)
 * with a linear sweep.  Returns a malloc'd array of
 * hdn_disassembly_data_t (*num_insns entries, possibly including
 * insn_status_bad bytes for undecodable positions); NULL when no code.
 */
hdn_disassembly_data_t *hdn_disassemble_all (hdn_sections_t *s,
                                              uint32_t *max_insns);

/*
 * fills `out` from a successful Zydis decode: size/mnemonic, raw copy
 * is the caller's job; here we map operand types/sizes/values and CPU
 * flag access (tested/modified) onto the old libdisasm-style fields.
 * Only the first min(3, visible) operands are mapped -- enough for the
 * substitution classes -- and non-immediate operands carry no value.
 */
void hdn_populate_insn_from_zydis (x86_insn_t *out,
                                    const ZydisDecodedInstruction *z,
                                    const ZydisDecodedOperand *ops);

#endif

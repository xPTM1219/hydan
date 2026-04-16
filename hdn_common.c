/*
 * $Id: hdn_common.c,v 1.16 2004/04/29 21:12:56 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#include "hdn_common.h"
#include <Zydis/Zydis.h>

/*
 * disassemble every section
 */
hdn_disassembly_data_t *hdn_disassemble_all (hdn_sections_t *hs,
                                              uint32_t *num_insns)
{
    hdn_disassembly_data_t *dis = NULL;
    hdn_disassembly_data_t d;
    uint32_t host_curr_pos = 0;
    ZydisDecoder decoder;

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    (*num_insns) = 0;

    /*
     * only disassemble the code sections
     */
    while (hs)
    {
        if (!hdn_exe_section_is_code (hs))
            goto next_section;

        bzero (&d, sizeof d);
        d.memaddr = (uint8_t*) hs->data.content + host_curr_pos;
        d.effaddr = hs->address + host_curr_pos;
        d.status  = insn_status_none;

        ZydisDecoderContext context;
        ZyanStatus status = ZydisDecoderDecodeInstruction(&decoder, &context, d.memaddr, (ZyanUSize)(hs->data.sz - host_curr_pos), &d.insn.zydis);
        if (ZYAN_SUCCESS(status)) {
            d.insn.size = d.insn.zydis.length;
            memcpy(d.insn.raw, d.memaddr, d.insn.size);
            d.insn.type = (enum x86_insn_type) d.insn.zydis.mnemonic;
            // populate operands - simplified
            d.insn.operands[0].type = op_register; // dummy
            d.insn.operands[1].type = op_immediate; // dummy
            d.insn.operands[2].type = op_register; // dummy
            d.insn.operands[0].datatype = op_dword;
            d.insn.operands[1].datatype = op_dword;
            d.insn.operands[2].datatype = op_dword;
            // populate flags - dummy
            d.insn.flags_set = 0;
            d.insn.flags_tested = 0;
        } else {
            d.status = insn_status_bad;
            d.insn.size = 1;
            d.insn.raw[0] = d.memaddr[0];
        }

        /*
         * unknown insn, tag it as such, and move on.
         */
        if (!d.insn.size)
        {
            d.status    = insn_status_bad;
            d.insn.size = 1;
        }

        /*
         * if disas is unbounded, goto next section.
         */
        if ((host_curr_pos + d.insn.size) > hs->data.sz)
            goto next_section;

        //XXX is it ok to have the insn in there, even tho it's invalid?

        /*
         * allocate mem when necessary
         */
        if (!((*num_insns) % 1000))
        {
            dis = realloc (dis, sizeof (hdn_disassembly_data_t) *
                            ((*num_insns) + 1000));
        }

        /*
         * we have disassembled another insn
         */
        bcopy (&d, &dis[(*num_insns)], sizeof d);
        (*num_insns)++;

        /*
         * move to the next instruction
         */
        host_curr_pos += d.insn.size;
        //XXX -- add some clause not to embed if we fall on an unknown insn?
        continue;

    next_section:
        hs            = hs->next;
        host_curr_pos = 0;
    }

    return dis;
}


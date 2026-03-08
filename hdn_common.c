/*
 * $Id: hdn_common.c,v 1.16 2004/04/29 21:12:56 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#include "hdn_common.h"

/*
 * disassemble every section
 */
hdn_disassembly_data_t *hdn_disassemble_all (hdn_sections_t *hs,
                                             uint32_t *num_insns)
{
    hdn_disassembly_data_t *dis = NULL;
    hdn_disassembly_data_t d;
    uint32_t host_curr_pos = 0;

    (*num_insns) = 0;

    /*
     * only disassemble the code sections
     */
    while (hs)
    {
        if (!hdn_exe_section_is_code (hs))
            goto next_section;

        bzero (&d, sizeof d);
        d.memaddr = hs->data.content + host_curr_pos;
        d.effaddr = hs->address + host_curr_pos;
        d.status  = insn_status_none;

        x86_disasm (hs->data.content,
                    hs->data.sz, 0, host_curr_pos, &d.insn);

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


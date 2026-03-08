/*
 * $Id: hdn_insns_reord.c,v 1.1 2004/04/30 05:27:15 xvr Exp $
 * Created: 04/29/2004
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#include "hdn_reord_insns.h"

void hdn_reord_insns_tag_valid (hdn_disassembly_data_t *code, uint32_t num)
{
    uint32_t i;

    for (i = 0; i < num; i++)
    {
        /*
         * already been initialized, skip
         */
        if (code[i].status != insn_status_none)
            continue;

        if (hdn_reord_insns_is_possible (code, i, num) > 1)
            code[i].status = insn_status_valid;
    }
}


static void _q_sort (hdn_disassembly_data_t *block, int left, int right)
{
    int l_hold, r_hold;
    hdn_disassembly_data_t pivot;
    uint32_t sz = sizeof pivot;

    l_hold = left;
    r_hold = right;
    bcopy (&block[left], &pivot, sz);

    while (left < right)
    {
        while ( (memcmp (block[right].insn.bytes,
                         pivot.insn.bytes, MAX_INSN_SIZE) >= 0) &&
               (left < right) )
            right--;

        if (left != right)
        {
            bcopy (&block[right], &block[left], sz);
            left++;
        }

        while ((memcmp (block[left].insn.bytes,
                        pivot.insn.bytes, MAX_INSN_SIZE) <= 0) &&
               (left < right))
            left++;

        if (left != right)
        {
            bcopy (&block[left], &block[right], sz);
            right--;
        }
    }

    bcopy (&pivot, &block[left], sz);

    if (l_hold < left)
        _q_sort (block, l_hold, left - 1);
    if (r_hold > left)
        _q_sort (block, left + 1, r_hold);
}

static void _sort_insn_block (hdn_disassembly_data_t *block,
                              uint32_t num_insns)
{
    uint32_t i;
    uint8_t *min, *t;

    _q_sort (block, 0, num_insns - 1);

    /*
     * after sorting, the addresses are out of order.  Adjust them
     * properly.
     */

    //locate smallest address
    min = block[0].effaddr;
    t   = block[0].memaddr;
    for (i = 1; i < num_insns; i++)
    {
        if (block[i].effaddr < min)
        {
            min = block[i].effaddr;
            t   = block[i].memaddr;
        }
    }

    //map first insn to the smallest address, and all subsequent insns
    //appropriately
    block[0].effaddr = min;
    block[0].memaddr = t;
    for (i = 1; i < num_insns; i++)
    {
        block[i].memaddr = block[i-1].memaddr + block[i-1].insn.size;
        block[i].effaddr = block[i-1].effaddr + block[i-1].insn.size;
    }
}

/*
 * First swap the addresses, then the blocks themselves.
 */
#define SWAP_BLOCKS(a,b) do {      \
    hdn_disassembly_data_t  _d;    \
    bcopy (&a , &_d, sizeof _d);   \
    bcopy (&b , &a , sizeof _d);   \
    bcopy (&_d, &b , sizeof _d);   \
    b.memaddr =  a.memaddr;        \
    b.effaddr =  a.effaddr;        \
    a.memaddr = _d.memaddr;        \
    a.effaddr = _d.effaddr;        \
} while (0)


uint32_t hdn_reord_insns (hdn_disassembly_data_t *dis,
                          uint32_t curr_elt,
                          uint32_t num_elts,
                          uint8_t *source,
                          uint32_t bit_offset)
{
    uint32_t i, bitmask;
    uint32_t num_insns, num_bits;
    uint32_t source_idx = 0;
    hdn_disassembly_data_t *block;

    num_insns = hdn_reord_insns_is_possible (dis, curr_elt, num_elts);
    num_bits  = hdn_math_numbits_if_reordered (num_insns);

    if (num_insns <= 1) return 0;

    //we can embed num_bits into num_insns
    //first, we create a duplicate list of the instruction block
    block = malloc (sizeof (hdn_disassembly_data_t) * num_insns);
    bcopy (&dis[curr_elt], block,
           sizeof (hdn_disassembly_data_t) * num_insns);

    fprintf (stderr, "numinsns: %d\nbefore:\n", num_insns);
    for (i = 0; i < num_insns; i++)
    {
        fprintf (stderr, "%p\t", block[i].memaddr);
        hdn_io_print_insn (stderr, &block[i].insn);
    }

    //sort it in place
    _sort_insn_block (block, num_insns);
    //set the used bits
    for (i = 0; i < num_insns; i++)
    {
        block[i].status |= insn_status_used;
    }

    /*
     * Block is now in the 0 state.  We create a bitmask to test the
     * appropriate bit in the source, and if the bit is set, we swap
     * the appropriate instructions around.
     */
    for (i = 0; i < num_bits; i++)
    {
        bitmask = i << (7 - ((bit_offset + (i % 8)) % 8));

        /*
         * move to the next byte in source if necessary.
         */
        if (!((bit_offset + i) % 8) && i)
            source_idx++;

        /*
         * we use the bitmask to test a given bit in the source.  If
         * it's set, do the swapping.
         */
        if ((source[source_idx] & bitmask) == 0)
            continue;

        /*
         * Swapping mainly swaps the address of the instructions in
         * the block.  But, for convenience, it also swaps the
         * location of the instructions within the block so that we
         * can easily tell the order the instructions should appear
         * in.
         */
        SWAP_BLOCKS(block[i],
                    block[ i ? i-1 : num_insns-1]);
    }

    /*
     * Now, block contains correctly encoded instructions.  We must
     * adjust the addresses however, as they have merely been swapped
     * around.  Since instructions have different lengths, some
     * instructions might overlap or have gaps in between them.  So we
     * adjust them by starting at the first instruction, and moving
     * the next instruction relative to the first one, and so on.
     */
    fprintf (stderr, "after:\n");
    for (i = 0; i < num_insns; i++)
    {
        fprintf (stderr, "%p\t", block[i].memaddr);
        hdn_io_print_insn (stderr, &block[i].insn);
    }

    for (i = 0; i < num_insns-1; i++)
    {
        block[i+1].memaddr = block[i].memaddr + block[i].insn.size;
        block[i+1].effaddr = block[i].effaddr + block[i].insn.size;
    }

    /*
     * now go ahead and commit this data, both to the dis array and to
     * the source file.
     */
    bcopy (block, &dis[curr_elt],
           sizeof (hdn_disassembly_data_t) * num_insns);

    for (i = 0; i < num_insns; i++)
    {
        bcopy (block[i].insn.bytes,
               block[i].memaddr,
               block[i].insn.size);
    }

    return num_bits;
}

static int _is_reorderable_insn (hdn_disassembly_data_t *dis)
{
        // XXX make this more fine grained, esp re: insn_stack
        return (!(dis->insn.group == insn_controlflow ||
                  dis->insn.group == insn_stack       ||
                  dis->insn.group == insn_interrupt   ||
                  dis->insn.group == insn_system));
}

static uint32_t _operands_clash (x86_op_t *dst, x86_op_t *src)
{
        if (dst->type == op_unknown ||
            src->type == op_unknown) return 1;

        //can't clash if they're not of same type
        if (dst->type != src->type) return 0;

        //now we look to see if they're the same type, but don't point
        //to the same thing

        switch (dst->type)
        {
                case op_unused:
                        return 0;

                //clash if they're the same
                case op_register:
                        return (dst->data.reg.id == src->data.reg.id);

                //immediate values can't clash
                case op_immediate:
                        return 0;

                //XXX - should add more stuff here
                default:
                        return 1;
        }

        return 1;
}

static uint32_t _dest_operands_clash (x86_op_t *a, x86_op_t *b)
{
        if (a->type == op_unknown ||
            b->type == op_unknown) return 1;

        if (a->type == op_unused ||
            b->type == op_unused) return 0;

        //registers can't clash with other dest types, nor amongst themselves.
        if (a->type == op_register ||
            b->type == op_register) return 0;

        //ignore the case where dest is an imm ... not possible

        //in every other case, they're both addresses of some kind,
        //which might clash.  this can be fine tuned [XXX] but for
        //now, reject!
        return 1;
}

static uint32_t _clashes (hdn_disassembly_data_t *dis1,
                          hdn_disassembly_data_t *dis2)
{
        if (!_is_reorderable_insn (dis1)) goto out;

        if (dis2)
        {
                //control flow and other insns are never reorderable
                if (!_is_reorderable_insn (dis2)) goto out;

                //do flags clash
                if ((dis1->insn.flags_set    & dis2->insn.flags_tested) ||
                    (dis1->insn.flags_tested & dis2->insn.flags_set))
                        goto out;

                /*
                 * check to see if the operands clash.
                 *
                 * We wouldn't want the source of one operand to
                 * affect the destination of another one.  Likewise,
                 * we wouldn't want the result of some operation to be
                 * stored in the same place as the result of some
                 * other operation.  Hence the dest_operands test.
                 */
                if (_operands_clash (&dis1->insn.operands[op_dest],
                                     &dis2->insn.operands[op_src]) ||
                    _operands_clash (&dis1->insn.operands[op_src],
                                     &dis2->insn.operands[op_dest]))
                        goto out;


                if (_dest_operands_clash (&dis1->insn.operands[op_dest],
                                          &dis2->insn.operands[op_dest]))
                        goto out;

                /*
                 * for now we don't support any instruction that has
                 * relative operands.  just because, we would need to
                 * fix them after they've been reordered.  this is no
                 * big deal, but can be done later XXX.  Also, we need
                 * to keep in mind that the instruction might not be
                 * unique anymore after reordering it if we're
                 * patching it after reordering.
                 */



                /*
                 * We're embedding data by re-ordering functions.  But
                 * in order to know what the 'original' ordering is,
                 * we agree that the 0 state is when the functions are
                 * ordered lexicographically.  Hence, we have to make
                 * sure that there are no duplicates as part of the
                 * list of functions.  Right now I simply clash if i
                 * have a match.  A smarter way of doing this would be
                 * to move the function out of harms way.  Might
                 * implement this later XXX.
                 */
                if (!memcmp (dis1->insn.bytes,
                             dis2->insn.bytes,
                             MAX_INSN_SIZE))
                        goto out;
        }

        return 0;

 out:
        return 1;
}

//returns the number of reorderable instructions
static unsigned int _no_clashes_until (hdn_disassembly_data_t *dis,
                                       uint32_t curr_insn, uint32_t max_insn)
{
    uint32_t i, n=1;

    if (curr_insn >= max_insn-1) return 0;

    if (_clashes (&dis[curr_insn], NULL)) return 0;

    for (i = curr_insn+1; i < max_insn; i++)
    {
        if (_clashes (&dis[curr_insn], &dis[i]))
            break;
        n++;
    }

    return n;
}

static uint32_t _find_addr (hdn_disassembly_data_t *dis,
                            uint32_t num_elts, uint8_t *addr)
{
    uint32_t i;

    for (i = 0; i < num_elts; i++)
    {
        if (addr == dis[i].effaddr)
            break;
    }

    return i;
}

static uint64_t _get_imm_val (x86_insn_t *insn)
{
    switch (insn->operands[op_src].datatype)
    {
        case op_byte:  return insn->operands[op_src].data.sbyte;
        case op_word:  return insn->operands[op_src].data.sword;
        case op_dword: return insn->operands[op_src].data.sdword;
        case op_qword: return insn->operands[op_src].data.sqword;
        case op_sreal: return insn->operands[op_src].data.sreal;
        case op_dreal: return insn->operands[op_src].data.dreal;

        default:
            return insn->operands[op_src].data.sqword;
    }
}

static uint32_t _read_address (hdn_sections_t *hs, uint32_t addr)
{
    while (hs)
    {
        //the address we're looking for is within this section
        if (!((uint8_t *)addr >= hs->address &&
              (uint8_t *)addr <= (hs->address + hs->data.sz)))
            goto next;

        //return it
        return *(uint32_t *)&hs->data.content[addr - (uint32_t)(hs->address)];

    next:
        hs = hs->next;
    }

    return 0;
}

static void _hdn_reord_insns_mark_jumped_to (hdn_sections_header_t *sh,
                                             hdn_disassembly_data_t *dis,
                                             uint32_t max_insn,
                                             uint32_t curr_insn,
                                             char first_time)
{
    uint32_t idx;
    enum x86_insn_type stype;
    hdn_vm_t vm;

    if (first_time)
    {
        /*
         * we start by looking at the starting address, and follow
         * every jmp and call.  all jumped to/called instruction is
         * marked.
         */
        curr_insn = _find_addr (dis, max_insn, (uint8_t *)sh->start_addr);

        if (curr_insn == max_insn)
        {
            HDN_WARN ("start address [0x%x] not found!", sh->start_addr);
            return;
        }

        hdn_vm_init (&vm);
    }

    for (idx = curr_insn; idx < max_insn; idx++)
    {
        //have we been here already?  if so, return.
        if (dis[idx].status & insn_status_misc)
            HDN_WARN ("been here already..");

        /*
         * evaluate the instructions in my bloody VM
         */
        hdn_vm_eval (
        /*
         * we set the misc flag to indicate we've come here already
         */
        dis[idx].status |= insn_status_misc;

        stype = dis[idx].insn.type;

        //XXX add case when code is read
        if (stype == insn_jmp  || stype == insn_jcc ||
            stype == insn_call || stype == insn_callcc)
        {
            enum x86_op_type dtype = dis[idx].insn.operands[op_dest].type;
            uint64_t offset = 0;
            uint32_t next_idx;

            if (dtype == op_relative)
            {
                offset = _get_imm_val (&dis[idx].insn);

                //hydan will make ya, jmp jmp
                next_idx = _find_addr (dis, max_insn,
                                       dis[idx].effaddr +
                                       dis[idx].insn.size + offset);

                if (next_idx == max_insn)
                {
                    HDN_WARN ("offset = %lld\n", offset);
                    goto notfound;
                }

                /*
                 * else, we've found the address, and that instruction
                 * cannot be embedded into.
                 */
                dis[next_idx].status |= insn_status_invalid;

                /*
                 * if this is a conditional instruction, we simulate
                 * both branches by first not taking it, and then
                 * taking it.
                 */
                if (stype == insn_jcc || stype == insn_callcc)
                    _hdn_reord_insns_mark_jumped_to (sh, dis, max_insn,
                                                     idx + 1, 0);

                //take the branch.
                idx = next_idx;
                continue;
            }

            if (dtype == op_expression)
            {
                x86_ea_t *ea =
                    &dis[idx].insn.operands[op_dest].data.effective_addr;
                uint32_t addr, effaddr;

                fprintf (stderr, "expression\t");

                //if we use any registers, skip for now XXX
                if (ea->index.type || ea->base.type)
                {
                    fprintf (stderr, "registers...\t");
                    goto notfound;
                }

                /*
                 * compute the effective address otherwise
                 * ea = %base + %index * $scale + $disp
                 *
                 * since we don't use registers, it's just $disp for now XXX
                 */
                addr = ea->disp;

                /*
                 * get that address from memory now
                 */
                effaddr = _read_address (sh->sections, addr);

                next_idx = _find_addr (dis, max_insn, (uint8_t *)effaddr);

                /*
                 * either not found, or the address really is
                 * 0x00000000.  this happens when the address needs to
                 * be filled in by ld, because it points to some
                 * dynamic symbol, like an external library
                 */
                if (!effaddr)
                {
                    fprintf (stderr, "!effaddr\t");
                    goto notfound;
                }

                if (next_idx == max_insn)
                {
                    fprintf (stderr, "effaddr not found\t");
                    goto notfound;
                }

                /*
                 * referred to insn cannot be reordered.
                 */
                fprintf (stderr, "found!\t");
                dis[next_idx].status |= insn_status_invalid;
                idx = next_idx;
                goto notfound;
                //XXX deal with cc calls/jumps?
                continue;
            }

        notfound:
            hdn_io_print_insn (stderr, &dis[idx].insn);
        }
    }
}

void hdn_reord_insns_mark_jumped_to (hdn_sections_header_t *sh,
                                     hdn_disassembly_data_t *dis,
                                     uint32_t max_insn)
{
    _hdn_reord_insns_mark_jumped_to (sh, dis, max_insn, 0, 1);
}

uint32_t hdn_reord_insns_is_possible (hdn_disassembly_data_t *dis,
                                      uint32_t curr_insn,
                                      uint32_t max_insn)
{
    int i;

    //scan forwards from current instruction, to see how many it
    //can go until before clashing with something.
    uint32_t n = _no_clashes_until (dis, curr_insn, max_insn);

    if (n <= 1) return 0;

    //look at every 'n' instructions that follow and see how many
    //'n' instructions they can go for until they clash with
    //something.  we update 'n' whenever we get a smaller number
    //than we currently have.  when we hit the limit, we're done.
    for (i = 1; i < n; i++)
    {
        uint32_t n2 = _no_clashes_until (dis, curr_insn + i, max_insn);

        if (n2 < n) n = n2;
    }

#if 0
    {
        uint32_t j;
        fprintf (stderr, "No clashes:\n");
        for (j = 0; j < i; j++)
            hdn_io_print_insn (stderr, &dis[curr_insn + j].insn) ;
    }
#endif

    return i;
}

/*
 * $Id: hdn_common.c,v 1.16 2004/04/29 21:12:56 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 *
 * Disassembly core.  Everything that reads host code goes through
 * hdn_disassemble_all(), which decodes each code section with a
 * linear sweep in 32-bit compat mode (Zydis v4) and then translates
 * the result into the legacy x86_insn_t layout via
 * hdn_populate_insn_from_zydis().  Keeping the translation here means
 * embed, decode and stats all see identical operand/flag data -- which
 * is essential, since encoder and decoder must agree on which
 * instructions are substitutable.
 */

#include "hdn_common.h"
#include <Zydis/Zydis.h>

/*
 * Zydis operand type -> old libdisasm op_type.  Memory flavours
 * collapse into op_expression; we only ever need to distinguish
 * register / immediate / "other" for the table matcher.
 */
static enum x86_op_type _map_zydis_op_type (ZydisOperandType zt)
{
    switch (zt)
    {
        case ZYDIS_OPERAND_TYPE_REGISTER:  return op_register;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE: return op_immediate;
        case ZYDIS_OPERAND_TYPE_MEMORY:    return op_expression;
        case ZYDIS_OPERAND_TYPE_POINTER:   return op_absolute;
        default:                           return op_register;
    }
}

/*
 * operand bit-size -> old libdisasm datatype enum (size in bytes).
 * Unknown widths fall back to dword, matching the historical default.
 */
static enum x86_op_datatype _map_zydis_size (ZyanU16 size_bits)
{
    switch (size_bits / 8)
    {
        case 1:  return op_byte;
        case 2:  return op_word;
        case 4:  return op_dword;
        case 8:  return op_qword;
        case 16: return op_dqword;
        case 10: return op_extreal;
        case 28: return op_fpuenv;
        default: return op_dword;
    }
}

/*
 * Zydis flag mask (EFLAGS bit positions) -> old x86_flag_status bits.
 * Only the six flags the substitution analysis cares about are mapped.
 */
static enum x86_flag_status _map_zydis_flags (ZydisAccessedFlagsMask mask)
{
    enum x86_flag_status result = 0;

    if (mask & ZYDIS_CPUFLAG_CF) result |= insn_carry_set;
    if (mask & ZYDIS_CPUFLAG_PF) result |= insn_parity_set;
    if (mask & ZYDIS_CPUFLAG_ZF) result |= insn_zero_set;
    if (mask & ZYDIS_CPUFLAG_SF) result |= insn_sign_set;
    if (mask & ZYDIS_CPUFLAG_DF) result |= insn_dir_set;
    if (mask & ZYDIS_CPUFLAG_OF) result |= insn_oflow_set;

    return result;
}

/*
 * see hdn_common.h.  Immediate values are stored sign-extended into
 * the smallest matching field (sbyte..sqword) so that _get_imm_val()
 * in hdn_subst_insns.c reads back exactly what the instruction
 * encodes.  Registers/memory carry no value here.
 */
void hdn_populate_insn_from_zydis (x86_insn_t *out,
                                    const ZydisDecodedInstruction *z,
                                    const ZydisDecodedOperand *ops)
{
    uint8_t count, i;

    out->size = z->length;
    out->type = (enum x86_insn_type) z->mnemonic;

    out->flags_set = 0;
    out->flags_tested = 0;
    if (z->cpu_flags)
    {
        out->flags_set    = _map_zydis_flags (z->cpu_flags->modified);
        out->flags_tested = _map_zydis_flags (z->cpu_flags->tested);
    }

    count = z->operand_count_visible;
    if (count > 3) count = 3;

    for (i = 0; i < count; i++)
    {
        out->operands[i].type     = _map_zydis_op_type (ops[i].type);
        out->operands[i].datatype = _map_zydis_size (ops[i].size);

        switch (ops[i].type)
        {
            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                if (ops[i].imm.is_signed)
                {
                    switch (out->operands[i].datatype)
                    {
                        case op_byte:  out->operands[i].data.sbyte  = (int8_t)ops[i].imm.value.s;  break;
                        case op_word:  out->operands[i].data.sword  = (int16_t)ops[i].imm.value.s; break;
                        case op_dword: out->operands[i].data.sdword = (int32_t)ops[i].imm.value.s; break;
                        case op_qword: out->operands[i].data.sqword = ops[i].imm.value.s;           break;
                        default:       out->operands[i].data.sqword = ops[i].imm.value.s;           break;
                    }
                }
                else
                {
                    switch (out->operands[i].datatype)
                    {
                        case op_byte:  out->operands[i].data.sbyte  = (int8_t)ops[i].imm.value.u;  break;
                        case op_word:  out->operands[i].data.sword  = (int16_t)ops[i].imm.value.u; break;
                        case op_dword: out->operands[i].data.sdword = (int32_t)ops[i].imm.value.u; break;
                        case op_qword: out->operands[i].data.sqword = (int64_t)ops[i].imm.value.u; break;
                        default:       out->operands[i].data.sqword = (int64_t)ops[i].imm.value.u; break;
                    }
                }
                break;

            default:
                out->operands[i].data.sqword = 0;
                break;
        }
    }

    for (; i < 3; i++)
    {
        out->operands[i].type     = op_register;
        out->operands[i].datatype = op_dword;
        out->operands[i].data.sqword = 0;
    }
}

/*
 * Linear-sweep disassembly of every code section (see header).  Each
 * section restarts at curr_pos 0; undecodable bytes are recorded as
 * one-byte insn_status_bad entries so the sweep keeps moving and
 * embed/decode stay in lockstep.
 */
hdn_disassembly_data_t *hdn_disassemble_all (hdn_sections_t *hs,
                                              uint32_t *num_insns)
{
    hdn_disassembly_data_t *dis = NULL;
    hdn_disassembly_data_t d;
    uint32_t host_curr_pos = 0;
    ZydisDecoder decoder;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];

    ZydisDecoderInit (&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    (*num_insns) = 0;

    while (hs)
    {
        if (!hdn_exe_section_is_code (hs))
            goto next_section;

        bzero (&d, sizeof d);
        d.memaddr = (uint8_t *) hs->data.content + host_curr_pos;
        d.effaddr = hs->address + host_curr_pos;
        d.status  = insn_status_none;

        ZyanStatus status = ZydisDecoderDecodeFull (&decoder,
            d.memaddr, (ZyanUSize)(hs->data.sz - host_curr_pos),
            &d.insn.zydis, ops);

        if (ZYAN_SUCCESS (status))
        {
            memcpy (d.insn.raw, d.memaddr, d.insn.zydis.length);
            hdn_populate_insn_from_zydis (&d.insn, &d.insn.zydis, ops);
        }
        else
        {
            d.status = insn_status_bad;
            d.insn.size = 1;
            d.insn.raw[0] = d.memaddr[0];
        }

        if (!d.insn.size)
        {
            d.status    = insn_status_bad;
            d.insn.size = 1;
        }

        if ((host_curr_pos + d.insn.size) > hs->data.sz)
            goto next_section;

        if (!((*num_insns) % 1000))
        {
            dis = realloc (dis, sizeof (hdn_disassembly_data_t) *
                            ((*num_insns) + 1000));
        }

        bcopy (&d, &dis[(*num_insns)], sizeof d);
        (*num_insns)++;

        host_curr_pos += d.insn.size;
        continue;

    next_section:
        hs            = hs->next;
        host_curr_pos = 0;
    }

    return dis;
}

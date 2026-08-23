/*
 * $Id: hdn_insns.c,v 1.16 2004/04/28 22:27:34 xvr Exp $
 * Created: 08/23/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 *
 * Equivalent-instruction substitution engine.
 *
 * HOW ENCODING WORKS
 * ------------------
 * Each table below lists members of one equivalence class.  For a
 * class of N instructions, floor(log2(N)) message bits select which
 * member an instruction encodes as (index into the table).  Example:
 * {"add eax, imm32", "sub eax, imm32"} is a 2-member class (the
 * immediate is negated when switching), so each such instruction
 * carries exactly 1 bit.
 *
 * TABLE ENTRY ANATOMY (struct _sinstr)
 * ------------------------------------
 *   opcd        opcode byte the member must have
 *   mod/reg/rm  constraints on the mod/r/m fields of the ModRM byte,
 *               each with an operator (see NU..NEG macros below)
 *   immval_op   operator for the immediate constraint; immval is the
 *               expected value (EQ) or ignored (NU/NEG)
 *   flags_affected  flags whose value may DIFFER between members of
 *               this class -- used by _adversely_affects_flags()
 *
 * Operators:
 *   NU  field not used / always matches
 *   EQ  field must equal the given value
 *   GT/GE/LT/LE  ordered comparisons
 *   RR  special case: REG field must equal RM field
 *   SRR special case: REG/RM may be swapped (opcode pair forms)
 *   NEG always matches; encoding negates the immediate
 *
 * MATCHING (_test_insn)
 * ---------------------
 * A host instruction matches a table entry when opcode byte and all
 * constrained ModRM/immediate fields agree.  Raw bytes are read from
 * memaddr[0]/[1] (opcode + ModRM); immediates come from the Zydis-
 * populated operands via _get_imm_val().  Instructions with prefixes
 * never match (memaddr[0] is the prefix byte), so they are simply not
 * embeddable.
 *
 * IMMEDIATES (_get_imm_val/_set_imm_val/_truncate_number)
 * ------------------------------------------------------
 * x86 places trailing immediates at the very end of an instruction,
 * so writing `sz` bytes at host[size - sz] patches it in place.  All
 * three helpers derive sz from the source-operand datatype populated
 * by hdn_populate_insn_from_zydis() -- getting this wrong corrupts
 * neighbouring bytes (e.g. treating an imm8 as imm32).
 *
 * VARBITS (-DVARBITS)
 * -------------------
 * When N is not a power of two, log2(N) bits can address more values
 * than there are members.  If the surplus is > 2, the last member is
 * reserved as an "invalid" marker and one extra bit is encoded;
 * otherwise the extra codes are unused.  See _is_valid_insn().
 */

#include "hdn_subst_insns.h"

/*
 * the following macros allow to easily test the values in the mod/rm
 * byte in the instruction, which is structured as follows:
 *   00 000 000
 * mod |reg| rm
 */
#define MOD_VAL(modrmb) ( (modrmb & 192) >> 6)
#define REG_VAL(modrmb) ( (modrmb &  56) >> 3)
#define RM_VAL(modrmb)  ( (modrmb &   7)     )

/*
 * defines the relationship between the *_op fields in the
 * instruction structure and the value itself
 */
#define NU 0x00   /* Field Not Used                     */
#define EQ 0x01   /* Field should be equal to the value */
#define GT 0x02   /* Greater than the value             */
#define GE 0x03   /* Greater than or equal to the value */
#define LT 0x04   /* Less than the value                */
#define LE 0x05   /* Less than or equal to the value    */
#define RR 0x06   /* Special case: REG_VAL == RM_VAL    */
#define SRR 0x07  /* Special case: swap the REG and RM vals */
#define NEG 0x08  /* Special case: always match, return the negative */

/*
 * define the different flags an operation can affect.  this lets us
 * do permutations that retain functional equivalence. (Eg: add/sub
 * affects the cf, so don't do it if there's a jb in the
 * neighbourhood).
 */
#define NF 0x00            /* no flag at all */
#define CF insn_carry_set  /* carry flag     */
#define ZF insn_zero_set   /* zero flag      */
#define OF insn_oflow_set  /* overflow flag  */
#define DF insn_dir_set    /* direction flag  */
#define SF insn_sign_set   /* sign flag      */
#define PF insn_parity_set /* parity flag    */

/*
 * description of an instruction that can be substituted
 */
struct _sinstr
{
    char opcd;         /* its opcode */

    char modval_op;
    char modval;       /* mod value */

    char regval_op;
    char regval;       /* the reg value in the mod/rm byte */

    char rmval_op;
    char rmval;        /* the rm value in the mod/rm byte */

    char immval_op;
    uint64_t immval; /* the immediate value */

    /*
     * What flags are affected, if any.  Note: only put here flags
     * that might *adversely* affect program flow. EG: the add/sub
     * combination affects OF, SZ, ZF, AF, CF, and PF.  However, only
     * OF and CF might be set differently if we use add instead of sub
     * -- the others are set based on the result of the operation
     * (which is the same in both cases).  So add/sub only adversely
     * affects OF and CF
     */
    char flags_affected;

    char *desc;       /* instruction description */

    uint32_t : 0;  /* pad to the next word boundary */
};

/*
 * the following affect all flags the same way, except for add/sub and
 * cmp.  those set the CF and OF flags according to the operation
 * instead of clearing them.  However, since the operand is 0, those
 * flags will be cleared anyways.  So it's all good.  The AF flag is
 * set as per operation in add/sub/cmp case, and undefined elsewhere.
 * But AF is only ever used in BCD operations, which means never.  So
 * we needn't worry about this now ... besides, libdisasm doesn't
 * support the AF flag atm.
 */
/*
 * AL, EAX-only no-op pairs: same result and flags for every member.
 * The immediate is a fixed constant per member (EQ), e.g. "test al,-1"
 * or "or al,0" -- encoding just swaps opcode + constant.
 */
struct _sinstr toasxc8_table[] =
{
    { 0xA8, NU, -1, NU, -1, NU, -1, EQ, -1, NF, "test al , -1" },
    { 0x0C, NU, -1, NU, -1, NU, -1, EQ,  0, NF, "or   al ,  0" },
    { 0x24, NU, -1, NU, -1, NU, -1, EQ, -1, NF, "and  al , -1" },
    { 0x04, NU, -1, NU, -1, NU, -1, EQ,  0, NF, "add  al ,  0" },
    { 0x2C, NU, -1, NU, -1, NU, -1, EQ,  0, NF, "sub  al ,  0" },
    { 0x34, NU, -1, NU, -1, NU, -1, EQ,  0, NF, "xor  al ,  0" },
    { 0x3C, NU, -1, NU, -1, NU, -1, EQ,  0, NF, "cmp  al ,  0" },
};

struct _sinstr toasxc32_table[] =
{
    { 0xA9, NU, -1, NU, -1, NU, -1, EQ, -1, NF, "test eax, -1" },
    { 0x0D, NU, -1, NU, -1, NU, -1, EQ,  0, NF, "or   eax,  0" },
    { 0x25, NU, -1, NU, -1, NU, -1, EQ, -1, NF, "and  eax, -1" },
    { 0x05, NU, -1, NU, -1, NU, -1, EQ,  0, NF, "add  eax,  0" },
    { 0x2D, NU, -1, NU, -1, NU, -1, EQ,  0, NF, "sub  eax,  0" },
    { 0x35, NU, -1, NU, -1, NU, -1, EQ,  0, NF, "xor  eax,  0" },
    { 0x3D, NU, -1, NU, -1, NU, -1, EQ,  0, NF, "cmp  eax,  0" },
};

/*
 * using add or sub affects the CF, OF, and AF flags differently.
 */
/*
 * add/sub pairs that affect OF|CF differently (see the NEG note
 * above): switching member negates the immediate, which keeps the
 * arithmetic result identical.  AL/EAX short forms.
 */
struct _sinstr addsub8_table[] =
{
    { 0x04, NU, -1, NU, -1, NU, -1, NEG, -1, OF | CF, "add  al , imm8" },
    { 0x2C, NU, -1, NU, -1, NU, -1, NEG, -1, OF | CF, "sub  al , imm8" },
};

/* add/sub imm8 via opcode 0x80, ModRM reg field selects add(0)/sub(5) */
struct _sinstr addsub8_table2[] =
{
    { 0x80, NU, -1, EQ,  0, NU, -1, NEG, -1, OF | CF, "add  r/m8 , imm8" },
    { 0x80, NU, -1, EQ,  5, NU, -1, NEG, -1, OF | CF, "sub  r/m8 , imm8" },
};

/* add/sub EAX,imm32 short form (no ModRM); OF|CF differ, imm negated */
struct _sinstr addsub32_table[] =
{
    { 0x05, NU, -1, NU, -1, NU, -1, NEG, -1, OF | CF, "add  eax, imm32" },
    { 0x2D, NU, -1, NU, -1, NU, -1, NEG, -1, OF | CF, "sub  eax, imm32" },
};

/* add/sub r/m32,imm32 via 0x81; ModRM reg selects add(0)/sub(5) */
struct _sinstr addsub32_table2[] =
{
    { 0x81, NU, -1, EQ,  0, NU, -1, NEG, -1, OF | CF, "add  r/m32, imm32" },
    { 0x81, NU, -1, EQ,  5, NU, -1, NEG, -1, OF | CF, "sub  r/m32, imm32" },
};

/* add/sub r/m32,imm8 via 0x83 (sign-extended imm8); OF|CF differ */
struct _sinstr addsub32_table3[] =
{
    { 0x83, NU, -1, EQ,  0, NU, -1, NEG, -1, OF | CF, "add  r/m32, imm8" },
    { 0x83, NU, -1, EQ,  5, NU, -1, NEG, -1, OF | CF, "sub  r/m32, imm8" },
};

/**********************************************************************
 * the following sets are valid when destination and source operand
 * are the same only.
 **********************/

/*
 * the toac set affects all flags the same way.
 */
/*
 * the following sets are valid when destination and source operand
 * are the same only (RR: ModRM reg field must equal rm field).
 * test/or/and with identical operands all clear CF/OF and set
 * SF/ZF/PF identically.
 */
struct _sinstr toac8_table[] =
{
    { 0x84, NU, -1, RR, -1, RR, -1, NU, -1, NF, "test r/m8 , r8"   },
    { 0x08, NU, -1, RR, -1, RR, -1, NU, -1, NF, "or   r/m8 , r8"   },
    { 0x0A, NU, -1, RR, -1, RR, -1, NU, -1, NF, "or   r8   , r/m8" },
    { 0x20, NU, -1, RR, -1, RR, -1, NU, -1, NF, "and  r/m8 , r8"   },
    { 0x22, NU, -1, RR, -1, RR, -1, NU, -1, NF, "and  r8   , r/m8" },
};

/* same no-op family, 32-bit form; RR requires reg == rm */
struct _sinstr toac32_table[] =
{
    { 0x85, NU, -1, RR, -1, RR, -1, NU, -1, NF, "test r/m32, r32"   },
    { 0x09, NU, -1, RR, -1, RR, -1, NU, -1, NF, "or   r/m32, r32"   },
    { 0x0B, NU, -1, RR, -1, RR, -1, NU, -1, NF, "or   r32  , r/m32" },
    { 0x21, NU, -1, RR, -1, RR, -1, NU, -1, NF, "and  r/m32, r32"   },
    { 0x23, NU, -1, RR, -1, RR, -1, NU, -1, NF, "and  r32  , r/m32" },
};

/*
 * flags stay the same here since we're only changing the order of the
 * operands.
 */
/*
 * cmp with swapped operands sets the same flags when reg == rm
 * (subtraction is antisymmetric but only flags are observed).
 */
struct _sinstr cmp8_table[] =
{
    { 0x38, NU, -1, RR, -1, RR, -1, NU, -1, NF, "cmp  r/m8 , r8"   },
    { 0x3A, NU, -1, RR, -1, RR, -1, NU, -1, NF, "cmp  r8   , r/m8" },
};

/* 32-bit cmp operand-order pair; RR reg == rm */
struct _sinstr cmp32_table[] =
{
    { 0x39, NU, -1, RR, -1, RR, -1, NU, -1, NF, "cmp  r/m32, r32"   },
    { 0x3B, NU, -1, RR, -1, RR, -1, NU, -1, NF, "cmp  r32  , r/m32" },
};


/*
 * clear register instructions: only works on registers (mod == 3),
 * since result is stored in destination, and the source and
 * destination operands must be the same (RR).
 * Flags affected are identical, since an xor is a sub anyways.
 */
struct _sinstr xorsub8_table1[] =
{
    { 0x30, EQ, 3, RR, -1, RR, -1, NU, -1, NF, "xor  r/m8 , r8"   },
    { 0x32, EQ, 3, RR, -1, RR, -1, NU, -1, NF, "xor  r8   , r/m8" },
    { 0x28, EQ, 3, RR, -1, RR, -1, NU, -1, NF, "sub  r/m8 , r8"   },
    { 0x2A, EQ, 3, RR, -1, RR, -1, NU, -1, NF, "sub  r8   , r/m8" },
};

struct _sinstr xorsub32_table1[] =
{
    { 0x31, EQ, 3, RR, -1, RR, -1, NU, -1, NF, "xor  r/m32, r32"   },
    { 0x33, EQ, 3, RR, -1, RR, -1, NU, -1, NF, "xor  r32  , r/m32" },
    { 0x29, EQ, 3, RR, -1, RR, -1, NU, -1, NF, "sub  r/m32, r32"   },
    { 0x2B, EQ, 3, RR, -1, RR, -1, NU, -1, NF, "sub  r32  , r/m32" },
};

/*
 * following sets are the same only when both operands refer to
 * registers. (mod == 3)  Same instructions, same flags..
 */
struct _sinstr add8_table1[] =
{
    { 0x00, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "add  r/m8 , r8"   },
    { 0x02, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "add  r8   , r/m8" },
};

struct _sinstr add32_table1[] =
{
    { 0x01, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "add  r/m32, r32"   },
    { 0x03, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "add  r32  , r/m32" },
};

struct _sinstr adc8_table1[] =
{
    { 0x10, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "adc  r/m8 , r8"   },
    { 0x12, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "adc  r8   , r/m8" },
};

struct _sinstr adc32_table1[] =
{
    { 0x11, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "adc  r/m32, r32"   },
    { 0x13, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "adc  r32  , r/m32" },
};

struct _sinstr and8_table1[] =
{
    { 0x20, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "and  r/m8 , r8"   },
    { 0x22, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "and  r8   , r/m8" },
};

struct _sinstr and32_table1[] =
{
    { 0x21, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "and  r/m32, r32"   },
    { 0x23, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "and  r32  , r/m32" },
};


struct _sinstr cmp8_table1[] =
{
    { 0x38, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "cmp  r/m8 , r8"   },
    { 0x3A, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "cmp  r8   , r/m8" },
};

struct _sinstr cmp32_table1[] =
{
    { 0x39, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "cmp  r/m32, r32"   },
    { 0x3B, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "cmp  r32  , r/m32" },
};


struct _sinstr mov8_table1[] =
{
    { 0x88, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "mov  r/m8 , r8"   },
    { 0x8A, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "mov  r8   , r/m8" },
};

struct _sinstr mov32_table1[] =
{
    { 0x89, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "mov  r/m32, r32"   },
    { 0x8B, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "mov  r32  , r/m32" },
};


struct _sinstr or8_table1[] =
{
    { 0x08, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "or   r/m8 , r8"   },
    { 0x0A, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "or   r8   , r/m8" },
};

struct _sinstr or32_table1[] =
{
    { 0x09, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "or   r/m32, r32"   },
    { 0x0B, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "or   r32  , r/m32" },
};


struct _sinstr sbb8_table1[] =
{
    { 0x18, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "sbb  r/m8 , r8"   },
    { 0x1A, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "sbb  r8   , r/m8" },
};

struct _sinstr sbb32_table1[] =
{
    { 0x19, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "sbb  r/m32, r32"   },
    { 0x1B, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "sbb  r32  , r/m32" },
};


struct _sinstr sub8_table1[] =
{
    { 0x28, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "sub  r/m8 , r8"   },
    { 0x2A, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "sub  r8   , r/m8" },
};

struct _sinstr sub32_table1[] =
{
    { 0x29, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "sub  r/m32, r32"   },
    { 0x2B, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "sub  r32  , r/m32" },
};


struct _sinstr xor8_table1[] =
{
    { 0x30, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "xor  r/m8 , r8"   },
    { 0x32, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "xor  r8   , r/m8" },
};

struct _sinstr xor32_table1[] =
{
    { 0x31, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "xor  r/m32, r32"   },
    { 0x33, EQ, 3, SRR, -1, SRR, -1, NU, -1, NF, "xor  r32  , r/m32" },
};


struct _sinstr_desc
{
    char          *desc;
    struct _sinstr *table;
    uint32_t       table_sz;
};

#define SINSTR_SZ (sizeof(struct _sinstr))
#define SINSTR_TABLE_ENTRY(desc,table) {desc,table,(sizeof(table)/SINSTR_SZ)}

struct _sinstr_desc sinstr_table[] =
{
    SINSTR_TABLE_ENTRY("toac8"       , toac8_table)    ,
    SINSTR_TABLE_ENTRY("toac32"      , toac32_table)   ,
    SINSTR_TABLE_ENTRY("rrcmp8"      , cmp8_table)     ,
    SINSTR_TABLE_ENTRY("rrcmp32"     , cmp32_table)    ,
    SINSTR_TABLE_ENTRY("toasxc8"     , toasxc8_table)  ,
    SINSTR_TABLE_ENTRY("toasxc32"    , toasxc32_table) ,
    SINSTR_TABLE_ENTRY("addsub8"     , addsub8_table)  ,
    SINSTR_TABLE_ENTRY("addsub8-2"   , addsub8_table2) ,
    SINSTR_TABLE_ENTRY("addsub32-1"  , addsub32_table) ,
    SINSTR_TABLE_ENTRY("addsub32-2"  , addsub32_table2),
    SINSTR_TABLE_ENTRY("addsub32-3"  , addsub32_table3),
    SINSTR_TABLE_ENTRY("xorsub8"     , xorsub8_table1) ,
    SINSTR_TABLE_ENTRY("xorsub32"    , xorsub32_table1),
    SINSTR_TABLE_ENTRY("add8"        , add8_table1)    ,
    SINSTR_TABLE_ENTRY("add32"       , add32_table1)   ,
    SINSTR_TABLE_ENTRY("adc8"        , adc8_table1)    ,
    SINSTR_TABLE_ENTRY("adc32"       , adc32_table1)   ,
    SINSTR_TABLE_ENTRY("and8"        , and8_table1)    ,
    SINSTR_TABLE_ENTRY("and32"       , and32_table1)   ,
    SINSTR_TABLE_ENTRY("cmp8"        , cmp8_table1)    ,
    SINSTR_TABLE_ENTRY("cmp32"       , cmp32_table1)   ,
    SINSTR_TABLE_ENTRY("mov8"        , mov8_table1)    ,
    SINSTR_TABLE_ENTRY("mov32"       , mov32_table1)   ,
    SINSTR_TABLE_ENTRY("or8"         , or8_table1)     ,
    SINSTR_TABLE_ENTRY("or32"        , or32_table1)    ,
    SINSTR_TABLE_ENTRY("sbb8"        , sbb8_table1)    ,
    SINSTR_TABLE_ENTRY("sbb32"       , sbb32_table1)   ,
    SINSTR_TABLE_ENTRY("sub8"        , sub8_table1)    ,
    SINSTR_TABLE_ENTRY("sub32"       , sub32_table1)   ,
    SINSTR_TABLE_ENTRY("xor8"        , xor8_table1)    ,
    SINSTR_TABLE_ENTRY("xor32"       , xor32_table1)   ,

    {NULL, NULL, 0},
};

void hdn_subst_insns_tag_valid (hdn_disassembly_data_t *code, uint32_t num)
{
    uint32_t i;

    for (i = 0; i < num; i++)
    {
        /*
         * already been initialized, skip
         */
        if (code[i].status != insn_status_none)
            continue;

        if (hdn_subst_insns_is_possible (&code[i], 1, 0))
            code[i].status = insn_status_valid;
    }
}


/*
 * compare orig and new using the supplied operation
 */
static uint32_t _test_val (char operation, uint64_t orig, uint64_t new)
{
    switch (operation)
    {
        case EQ: return (orig == new);
        case GT: return (orig >  new);
        case GE: return (orig >= new);
        case LT: return (orig <  new);
        case LE: return (orig <= new);

        case NEG:
        case RR: //handled elsewhere
        case SRR://handled elsewhere
        case NU: //skip
            return 1;
    }

    return 0;
}

/*
 * returns the size of the source
 */
static uint32_t _src_sz (x86_insn_t *insn)
{
    switch (insn->operands[op_src].datatype)
    {
        case op_byte:    return 1;
        case op_word:    return 2;
        case op_dword:   return 4;
        case op_qword:   return 8;
        case op_dqword:  return 16;
        case op_fpuenv:  return 28; /* 28 byte FPU environment data */
    }

    return 0;
}

/*
 * returns the immediate value
 */
static uint64_t _get_imm_val (x86_insn_t *insn, uint8_t *host)
{
    switch (insn->operands[op_src].datatype)
    {
        case op_byte:  return insn->operands[op_src].data.sbyte;
        case op_word:  return insn->operands[op_src].data.sword;
        case op_dword: return insn->operands[op_src].data.sdword;
        case op_qword: return insn->operands[op_src].data.sqword;

        default:
            return insn->operands[op_src].data.sqword;
    }
}

/*
 * return only the first sz bytes of n
 */
static uint64_t _truncate_number (x86_insn_t *insn, uint64_t n)
{
    int64_t temp = (int64_t)n;
    int sz = _src_sz (insn);

    switch (sz)
    {
        case 1: return (uint64_t)(int8_t)temp;
        case 2: return (uint64_t)(int16_t)temp;
        case 4: return (uint64_t)(int32_t)temp;
        case 8: return (uint64_t)temp;
        default: return n;
    }
}

/*
 * set the immediate value
 */
static void _set_imm_val (x86_insn_t *insn, uint8_t *host,
                          uint64_t imm)
{
    int sz = _src_sz (insn);

    memcpy (host + insn->size - sz, &imm, sz);
}

/*
 * does the instruction encoded by opcd,mdrm match what's in instr?
 */
static int _test_insn (char opcd, char mdrm, struct _sinstr *instr,
                       x86_insn_t *insn,
                       uint8_t *host)
{
    /* test the opcode */
    if (!_test_val (EQ, instr->opcd, opcd)) return 0;

    /* lookout for special RR case */
    if (instr->regval_op == RR || instr->rmval_op == RR)
        if (!_test_val (EQ, REG_VAL(mdrm), RM_VAL(mdrm)))
            return 0;

    /* test the mod val */
    if (!_test_val (instr->modval_op,
                    instr->modval,
                    MOD_VAL(mdrm))) return 0;

    /* test the reg val */
    if (!_test_val (instr->regval_op,
                    instr->regval,
                    REG_VAL(mdrm))) return 0;

    /* test the rm val */
    if (!_test_val (instr->rmval_op,
                    instr->rmval,
                    RM_VAL(mdrm))) return 0;

    /* immediate value */
    if (!_test_val (instr->immval_op,
                    _truncate_number (insn, instr->immval),
                    _get_imm_val (insn, host))) return 0;

    return 1;
}

struct address_array
{
    uint32_t num_elts; //number of addresses assigned
    uint32_t max_elts; //number of addresses allocated

    uint8_t **addr; //array of addresses
};

static char _address_was_visited (struct address_array *addr_arr,
                                  uint8_t *addr)
{
    uint32_t i;

    for (i = 0; i < addr_arr->num_elts; i++)
    {
        if (addr_arr->addr[i] == addr) return 1;
    }

    return 0;
}

static char _address_add_visited (struct address_array *addr_arr,
                                  uint8_t *addr)
{
    int alloc_num = 1000;

    //if it's there already, don't do nuthin
    if (_address_was_visited (addr_arr, addr)) return 1;

    //allocate some memory for the address array
    if (addr_arr->num_elts == addr_arr->max_elts)
    {
        addr_arr->max_elts += alloc_num;
        addr_arr->addr = realloc (addr_arr->addr,
                                  sizeof (char *) * addr_arr->max_elts);
    }

    //add it
    addr_arr->addr[addr_arr->num_elts] = addr;
    addr_arr->num_elts++;
    return 0;
}

static uint32_t _find_addr (hdn_disassembly_data_t *dis_array,
                            uint32_t num_elts,
                            uint8_t *addr)
{
    uint32_t i;

    for (i = 0; i < num_elts; i++)
    {
        if (addr == dis_array[i].memaddr)
            break;
    }

    return i;
}


/*
 * looks in the disassembly array, starting from element elt, to see
 * if the that elt will affect any of the following instructions.  For
 * the time being, we keep going until either we hit a ret, or another
 * instruction that affects those same flags.  In the case of a ret,
 * it's safe because any registers that are wished to be kept would be
 * popped off the stack.  In the other case, we can also safely
 * clobber those flags since no instruction needs them, the next
 * instruction is going to clobber the flags anyways.  altho we follow
 * unconditional jumps, we don't follow calls since flags shouldn't
 * affect the call'ed function.
 */
static int _adversely_affects_flags (hdn_disassembly_data_t *dis_array,
                                     uint32_t num_elts, uint32_t elt,
                                     struct _sinstr *instr)
{
    return 0;
}

/*
 * same as below, except returns the index of the set of instructions
 * where the instruction was found.
 */
static int _is_valid_insn (hdn_disassembly_data_t *dis_array,
                           uint32_t num_elts, uint32_t elt,
                           int val, int *insn_set)
{
    int set, ins, num_insns, tmp_bits, ret, max_bits = 0;
    uint8_t opcd = dis_array[elt].memaddr[0];
    uint8_t mdrm = dis_array[elt].memaddr[1];

    for (set = 0; sinstr_table[set].table; set++)
    {
        num_insns = sinstr_table[set].table_sz;

        /*
         * If val is specified, see if we can express it using this
         * set of instructions.  else, don't waste time here.
         */
        if (val >= 0 && val > num_insns) continue;

        for (ins = 0; ins < num_insns; ins++)
        {
            //have we found the instruction?
            ret = _test_insn (opcd, mdrm, &sinstr_table[set].table[ins],
                              &dis_array[elt].insn, dis_array[elt].memaddr);
            if (!ret) continue;

            /*
             * make sure that the instruction doesn't affect flags
             * that are used in instructions following it
             */
            if (_adversely_affects_flags (dis_array, num_elts, elt,
                                          &sinstr_table[set].table[ins]))
                continue;

            /*
             * have to use our version of log, since log () rounds too
             * much, and log1p doesn't work consistently accross
             * platforms.
             */
            tmp_bits = hdn_math_log2 (num_insns);

#ifdef VARBITS
            /*
             * if we have more than 2 more instructions than the
             * number of bits that we can fully express, use the last
             * instruction as an 'invalid' marker, and encode one more
             * bit than we normally could.  Assuming random
             * distribution in 0s and 1s, this means that at the worst
             * case, half of the instructions will not get used --
             * which is equivalent to using the lesser bit encoding
             * scheme.  But in the better cases, we can gain from
             * this, despite the waste.
             */
            if ((num_insns - pow (2, tmp_bits)) > 2)
            {
                //this the invalid marker, don't use to encode
                if (ins == (num_insns - 1))
                    continue;

                tmp_bits++;
            }
#endif
            if (tmp_bits > max_bits)
            {
                if (insn_set) *insn_set = set;
                max_bits = tmp_bits;
            }
        }
    }

    return max_bits;
}

/*
 * returns the max number of bits that can be encoded, 0 if invalid
 * instruction.
 */
uint32_t hdn_subst_insns_is_possible (hdn_disassembly_data_t *dis_array,
                                      uint32_t num_elts, uint32_t elt)
{
    return _is_valid_insn (dis_array, num_elts, elt, -1, NULL);
}

/*
 * returns the description of the encoded instruction
 */
char *hdn_subst_insns_desc (x86_insn_t *insn, uint8_t *host, char **insn_desc)
{
    char *ret = NULL;
    int insn_set, bits;
    hdn_disassembly_data_t dis;

    if (insn_desc)
        *insn_desc = NULL;

    dis.memaddr = host;
    memmove (&dis.insn, insn, sizeof (x86_insn_t));

    if (!(bits = _is_valid_insn (&dis, 1, 0, -1, &insn_set)))
        goto out;

    ret = sinstr_table[insn_set].desc;
    if (insn_desc)
        *insn_desc =
            sinstr_table[insn_set].table[
                hdn_subst_insns_val (insn, host, NULL)
            ].desc;

  out:
    return ret;
}

uint32_t hdn_subst_insns_is_neg (x86_insn_t *insn, uint8_t *host)
{
    int bits, i;
    int insn_set, num_insns;
    uint8_t opcd = host[0];
    uint8_t mdrm = host[1];
    hdn_disassembly_data_t dis;

    dis.memaddr = host;
    memmove (&dis.insn, insn, sizeof (x86_insn_t));

    if (!(bits = _is_valid_insn (&dis, 1, 0, -1, &insn_set)))
        return 0;

    num_insns = sinstr_table[insn_set].table_sz;

    for (i = 0; i < num_insns; i++)
    {
        /*
         * look for the instruction
         */
        if (_test_insn (opcd, mdrm, &sinstr_table[insn_set].table[i],
                        insn, host))
        {
            if (sinstr_table[insn_set].table[i].immval_op == NEG &&
                _get_imm_val(insn, host) < 0)
                return 1;
        }
    }

    return 0;
}

/*
 * return the value of the encoded instruction.
 */
uint32_t hdn_subst_insns_val (x86_insn_t *insn, uint8_t *host, int *numbits)
{
    int ret = 0;
    int insn_set, bits, num_insns;
    uint8_t opcd = host[0];
    uint8_t mdrm = host[1];
    hdn_disassembly_data_t dis;

    dis.memaddr = host;
    memmove (&dis.insn, insn, sizeof (x86_insn_t));

    if (!(bits = _is_valid_insn (&dis, 1, 0, -1, &insn_set))) goto out;
    num_insns = sinstr_table[insn_set].table_sz;

    for (ret = 0; ret < num_insns; ret++)
    {
        if (_test_insn (opcd, mdrm, &sinstr_table[insn_set].table[ret],
                        insn, host))
            goto out;
    }

    bits = 0;
    ret  = 0;

  out:
    if (numbits)
        (*numbits) = bits;
    return ret;
}

/*
 * flips the instruction to the appropriate one, returns the number of
 * bits encoded
 */
uint32_t hdn_subst_insns (x86_insn_t *insn, uint8_t *host,
                          uint8_t *source, int bit_offset)
{
    int insn_set, bits;
    int val = -1, bitmask;
    int num_insns;
    hdn_disassembly_data_t dis;

    dis.memaddr = host;
    memmove (&dis.insn, insn, sizeof (x86_insn_t));

#ifdef VARBITS
    do {
#endif
        /*
         * Get the number of bits we can encode, and using which set of
         * instructions
         */
        if (!(bits = _is_valid_insn (&dis, 1, 0, val, &insn_set)))
            return 0;
        num_insns = sinstr_table[insn_set].table_sz;

        /*
         * create a bitmask for the first n bits
         */
        bitmask = ((1 << bits) - 1) << (8 - bits);

        /*
         * Get the next n bits from the source, even if they cross
         * byte boundaries.  Note: max number of bits we can encode is 8!
         */
        val = (((source[0] << bit_offset) | (source[1] >> (8 - bit_offset)))
               & bitmask) >> (8 - bits);

        /*
         * Val now contains the next bits to be encoded.  As we have
         * limited the range of val, we can use it to index which
         * instruction to flip to.
         */

#ifdef VARBITS
        /*
         * make sure that we really can encode val with the given
         * number of bits.
         */

    } while (bits != _is_valid_insn (&dis, 1, 0, val, &insn_set));
#endif

    /*
     * do nothing if we already have what we need
     */
    if (hdn_subst_insns_val (&dis.insn, dis.memaddr, &bits) == val)
        return bits;

#ifdef VARBITS
    /*
     * this value cannot be expressed, so replaced it with the invalid
     * marker.
     */
    if (((num_insns - pow(2, hdn_math_log2 (num_insns))) > 2) &&
        val >= (num_insns - 1))
    {
        val = num_insns - 1;
        bits = 0;
    }
#endif

    /* change the opcode to the appropriate one */
    host[0] = sinstr_table[insn_set].table[val].opcd;

    /* reg bits */
    if (sinstr_table[insn_set].table[val].regval_op == EQ)
    {
        host[1] &= 0xC7;  //clear out the bits
        host[1] |= (sinstr_table[insn_set].table[val].regval << 3) & 0x38;
    }

    /* rm bits */
    if (sinstr_table[insn_set].table[val].rmval_op == EQ)
    {
        host[1] &= 0xF8;  //clear out the bits
        host[1] |= (sinstr_table[insn_set].table[val].rmval) & 0x07;
    }

    /* imm val */
    if (sinstr_table[insn_set].table[val].immval_op == EQ)
    {
        _set_imm_val (insn, host, sinstr_table[insn_set].table[val].immval);
    }
    if (sinstr_table[insn_set].table[val].immval_op == NEG)
    {
        _set_imm_val (insn, host, -_get_imm_val (insn, host));
    }

    /* swap REG and R/M */
    if (sinstr_table[insn_set].table[val].regval_op == SRR &&
        sinstr_table[insn_set].table[val].rmval_op  == SRR)
    {
        uint8_t modrmb = host[1];

        host[1] &= 0xC7; //clear out reg bits
        host[1] |= RM_VAL(modrmb) << 3;

        host[1] &= 0xF8; //clear out the rm bits
        host[1] |= REG_VAL(modrmb);
    }

    //done
    return bits;
}

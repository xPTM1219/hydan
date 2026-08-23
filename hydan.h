/*
 * $Id: hydan.h,v 1.11 2004/04/30 05:27:15 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

/*
 * Hydan -- information hiding in ELF executables via equivalent
 * instruction substitution.
 *
 * ARCHITECTURE
 * ------------
 * One binary (`hydan`) serves three roles, dispatched on argv[0]
 * (see hydan.c): embedding (`hydan`), extraction (`hydan-decode`),
 * and statistics (`hydan-stats`).  All core logic lives in the hdn_*
 * modules:
 *
 *   hdn_exe        parse host executable into a section list
 *                  (ELF32 LSB only today; PE stub is dead code)
 *   hdn_common     linear-sweep disassembly of code sections using
 *                  Zydis + population of our x86_insn_t view
 *   hdn_subst_insns equivalence tables + bit encode/decode per insn
 *   hdn_crypto     AES-256-GCM encryption of the message (binary blob)
 *   hdn_embed      encrypt msg, prepend 4-byte length, embed bit by bit
 *   hdn_decode     extract length prefix, extract exact payload, decrypt
 *   hdn_stats      embeddable-bit counting and instruction-class stats
 *   hdn_io         whole-file read/write helpers (hdn_data_t)
 *
 * DATA FLOW (embed)
 * -----------------
 *   io_fileread(msg)
 *     -> hdn_crypto_encrypt            msg -> [salt16|iv12|tag16|ct] blob
 *     -> prepend 4-byte big-endian ct length (cleartext prefix)
 *     -> hdn_exe_get_sections(host)    linked list of sections
 *     -> hdn_disassemble_all           Zydis decode + populate operands
 *     -> hdn_subst_insns_tag_valid     mark substitutable insns
 *     -> _embed loop                   walk insns, patch bytes per message
 *                                      bit(s) via hdn_subst_insns()
 *     -> copy patched sections back into host image -> io_fdwrite
 *
 * DATA FLOW (decode)
 * ------------------
 *   io_fileread(stegged host)
 *     -> hdn_exe_get_sections -> hdn_disassemble_all -> tag_valid
 *     -> extract bits from every valid insn until 4 bytes are known,
 *        then continue until exactly prefix+payload bytes are read
 *     -> strip prefix, hdn_crypto_decrypt (GCM tag verifies integrity
 *        and the passphrase), io_fdwrite plaintext
 *
 * The cleartext length prefix is what makes extraction exact: the
 * decoder knows when to stop reading instead of draining the entire
 * code section (the old scheme over-extracted and truncated after an
 * early partial decrypt, which broke with authenticated encryption).
 */

#ifndef _HYDAN_H_
#define _HYDAN_H_

#if (defined(__CYGWIN32__) || defined(_Windows) || defined(_WIN32))
#include <windows.h>
#elif defined(__OpenBSD__)
#include <elf_abi.h>
#else
#include <elf.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <openssl/evp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <Zydis/Zydis.h>

/*
 * compatibility layer over Zydis.  x86_insn_t mirrors the interface of
 * the old libdisasm (type/flags/operands) so the substitution tables
 * keep working, while `zydis` retains the full decoder output.  The
 * operands[] array holds at most the first three decoded operands;
 * operands[1] is conventionally the source (`op_src`), which for our
 * table classes is the immediate when one exists.
 */

enum x86_op_type {
    op_register = ZYDIS_OPERAND_TYPE_REGISTER,
    op_immediate = ZYDIS_OPERAND_TYPE_IMMEDIATE,
    op_relative = ZYDIS_OPERAND_TYPE_MEMORY,
    op_absolute = ZYDIS_OPERAND_TYPE_MEMORY,
    op_expression = ZYDIS_OPERAND_TYPE_MEMORY,
    op_offset = ZYDIS_OPERAND_TYPE_MEMORY,
};

enum x86_op_datatype {
    op_byte = 1,
    op_word = 2,
    op_dword = 4,
    op_qword = 8,
    op_dqword = 16,
    op_sreal = 4,
    op_dreal = 8,
    op_extreal = 10,
    op_bcd = 10,
    op_simd = 16,
    op_fpuenv = 28,
};

typedef struct {
    enum x86_op_type type;
    enum x86_op_datatype datatype;
    union {
        int8_t sbyte;
        int16_t sword;
        int32_t sdword;
        int64_t sqword;
        float sreal;
        double dreal;
    } data;
} x86_op_t;

enum x86_flag_status {
    insn_carry_set = 1 << 0,
    insn_zero_set = 1 << 1,
    insn_oflow_set = 1 << 2,
    insn_dir_set = 1 << 3,
    insn_sign_set = 1 << 4,
    insn_parity_set = 1 << 5,
};

enum x86_insn_type {
    insn_return = ZYDIS_MNEMONIC_RET,
    insn_leave = ZYDIS_MNEMONIC_LEAVE,
    insn_pushflags = ZYDIS_MNEMONIC_PUSHF,
    insn_popflags = ZYDIS_MNEMONIC_POPF,
    insn_jmp = ZYDIS_MNEMONIC_JMP,
    insn_jcc = ZYDIS_MNEMONIC_JB, // approximate for conditional jumps
    insn_call = ZYDIS_MNEMONIC_CALL,
    insn_callcc = ZYDIS_MNEMONIC_CALL, // approximate
    insn_clear_carry = ZYDIS_MNEMONIC_CLC,
    insn_set_carry = ZYDIS_MNEMONIC_STC,
    insn_clear_zero = 0, // not direct
    insn_set_zero = 0,
    insn_clear_oflow = 0,
    insn_set_oflow = 0,
    insn_clear_dir = ZYDIS_MNEMONIC_CLD,
    insn_set_dir = ZYDIS_MNEMONIC_STD,
    insn_clear_sign = 0,
    insn_set_sign = 0,
    insn_clear_parity = 0,
    insn_set_parity = 0
};

#define op_src 1
#define op_dest 0

/*
 * our per-instruction view.  `raw` holds the original instruction
 * bytes (the substitution engine patches raw bytes in the host buffer,
 * not this struct), `size` is the instruction length, and `type` is a
 * mnemonic used by the flag-safety analysis.
 */
typedef struct {
    ZydisDecodedInstruction zydis;
    uint32_t size;
    uint8_t raw[ZYDIS_MAX_INSTRUCTION_LENGTH];
    enum x86_insn_type type;
    enum x86_flag_status flags_set;
    enum x86_flag_status flags_tested;
    x86_op_t operands[3];
} x86_insn_t;

/*
 * number of instructions to skip max in random walk.  The more, the
 * slower..
 */
#define HDN_MAX_SKIP_INSNS 100

/*
 * _PASSWORD_LEN is not always defined
 */
#ifndef _PASSWORD_LEN
#ifdef PASS_MAX
#define _PASSWORD_LEN PASS_MAX
#else
#define _PASSWORD_LEN 8
#endif
#endif

/*
 * holds arbitrarily sized data: `sz` bytes of payload follow the
 * struct header in the same allocation
 * (malloc(sizeof(hdn_data_t) + n)).  Used for files, messages, and
 * section contents alike.
 */
typedef struct hdn_data_s
{
    uint32_t sz;

    char content[1]; //placeholder for more data
} hdn_data_t;

/*
 * linked list of an application's sections -- both data and code.
 * `offset` is where the section lives in the host file image (used to
 * patch embedded bytes back), `type`/`flags` are ELF section type and
 * flags (code sections: SHT_PROGBITS + SHF_ALLOC|SHF_EXECINSTR).
 */
typedef struct hdn_sections_s
{
    struct hdn_sections_s *next;

    uint32_t   offset;  //data offset in original file
    uint8_t   *address; //location in the exe's memory
    uint32_t   type;    //section type
    uint32_t   flags;   //section flags

    hdn_data_t data;    //data itself
} hdn_sections_t;

/*
 * contains meta data about a program's section.  like starting
 * address [so far only thing there, maybe more in the future].
 */
typedef struct hdn_sections_header_s
{
    uint32_t start_addr;

    hdn_sections_t *sections;
} hdn_sections_header_t;

/*
 * denotes wether an insn is valid for disassembly and/or used.
 * Note: these can be ORed together.
 */
enum hdn_insn_status
{
    insn_status_none    = 0x00,
    insn_status_valid   = 0x01, //can be embedded into
    insn_status_bad     = 0x02, //bad instruction
    insn_status_invalid = 0x04, //shouldn't be embedded into
    insn_status_used    = 0x08, //been embedded into
    insn_status_misc    = 0x10, //flag used for misc things like
                                //indicating wether a particular
                                //instruction has been visited before
                                //etc.
};

/*
 * one entry per disassembled instruction.  `memaddr` points into the
 * section buffer (this is what the substitution engine patches in
 * place); `effaddr` is the section's runtime address.  `status` is
 * tagged by hdn_subst_insns_tag_valid().
 */
typedef struct hdn_disassembly_data_s
{
    uint8_t             *memaddr; //where the instruction is our memory
    uint8_t             *effaddr; //effective insn address
    x86_insn_t           insn;
    enum hdn_insn_status status;
} hdn_disassembly_data_t;

#include "hdn_common.h"
#include "hdn_crypto.h"
#include "hdn_decode.h"
#include "hdn_embed.h"
#include "hdn_exe.h"
#include "hdn_io.h"
#include "hdn_math.h"
#include "hdn_reord_insns.h"
#include "hdn_stats.h"
#include "hdn_subst_insns.h"

#endif

/*
 * $Id: hydan.h,v 1.11 2004/04/30 05:27:15 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
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

#include "libdis.h"

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
 * holds arbitrarily sized data
 */
typedef struct hdn_data_s
{
    uint32_t sz;

    char content[1]; //placeholder for more data
} hdn_data_t;

/*
 * linked list of an application's sections -- both data and code.
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
 * holds the data specific from disassembly
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

#ifndef EXTENSION_H
#define EXTENSION_H

#include "bastard.h"
#include "./qword.h"

struct ARCH_INVARIANT {
	unsigned char buf[64];
	int buf_len;
	int insn_type;
	int dest_type, src_type, aux_type;
};


typedef void (*ext_init_fn)(void *);
typedef void (*ext_clean_fn)(void);
struct EXTENSION {
   char *filename;      /* name of extension file [full path] */
   int flags;           /* uhh..... */
   void *lib;           /* pointer to library */
   float version;	/* version # of this plugin */
   ext_init_fn fn_init;       /* init function for extension */
   ext_clean_fn fn_cleanup;    /* cleanup function for extension */
}; /* these are linked to from standard extensions : hll, engine, etc */

/* predef 's for use with dynamic loading */
typedef int (*disaddr_fn)(unsigned char *, int, struct code *, qword qword);
typedef int (*disinv_fn)(unsigned char *, int, struct ARCH_INVARIANT *);
typedef int (*pattern_fn)( qword , int );
typedef int (*geneffect_fn)(struct code *, struct code_effect *);
typedef int (*genint_fn)(struct function *);
struct EXT__ARCH {   /* disassembler information */
   struct EXTENSION ext;
   int options;             // module-specific options
   /* ------------------  CPU Information  -------------------- */
   int cpu_hi, cpu_lo;      // CPU high and low version numbers
   unsigned char endian;    // 0 = BIG, 1 = LITTLE
   unsigned char wc_byte;   // wildcard byte for signatures
   unsigned char sz_addr;   // Default Size of Address in Bytes
   unsigned char sz_oper;   // Default Size of Operand in Bytes
   unsigned char sz_inst;   // Default Size of Instruction in Bytes
   unsigned char sz_byte;   // Size of Machine Byte in Bits
   unsigned char sz_word;   // Size of Machine Word in Bytes
   unsigned char sz_dword;  // Size of Machine DoubleWord in Bytes
   int SP;                  // RegID of Stack Pointer
   int FP;                  // RegID of Frame Pointer
   int IP;                  // RegID of Instruction Pointer
   int reg_gen;             // start of General regs in table
   int reg_seg, reg_fp;     // start of seg, FPU regs in table
   int reg_in, reg_out;     // start of procedure IN, OUT regs in table

   /* ------------------ Register Tables ---------------------- */
   struct REGTBL_ENTRY *reg_table;
   int sz_regtable;
   unsigned char *reg_storage;
   /* ------------------ Library Functions -------------------- */
   disaddr_fn   fn_disasm_addr;      // ptr to disassembly routine
   disinv_fn    fn_disasm_inv;
   pattern_fn   fn_code_pat;
   geneffect_fn fn_gen_effect;
   genint_fn    fn_gen_int;
};
#endif

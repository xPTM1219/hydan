#ifndef LIBDISASM_H
#define LIBDISASM_H

/* 'NEW" types
 * __________________________________________________________________________*/
#ifndef LIBDISASM_QWORD_H	/* do not interfere with qword.h */
	#define LIBDISASM_QWORD_H
	#ifdef _MSC_VER
		typedef __int64		qword;
	#else
		typedef long long	qword;
	#endif
#endif

/* 'NEW" x86 API 
 * __________________________________________________________________________*/


/* ========================================= Error Reporting */
/* REPORT CODES
 * 	These are passed to a reporter function passed at initialization.
 * 	Each code determines the type of the argument passed to the reporter;
 * 	this allows the report to recover from errors, or just log them.
 */
enum x86_report_codes {
	report_disasm_bounds,	/* RVA OUT OF BOUNDS : The disassembler could
				   not disassemble the supplied RVA as it is
				   out of the range of the buffer. The 
				   application should store the address and
				   attempt to determine what section of the 
				   binary it is in, then disassemble the
				   address from the bytes in that section.
				   	arg: unsigned long rva */
	report_insn_bounds,     /* INSTRUCTION OUT OF BOUNDS: The disassembler
				   could not disassemble the instruction as
				   the instruction would require bytes beyond
				   the end of the current buffer. This usually
				   indicated garbage bytes at the end of a
				   buffer, or an incorrectly-sized buffer.
				   	arg: unsigned long rva */
	report_invalid_insn,	/* INVALID INSTRUCTION: The disassembler could
				   not disassemble the instruction as it has an
				   invalid combination of opcodes and operands.
				   This will stop automated disassembly; the
				   application can restart the disassembly
				   after the invalid instruction.
				   	arg: unsigned long rva */
	report_unknown
};

typedef void (*DISASM_REPORTER)( enum x86_report_codes code, void *arg );

/* x86_report_error : Call the register reporter to report an error */
void x86_report_error( enum x86_report_codes code, void *arg );

/* ========================================= Libdisasm Management Routines */
enum x86_options {
	opt_none= 0,
	opt_ignore_nulls=1,	/* ignore sequences of > 4 NULL bytes */
	opt_16_bit=2,		/* 16-bit/DOS disassembly */
	opt_unknown
};

int x86_init( enum x86_options options, DISASM_REPORTER reporter);
void x86_set_options( enum x86_options options );
int x86_get_options( void );
int x86_cleanup(void);


/* ========================================= Instruction Representation */
/* these defines are only intended for use in the array decl's */
#define MAX_REGNAME 8
#define MAX_INSN_SIZE 20	/* same as in i386.h */
#define MAX_OP_STRING 32	/* max possible operand size in string form */

enum x86_reg_type { 	/* NOTE: these may be ORed together */
	reg_gen 	= 0x00001,	/* general purpose */
	reg_in 		= 0x00002,	/* incoming args, ala RISC */ 
	reg_out 	= 0x00004,	/* args to calls, ala RISC */
	reg_local 	= 0x00008,	/* local vars, ala RISC */
	reg_fpu 	= 0x00010,	/* FPU data register */
	reg_seg 	= 0x00020,	/* segment register */
	reg_simd 	= 0x00040,	/* SIMD/MMX reg */
	reg_sys 	= 0x00080,	/* restricted/system register */
	reg_sp 		= 0x00100,	/* stack pointer */
	reg_fp		= 0x00200,	/* frame pointer */
	reg_pc		= 0x00400,	/* program counter */
	reg_retaddr 	= 0x00800,	/* return addr for func */
	reg_cond 	= 0x01000,	/* condition code / flags */
	reg_zero 	= 0x02000,	/* zero register, ala RISC */
	reg_ret 	= 0x04000,	/* return value */
	reg_src 	= 0x10000,	/* array/rep source */
	reg_dest	= 0x20000,	/* array/rep destination */
	reg_count 	= 0x40000	/* array/rep/loop counter */
};

typedef struct {
	char name[MAX_REGNAME];
	int type;			/* what register is used for */
	int size;			/* size of register in bytes */
	int id;				/* register ID #, for quick compares */
} x86_reg_t;

typedef struct {
	unsigned int     scale;		/* scale factor */
	x86_reg_t        index, base;	/* index, base registers */
	long             disp;		/* displacement */
	char             disp_sign;	/* is negative? 1/0 */
	char             disp_size;	/* 0, 1, 2, 4 */
} x86_ea_t;

enum x86_op_type {	/* mutually exclusive */
	op_unused = 0,		/* empty/unused operand */
	op_register = 1,	/* CPU register */
	op_immediate = 2,	/* Immediate Value */
	op_relative = 3,	/* Relative offset from IP */
	op_absolute = 4,	/* Absolute address (ptr16:32) */
	op_expression = 5,	/* Address expression (scale/index/base/disp) */
	op_offset = 6,		/* Offset from start of segment (m32) */
	op_unknown
};

enum x86_op_datatype {		/* these use Intel's lame terminology */
	op_byte = 1,		/* 1 byte integer */
	op_word = 2,		/* 2 byte integer */
	op_dword = 3,		/* 4 byte integer */
	op_qword = 4,		/* 8 byte integer */
	op_dqword = 5,		/* 16 byte integer */
	op_sreal = 6,		/* 4 byte real (single real) */
	op_dreal = 7,		/* 8 byte real (double real) */
	op_extreal = 8,		/* 10 byte real (extended real) */
	op_bcd = 9,		/* 10 byte binary-coded decimal */
	op_simd = 10,		/* 16 byte packed (SIMD, MMX) */
	op_fpuenv = 11		/* 28 byte FPU control/environment data */
};

enum x86_op_access {	/* ORed together */
	op_read = 1,
	op_write = 2,
	op_execute = 4
};

enum x86_op_flags {	/* ORed together, but segs are mutually exclusive */
	op_signed = 1,		/* signed integer */
	op_string = 2,		/* possible string or array */
	op_constant = 4,	/* symbolic constant */
	op_pointer = 8,		/* operand points to a memory address */
	op_es_seg = 0x100,	/* ES segment override */
	op_cs_seg = 0x200,	/* CS segment override */
	op_ss_seg = 0x300,	/* SS segment override */
	op_ds_seg = 0x400,	/* DS segment override */
	op_fs_seg = 0x500,	/* FS segment override */
	op_gs_seg = 0x600	/* GS segment override */
};
	

typedef struct {
	enum x86_op_type 	type;		/* operand type */
	enum x86_op_datatype 	datatype;	/* operand size */
	enum x86_op_access 	access;		/* operand access [RWX] */
	enum x86_op_flags	flags;		/* misc flags */
	union {
		/* immediate values */
		char 		sbyte;
		short 		sword;
		long 		sdword;
		unsigned char 	byte;
		unsigned short 	word;
		unsigned long 	dword;
		qword 		sqword;
		float	        sreal;	
		double	        dreal;	
		/* misc large/non-native types */
		unsigned char 	extreal[10];
		unsigned char 	bcd[10];
		qword		dqword[2];
		unsigned char	simd[16];
		unsigned char	fpuenv[28];
		/* absolute address */
		void 		* address;
		/* offset from segment */
		unsigned long	offset;
		/* ID of CPU register */
		x86_reg_t	reg;
		/* offsets from current insn */
		char 		near_offset;
		long 		far_offset;
		/* effective address [expression] */
		x86_ea_t 	effective_addr;
	} data;
} x86_op_t;

enum x86_insn_group {
	insn_controlflow = 1,
	insn_arithmetic = 2,
	insn_logic = 3,
	insn_stack = 4,
	insn_comparison = 5,
	insn_move = 6,
	insn_string = 7,
	insn_bit_manip = 8,
	insn_flag_manip = 9,
	insn_fpu = 10,
	insn_interrupt = 13,
	insn_system = 14,
	insn_other = 15
};

enum x86_insn_type {
	/* insn_controlflow */
	insn_jmp = 0x1001,
	insn_jcc = 0x1002,
	insn_call = 0x1003,
	insn_callcc = 0x1004,
	insn_return = 0x1005,
	insn_loop = 0x1006,
	/* insn_arithmetic */
	insn_add = 0x2001,
	insn_sub = 0x2002,
	insn_mul = 0x2003,
	insn_div = 0x2004,
	insn_inc = 0x2005,
	insn_dec = 0x2006,
	insn_shl = 0x2007,
	insn_shr = 0x2008,
	insn_rol = 0x2009,
	insn_ror = 0x200A,
	/* insn_logic */
	insn_and = 0x3001,
	insn_or = 0x3002,
	insn_xor = 0x3003,
	insn_not = 0x3004,
	insn_neg = 0x3005,
	/* insn_stack */
	insn_push = 0x4001,
	insn_pop = 0x4002,
	insn_pushregs = 0x4003,
	insn_popregs = 0x4004,
	insn_pushflags = 0x4005,
	insn_popflags = 0x4006,
	insn_enter = 0x4007,
	insn_leave = 0x4008,
	/* insn_comparison */
	insn_test = 0x5001,
	insn_cmp = 0x5002,
	/* insn_move */
	insn_mov = 0x6001,	/* move */
	insn_movcc = 0x6002,	/* conditional move */
	insn_xchg = 0x6003,	/* exchange */
	insn_xchgcc = 0x6004,	/* conditional exchange */
	/* insn_string */
	insn_strcmp = 0x7001,
	insn_strload = 0x7002,
	insn_strmov = 0x7003,
	insn_strstore = 0x7004,
	insn_translate = 0x7005,	/* xlat */
	/* insn_bit_manip */
	insn_bittest = 0x8001,
	insn_bitset = 0x8002,
	insn_bitclear = 0x8003,
	/* insn_flag_manip */
	insn_clear_carry = 0x9001,
	insn_clear_zero = 0x9002,
	insn_clear_oflow = 0x9003,
	insn_clear_dir = 0x9004,
	insn_clear_sign = 0x9005,
	insn_clear_parity = 0x9006,
	insn_set_carry = 0x9007,
	insn_set_zero = 0x9008,
	insn_set_oflow = 0x9009,
	insn_set_dir = 0x900A,
	insn_set_sign = 0x900B,
	insn_set_parity = 0x900C,
	insn_tog_carry = 0x9010,
	insn_tog_zero = 0x9020,
	insn_tog_oflow = 0x9030,
	insn_tog_dir = 0x9040,
	insn_tog_sign = 0x9050,
	insn_tog_parity = 0x9060,
	/* insn_fpu */
	insn_fmov = 0xA001,
	insn_fmovcc = 0xA002,
	insn_fneg = 0xA003,
	insn_fabs = 0xA004,
	insn_fadd = 0xA005,
	insn_fsub = 0xA006,
	insn_fmul = 0xA007,
	insn_fdiv = 0xA008,
	insn_fsqrt = 0xA009,
	insn_fcmp = 0xA00A,
	insn_fcos = 0xA00C,
	insn_fldpi = 0xA00D,
	insn_fldz = 0xA00E,
	insn_ftan = 0xA00F,
	insn_fsine = 0xA010,
	insn_fsys = 0xA020,
	/* insn_interrupt */
	insn_int = 0xD001,
	insn_intcc = 0xD002, 	/* not present in x86 ISA */
	insn_iret = 0xD003,
	insn_bound = 0xD004,
	insn_debug = 0xD005,
	insn_trace = 0xD006,
	insn_invalid_op = 0xD007,
	insn_oflow = 0xD008,
	/* insn_system */
	insn_halt = 0xE001,
	insn_in = 0xE002,	/* input from port/bus */
	insn_out = 0xE003, 	/* output to port/bus */
	insn_cpuid = 0xE004,
	/* insn_other */
	insn_nop = 0xF001,
	insn_bcdconv = 0xF002, 	/* convert to or from BCD */
	insn_szconv = 0xF003	/* change size of operand */
};

enum x86_flag_status {
	insn_carry_set = 0x1,
	insn_zero_set = 0x2,
	insn_oflow_set = 0x4,
	insn_dir_set = 0x8,
	insn_sign_set = 0x10,
	insn_parity_set = 0x20,
	insn_carry_or_zero_set = 0x40,
	insn_zero_set_or_sign_ne_oflow = 0x80,
	insn_carry_clear = 0x100,
	insn_zero_clear = 0x200,
	insn_oflow_clear = 0x400,
	insn_dir_clear = 0x800,
	insn_sign_clear = 0x1000,
	insn_parity_clear = 0x2000,
	insn_sign_eq_oflow = 0x4000,
	insn_sign_ne_oflow = 0x8000
};

enum x86_insn_prefix {
	insn_no_prefix = 0,
	insn_rep_zero = 1,
	insn_rep_notzero = 2,
	insn_lock = 4,
	insn_delay = 8
};

enum x86_operand_id { op_dest=0, op_src=1, op_imm=2 };

typedef struct {
	/* information about the instruction */
	unsigned long addr;		/* load address */
	unsigned long offset;		/* offset into file/buffer */
	enum x86_insn_group group;	/* meta-type, e.g. INSN_EXEC */
	enum x86_insn_type type;	/* type, e.g. INSN_BRANCH */
	unsigned char bytes[MAX_INSN_SIZE];
	unsigned char size;		/* size of insn in bytes */
	enum x86_insn_prefix prefix;
	enum x86_flag_status flags_set; /* flags set or tested by insn */
	enum x86_flag_status flags_tested; 
	/* the instruction proper */
	char prefix_string[32];		/* prefixes [might be truncated] */
	char mnemonic[8];
	x86_op_t operands[3];
	/* convenience fields for user */
	void *block;			/* code block containing this insn */
	void *function;			/* function containing this insn */ 
	void *tag;			/* tag the insn as seen/processed */
} x86_insn_t;
	

/* DISASSEMBLY ROUTINES
 * 	Canonical order of arguments is
 * 	  (buf, buf_len, buf_rva, offset, len, insn, func, arg, resolve_func)
 * 	...but of course all of these are not used at the same time.
 */


/* Function prototype for caller-supplied callback routine 
 * 	These callbacks are intended to process 'insn' further, e.g. by
 * 	adding it to a linked list, database, etc */
typedef void (*DISASM_CALLBACK)( x86_insn_t *insn, void * arg );

/* Function prototype for caller-supplied address resolver.
 *  	This routine is used to determine the rva to disassemble next, given 
 *  	the 'dest' operand of a jump/call. This allows the caller to resolve 
 *  	jump/call targets stored in a register or on the stack, and also allows
 *  	the caller to prevent endless loops by checking if an address has 
 *  	already been disassembled. If an address cannot be resolved from the 
 *  	operand, or if the address has already been disassembled, this routine 
 *  	should return -1; in all other cases the RVA to be disassembled next 
 *  	should be returned. */
typedef long (*DISASM_RESOLVER)( x86_op_t *op, x86_insn_t * current_insn );

/* x86_disasm: Disassemble a single instruction from a buffer of bytes. 
 *             Returns size of instruction in bytes.
 *	buf     : Buffer of bytes to disassemble
 *	buf_len : Length of the buffer
 *	buf_rva : Load address of the start of the buffer
 * 	offset  : Offset in buffer to disassemble 
 *	insn    : Structure to fill with disassembled instruction
 */
int x86_disasm( unsigned char *buf, unsigned int buf_len, 
		unsigned long buf_rva, unsigned int offset,
		x86_insn_t * insn );

/* x86_disasm_range: Sequential disassembly of a range of bytes in a buffer,
 *                   invoking a callback function each time an instruction
 *                   is successfully disassembled. The 'range' refers to the 
 *                   bytes between 'offset' and 'offset + len' in the buffer;
 *                   'len' is assumed to be less than the length of the buffer.
 *                   Returns number of instructions processed.
 * 	buf     : Buffer of bytes to disassemble (e.g. .text section)
 * 	buf_rva : Load address of buffer (e.g. ELF Virtual Address)
 * 	offset  : Offset in buffer to start disassembly at 
 * 	len     : Number of bytes to disassemble 
 * 	func    : Callback function to invoke (may be NULL)
 * 	arg     : Arbitrary data to pass to callback (may be NULL)
 */
int x86_disasm_range( unsigned char *buf, unsigned long buf_rva, 
		      unsigned int offset, unsigned int len, 
		      DISASM_CALLBACK func, void *arg );

/* x86_disasm_forward: Flow-of-execution disassembly of the bytes in a buffer,
 *                     invoking a callback function each time an instruction
 *                     is successfully disassembled.
 * 	buf     : Buffer to disassemble (e.g. .text section)
 * 	buf_len : Number of bytes in buffer
 * 	buf_rva : Load address of buffer (e.g. ELF Virtual Address)
 * 	offset  : Offset in buffer to start disassembly at (e.g. entry point)
 * 	func    : Callback function to invoke (may be NULL)
 * 	arg     : Arbitrary data to pass to callback (may be NULL)
 * 	resolver: Caller-supplied address resolver. If no resolver is
 * 	          supplied, a default internal one is used -- however the
 * 	          internal resolver does NOT catch loops and could end up
 * 	          disassembling forever..
 */
int x86_disasm_forward( unsigned char *buf, unsigned int buf_len, 
			unsigned long buf_rva, unsigned int offset, 
			DISASM_CALLBACK func, void *arg,
			DISASM_RESOLVER resolver );

x86_op_t * x86_get_operand( x86_insn_t *insn, enum x86_operand_id id );
x86_op_t * x86_get_dest_operand( x86_insn_t *insn );
x86_op_t * x86_get_src_operand( x86_insn_t *insn );
x86_op_t * x86_get_imm_operand( x86_insn_t *insn );
/* get size of operand data in bytes */
int x86_operand_size( x86_op_t *op );

/* Get Raw Immediate Data: returns a pointer to the immediate data encoded
 * in the instruction. This is useful for large data types [>32 bits] currently
 * not supported by libdisasm, or for determining if the disassembler
 * screwed up the conversion of the immediate data. Note that 'imm' in this
 * context refers to immediate data encoded at the end of an instruction as
 * detailed in the Intel Manual Vol II Chapter 2; it does not refer to the
 * 'op_imm' operand (the third operand in instructions like 'mul' */
unsigned char * x86_get_raw_imm( x86_insn_t *insn );

void x86_set_insn_addr( x86_insn_t *insn, unsigned long addr );
void x86_set_insn_offset( x86_insn_t *insn, unsigned int offset );
void x86_set_insn_function( x86_insn_t *insn, void * func );
void x86_set_insn_block( x86_insn_t *insn, void * block );
void x86_tag_insn( x86_insn_t *insn );
void x86_untag_insn( x86_insn_t *insn );
int x86_insn_is_tagged( x86_insn_t *insn );


/* Disassembly formats:
 * 	AT&T is standard AS/GAS-style: "mnemonic\tsrc, dest, imm"
 * 	Intel is standard MASM/NASM/TASM: "mnemonic\tdest,src, imm"
 * 	Native is tab-delimited: "RVA\tbytes\tmnemonic\tdest\tsrc\timm"
 */
enum x86_asm_format { native_syntax, intel_syntax, att_syntax };

int x86_format_operand(x86_op_t *op, x86_insn_t *insn, char *buf, int len, 
		  enum x86_asm_format);

int x86_format_mnemonic(x86_insn_t *insn, char *buf, int len, 
		        enum x86_asm_format);

int x86_format_insn(x86_insn_t *insn, char *buf, int len, enum x86_asm_format);

/* Endianness of CPU */
int x86_endian(void);

/* Default address and operand size in bytes */
int x86_addr_size(void);
int x86_op_size(void);

/* Size of a machine word in bytes */
int x86_word_size(void);

/* maximum size of a code instruction */
int x86_max_inst_size(void);

/* register IDs of Stack, Frame, and Instruction pointer */
int x86_sp_reg(void);
int x86_fp_reg(void);
int x86_ip_reg(void);


/* allow users to remove the old, bad-namespace API with a #define */
#ifndef LIBDISASM_NO_COMPAT

/* "OLD" libdisasm API 
 * __________________________________________________________________________*/

#include "bastard.h"
/* "legacy" routines provided for backwards compatibility */
struct x86_old_instr {
    char    mnemonic[16];
    char    dest[32];
    char    src[32];
    char    aux[32];
    int     mnemType;
    int     destType;
    int     srcType;
    int     auxType;
    int     size;
};

int x86_old_init(int options, int format);

int x86_old_sprint_addexp(char *str, int len, struct addr_exp *e);

int x86_old_disasm_addr(char *buf, int buf_len, struct x86_old_instr *i);

int x86_old_sprint_addr(char *str, int len, char *buf, int buf_len);

/* x86_old_disasm_addr_raw() fills a bastard-style code struct instead of a
 * libdisasm instr struct. The code struct contains the operands in their
 * binary format -- the operand type must be used to determine how to
 * display the operand:
 *   OP_REG  - operand is a pointer to a string constant 
 *   OP_IMM  - operand is an immediate value
 *   OP_REL  - operand is a val to be added to %eip
 *   OP_ADDR - operand is an absolute address
 *   OP_EXPR - operand is a pointer to an addr_exp struct
 *   OP_OFF  - operand is a segment offset 
 * Note that the operand should be tested to determine if it is signed
 * (op_type & OP_SIGNED) for OP_IMM and OP_REL types. The string reference
 * in an OP_REG operand is static & constant and should NOT be free()ed; the
 * addr_exp reference in an OP_EXPR operand is dynamically allocated and
 * MUST be free()ed.
 * The code struct is defined in bastard.h
 */
int x86old_disasm_addr_raw(char *buf, int buf_len, struct code *c);

/* formats : */
#define NATIVE_SYNTAX 0
#define INTEL_SYNTAX  1
#define ATT_SYNTAX    2

#define instr x86_old_instr

#define disassemble_init x86_old_init
#define disassemble_cleanup x86_cleanup

#define sprint_addrexp x86_old_sprint_addexp
#define disassemble_address x86_old_disasm_addr
#define sprint_address x86_old_sprint_addr
#define disassemble_address_raw x86old_disasm_addr_raw

#define cpu_endian x86_endian
#define cpu_addr_size x86_addr_size
#define cpu_op_size x86_op_size
#define cpu_word_size x86_word_size
#define cpu_inst_size x86_max_inst_size
#define cpu_sp x86_sp_reg
#define cpu_fp x86_fp_reg
#define cpu_ip x86_ip_reg

#define op_type(x) (x & OP_TYPE_MASK)
#define op_size(x) (x & OP_SIZE_MASK)
#define op_perm(x) (x & OP_PERM_MASK)
#define op_mod(x) (x & OP_MOD_MASK)
/* operand segment override */
#define op_seg(x) (x & OP_SEG_MASK)
/* is operand a register */
#define op_isreg(x) (x & OP_REG)

/* These take instruction type as a parameter */
#define insn_type(x)  (x & INSN_TYPE_MASK)
#define insn_group(x) (x & INSN_GROUP_MASK)
#define insn_mod(x) (x & INSN_MOD_MASK)
#define insn_size(x) (x & INSN_SIZE_MASK)

#endif


#endif

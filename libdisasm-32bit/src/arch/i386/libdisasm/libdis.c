#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "./libdis.h"
#include "./i386.h"

#ifdef _MSC_VER
	#define snprintf	_snprintf
	#define inline		__inline
#endif


/* =========================================================== INIT/TERM */
struct EXT__ARCH ext_arch = {0};
static DISASM_REPORTER reporter_func = NULL;

int x86_init(enum x86_options options, DISASM_REPORTER reporter)
{
	ext_arch.options = (int) options;
	reporter_func = reporter;

	ext_arch_init(&ext_arch);
	return (1);
}

void x86_set_options( enum x86_options options ){
	ext_arch.options = (int) options;
}

int x86_get_options( void ) {
	return(ext_arch.options);
}

int x86_cleanup(void)
{
	ext_arch_cleanup();
	return (1);
}

/* =========================================================== ERRORS */
void x86_report_error( enum x86_report_codes code, void *arg ) {
	if ( reporter_func ) {
		(*reporter_func)(code, arg);
	}
}

/* =========================================================== UTILITY */


static __inline void get_reg( int id, x86_reg_t *reg ) {
	strncpy(reg->name, vm_get_reg_name(id), MAX_REGNAME);
	reg->type = vm_get_reg_type( id );
	reg->size = vm_get_reg_size( id );
	reg->id = id;
}

/* Each addrexp can only be used once; this call removes the addr_exp from
 * the list. */
static int get_ea_from_addrexp(unsigned long id, x86_ea_t *ea ) {
	struct EXPRLIST e;
	if (! ea ) {
		return(0);
	}

	memset( ea, 0, sizeof(x86_ea_t) );

	if ( addrexp_get(id, &e) ) {
		ea->disp_sign = ea->disp_size = 0;
		ea->disp = (long) e.disp;
		ea->scale = e.scale ? e.scale : 1;
		if ( AddrExp_IndexType(e.flags) ) {
			get_reg(e.index, &ea->index);
		}
		if ( AddrExp_BaseType(e.flags) ) {
			get_reg(e.base, &ea->base);
		}
		/* get size, sign of displacement */
		if ( AddrExp_DispType(e.flags) == ADDREXP_BYTE ) {
			if ( (char) e.disp < 0 ) {
				ea->disp_sign = 1;
			}
			ea->disp_size = 1;
		} else if ( AddrExp_DispType(e.flags) == ADDREXP_WORD ) {
			if ( (short) e.disp < 0 ) {
				ea->disp_sign = 1;
			}
			ea->disp_size = 2;
		} else if ( AddrExp_DispType(e.flags) == ADDREXP_DWORD ) {
			if ( (long) e.disp < 0 ) {
				ea->disp_sign = 1;
			}
			ea->disp_size = 4;
		}
		return(1);
	}

	return(0);
}

static int insn_op_from_code( x86_op_t *op, qword op_val, int op_type ){
	x86_ea_t *ea;
	x86_reg_t *reg;
	int iop = (int) op_val;

	if (! op ) { return(0); }

	if (! op_type ) {
		op->type = op_unused;
		return(1);
	}
	/* set operand type and value */
	op->access = OP_PERM(op_type);
	op->type = OP_TYPE(op_type) >> 8;
	if (! op->type ) {
		op->type = op_unknown;
	}
	op->flags = OP_MOD(op_type) >> 12;
	op->datatype = OP_SIZE(op_type) >> 24;
	if (! op->datatype ) {
		op->datatype = op_dword;
	}

	/* TODO: handle float, etc types */
	switch ( OP_TYPE(op_type) ) {
		case OP_REG:
			/* op_val is reg ID */
			get_reg( iop, &op->data.reg );
			break;
		case OP_IMM:
			if ( OP_SIZE(op_type) == OP_BYTE ) {
				if ( OP_MOD(op_type) & OP_SIGNED )
					op->data.sbyte = (char) iop;
				else
					op->data.byte = (unsigned char) iop;
			} else if (OP_SIZE(op_type) == OP_HWORD ) {
				if ( OP_MOD(op_type) & OP_SIGNED )
					op->data.sword = (short) iop;
				else
					op->data.word = (unsigned short) iop;
			} else if (OP_SIZE(op_type) == OP_DWORD ) {
				op->data.sqword = op_val;
			} else  { /* WORD is default */
				if ( OP_MOD(op_type) & OP_SIGNED )
					op->data.sdword = (long) iop;
				else
					op->data.dword = (unsigned long) iop;
			}
			break;
		case OP_REL:
			/* op_val is a signed something */
			if ( OP_SIZE(op_type) == OP_BYTE ) {
				op->data.near_offset = (char) iop;
			} else {
				op->data.far_offset = (long) iop;
			}
			break;
		case OP_ADDR:
			/* op_val is an unsigned long */
			op->data.address = (void *) ((unsigned long) iop);
			break;
		case OP_EXPR:
			/* op_val is expr ID */
			get_ea_from_addrexp( (unsigned long) iop, 
					     &op->data.effective_addr);
			break;
		case OP_OFF:
			/* op_val is an unsigned long */
			op->data.offset = (unsigned long) iop;
			break;
		default:
			break;
	}
	return(1);
}

static char *prefix_strings[] = {
	"",	/* no prefix */
	"repz ", /* the trailing spaces make it easy to prepend to mnemonic */
	"repnz ",
	"lock ",
	"branch delay " /* unused in x86 */
};

static int x86insn_from_code( x86_insn_t *insn, struct code *code ) {
	char *ptr;
	unsigned int flags;

	if ( ! insn || ! code ) {
		return(0);
	}

	insn->group = INS_GROUP(code->mnem_type) >> 12;
	insn->type = INS_TYPE(code->mnem_type);
	insn->prefix = INS_MOD(code->mnem_type) >> 20;
	if ( (unsigned int) insn->prefix > 8 ) {
		insn->prefix = insn_no_prefix;
	}

	/* handle flags effected */
	flags = INS_FLAGS_TEST(code->flags_st);
	/* handle weird OR cases */
	/* these are either JLE (ZF | SF<>OF) or JBE (CF | ZF) */
	if (flags & INS_TEST_OR) {
		flags &= ~INS_TEST_OR;
		if ( flags & INS_TEST_ZERO ) {
			flags &= ~INS_TEST_ZERO;
			if ( flags & INS_TEST_CARRY ) {
				flags &= ~INS_TEST_CARRY ;
				flags |= (int)insn_carry_or_zero_set;
			} else if ( flags & INS_TEST_SFNEOF ) {
				flags &= ~INS_TEST_SFNEOF; 
				flags |= (int)insn_zero_set_or_sign_ne_oflow;
			}
		}
	}
	insn->flags_tested = flags;
	
	insn->flags_set = INS_FLAGS_SET(code->flags_st) >> 16;


	/* concat all prefix strings */
	if ( (int)insn->prefix & 1 ) {
		strncat(insn->prefix_string, prefix_strings[1], 32);
	} else if ( (int)insn->prefix & 2 ) {
		strncat(insn->prefix_string, prefix_strings[2], 32);
	}
	if ( (int)insn->prefix & 4 ) {
		strncat(insn->prefix_string, prefix_strings[3], 32);
	}
	if ( (int)insn->prefix & 8 ) {
		strncat(insn->prefix_string, prefix_strings[4], 32);
	}
	
	/* create mnemonic and operands */
	strncpy(insn->mnemonic, code->mnemonic, 7);
	insn_op_from_code( &insn->operands[(int)op_dest], code->dest,
			   code->dest_type );
	insn_op_from_code( &insn->operands[(int)op_src], code->src,
			   code->src_type );
	insn_op_from_code( &insn->operands[(int)op_imm], code->aux,
			   code->aux_type );

	return(1);
	
}

int x86_disasm( unsigned char *buf, unsigned int buf_len, 
		unsigned long buf_rva, unsigned int offset,
		x86_insn_t *insn ){
	int len, size;
	struct code c = { 0 };
	unsigned char disasm_buf[32] = {0};

	if ( ! buf || ! insn || ! buf_len ) {
		/* caller screwed up somehow */
		return(0);
	}

	/* clear insn struct */
	memset(insn, 0, sizeof (x86_insn_t));

	if ( offset >= buf_len ) {
		/* another caller screwup ;) */
		x86_report_error(report_disasm_bounds, (char*)buf_rva+offset);
		return(0);
	}

	/* copy binary code to temporary buffer */
	len = buf_len - offset;
	memcpy( disasm_buf, buf + offset, (len > cpu_inst_size()) ? 
			               cpu_inst_size() : len  );

	/* actually do the disassembly */
	size = disasm_addr(disasm_buf, 0, &c, 0);
	
	/* check and see if we had an invalid instruction */
	if (! size ) {
		x86_report_error(report_invalid_insn, (char*)buf_rva+offset );
		return(0);
	}

	/* check if we overran the end of the buffer */
	if ( size > len ) {
		x86_report_error( report_insn_bounds, (char*)buf_rva + offset );
		return(0);
	}

	/* fill x86_insn_t with struct code stuff */
	x86insn_from_code( insn, &c );

	/* fill rva, offset, and bytes fields of insn */
	insn->addr = buf_rva + offset;
	insn->offset = offset;
	insn->size = size;
	memcpy( insn->bytes, buf + offset, size );

	return (size);
}

int x86_disasm_range( unsigned char *buf, unsigned long buf_rva, 
		      unsigned int offset, unsigned int len,
		      DISASM_CALLBACK func, void *arg ) {
	x86_insn_t insn;
	int buf_len, size, count = 0, bytes = 0;

	/* buf_len is implied by the arguments */
	buf_len = len + offset;

	while ( bytes < len ) {
		size = x86_disasm( buf, buf_len, buf_rva, offset + bytes, 
				   &insn );
		if ( size ) {
			/* invoke callback if it exists */
			if ( func ) {
				(*func)( &insn, arg );
			}
			bytes += size;
			count ++;
		} else {
			/* error */
			bytes++;	/* try next byte */
		}
	}

	return( count );
}

static inline int follow_insn_dest( x86_insn_t *insn ) {
	if ( insn->type == insn_jmp || insn->type == insn_jcc ||
	     insn->type == insn_call || insn->type == insn_callcc ) {
		return(1);
	}
	return(0);
}

static inline int insn_doesnt_return( x86_insn_t *insn ) {
	return( (insn->type == insn_jmp || insn->type == insn_return) ? 1: 0 );
}

static long internal_resolver( x86_op_t *op, x86_insn_t *insn ){
	long next_addr = -1;
	if ( op->type == op_absolute || op->type == op_offset ) {
		next_addr = op->data.sdword;
	} else if ( op->type == op_relative ){
		/* add offset to current rva+size based on op size */
		if ( op->datatype == op_byte ) {
			next_addr = insn->addr + insn->size + op->data.sbyte;
		} else if ( op->datatype == op_word ) {
			next_addr = insn->addr + insn->size + op->data.sword;
		} else if ( op->datatype == op_dword ) {
			next_addr = insn->addr + insn->size + op->data.sdword;
		}
	}
	return( next_addr );
}

int x86_disasm_forward( unsigned char *buf, unsigned int buf_len, 
			unsigned long buf_rva, unsigned int offset, 
			DISASM_CALLBACK func, void *arg,
			DISASM_RESOLVER resolver ){
	x86_insn_t insn;
	x86_op_t *op;
	long next_addr;
	unsigned long next_offset;
	int size, count = 0, bytes = 0, cont = 1;

	while ( cont && bytes < buf_len ) {
		size = x86_disasm( buf, buf_len, buf_rva, offset + bytes, 
			   &insn );

		if ( size ) {
			/* invoke callback if it exists */
			if ( func ) {
				(*func)( &insn, arg );
			}
			bytes += size;
			count ++;
		} else {
			/* error */
			bytes++;	/* try next byte */
		}

		if ( follow_insn_dest(&insn) ) {
			op = &insn.operands[0];
			next_addr = -1;

			/* if caller supplied a resolver, use it to determine
			 * the address to disassemble */
			if ( resolver ) {
				next_addr = resolver(op, &insn);
			} else {
				next_addr = internal_resolver(op, &insn);
			}
			
			if (next_addr != -1 ) {
				next_offset = next_addr - buf_rva;
				/* if offset is in this buffer... */
				if ( next_offset >= 0 && 
				     next_offset < buf_len ) {
					/* go ahead and disassemble */
					count += x86_disasm_forward( buf, 
							    buf_len,
							    buf_rva, 
							    next_offset,
							    func, arg,
							    resolver );
				} else  {
					/* report unresolved address */
					x86_report_error( report_disasm_bounds,
						     (void *) next_addr );
				}
			}
		} /* end follow_insn */

		if ( insn_doesnt_return(&insn) ) {
			/* stop disassembling */
			cont = 0;
		}
	}
	return( count );
}

#define PRINT_DISPLACEMENT(ea)						\
		if ( ea->disp ) {					\
			if ( ea->disp_size > 1 && ! ea->disp_sign ) {	\
				sprintf(str, "0x%X", ea->disp);		\
			} else {					\
				sprintf(str, "%d", ea->disp);		\
			}						\
			strncat( buf, str, len );			\
			len -= strlen(str);				\
		}

static int format_expr( x86_ea_t *ea, char *buf, int len,
		enum x86_asm_format format ) {
	char str[MAX_OP_STRING];

	if ( format == att_syntax ) {
		PRINT_DISPLACEMENT(ea);
		strncat( buf, "(", len );
		len--;

		if ( ea->base.name[0]) {
			strncat( str, "%", len );
			len--;
			strncat( buf, ea->base.name, len );
			len -= strlen(ea->base.name);
		}
		if ( ea->index.name[0]) {
			strncat( buf, ",%", len );
			len -= 2;
			strncat( buf, ea->index.name, len );
			len -= strlen(ea->index.name);
			if ( ea->scale > 1 ) {
				sprintf( str, ",%d", ea->scale );
				strncat( buf, str, len );
				len -= strlen(str);
			}
		}
		/* handle the syntactic exception */
		if ( ! ea->base.name[0] && 
		     ! ea->index.name[0]   ) {
			sprintf( str, ",%d", ea->scale );
			strncat( buf, str, len );
			len -= strlen(str);
		}
		strncat( buf, ")", len );
		len--;
	} else {
		strncat( buf, "[", len );
		len--;
		if ( ea->base.name[0] ) {
			strncat( buf, ea->base.name, len );
			len -= strlen(ea->base.name);
			if (  ea->index.name[0] || 
			      (ea->disp && ! ea->disp_sign) ) {
				strncat( buf, "+", len );
				len--;
			}
		}
		if ( ea->index.name[0] ) {
			strncat( buf, ea->index.name, len );
			len -= strlen(ea->index.name);
			if ( ea->scale > 1 ) {
				sprintf(str, "*%d", ea->scale);
				strncat( buf, str, len );
				len -= strlen(str);
			}
			if (  ea->disp && ! ea->disp_sign ) {
				strncat( buf, "+", len );
				len--;
			}
		}
			
		if (ea->disp || (! ea->index.name[0] && ! ea->base.name[0])){
			PRINT_DISPLACEMENT(ea);
		}

		strncat( buf, "]", len );
		len--;
	}

	return( strlen(buf) );
}

static int format_seg( x86_op_t *op, char *buf, int len,
		enum x86_asm_format format ) {
	int total = 0;
	char *reg = "";

	if (! op || ! buf || ! len || ! op->flags) {
		return(0);
	}
	if ( op->type != op_absolute && op->type != op_offset &&
	     op->type != op_expression ){
		return(0);
	}
	if (! (int) op->flags & 0xF00 ) {
		return(0);
	}

	if ( format == att_syntax ) {
		strncat(buf, "%", len);
		len--;
		total++;
	}
	switch (op->flags & 0xF00) {
		case op_es_seg: reg = "es:"; break;
		case op_cs_seg: reg = "cs:"; break;
		case op_ss_seg: reg = "ss:"; break;
		case op_ds_seg: reg = "ds:"; break;
		case op_fs_seg: reg = "fs:"; break;
		case op_gs_seg: reg = "gs:"; break;
		default:
			break;
	}
	strncat(buf, reg, len);
	return( total + 3 ); /* return length of string */
}

int x86_format_operand( x86_op_t *op, x86_insn_t *insn, char *buf, int len, 
		        enum x86_asm_format format ){
	char str[MAX_OP_STRING];

	if ( ! op || ! buf || len < 1 ) {
		return(0);
	}

	memset(buf, 0, len);
	switch( op->type ) {
		case op_register:
			if ( format == att_syntax ){
				strncat(buf, "%", len);
				len--;
			}
			strncat(buf, op->data.reg.name, len);
			break;
		case op_immediate:
			if ( format == att_syntax ){
				strncat(buf, "$", len);
				len--;
			}
			if ( op->flags & op_signed ) {
				if ( op->datatype == op_byte ) {
					sprintf(str, "%d", op->data.sbyte );
				} else if ( op->datatype == op_word ) {
					sprintf(str, "%d", op->data.sword );
				} else if ( op->datatype == op_qword ) {
					sprintf(str, "%lld", op->data.sqword );
				} else {
					sprintf(str, "%ld", op->data.sdword );
				}
			} else {
				if ( op->datatype == op_byte ) {
					sprintf(str, "0x%02X", op->data.byte );
				} else if ( op->datatype == op_word ) {
					sprintf(str, "0x%04X", op->data.word );
				} else if ( op->datatype == op_qword ) {
					sprintf(str,"0x%08llX",op->data.sqword);
				} else {
					sprintf(str, "0x%08lX", op->data.dword);
				}
			}
			strncat( buf, str, len );
			break;
		case op_relative:
			if (op->datatype == op_byte) {
				sprintf(str, "0x%02X", op->data.sbyte + 
						insn->addr + insn->size );
			} else if (op->datatype == op_word) {
				sprintf(str, "0x%04X", op->data.sword + 
						insn->addr + insn->size );
			} else {
				sprintf(str, "0x%08X", op->data.sdword + 
						insn->addr + insn->size );
			}
			strncat( buf, str, len );
			break;
		case op_absolute:
			/* AT&T requires a '*' before absolute JMP/CALL ops */
			if (insn->type == insn_jmp || insn->type == insn_call ){
				strncat(buf, "*", len);
				len --;
			}
			len -= format_seg( op, buf, len, format );
			sprintf(str, "0x%08X", op->data.sdword );
			strncat( buf, str, len );
			break;
		case op_expression:
			len -= format_seg( op, buf, len, format );
			format_expr( &op->data.effective_addr, buf, len, 
				     format );
			break;
		case op_offset:
			if (insn->type == insn_jmp || insn->type == insn_call ){
				strncat(buf, "*", len);
				len --;
			}
			len -= format_seg( op, buf, len, format );
			if (op->flags & op_pointer) {
				sprintf(str, "[0x%08X]", op->data.sdword);
			} else {
				sprintf(str, "0x%08X", op->data.sdword );
			}
			strncat( buf, str, len );
			break;
		case op_unused:
			/* return 0-truncated buffer */
			break;
	}

	return(strlen(buf));
}

#define is_imm_jmp(op)   (op.type == op_absolute   || \
		          op.type == op_immediate  || \
			  op.type == op_offset)
#define is_memory_op(op) (op.type == op_absolute   || \
		          op.type == op_expression || \
			  op.type == op_offset)

static int format_att_mnemonic( x86_insn_t *insn, char *buf, int len) {
	int size = 0;
	char *prefix = "", *suffix;

	if (! insn || ! buf || ! len ) 
		return(0);

	memset(buf, 0, len);
	/* do long jump/call prefix */
	if ( insn->type == insn_jmp || insn->type == insn_call ) {
		if ( is_imm_jmp(insn->operands[op_dest]) && 
		    insn->operands[op_dest].datatype != op_byte ) {
			prefix = "l";
		}
	} 
	strncat( buf, prefix, len );
	len -= strlen(prefix);

	/* do mnemonic */
	strncat( buf, insn->mnemonic, len );
	len -= strlen(insn->mnemonic);

	/* do suffixes for memory operands */
	if ( is_memory_op(insn->operands[op_dest]) ){
		size = x86_operand_size(&insn->operands[op_dest]);
	} else if ( is_memory_op(insn->operands[op_dest]) ) {
		size = x86_operand_size(&insn->operands[op_src]);
	}

	if ( size == 1 ) suffix = "b";
	else if ( size == 2 ) suffix = "w";
	else if ( size == 4 ) suffix = "l";
	else if ( size == 8 ) suffix = "q";
	else suffix = "";
	
	strncat( buf, suffix, len );
	return(strlen(buf));
}

int x86_format_mnemonic(x86_insn_t *insn, char *buf, int len, 
		        enum x86_asm_format format){
	char str[MAX_OP_STRING];

	memset(buf, 0, len);
	strncat(buf, insn->prefix_string, len);
	len -= strlen(insn->prefix_string);
	if ( format == att_syntax ) {
		format_att_mnemonic(insn, str, MAX_OP_STRING);
		strncat(buf, str, len);
		len -= strlen(str);
	} else {
		strncat(buf, insn->mnemonic, len);
		len -= strlen(insn->mnemonic);
	}

	return( strlen(buf) );
}

int x86_format_insn( x86_insn_t *insn, char *buf, int len, 
		     enum x86_asm_format format ){
	char str[MAX_OP_STRING];
	int i;

	memset(buf, 0, len);
	if ( format == intel_syntax ) {
		/* INTEL STYLE: mnemonic dest, src, imm */
		strncat(buf, insn->prefix_string, len);
		len -= strlen(insn->prefix_string);
		strncat(buf, insn->mnemonic, len);
		len -= strlen(insn->mnemonic);
		strncat(buf, "\t", len);
		len--;

		/* dest */
		x86_format_operand(&insn->operands[op_dest], insn, str, 
				   MAX_OP_STRING, format);
		strncat(buf, str, len);
		len -= strlen(str);

		/* src */
		if ( insn->operands[op_src].type != op_unused ) {
			strncat(buf, ", ", len);
			len -= 2;
		}
		x86_format_operand(&insn->operands[op_src], insn, str, 
				   MAX_OP_STRING, format);
		strncat(buf, str, len);
		len -= strlen(str);

		/* imm */
		if ( insn->operands[op_imm].type != op_unused ) {
			strncat(buf, ", ", len);
			len -= 2;
		}
		x86_format_operand(&insn->operands[op_imm], insn, str, 
				   MAX_OP_STRING, format);
		strncat(buf, str, len);
		len -= strlen(str);
	} else if ( format == att_syntax ) {
		/* ATT STYLE: mnemonic src, dest, imm */
		format_att_mnemonic(insn, str, MAX_OP_STRING);
		strncat(buf, str, len);
		len -= strlen(str);
		strncat(buf, "\t", len);
		len--;

		/* src */
		x86_format_operand(&insn->operands[op_src], insn, str, 
				   MAX_OP_STRING, format);
		strncat(buf, str, len);
		len -= strlen(str);

		/* dest */
		if ( insn->operands[op_src].type != op_unused && 
		     insn->operands[op_dest].type != op_unused ) {
			strncat(buf, ", ", len);
			len -= 2;
		}

		x86_format_operand(&insn->operands[op_dest], insn, str, 
				   MAX_OP_STRING, format);
		strncat(buf, str, len);
		len -= strlen(str);

		/* imm */
		if ( insn->operands[op_imm].type != op_unused ) {
			strncat(buf, ", ", len);
			len -= 2;
		}
		x86_format_operand(&insn->operands[op_imm], insn, str, 
				   MAX_OP_STRING, format);
		strncat(buf, str, len);
		len -= strlen(str);
	} else { /* default to native */
		/* NATIVE style: RVA\tBYTES\tMNEMONIC\tOPERANDS */
		/* print address */
		sprintf( str, "%08X\t", insn->addr );
		strncat(buf, str, len);
		len -= strlen(str);

		/* print bytes */
		for ( i = 0; i < insn->size; i++ ) {
			sprintf( str, "%02X ", insn->bytes[i] );
			strncat(buf, str, len);
			len -= strlen(str);
		}

		strncat( buf, "\t", len );
		len--;

		/* print mnemonic */
		strncat(buf, insn->prefix_string, len);
		len -= strlen(insn->prefix_string);
		strncat(buf, insn->mnemonic, len);
		len -= strlen(insn->mnemonic);
		strncat(buf, "\t", len);
		len--;

		/* print operands */
		/* dest */
		x86_format_operand(&insn->operands[op_dest], insn, str, 
				   MAX_OP_STRING, format);
		strncat(buf, str, len);
		len -= strlen(str);
		strncat(buf, "\t", len);
		len--;

		/* src */
		x86_format_operand(&insn->operands[op_src], insn, str, 
				   MAX_OP_STRING, format);
		strncat(buf, str, len);
		len -= strlen(str);
		strncat(buf, "\t", len);
		len--;

		/* imm */
		x86_format_operand(&insn->operands[op_imm], insn, str, 
				   MAX_OP_STRING, format);
		strncat(buf, str, len);
		len -= strlen(str);
	}
	return(strlen(buf));
}

x86_op_t * x86_get_operand( x86_insn_t *insn, enum x86_operand_id id ){
	if ( insn ) return( &insn->operands[(int)id] );
	return( NULL );
}

x86_op_t * x86_get_dest_operand( x86_insn_t *insn ) {
	if ( insn ) return( &insn->operands[(int)op_dest] );
	return( NULL );
}

x86_op_t * x86_get_src_operand( x86_insn_t *insn ) {
	if ( insn ) return( &insn->operands[(int)op_src] );
	return( NULL );
}

x86_op_t * x86_get_imm_operand( x86_insn_t *insn ) {
	if ( insn ) return( &insn->operands[(int)op_imm] );
	return( NULL );
}

unsigned char * x86_get_raw_imm( x86_insn_t *insn ) {
	int size, offset;
	x86_op_t *op;

	if ( insn ) {
		if ( insn->operands[0].type == op_immediate ) {
			op = &insn->operands[0];
		} else if ( insn->operands[1].type == op_immediate ) {
			op = &insn->operands[1];
		} else if ( insn->operands[2].type == op_immediate ) {
			op = &insn->operands[2];
		} else {
			return( NULL );
		}
		/* immediate data is at the end of the insn */
		size = x86_operand_size( op );
		offset = insn->size - size;
		return( &insn->bytes[offset] );
	}
	return(NULL);
}


int x86_operand_size( x86_op_t *op ) {
	switch (op->datatype ) {
		case op_byte: return 1;
		case op_word: return 2;
		case op_dword: return 4;
		case op_qword: return 8;
		case op_dqword: return 16;
		case op_sreal: return 4;
		case op_dreal: return 8;
		case op_extreal: return 10;
		case op_bcd: return 10;
		case op_simd: return 16;
		case op_fpuenv: return 28;
	}
	return(4);	/* default size */
}

void x86_set_insn_addr( x86_insn_t *insn, unsigned long addr ) {
	if ( insn ) insn->addr = addr; 
}

void x86_set_insn_offset( x86_insn_t *insn, unsigned int offset ){
	if ( insn ) insn->offset = offset; 
}

void x86_set_insn_function( x86_insn_t *insn, void * func ){
	if ( insn ) insn->function = func; 
}

void x86_set_insn_block( x86_insn_t *insn, void * block ){
	if ( insn ) insn->block = block; 
}

void x86_tag_insn( x86_insn_t *insn ){
	if ( insn ) insn->tag = (void *) 1; 
}

void x86_untag_insn( x86_insn_t *insn ){
	if ( insn ) insn->tag = (void *) 0; 
}

int x86_insn_is_tagged( x86_insn_t *insn ){
	return( insn && insn->tag ? 1 : 0 );
}

/* accessor functions for the private 'ext_arch' structure */
int x86_endian(void) { return(ext_arch.endian); }
int x86_addr_size(void) { return(ext_arch.sz_addr); }
int x86_op_size(void) { return(ext_arch.sz_oper); }
int x86_word_size(void) { return(ext_arch.sz_word); }
int x86_max_inst_size(void) { return(ext_arch.sz_inst); }
int x86_sp_reg(void) { return(ext_arch.SP); }
int x86_fp_reg(void) { return(ext_arch.FP); }
int x86_ip_reg(void) { return(ext_arch.IP); }


/* OLD API
 * ------------------------------------------------------------------------ */
static enum x86_asm_format assembler_format = native_syntax;
/* From here down are the routines in the old legacy api -- used in 
 * libdisasm .16 and under. Obviously big fans of the library will want 
 * these to stick around, even though the API sucks like a jet intake */

static void fix_op( qword * op, unsigned int type ) {
	struct addr_exp *e;
	struct EXPRLIST expl;

	if ( OP_TYPE(type) == OP_REG ) {
		*op = (qword) ((long) vm_get_reg_name((int)*op));
	} else if ( OP_TYPE(type) == OP_EXPR ) {
		e = calloc( sizeof(struct addr_exp), 1 );
		addrexp_get((int) *op, &expl);
		e->scale = expl.scale;
		e->index = expl.index;
		e->base = expl.base;
		e->disp = expl.disp;
		e->flags = expl.flags;
		e->used = expl.used;
		*op = (qword) ((long) e);
	}
	return;
}

int x86old_disasm_addr_raw(char *buf, int buf_len, struct code *c){
	int size;
	unsigned char disasm_buf[32] = {0};

	/* copy binary code to temporary buffer */
	memcpy( disasm_buf, buf, ( buf_len > cpu_inst_size() ) ? 
			               cpu_inst_size() : buf_len     );

	/* actually do the disassembly  -- note we do not zero 'c' */
	size = disasm_addr(disasm_buf, 0, c, 0);

	/* check if we overran the end of the buffer */
	if ( size > buf_len ) {
		return(0);
	}

	fix_op( &c->dest, c->dest_type );
	fix_op( &c->src, c->src_type );
	fix_op( &c->aux, c->aux_type );

	return(size);
}

/* format an address expression */
static int fmt_expr_op(long operand, int flags, char *buf, int len)
{
	if (!operand && flags != ADDREXP_REG) {
		buf[0] = '\0';
		return (0);
	}
	
	switch (flags) {
	case ADDREXP_REG:
		if (assembler_format == ATT_SYNTAX)
			snprintf(buf, len, "%%%s", vm_get_reg_name(operand));
		else
			strncpy(buf, vm_get_reg_name(operand), len);
		break;
	case ADDREXP_WORD:
		if (operand)
			snprintf(buf, len, "%04X", (short) operand);
		break;
	case ADDREXP_DWORD:
		if (operand)
			snprintf(buf, len, "%08lX", operand);
		break;
	case ADDREXP_QWORD:
		if (operand)
			snprintf(buf, len, "%012X", operand);
		break;
	case ADDREXP_BYTE:
	default:
		if (operand)
			snprintf(buf, len, "%02X", (char) operand);
	}

	return (strlen(buf));
}

int x86_old_sprint_addexp(char *str, int len, struct addr_exp *e)
{
	char scale[32] = { 0 }, index[32] = {0}, 
			base[32] = {0}, disp[32] = {0};
	char sd, idx[16] = { 0 }, tmp[32] = {0};
	
	/* normalize negatives */
	if (e->disp < 0) {
		sd = '-';
		e->disp *= -1;
	} else if ( assembler_format == ATT_SYNTAX) {
		sd = ' ';
	} else {
		sd = '+';
	}
	
	/* do scale */
	fmt_expr_op(e->scale, AddrExp_ScaleType(e->flags), scale, 32);
	/* do index */
	fmt_expr_op(e->index, AddrExp_IndexType(e->flags), index, 32);
	/* do byte */
	fmt_expr_op(e->base, AddrExp_BaseType(e->flags), base, 32);
	/* do disp */
	fmt_expr_op((long)e->disp, AddrExp_DispType(e->flags), disp, 32);

	str[0] = '\0';
	
	switch (assembler_format) {
	case ATT_SYNTAX:
		if (disp[0]) {
			snprintf(str, len - strlen(str), "%c%s", sd, disp);
		}
		
		if (base[0]) {
			strncat(tmp, base, 32 - strlen(tmp));
		}
		if (index[0]) {
			strncat(tmp, ", ", 32 - strlen(tmp));
			strncat(tmp, index, 32 - strlen(tmp));
		} else if (scale[0]) {
			strncat(tmp, ",", 32 - strlen(tmp));
		}
		if (scale[0]) {
			strncat(tmp, ",", 32 - strlen(tmp));
			strncat(tmp, scale, len - strlen(tmp));
		}
		if (tmp[0]) {
			strncat(str, "(", len - strlen(str));
			strncat(str, tmp, len - strlen(str));
			strncat(str, ")", len - strlen(str));
		}
		break;
	case INTEL_SYNTAX:
	case NATIVE_SYNTAX:
	default:
		snprintf(str, len, "[%s", base);
		if (scale[0] && index[0])
			snprintf(idx, 16, "(%s*%s)", scale, index);
		else if (index[0])
			snprintf(idx, 16, "%s", index);

		if (base[0]) {
			if (idx[0]) {
				strncat(str, "+", len - strlen(str));
				strncat(str, idx, len - strlen(str));
			}
			if (disp[0]) {
				snprintf(tmp, 32, "%c%s", sd, disp);
				strncat(str, tmp, len - strlen(str));
			}
		} else if (idx[0]) {
			snprintf(str, len, "%s%c%s", idx, sd, disp);
		} else {
			if ( sd == '-' ) strncat( str, "-", len - strlen(str) );
			strncat(str, disp, len - strlen(str));
		}
		strncat(str, "]", len - strlen(str));

	}
	return (strlen(str));
}


static int sprint_seg(char *str, int len, int seg)
{
	seg = seg >> 16;
	if (assembler_format == ATT_SYNTAX)
		snprintf(str, len, "%%%s:",
			 vm_get_reg_name(ext_arch.reg_seg + seg - 1));
	else
		snprintf(str, len, "%s:",
			 vm_get_reg_name(ext_arch.reg_seg + seg - 1));
	return (strlen(str));
}

static int sprint_op(char *str, int len, qword op, int type)
{
	int diff, seg, iop;
	
	if (!type) {
		memset(str, 0, len);
		return (0);
	}

	seg = type & OP_SEG_MASK;	/* segment override for operand */
	iop = (int) op;

	switch (type & OP_TYPE_MASK) {
		case OP_PTR:
		case OP_ADDR:
			if (assembler_format == ATT_SYNTAX) {
				strcat( str, "*" );
				str++;
				len--;
			}
			snprintf(str, len, "0x%08X", (long)iop);
			break;
		case OP_REG:
			if (assembler_format == ATT_SYNTAX){
				strncat(str, "%s", len);
				str++;
				len--;
			} else if (seg) {
				diff = sprint_seg(str, len, seg);
				str += diff;
				len -= diff;
			}
			snprintf(str, len, "%s", vm_get_reg_name(iop));
			break;
		case OP_EXPR:
			if (assembler_format != ATT_SYNTAX && seg) {
				diff = sprint_seg(str, len, seg);
				str += diff;
				len -= diff;
			}
			x86_old_sprint_addexp(str, len, (struct addr_exp *)iop);
			break;
		case OP_REL:
			if (op < 0) {
				op *= -1;
				strncat(str, "-", len);
			} else {
				strncat(str, "+", len);
			}
			str++;
			len--;
			snprintf(str, len, "0x%X", iop);
			break;
		case OP_OFF:
			if (assembler_format != ATT_SYNTAX && seg) {
				diff = sprint_seg(str, len, seg);
				str += diff;
				len -= diff;
			}
			snprintf(str, len, "0x%08lX", (long)iop);
			break;
		case OP_IMM:
		default:
			if (assembler_format == ATT_SYNTAX) {
				strcat( str, "$" );
				str++;
				len--;
			}
			if (  type & OP_SIGNED ) {
				if (op < 0) {
					strncat(str, "-", len);
					len--;
					str++;
					op *= -1;
				}
				snprintf( str, len, "0x%lX", *(long *)&iop );
			} else {
				snprintf( str, len, "0x%lX",
						*(unsigned long *)&iop );
			}
			break;
	}
	return (strlen(str));
}

int x86_old_disasm_addr(char *buf, int buf_len, struct x86_old_instr *i) {
	int size;
	struct code c = { 0 };
	unsigned char disasm_buf[32] = {0};

	/* clear addr_exp */
	memset(i, 0, sizeof (struct x86_old_instr));
	memcpy( disasm_buf, buf, ( buf_len > cpu_inst_size() ) ?
			cpu_inst_size() : buf_len     );

	size = disasm_addr(disasm_buf, 0, &c, 0);
	if ( size ) {
		fix_op( &c.dest, c.dest_type );
		fix_op( &c.src, c.src_type );
		fix_op( &c.aux, c.aux_type );
		strncpy(i->mnemonic, c.mnemonic, 16);
		sprint_op(i->dest, 32, c.dest, c.dest_type);
		sprint_op(i->src, 32, c.src, c.src_type);
		sprint_op(i->aux, 32, c.aux, c.aux_type);
		i->mnemType = c.mnem_type;
		i->destType = c.dest_type;
		i->srcType = c.src_type;
		i->auxType = c.aux_type;
		i->size = size;
	}
	return (size);
}

int x86_old_sprint_addr(char *str, int len, char *buf, int buf_len) {
	struct x86_old_instr i;
	int size;

	size = x86_old_disasm_addr(buf, buf_len, &i);
	if (! size) {
		snprintf(str, len, "invalid instruction: %02X\n", *buf);
		return(0);
	}
	snprintf(str, len, "%s\t%s", i.mnemonic, i.dest);
	if (i.src[0])
		snprintf(str, len - strlen(str), "%s, %s", str, i.src);
	if (i.aux[0])
		snprintf(str, len - strlen(str), "%s, %s", str, i.aux);
	return (size);
}

int x86_old_init(int options, int format){
	assembler_format = format;
	return( x86_init(options, NULL) );
}


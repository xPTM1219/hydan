#include <stdio.h>
#include <stdlib.h>
#include "./i386_opcode.h"
#ifdef _MSC_VER
	#include <memory.h>
#endif


#define WILDCARD_BYTE 0xF4

extern struct EXT__ARCH *settings;
extern int mode_16;
extern int byte_decode(BYTE b, struct modRM_byte *modrm);

int disasm_invariant_modrm( unsigned char *in, unsigned char *out ) {
	struct modRM_byte modrm;
	struct SIB_byte sib;
	unsigned char *c, *cin;
	unsigned short *s;
	unsigned int *i;
	int size = 0;	/* modrm byte is already counted */


	byte_decode(*in, &modrm);	/* get bitfields */

	out[0] = in[0];	/* save modrm byte */
	cin = &in[1];
	c = &out[1];
	s = (unsigned short *)&out[1];
	i = (unsigned int *)&out[1];

	if ( ! mode_16 && modrm.rm == MODRM_RM_SIB && 
			      modrm.mod != MODRM_MOD_NOEA ) {
		size ++;
		byte_decode(*cin, (struct modRM_byte *)&sib);

		out[1] = in[1];	/* save sib byte */
		cin = &in[2];
		c = &out[2];
		s = (unsigned short *)&out[2];
		i = (unsigned int *)&out[2];

		if ( sib.base == SIB_BASE_EBP && ! modrm.mod ) {
			/* disp 32 is variant! */
			memset( i, WILDCARD_BYTE, 4 );
			size += 4;
		}
	}

	if (! modrm.mod && modrm.rm == 101) {
		if ( mode_16 ) {	/* straight RVA in disp */
			memset( s, WILDCARD_BYTE, 2 );
			size += 2;
		} else {
			memset( i, WILDCARD_BYTE, 2 );
			size += 4;
		}
	} else if (modrm.mod && modrm.mod < 3) {
		if (modrm.mod == MODRM_MOD_DISP8) {	 /* offset in disp */
			*c = *cin;	
			size += 1;
		} else if ( mode_16 ) {
			*s = (* ((unsigned short *) cin));
			size += 2;
		} else {
			*i = (*((unsigned int *) cin));
			size += 4;
		}
	}
	return (size);
}


/* TODO: test this in insns like "insn IMM, MODRM" to make sure IMM
         does not overwrite MODRM byte!! */
int disasm_invariant_decode( instr *t, unsigned char *in, unsigned char *out,
						int prefix ) {
	unsigned int addr_size, op_size;
	unsigned int operands[3] = { t->dest, t->src, t->aux };
	unsigned int op_flags[3] = { t->destFlg, t->srcFlg, t->auxFlg };
	int x, bytes = 0, size = 0, modrm = 0;

	/* set addressing mode */
	mode_16 = settings->options & LEGACY_MODE;

	addr_size = settings->sz_addr;
	if (prefix & PREFIX_ADDR_SIZE) {
		if (addr_size == 4) {
			addr_size = 2;
			mode_16 = 1;
		} else {
			addr_size = 4;
			mode_16 = 0;
		}
	}

	op_size = settings->sz_oper;
	if (prefix & PREFIX_OP_SIZE) {
		if (op_size == 4) 	op_size = 2;
		else 				op_size = 4;
	}

	for (x = 0; x < 3; x++) {
		if (operands[x] || op_flags[x] & OP_REG) { 
			/* operand is hard-coded */
			continue;
		}

		switch (op_flags[x] & OPTYPE_MASK) {
			case OPTYPE_c:
				size = (op_size == 4) ? 2 : 1;
				break;
			case OPTYPE_a: case OPTYPE_v:
				size = (op_size == 4) ? 4 : 2;
				break;
			case OPTYPE_p:
				size = (op_size == 4) ? 6 : 4;
				break;
			case OPTYPE_b:
				size = 1;
				break;
			case OPTYPE_w:
				size = 2;
				break;
			case OPTYPE_d: case OPTYPE_fs: case OPTYPE_fd:
			case OPTYPE_fe: case OPTYPE_fb: case OPTYPE_fv:
				size = 4;
				break;
			case OPTYPE_s:
				size = 6;
				break;
			case OPTYPE_q:
				size = 8;
				break;
			case OPTYPE_dq: case OPTYPE_ps: case OPTYPE_ss:
				size = 16;
				break;
			default:
				break;
		}

		switch (op_flags[x] & ADDRMETH_MASK) {
			case ADDRMETH_E: case ADDRMETH_M: case ADDRMETH_Q:
			case ADDRMETH_R: case ADDRMETH_W:
				modrm = 1;	
				bytes += disasm_invariant_modrm( in, out );
				break;
			case ADDRMETH_C: case ADDRMETH_D: case ADDRMETH_G:
			case ADDRMETH_P: case ADDRMETH_S: case ADDRMETH_T:
			case ADDRMETH_V:
				modrm = 1;
				break;
			case ADDRMETH_A: case ADDRMETH_O:
				/* pad with xF4's */
				memset( &out[bytes + modrm], WILDCARD_BYTE, 
					size );
				bytes += size;
				break;
			case ADDRMETH_I: case ADDRMETH_J:
				/* grab imm value */
				if ((op_flags[x] & OPTYPE_MASK) == OPTYPE_v) {
					memset( &out[bytes + modrm], 
						WILDCARD_BYTE, size );
				} else {
					memcpy( &out[bytes + modrm], 
						&in[bytes + modrm], size );
				}
					
				bytes += size;
				break;
			case ADDRMETH_F:
			default:
				break;
		}
	}

	return (bytes + modrm);
}


int disasm_invariant_tbllookup( unsigned char *buf, int tbl, char *out, int p, 
		struct ARCH_INVARIANT *inv ){
	int x, size = 1;
	instr *t;
	unsigned char op = buf[0];

	out[0] = op;

	/* normalize table for lookup */
	if ((tables86[tbl].maxlim < 0xff) && op > tables86[tbl].maxlim) 
		tbl++;
	if (tables86[tbl].minlim) 
		op -= tables86[tbl].minlim;
	t = tables86[tbl].table;
	op >>= tables86[tbl].shift;
	if ((unsigned char) tables86[tbl].mask != 0xFF) 
		size--;	/* this byte is shared w/modrm */
	op &= tables86[tbl].mask;

	/* lookup opcode byte in table */
	if (t[op].mnemFlg & INSTR_PREFIX) {
		for (x = 0; prefix_table[x][0] != 0; x++) {
			if (prefix_table[x][0] == op) 	
				p |= prefix_table[x][1];
		}
		size += disasm_invariant_tbllookup(&buf[1], tbl, &out[1], p, inv);
	} else if (t[op].table && !t[op].mnemonic[0]) {
		/* recurse looking up sub-table */
		size += disasm_invariant_tbllookup( &buf[1], 
				t[op].table, &out[1], p, inv);
	} else if (!t[op].mnemonic[0]) {
		/* invalid insn */
		size = 0;
		out[0] = 0;
	} else {
		size += disasm_invariant_decode(&t[op], &buf[size], 
						&out[size], p);
		inv->insn_type = t->mnemFlg;
		inv->dest_type = t->destFlg;
		inv->src_type = t->srcFlg;
		inv->aux_type = t->auxFlg;
	}

	return(size);
}

int disasm_invariant(unsigned char *in, int in_len, struct ARCH_INVARIANT *inv){
	unsigned char bytes[MAX_INSTRUCTION_SIZE] = {0};	/* safe input buffer */
	unsigned char buf[MAX_INSTRUCTION_SIZE]   = {0};	/* safe output buffer */
	int len, size;

	len = (in_len > 20) ? 20 : in_len;
	memcpy( bytes, in, len );

	size = disasm_invariant_tbllookup( bytes, x86_MAIN, buf, 0, inv ); 
	
	inv->buf_len = (size > 20) ? 20 : size;
	memcpy( inv->buf, buf, inv->buf_len );
	return( inv->buf_len );
}

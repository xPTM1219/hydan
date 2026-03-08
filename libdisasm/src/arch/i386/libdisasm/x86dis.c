/* Compile with  `gcc -I. -O3 -L. -ldisasm quikdis.c -o quikdis` */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <elf.h>
#include "libdis.h"

void quikdis_reporter( enum x86_report_codes code, void *arg ) {
	char * str;

	/* here would could examine the error and do something useful;
	 * instead we just print that an error occurred */
	switch ( code ) {
		case report_disasm_bounds:
			str = "Attempt to disassemble RVA beyond end of buffer";
			break;
		case report_insn_bounds:
			str = "Instruction at RVA extends beyond buffer";
			break;
		case report_invalid_insn:
			str = "Invalid opcode at RVA";
			break;
		case report_unknown:
			str = "Unknown Error";
			break;
	}

	fprintf(stderr, "QUIKDIS: ERROR \'%s:\' %X\n", str, arg);
}

void quikdis_att_print( x86_insn_t *insn, void *arg ) {
	char line[256];
	x86_format_insn(insn, line, 256, att_syntax);
	printf( "%s\n", line);
}

void quikdis_native_print( x86_insn_t *insn, void *arg ) {
	char line[256];
	x86_format_insn(insn, line, 256, native_syntax);
	printf( "%s\n", line);
}

void quikdis_manual_print( x86_insn_t *insn, void *arg ) {
	char buf[MAX_OP_STRING];
	int i;

	printf("%08X", insn->addr );
	for ( i = 0; i < 10; i++ ) {
		if ( i < insn->size ) {
			printf(" %02X", insn->bytes[i]);
		} else {
			printf("   ");
		}
	}
	
	x86_format_mnemonic( insn, buf, MAX_OP_STRING, att_syntax );
	printf( "\t%s\t", buf );

	if ( insn->operands[op_src].type != op_unused ) {
		x86_format_operand( &insn->operands[op_src], insn, buf, 
			       MAX_OP_STRING, att_syntax );
		/* if src is present, so is dest */
		printf("%s, ", buf);
	}
	if ( insn->operands[op_dest].type != op_unused ) {
		x86_format_operand( &insn->operands[op_dest], insn, buf, 
			       MAX_OP_STRING, att_syntax );
		printf("%s", buf);
	}
	if ( insn->operands[op_imm].type != op_unused ) {
		x86_format_operand( &insn->operands[op_imm], insn, buf, 
			       MAX_OP_STRING, att_syntax );
		/* if src is present, so is dest */
		printf(", %s", buf);
	}
	printf("\n");
}

/* RESOLVER List support */
struct RVALIST {
	unsigned long rva;
	struct RVALIST *next;
} rva_list_head = {0};

static int rva_list_add( unsigned long rva ) {
	struct RVALIST *rl, *rl_new;

	for ( rl = &rva_list_head; rl; rl = rl->next ) {
		/* first rva is always 0 -- the list head */
		if ( rva > rl->rva ) {
			if ( ! rl->next || rva < rl->next->rva ) {
				/* we use exit() to free this, btw */
				rl_new = calloc(sizeof(struct RVALIST), 1);
				rl_new->rva = rva;
				rl_new->next = rl->next;
				rl->next = rl_new;
				return(1);
			}
		} else if ( rva == rl->rva ) {
			return(0);	/* already seen this rva */
		}
	}
	return(0);
}

/* In the resolver, we keep a list of RVAs we have seen and weed these out.
 * Needless to say, this is a simple example with poor performance. */

long quikdis_resolver( x86_op_t *op, x86_insn_t *insn ) {
	long retval = -1;

	if (! rva_list_add(insn->addr) ) {
		/* we have seen this one already; return -1 */
		return(-1);
	}

	/* this part is a flat ripoff of internal_resolver in libdis.c */
	/* we don't do any register or stack resolving */
	if ( op->type == op_absolute || op->type == op_offset ) {
		retval = op->data.sdword; /* no need to cast the void* */
	} else if (op->type == op_relative ){
		if ( op->datatype == op_byte ) {
			retval = insn->addr + insn->size + op->data.sbyte;
		} else if ( op->datatype == op_word ) {
			retval = insn->addr + insn->size + op->data.sword;
		} else if ( op->datatype == op_dword ) {
			retval = insn->addr + insn->size + op->data.sdword;
		}
	}

	return( retval );
}

int main(int argc, char *argv[])
{
	void *image;
	int target_fd;
	struct stat sb;
	unsigned long buf_rva;
	unsigned char *buf = NULL, line[256];
	unsigned int entry, i, size, buf_len;
	Elf32_Ehdr *elf_hdr;
	Elf32_Phdr *prog_hdr;
	x86_insn_t insn;	/* used for intel/loop disassembly */



	if (argc != 2) {
		printf("Usage: %s filename\n", argv[0]);
		return 1;
	}

	/* initialize libdisasm */
	x86_init(opt_none, quikdis_reporter);

	/* load target */
	target_fd = open(argv[1], O_RDONLY);
	fstat(target_fd, &sb);
	image = mmap(0, sb.st_size, PROT_READ, MAP_SHARED, target_fd, 0);
	if ((int) image < 1)
		return (-1);
	close(target_fd);
	printf("Target File Name: %s\n", argv[1]);

	/* read ELF header */
	elf_hdr = image;

	/* iterate through program header table entries */
	for (i = 0; i < elf_hdr->e_phnum; i++) {
		prog_hdr = image + elf_hdr->e_phoff +
		           (i * elf_hdr->e_phentsize);

		/* IF entry point is in this section */
		if (elf_hdr->e_entry >= prog_hdr->p_vaddr &&
		    elf_hdr->e_entry <=
		    (prog_hdr->p_vaddr + prog_hdr->p_filesz)) {

			/* resolve entry point RVA to a file offset */
			entry = elf_hdr->e_entry -
			    (prog_hdr->p_vaddr - prog_hdr->p_offset);

			/* use entire program segment as buffer */
			buf = image + prog_hdr->p_offset;
			buf_len = prog_hdr->p_filesz;
			buf_rva = prog_hdr->p_vaddr;

			break;	/* found what we need, now terminate */
		}
	}

	if ( buf ) {

		/* ------------------------------------------- */
		/* Disassembly using x86_disasm_range() */
		printf("\n\n\n");
		printf("QUICKDIS Disassembly of .text: AT&T syntax\n");
		x86_disasm_range( buf, buf_rva, 0, buf_len, 
				  quikdis_att_print, NULL );


		/* ------------------------------------------- */
		/* Disassembly using x86_disasm in a loop */
		printf("\n\n\n");
		printf("QUICKDIS Disassembly of .text: Intel syntax\n");
		for ( i = 0; i < buf_len; ) {
			size = x86_disasm( buf, buf_len, buf_rva, i, &insn );
			if ( size ) {
				x86_format_insn(&insn, line, 256, intel_syntax);
				printf("%s\n", line);
				i += size;
			} else {
				printf("invalid opcode %02X\n", buf[i]);
				i++;
			}
		}



		/* ------------------------------------------- */
		/* Disassembly using x86_disasm_forward */
		printf("\n\n\n");
		printf("QUICKDIS Disassembly following entry point\n");
		x86_disasm_forward( buf, buf_len, buf_rva, entry, 
				    quikdis_native_print, NULL,
				    quikdis_resolver );



		/* ------------------------------------------- */
		/* Disassembly using x86_disasm_range and manual formatting */
		printf("\n\n\n");
		printf("QUICKDIS Disassembly of .text: Manual AT&T syntax\n");
		x86_disasm_range( buf, buf_rva, 0, buf_len, 
				  quikdis_manual_print, NULL );

	}

	/* shut down disassembler */
	x86_cleanup();

	/* close everything */
	munmap(image, sb.st_size);
	return 0;
}
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/*
       x86dis [-a offset|--addr=offset]
              [-r offset len|--range=offset len]
              [-e offset|--entry=offset]
              [-s name|--syntax=name]
              [-f file|--file=file]
              [-o file|--out=file]
              [-l file|--log=file]
              [-h|-?|--help]
              [-v|--version]
*/

enum dis_syntax { fmt_intel, fmt_att, fmt_raw };

enum dis_req_type { req_addr = 1, req_range, req_entry };

static struct DIS_REQ {
	unsigned long offset;
	unsigned int length;
	enum dis_req_type type;
	struct DIS_REQ *next;
} *dis_requests = NULL;

static struct DIS_INFO {
	/* file streams */
	FILE *in, *out, *err;
	/* size of input file */
	unsigned long size;
	/* flag for occurence of entry flag */
	int entry;
	/* output syntax */
	enum dis_syntax syntax;
} info = { stdin, stdout, stderr, 0, fmt_raw };

static int insert_request_after(struct DIS_REQ *req, struct DIS_REQ *curr ) {
	if (! curr ) {
		req->next = dis_requests;
		dis_requests = req;
	} else {
		req->next = curr->next;
		curr->next = req;
	}
	return(1);
}

static int add_request( enum dis_req type, unsigned long offset, 
		        unsigned int len ){
	struct DIS_REQ *request, *curr, *prev = NULL;

	if ( type == req_entry ) {
		info.entry = 1;
	}

	request = calloc( sizeof(struct DIS_REQ), 1 );
	if (! request ) {
		return(0);
	}

	request->type = type;
	request->offset = offset;
	request->len = len;

	if (! dis_requests ) {
		dis_requests = request;
		return(1);
	}

	curr = dis_requests;
	for ( curr = dis_requests; curr; prev = curr, curr = curr->next ) {
		/* put request in before current */
		if ( curr->offset > request->offset ) {
			insert_request_after( req, prev );
			break;
		}

		if ( curr->offset == offset ) {
			/* follow precedence of request types */
			if ( curr->type > req->type ) {
				insert_request_after( req, prev );
			} else {
				insert_request_after( req, curr );
			}
			break;
		}

		if ( ! curr->next ) {
			insert_request_after( req, curr );
			break;
		}

		/* else wait until one of the above conditions applies */
	}

	return(1);
}

static int do_request( enum dis_req type, unsigned char *buf, unsigned int 
		       buf_len, unsigned long buf_rva, unsigned int len ) {

	/* 'len' is optional, i.e. for a range param */
	switch (type) {
		case req_addr:
			break;
		case req_range:
			break;
		case req_entry:
			break;
	}
}
static int act_on_mmap( struct DIS_REQ *list, unsigned char *image, int len, 
		int base ){
	unsigned int offset;
	unsigned char *buf;

	/* cycle through requests, performing each on image */
	for ( req = list; req; req = req->next ) {
		offset = req->offset - base;
		buf = &image[offset];
		do_request( req->type, buf, len, req->offset, req->length ); 
	}
	return(1);
}

static int act_on_mmap_file( void ){
	unsigned char *image;
	struct stat sb;
	int fd = fileno(info.in);
	
	fstat(fd, &db);

	/* create image from file */
	image = (unsigned char *) mmap( NULL, sb.st_size, PROT_READ, 
				        MAP_SHARED, fd, 0 );
	if ( (int) image == -1 ) {
		return(0);
	}

	return( act_on_mmap(debug_requests, image, sb.st_size, 0) );
}

#define STDIN_PAGE_SIZE 524288	/* 512 K */
static unsigned char * mmap_stream( FILE *f, unsigned char **image ){
	int pos = 0, size = STDIN_PAGE_SIZE, cont = 1;

	/* create image from stream */
	*image = malloc( size );
	while ( cont ) {
		pos += fread((*image)[pos], STDIN_PAGE_SIZE, 1, info.in);
		cont = !feof(info.in);
		if ( cont ) {
			size += STDIN_PAGE_SIZE;
			*image = realloc( *image, size );
		}
	}
	return( size );
}

static int act_on_mmap_stream( void ){
	unsigned char *image;
	int len = mmap_stream(info.in, &image);
	return( act_on_mmap(debug_requests, image, len, 0) );
}

static int act_on_stream( void ){
	struct DIS_REQ *req;
	int size, pos = 0, cont = 1;
	char *bytes, buf[128];

	if ( info.entry ) {
		/* we need to have the whole stream in memory to do a -e */
		return( act_on_mmap_stream() );
	}

	while (cont) {
	for ( req = disasm_requests; req; req = req->next ) {
		/* advance the stream until we reach request offset */
		while ( req->offset > pos ) {
			size = req->offset - pos;
			size = size > 128 ? 128 : size;
			/* advance the stream to request offset */
			fread( buf, size, 1, stdin );
			pos += size;
			if ( feof ) {
				/* some kind of feedback here */
				break;
			}
		}

		if ( req->type == req_range && ! req->size ) {
			/* read to end of file ... via mmap ;) */
			size = mmap_stream( info.in, &bytes );
			act_on_mmap( req, bytes, size, pos );
			break;
		} else {
			if ( req->type == req_addr ) {
				size = x86_max_inst_size();
			} else {
				size = req->length;
			}
			if ( req->next && req->next->offset <= pos + size ) {
				/* crap ... overlapping requests
				 * mmap the thing and continue on from here */
				size = mmap_stream( info.in, &bytes );
				act_on_mmap( req, bytes, pos );
				break;
			}

			/* this calloc/free will need to be optimized
			 * if users do a lot of ops on STDIN ... hopefully
			 * they won't ;) */
			bytes = calloc( size, 1 );
			fread( bytes, size, 1, stdin );
			do_request( req->type, bytes, size, req->offset, 
				    req->length ); 
		}
	}
	
	return(1);
}

static int do_opt_s( char *name ) {
	char *s, *d, lname[16] = {0};
	int i;
	
	for ( s = name, d = lname, i = 0; *s; s++, d++, i++ ) {
		
		if ( *s < 0x61 ) {
			*d = *s + 0x20;
		} else {
			*d = *s;
		}
		if ( *d < 0x61 || *d > 0x7A || i >= 15 ) { 
			/* bad input */
			return(0);
		}
	}

	if (! strcmp(lname, "att") ) {
		info.syntax = fmt_att;
	} else if (! strcmp(lname, "intel") ) {
		info.syntax = fmt_intel;
	} else if (! strcmp(lname, "raw") ) {
		info.syntax = fmt_raw;
	} else {
		return(0);
	}

	return(1);
}

static int do_opt_f( char *name ) {
	struct stat sb;

	if (info.in != stdin ){
		fclose(info.in);
	}

	if ( stat(name, &sb) ) {
		info.in = stdin;
		return(0);
	}

	info.in = fopen(name, "r");

	if (info.in == -1 ) {
		info.in = stdin;
		return(0);
	}
	return(1);
}

static int do_opt_o( char *name ) {
	if (info.out != stdout ){
		fclose(info.out);
	}

	info.out = fopen(name, "w+");

	if (info.out == -1 ) {
		info.out = stdout;
		return(0);
	}
	return(1);
}

static int do_opt_l( char *name ) {
	if (info.err != stderr ){
		fclose(info.err);
	}

	info.err = fopen(name, "w+");

	if (info.err == -1 ) {
		info.err = stderr;
		return(0);
	}
	return(1);
}

#define X86DIS_VERSION 0.20
#define BASTARD_URL "bastard.sourceforge.net"

static void do_version(char *name) {
	printf("%s %.2f Distributed with libdisasm from %s\n", 
			name, X86DIS_VERSION, BASTARD_URL);
}
static void do_help(char *name) {
	printf( "%s -aresfolhv\n"
		"A command-line interface to the libdisasm x86 disassembler.\n"
		"This utility allows arbitrary bytes in a file or stream to\n"
		"be disassembled as Intel x86 instructions.\n"
		"Options:\n"
		"\t-a offset     : disassemble instruction at offset\n"
		"\t-r offset len : disassemble range of bytes\n"
		"\t-e offset     : disassemble forward from offset\n"
		"\t-s name       : set output syntax\n"
		"\t-f file       : take input from file\n"
		"\t-o file       : write output to file\n"
		"\t-l file       : write errors to file\n"
		"\t-v            : display version information\n"
		"\t-h            : display this help screen\n"
		"\n"
		"All 'offset' and 'len' parameters must entered in stroul(3)\n"
		"format; any number or combination of -a, -r, and -e options\n"
		"may be used. Syntax options are 'intel', 'att', and 'raw'.\n",
	      name );
}

static int do_longarg( int argc, char **argv, int num ) {
	char *p, *arg1 = NULL, *arg2 = NULL, *opt = &argv[num][2];
	int n = num;
	unsigned long  off;
	unsigned int len;
	
	/* these take no parameters -- easy :) */
	if (! strcmp("help", opt) ) {
		do_help( argv[0] );
		return(0);
	} else if (! strcmp("version", opt) ) {
		do_version( argv[0] );
		return(0);
	}

	for ( p = opt; *p; p++ ) {
		if ( *p == '=' ) {
			argv = p;
		}
	}

	if ( ! arg1 ) { 
		n++;
		/* no '=' in argv[num] ... check argv[num++] */
		if ( n < argc ) {
			for ( p = &argv[n]; *p; p++ ) {
				if ( *p == '=' ) {
					arg1 = p;
				}
			}
		}
	}

	if (! arg1 ) {
		return(-1);
	}

	/* arg1 and p now point to the '=' */
	for ( ; *p; p== ) {
		/* next arg is part of this opt */
		if ( *p >= '0' && *p <= 'z' ) {
			arg1 = p;
		}
	}

	if (! *p ) {
		/* we didn't find the next argument */
		n++;
		arg1 = &argv[n];
	}


	if (! strcmp("addr", opt) ) {
		off = strtoul( arg1, NULL, 0 );
		add_request( req_addr, off, 0 );
	} else if (! strcmp("range", opt) ) {
		n++;
		if ( n < argc ) {
			arg2 = &argv[n];
		} else {
			return(-1);
		}
		off = strtoul( arg1, NULL, 0 );
		len = (unsigned int) strtoul( arg2, NULL, 0 );
		add_request( req_range, off, len );
	} else if (! strcmp("entry", opt) ) {
		off = strtoul( arg1, NULL, 0 );
		add_request( req_entry, off, 0 );
	} else if (! strcmp("syntax", opt) ) {
		do_opt_s( arg1 );
	} else if (! strcmp("file", opt) ) {
		do_opt_f( arg1 );
	} else if (! strcmp("out", opt) ) {
		do_opt_o( arg1 );
	} else if (! strcmp("log", opt) ) {
		do_opt_l( arg1 );
	} else {
		return(0);
	}

	return(n - num);
}

int main( int argc, char **argv ) {
	char *name;
	int x, rv, error = 0;
	unsigned int len;
	unsigned long off;

	if ( argc < 2 ) {
		error = 1;
	}
	for (x = 1; x < argc && ! error; x++) {
		if (argv[x][0] == '-' ) {
			switch (argv[x][1]) {
				case '-':
				/* handle long arg */
					rv = do_longarg( argc, argv, x );
					if (rv < 0) {
						error = 1;
					}
					x+= rv;
					break;
				case 'a':
					x++;
					if ( x < argc ) {
						off = strtoul( argv[x-1], 
								NULL, 0 );
						add_request( req_addr, off, 0 );
					} else {
						error = 1;
					}
					break;
				case 'r':
					x+=2;
					if ( x < argc ) {
						off = strtoul( argv[x-1], 
								NULL, 0 );
						len = (unsigned int) 
						      strtoul(argv[x], NULL, 0);
						add_request( req_range, off, 
							     len );
					} else {
						error = 1;
					}
					break;
				case 'e':
					x++;
					if ( x < argc ) {
						off = strtoul( argv[x-1], 
								NULL, 0 );
						add_request(req_entry, off, 0);
					} else {
						error = 1;
					}
					break;
				case 's':
					x++;
					if ( x < argc ) {
						name = argv[x];
						do_opt_s( name );
					} else {
						error = 1;
					}
					break;
				case 'f':
					x++;
					if ( x < argc ) {
						name = argv[x];
						do_opt_f( name );
					} else {
						error = 1;
					}
					break;
				case 'o':
					x++;
					if ( x < argc ) {
						name = argv[x];
						do_opt_o( name );
					} else {
						error = 1;
					}
					break;
				case 'l':
					x++;
					if ( x < argc ) {
						name = argv[x];
						do_opt_l( name );
					} else {
						error = 1;
					}
					break;
				case 'v':
					name = argv[0];
					do_version( name );
					break;
				case 'h':
				case '?':
					name = argv[0];
					do_help( name );
					break;
				default:
					error = 1;
			}
		}
	}

	if ( error ) {
		do_help(argv[0]);
		/* perform any cleanup */
		return(-1);
	}

	/* OK, do disassembly requests */
	if ( info.in != stdin ) {
		act_on_mmap_file();
	} else {
		act_on_stream();
	}

	return(0);
}

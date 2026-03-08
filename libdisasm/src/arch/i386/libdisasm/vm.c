#include <stdio.h>
#include "./libdis.h"
#include "./i386.h"
#ifdef _MSC_VER
	#define snprintf _snprintf
#endif


extern struct EXT__ARCH ext_arch;

int vm_add_regtbl_entry(int index, char *name, int size, int type)
{
	if (index >= ext_arch.sz_regtable)
		return (0);
	ext_arch.reg_table[index].size = size;
	ext_arch.reg_table[index].type = type;
	strncpy(ext_arch.reg_table[index].mnemonic, name, 8);
	return (1);
}

/* return size of register */

int vm_get_reg_size( int id ) {
	if (id >= ext_arch.sz_regtable)
		return (0);
	
	return( ext_arch.reg_table[id].size );
}

/* return type encoding for register -- the vm.h types are enums in libdis.h*/
int vm_get_reg_type( int id ) {
	if (id >= ext_arch.sz_regtable)
		return (0);

	return( ext_arch.reg_table[id].type );
}

/* get mnemonic for register 'id' */
char * vm_get_reg_name( int id ) {
	if ( id >= ext_arch.sz_regtable ) {
		return(NULL);
	}
	return (ext_arch.reg_table[id].mnemonic);
}

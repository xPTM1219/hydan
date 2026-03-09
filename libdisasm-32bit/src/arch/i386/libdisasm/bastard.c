#include <stdio.h>
#include "./libdis.h"
#include "./bastard.h"
#ifdef _MSC_VER
	#define snprintf _snprintf
#endif

static struct EXPRLIST *expr_list = NULL;

/* Each addrexp can only be used once; this call removes the addr_exp from
 * the list. */
int addrexp_get( int id, struct EXPRLIST *dest ) {
	struct EXPRLIST *e;
	if (! expr_list || ! dest ) {
		return(0);
	}

	for ( e = expr_list; e; e = e->next ) {
		if ( e->id == id ) {
			if ( e->prev ) e->prev->next = e->next;
			if ( e->next ) e->next->prev = e->prev;
			memcpy( dest, e, sizeof(struct EXPRLIST) );
			free( e );
			return(1);
		}
	}

	return(0);
}

/* The addrexp_new call mimics the behavior of the bastard database api
 * by inserting the new address expression in a linked list. This allows
 * i386.c to be used unchanged.
 */
int addrexp_new(int scale, int index, int base, qword disp, int flags)
{
	struct EXPRLIST *e;
	static unsigned long id = 0;

	e = (struct EXPRLIST *) calloc( sizeof(struct EXPRLIST), 1);
	if (! e ) {
		return(0);
	}
	if ( expr_list ) {
		e->next = expr_list;
		expr_list->prev = e;
	}
	expr_list = e;

	e->scale = scale;
	e->index = index;
	e->base = base;
	e->disp = disp;
	e->flags = flags;
	e->id = ++id;

	return (id); /* id */
}


int bdb_index_find(int a, void *b, void *c)
{
	printf("you shouldn't be using this outside of the bastard!!!\n");
	return (0);
}
int bdb_index_next(int a, void *b)
{
	printf("you shouldn't be using this outside of the bastard!!!\n");
	return (0);
}

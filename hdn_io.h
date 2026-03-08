/*
 * $Id$
 * Created: 05/20/2004
 *
 * xvr (c) 2004
 * xvr@xvr.net
 */

#ifndef _HDN_IO_H_
#define _HDN_IO_H_

#include "hydan.h"

#define HDN_WARN(s, args...) do {                       \
    fprintf (stderr, "%s: " s "\n", __func__, ## args); \
} while (0)

#define HDN_EXIT(s, args...) do {  \
    HDN_WARN(s, ## args);          \
    exit (1);                      \
} while (0)


/*
 * print out the instruction in a human readable form
 */
void hdn_io_print_insn (FILE *stream, x86_insn_t *insn);

/*
 * dumps the content of a file into a hdn_data structure
 */
hdn_data_t *hdn_io_fileread (char *filename);

/*
 * dumps the content of a fd to a hdn_data structure
 */
hdn_data_t *hdn_io_fdread (int fd);

/*
 * saves the content of a hdn_data structure into a file
 */
void hdn_io_filewrite (char *filename, hdn_data_t *data);

/*
 * same as above, but to into an fd
 */
void hdn_io_fdwrite (int fd, hdn_data_t *data);


#endif //!HDN_IO_H_

/*
 * $Id$
 * Created: 05/20/2004
 *
 * xvr (c) 2004
 * xvr@xvr.net
 */

#include "hdn_io.h"


static void _sprintf_type (enum x86_op_type type, char *line, uint32_t sz)
{
    char *ret;

    switch (type)
    {
        case op_register:   ret = "reg"; break;
        case op_immediate:  ret = "imm"; break;
        case op_relative:   ret = "rel"; break;
        case op_absolute:   ret = "abs"; break;
        case op_expression: ret = "exp"; break;
        case op_offset:     ret = "oft"; break;
        default:            ret = "n-a"; break;
    }

    snprintf (line, sz, "%s", ret);
}

void hdn_io_print_insn (FILE *stream, x86_insn_t *insn)
{
    char line[256];
    uint32_t i;

    /*
     * print out raw code
     */
    for (i = 0; i < (insn->size ? insn->size : 1); i++)
        fprintf (stream, "%02X ", insn->bytes[i]);

    /*
     * formatted insn
     */
    x86_format_insn(insn, line, sizeof line, intel_syntax);
    fprintf(stream, "\t%s", line);

    /*
     * extra stuff
     */
    fprintf (stream, "\t");
    _sprintf_type (insn->operands[0].type, line, sizeof line);
    fprintf (stream, "%s", line);
    _sprintf_type (insn->operands[1].type, line, sizeof line);
    fprintf (stream, "/%s", line);
    _sprintf_type (insn->operands[2].type, line, sizeof line);
    fprintf (stream, "/%s", line);

    fprintf (stream, "\n");
}

/*
 * reads into hdn_data as much as possible from a file descriptor
 */
hdn_data_t *hdn_io_fdread (int fd)
{
    struct stat sta;
    hdn_data_t *data;

    if (fstat (fd, &sta) < 0)
    {
        perror ("fstat");
        return NULL;
    }

    if (!(data = malloc (sizeof (hdn_data_t) + sta.st_size)))
    {
        perror ("malloc");
        return NULL;
    }

    //fill out the data structure
    data->sz = sta.st_size;

    if (read (fd, data->content, data->sz) < 0)
    {
        perror ("read");
        return NULL;
    }

    close (fd);
    return data;
}

/*
 * same as above, but from a filename
 */
hdn_data_t *hdn_io_fileread (char *filename)
{
    int fd;

    if ( (fd = open (filename, O_RDONLY)) < 0)
    {
        perror ("open");
        return NULL;
    }

    return hdn_io_fdread (fd);
}

/*
 * writes to a file descriptor
 */
void hdn_io_fdwrite (int fd, hdn_data_t *data)
{
    if (write (fd, data->content, data->sz) < 0)
    {
        perror ("write");
        exit (1);
    }

    close (fd);
}

/*
 * writes to a filename
 */
void hdn_io_filewrite (char *filename, hdn_data_t *data)
{
    int fd;

    if ( (fd = open (filename, O_CREAT | O_WRONLY | O_TRUNC)) < 0)
    {
        perror ("open");
        exit (1);
    }

    hdn_io_fdwrite (fd, data);
}

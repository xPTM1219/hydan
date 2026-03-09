/*
 * $Id: hdn_decode.c,v 1.14 2003/12/09 18:23:36 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#include "hdn_decode.h"

static void _usage (void)
{
    fprintf (stderr,
             "Usage:\n"
             "\thydan-decode filename\n");
    exit (1);
}

/*
 * decode the message
 */
static
void _decode_message (hdn_sections_header_t *sh,
                      hdn_data_t *mesg_data, char *key)
{
    uint32_t mesg_curr_pos   = 0;
    uint8_t  mesg_curr_bit   = 0;
    uint8_t  is_sz_extracted = 0;
    hdn_disassembly_data_t *code = NULL;
    uint32_t num_elts, i;

    /*
     * disassemble everything
     */
    code = hdn_disassemble_all (sh->sections, &num_elts);

    /*
     * tag the instructions
     */
    hdn_subst_insns_tag_valid (code, num_elts);

    /*
     * while we have space and still have data to read
     */
    for (i = 0; (i < num_elts) && (mesg_curr_pos < mesg_data->sz); i++)
    {
        /*
         * only attempt embedding in valid instructions
         */
        if (code[i].status != insn_status_valid)
            continue;

        /*
         * if we can decode this instruction, do it.
         */
        if (hdn_subst_insns_is_possible (code, num_elts, i))
        {
            int j, bitval, bits = 0;

            //get the bit value encoded, and the number of bits
            bitval = hdn_subst_insns_val (&code[i].insn, code[i].memaddr, &bits);

            //set each bit appropriately at destination
            for (j = 0; (j < bits) && (mesg_curr_pos < mesg_data->sz); j++)
            {
                //if ith bit out of 'bits' is set
                if ((bitval << (8 - bits + j)) & 128)
                    *(mesg_data->content + mesg_curr_pos) |=
                        128 >> mesg_curr_bit;

                mesg_curr_bit++;
                mesg_curr_bit %= 8;
                if (!mesg_curr_bit) mesg_curr_pos++;
            }

            /*
             * if size of message has been extracted, decrypt it, and
             * use it to bound further extraction
             */
            if (!is_sz_extracted &&
                mesg_curr_pos > sizeof (mesg_data->sz) + 8)
            {
                hdn_data_t *tmp;

                tmp = malloc (8 + sizeof (tmp->sz) + sizeof (hdn_data_t));
                tmp->sz = 8 + sizeof (tmp->sz);
                memcpy (&tmp->content, mesg_data->content, 8 + sizeof (tmp->sz));
                //hdn_crypto_decrypt (&tmp, key);
                is_sz_extracted = 1;
                mesg_data->sz = tmp->sz + sizeof (tmp->sz);
            }
        }
    }

    //cleanup
    if (code) free (code);
}

int hdn_decode_main (int argc, char **argv)
{
    char *password;
    hdn_data_t *host_data = 0, *mesg_data = 0;
    hdn_sections_header_t *sh;
    hdn_sections_t *curr_section;

    /*
     * get application data
     */
    if      (argc == 1) host_data = hdn_io_fdread (STDIN_FILENO);
    else if (argc == 2) host_data = hdn_io_fileread (argv[1]);
    else                _usage ();

    if (!host_data)
        goto out;

    x86_init (opt_none, NULL);

    /*
     * get the code segments
     */
    if (!(sh = hdn_exe_get_sections (host_data->content)))
    {
        HDN_WARN ("Error extracting sections from host file");
        goto out;
    }

    /*
     * get all possible data, host_data->sz is the upper bound of
     * available data in the file
     */
    mesg_data = malloc (sizeof (hdn_data_t) + host_data->sz);

    if (!mesg_data)
    {
        perror ("malloc");
        goto out;
    }

    mesg_data->sz = host_data->sz;
    bzero (mesg_data->content, mesg_data->sz);

    /*
     * get password and seed the random number generator
     */
    password = getpass ("Password: ");
    hdn_crypto_srandom (password);
    _decode_message (sh, mesg_data, password);

    /*
     * decrypt it
     */
    //hdn_crypto_decrypt (&mesg_data, password);

    bzero (password, _PASSWORD_LEN);

    /*
     * out you go
     */
    hdn_io_fdwrite (STDOUT_FILENO, mesg_data);

  out:
    if (host_data) free (host_data);
    if (mesg_data) free (mesg_data);
    host_data = NULL;
    mesg_data = NULL;
    while (sh && sh->sections)
    {
        curr_section = sh->sections->next;
        free (sh->sections);
        sh->sections = curr_section;
    }
    if (sh) free (sh);

    x86_cleanup ();
    return 0;
}


/*
 * $Id: hdn_embed.c,v 1.21 2004/04/30 05:27:15 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#include "hdn_embed.h"

static void _usage (void)
{
    fprintf (stderr,
             "Usage:\n"
             "\thydan host_file [message_file]\n\n"
             "Takes in a binary executable (host_filename) and stores the\n"
             "message in message_filename inside of it.\n"
             "Takes input from stdin when message_file is not specified.\n"
             "Resulting application is output on stdout.\n\n"
             "Ex: ./hydan /bin/ls <msg> ls.stegged\n\n"
             "Use hydan-decode to retrieve the hidden message\n");
    exit (1);
}

static uint32_t _embed (hdn_sections_header_t *sh,
                        hdn_data_t *mesg_data, char *key)
{
    static uint32_t mesg_curr_pos = 0;
    static uint8_t  mesg_curr_bit = 0;
    uint32_t        mesg_sz = mesg_data->sz;

    hdn_disassembly_data_t *code = NULL;
    uint32_t num_elts = 0;
    uint32_t i = 0;

    if (!sh) return 0;

    /*
     * disassemble all the code sections first
     */
    code = hdn_disassemble_all (sh->sections, &num_elts);

    /*
     * do some initialization
     */
#if 0
    hdn_reord_insns_tag_valid (code, num_elts);
#endif
    hdn_subst_insns_tag_valid (code, num_elts);

#if 0
    hdn_reord_insns_mark_jumped_to (sh, code, num_elts);
#endif

    /*
     * don't forget to do some random walking XXX
     */


    /*
     * while we have space and still have data to embed
     */
    for (i = 0; (i < num_elts) && (mesg_curr_pos < mesg_sz); i++)
    {
        uint32_t num_bits1, num_bits2 = 0;

        /*
         * can we embed something into this instruction?
         */
        if (code[i].status != insn_status_valid)
            continue;

        /*
         * Only use method that gives us the most bits.
         */
        num_bits1 = hdn_subst_insns_is_possible (code, num_elts, i);

#if 0
        num_bits2 = hdn_reord_insns_is_possible (code, i, num_elts);
        num_bits2 = hdn_math_numbits_if_reordered (num_bits2);
#endif

        if (!num_bits1 && !num_bits2)
            continue;

        if (num_bits1 > num_bits2)
        {
            /*
             * embed a bit (or more) into this instruction, and return
             * the number of bits embedded.
             */
            mesg_curr_bit +=
                hdn_subst_insns (&code[i].insn, code[i].memaddr,
                                 mesg_data->content + mesg_curr_pos,
                                 mesg_curr_bit);
        }
        else
        {
#if 0
            mesg_curr_bit +=
                hdn_reord_insns (code, i, num_elts,
                                 mesg_data->content + mesg_curr_pos,
                                 mesg_curr_bit);
#endif
        }

        /*
         * increment mesg position and wrap byte counter around if
         * necessary.
         */
        if (mesg_curr_bit >= 8) mesg_curr_pos += mesg_curr_bit/8;
        mesg_curr_bit %= 8;
    }

    /*
     * cleanup
     */
    if (code) free (code);

    return mesg_curr_pos;
}

int hdn_embed_main (int argc, char **argv)
{
    uint32_t  bytes_embedded, code_sz = 0;
    char  *password;
    hdn_data_t *host_data = 0, *mesg_data = 0;
    hdn_sections_header_t *sh = NULL;
    hdn_sections_t *tmp_sections = NULL;

    /*
     * for stats
     */
    uint32_t num_bits = 0;

    /*
     * get message data
     */
    if      (argc == 2) mesg_data = hdn_io_fdread (STDIN_FILENO);
    else if (argc == 3) mesg_data = hdn_io_fileread (argv[2]);
    else                _usage ();

    /*
     * get password and encrypt message data
     */
    password = getpass ("Password: ");
    hdn_crypto_srandom (password);
    hdn_crypto_encrypt (&mesg_data, password);

    /*
     * read in application data
     */
    if (!(host_data = hdn_io_fileread (argv[1])))
        goto out;

    x86_init(opt_none, NULL);

    /*
     * extract application's sections
     */
    if (!(sh = hdn_exe_get_sections (host_data->content)))
        goto out;

    /*
     * count the number of embeddable instructions in all of the code
     * sections
     */
    tmp_sections = sh->sections;
    while (tmp_sections)
    {
        if (!hdn_exe_section_is_code (tmp_sections))
            goto next;

        code_sz += tmp_sections->data.sz;

        hdn_stats_embeddable_bits (&tmp_sections->data, &num_bits);

    next:
        tmp_sections = tmp_sections->next;
    }

    /*
     * make sure stego is possible
     */
    if (mesg_data->sz * 8  >  num_bits)
    {
        fprintf (stderr,
                 "Not enough place in host application to hide message.\n"
                 "Can only hide %u bytes in this application "
                 "(needed: %u bytes).\n"
                 "So choose a different host, or make your message smaller!\n",
                 (unsigned int)num_bits/8,
                 (unsigned int)mesg_data->sz);
        goto out;
    }

    /*
     * actually go thru and embed the message into the host proggie
     */
    bytes_embedded = _embed (sh, mesg_data, password);

    /*
     * patch modified code sections
     */
    tmp_sections = sh->sections;
    while (tmp_sections)
    {
        memcpy (host_data->content + tmp_sections->offset,
                tmp_sections->data.content,
                tmp_sections->data.sz);

        tmp_sections = tmp_sections->next;
    }

    /*
     * save new app
     */
    hdn_io_fdwrite (STDOUT_FILENO, host_data);

    fprintf (stderr,
             "Done.  Embedded %d/%u bytes out of"
             " a total possible %u bytes.\n"
             "Encoding rate: 1/%d\n",
             bytes_embedded,
             (unsigned int)mesg_data->sz,
             (unsigned int)num_bits/8,
             code_sz / (num_bits ? num_bits/8 : INT_MAX)
             );

    /*
     * cleanup
     */
  out:
    bzero (password, _PASSWORD_LEN);
    if (host_data) free (host_data);
    if (mesg_data) free (mesg_data);
    host_data = NULL;
    mesg_data = NULL;
    while (sh && sh->sections)
    {
        tmp_sections = sh->sections->next;
        free (sh->sections);
        sh->sections = tmp_sections;
    }
    if (sh) free (sh);

    x86_cleanup ();
    return 0;
}


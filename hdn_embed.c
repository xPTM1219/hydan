#include "hdn_embed.h"
#include <arpa/inet.h>

#define HDN_LEN_PREFIX_BYTES 4

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

    code = hdn_disassemble_all (sh->sections, &num_elts);

#if 0
    hdn_reord_insns_tag_valid (code, num_elts);
#endif
    hdn_subst_insns_tag_valid (code, num_elts);

#if 0
    hdn_reord_insns_mark_jumped_to (sh, code, num_elts);
#endif

    for (i = 0; (i < num_elts) && (mesg_curr_pos < mesg_sz); i++)
    {
        uint32_t num_bits1, num_bits2 = 0;

        if (code[i].status != insn_status_valid)
            continue;

        num_bits1 = hdn_subst_insns_is_possible (code, num_elts, i);

#if 0
        num_bits2 = hdn_reord_insns_is_possible (code, i, num_elts);
        num_bits2 = hdn_math_numbits_if_reordered (num_bits2);
#endif

        if (!num_bits1 && !num_bits2)
            continue;

        if (num_bits1 > num_bits2)
        {
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

        if (mesg_curr_bit >= 8) mesg_curr_pos += mesg_curr_bit / 8;
        mesg_curr_bit %= 8;
    }

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

    uint32_t num_bits = 0;

    if      (argc == 2) mesg_data = hdn_io_fdread (STDIN_FILENO);
    else if (argc == 3) mesg_data = hdn_io_fileread (argv[2]);
    else                _usage ();

    password = getenv ("HYDAN_TEST_PASS");
    if (!password)
        password = getpass ("Password: ");
    hdn_crypto_srandom (password);
    hdn_crypto_encrypt (&mesg_data, password);

    /*
     * prepend 4-byte big-endian length prefix (ciphertext size)
     */
    {
        uint32_t ct_len = mesg_data->sz;
        uint32_t total_len = HDN_LEN_PREFIX_BYTES + ct_len;
        uint32_t be_len = htonl (ct_len);
        hdn_data_t *new_mesg = realloc (mesg_data,
                                         sizeof (hdn_data_t) + total_len);
        if (!new_mesg)
        {
            fprintf (stderr, "Out of memory\n");
            goto out;
        }
        mesg_data = new_mesg;
        memmove (mesg_data->content + HDN_LEN_PREFIX_BYTES,
                 mesg_data->content, ct_len);
        memcpy (mesg_data->content, &be_len, HDN_LEN_PREFIX_BYTES);
        mesg_data->sz = total_len;
    }

    if (!(host_data = hdn_io_fileread (argv[1])))
        goto out;

    if (!(sh = hdn_exe_get_sections (host_data->content)))
        goto out;

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

    if (mesg_data->sz * 8 > num_bits)
    {
        fprintf (stderr,
                 "Not enough place in host application to hide message.\n"
                 "Can only hide %u bytes in this application "
                 "(needed: %u bytes).\n"
                 "So choose a different host, or make your message smaller!\n",
                 (unsigned int) num_bits / 8,
                 (unsigned int) mesg_data->sz);
        goto out;
    }

    bytes_embedded = _embed (sh, mesg_data, password);

    tmp_sections = sh->sections;
    while (tmp_sections)
    {
        memcpy (host_data->content + tmp_sections->offset,
                tmp_sections->data.content,
                tmp_sections->data.sz);

        tmp_sections = tmp_sections->next;
    }

    hdn_io_fdwrite (STDOUT_FILENO, host_data);

    fprintf (stderr,
             "Done.  Embedded %d/%u bytes out of"
             " a total possible %u bytes.\n"
             "Encoding rate: 1/%d\n",
             bytes_embedded,
             (unsigned int) mesg_data->sz,
             (unsigned int) num_bits / 8,
             code_sz / (num_bits ? num_bits / 8 : INT_MAX)
             );

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

    return 0;
}

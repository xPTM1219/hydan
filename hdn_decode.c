#include "hdn_decode.h"
#include <arpa/inet.h>

#define HDN_LEN_PREFIX_BYTES 4

static void _usage (void)
{
    fprintf (stderr,
             "Usage:\n"
             "\thydan-decode filename\n");
    exit (1);
}

static void _decode_message (hdn_sections_header_t *sh,
                              hdn_data_t *mesg_data, char *key)
{
    uint32_t mesg_curr_pos   = 0;
    uint8_t  mesg_curr_bit   = 0;
    uint8_t  is_len_extracted = 0;
    hdn_disassembly_data_t *code = NULL;
    uint32_t num_elts, i;

    code = hdn_disassemble_all (sh->sections, &num_elts);

    hdn_subst_insns_tag_valid (code, num_elts);

    for (i = 0; (i < num_elts) && (mesg_curr_pos < mesg_data->sz); i++)
    {
        if (code[i].status != insn_status_valid)
            continue;

        if (hdn_subst_insns_is_possible (code, num_elts, i))
        {
            int j, bitval, bits = 0;

            bitval = hdn_subst_insns_val (&code[i].insn, code[i].memaddr, &bits);

            for (j = 0; (j < bits) && (mesg_curr_pos < mesg_data->sz); j++)
            {
                if ((bitval << (8 - bits + j)) & 128)
                    *(mesg_data->content + mesg_curr_pos) |=
                        128 >> mesg_curr_bit;

                mesg_curr_bit++;
                mesg_curr_bit %= 8;
                if (!mesg_curr_bit) mesg_curr_pos++;
            }

            if (!is_len_extracted &&
                mesg_curr_pos >= HDN_LEN_PREFIX_BYTES)
            {
                uint32_t be_len;
                uint32_t payload_len;

                memcpy (&be_len, mesg_data->content, HDN_LEN_PREFIX_BYTES);
                payload_len = ntohl (be_len);
                mesg_data->sz = HDN_LEN_PREFIX_BYTES + payload_len;
                is_len_extracted = 1;
            }
        }
    }

    if (code) free (code);
}

int hdn_decode_main (int argc, char **argv)
{
    char *password;
    hdn_data_t *host_data = 0, *mesg_data = 0;
    hdn_sections_header_t *sh;
    hdn_sections_t *curr_section;

    if      (argc == 1) host_data = hdn_io_fdread (STDIN_FILENO);
    else if (argc == 2) host_data = hdn_io_fileread (argv[1]);
    else                _usage ();

    if (!host_data)
        goto out;

    if (!(sh = hdn_exe_get_sections (host_data->content)))
    {
        HDN_WARN ("Error extracting sections from host file");
        goto out;
    }

    mesg_data = malloc (sizeof (hdn_data_t) + host_data->sz);

    if (!mesg_data)
    {
        perror ("malloc");
        goto out;
    }

    mesg_data->sz = host_data->sz;
    bzero (mesg_data->content, mesg_data->sz);

    password = getenv ("HYDAN_TEST_PASS");
    if (!password)
        password = getpass ("Password: ");
    hdn_crypto_srandom (password);
    _decode_message (sh, mesg_data, password);

    /*
     * strip the 4-byte length prefix, then decrypt
     */
    if (mesg_data->sz > HDN_LEN_PREFIX_BYTES)
    {
        uint32_t payload_len = mesg_data->sz - HDN_LEN_PREFIX_BYTES;
        memmove (mesg_data->content,
                 mesg_data->content + HDN_LEN_PREFIX_BYTES,
                 payload_len);
        mesg_data->sz = payload_len;
    }
    else
    {
        mesg_data->sz = 0;
    }

    hdn_crypto_decrypt (&mesg_data, password);

    bzero (password, _PASSWORD_LEN);

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

    return 0;
}

/*
 * $Id: hdn_stats.c,v 1.12 2004/04/30 05:27:15 xvr Exp $
 * Created: 08/21/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#include "hdn_stats.h"
#include <Zydis/Zydis.h>

void hdn_stats_embeddable_bits (hdn_data_t *data, uint32_t *num)
{
    uint32_t curr_pos = 0;
    uint32_t num_insns = 0, i;
    hdn_disassembly_data_t *dis = NULL;
    hdn_disassembly_data_t d;
    ZydisDecoder decoder;
    ZydisDecoderContext context;

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    //disassemble the whole thing
    while (curr_pos < data->sz)
    {
        bzero (&d, sizeof d);
        d.memaddr = (uint8_t*) data->content + curr_pos;
        d.status = insn_status_none;

        ZyanStatus status = ZydisDecoderDecodeInstruction(&decoder, &context, d.memaddr, (ZyanUSize)(data->sz - curr_pos), &d.insn.zydis);
        if (ZYAN_SUCCESS(status)) {
            d.insn.size = d.insn.zydis.length;
            memcpy(d.insn.raw, d.memaddr, d.insn.size);
            d.insn.type = (enum x86_insn_type) d.insn.zydis.mnemonic;
            // dummy operands and flags
            d.insn.operands[0].type = op_register;
            d.insn.operands[1].type = op_immediate;
            d.insn.operands[2].type = op_register;
            d.insn.operands[0].datatype = op_dword;
            d.insn.operands[1].datatype = op_dword;
            d.insn.operands[2].datatype = op_dword;
            d.insn.flags_set = 0;
            d.insn.flags_tested = 0;
        } else {
            d.status = insn_status_bad;
            d.insn.size = 1;
            d.insn.raw[0] = d.memaddr[0];
        }

        //done disassembling
        if ((curr_pos + d.insn.size) > data->sz) goto done_disas;

        if (!(num_insns % 1000))
        {
            //fprintf (stderr, "--> %d\n", num_insns);
            dis = realloc (dis, sizeof (hdn_disassembly_data_t) *
                           (num_insns + 1000));
        }

        //we have disassembled another insn
        num_insns++;
        bcopy (&d, &dis[num_insns-1], sizeof d);

        if (d.insn.size) curr_pos += d.insn.size;
        else             curr_pos++; //unknown insn, move on
        //XXX -- add some clause not to embed if we fall on an unknown insn?
    }

 done_disas:

    for (i = 0; i < num_insns; i++)
    {
        uint32_t emb1 = 0;
        uint32_t emb2 = 0;

        emb1 = hdn_subst_insns_is_possible (dis, num_insns, i);
#if 0
        emb2 = hdn_reord_insns_is_possible (dis, i, num_insns);
#endif

        if (!emb1 && !emb2)
            continue;

        if (emb1 > emb2)
            (*num) += emb1;
        else
        {
            (*num) += hdn_math_numbits_if_reordered (emb2);
            i += emb2 - 1;
        }
    }

    //cleanup
    if (dis) free (dis);
}

static void _usage (void)
{
    fprintf (stderr,
             "Usage:\n"
             "\thydan-stats file\n\n"
             "Takes in a file, and prints out its statistical profile\n");
    exit (1);

}

static uint32_t _count_fns (char *argv0)
{
    hdn_data_t *host_data = NULL;
    hdn_sections_header_t *sh = NULL;
    hdn_sections_t *tmp_sections;
    uint32_t fn_count = 0;
    ZydisDecoder decoder;
    ZydisDecoderContext context;

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    /*
     * read in application data
     */
    if (!(host_data = hdn_io_fileread (argv0)))
        goto out;

    /*
     * get the text segment
     */
    if (!(sh = hdn_exe_get_sections ((uint8_t*)host_data->content)))
    {
        HDN_WARN ("Error extracting .text segment from host file");
        goto out;
    }

    /*
     * count the number of functions in each code section
     */
    tmp_sections = sh->sections;
    while (tmp_sections)
    {
        int pos = 0;
        x86_insn_t insn;
        char fn_start[5] = { 0x55, 0x89, 0xe5, 0x83, 0xec};

        if (!hdn_exe_section_is_code (tmp_sections))
            goto next;

        while (pos < tmp_sections->data.sz)
        {
            bzero (&insn, sizeof insn);
            ZyanStatus status = ZydisDecoderDecodeInstruction(&decoder, &context, (uint8_t*)tmp_sections->data.content + pos, tmp_sections->data.sz - pos, &insn.zydis);
            if (ZYAN_SUCCESS(status)) {
                insn.size = insn.zydis.length;
                memcpy(insn.raw, (uint8_t*)tmp_sections->data.content + pos, insn.size);
                insn.type = (enum x86_insn_type) insn.zydis.mnemonic;
                // dummy
                insn.operands[0].type = op_register;
                insn.operands[1].type = op_immediate;
                insn.operands[2].type = op_register;
                insn.operands[0].datatype = op_dword;
                insn.operands[1].datatype = op_dword;
                insn.operands[2].datatype = op_dword;
                insn.flags_set = 0;
                insn.flags_tested = 0;
            } else {
                insn.size = 1;
                insn.raw[0] = ((uint8_t*)tmp_sections->data.content)[pos];
            }

            if ((pos + insn.size) > tmp_sections->data.sz)
                break;

            //valid instruction
            if (insn.size)
            {
                if (!memcmp (tmp_sections->data.content + pos, fn_start, 5))
                    fn_count++;

                pos += insn.size;
            }
            else pos++; //unknown insn, move on
        }

    next:
        tmp_sections = tmp_sections->next;
    }

    /*
     * cleanup
     */
  out:
    if (host_data)
    {
        free (host_data);
        host_data = NULL;
    }

    while (sh && sh->sections)
    {
        tmp_sections = sh->sections->next;
        free (sh->sections);
        sh->sections = tmp_sections;
    }
    if (sh) free (sh);

    return fn_count;
}

struct _insns
{
    char **desc;
    int  *occ;
    int  *nocc; //negative occurrances

    struct _insns *next;
};

static struct _insns *_add_insn (struct _insns **insn, char *desc, int bits)
{
    struct _insns *temp;

    if (!desc) return NULL;

    /* first time */
    if (!*insn)
    {
        (*insn) = malloc (sizeof (struct _insns));
        bzero (*insn, sizeof (struct _insns));

        /* allocate 2^(bits+1) possible instructions */
        (*insn)->desc = malloc (sizeof (char *) * (pow (2, bits + 1) + 1));
        bzero ((*insn)->desc,   sizeof (char *) * (pow (2, bits + 1) + 1));
        (*insn)->desc[0] = strdup (desc);

        (*insn)->occ  = malloc (sizeof (int) * pow (2, bits+1));
        bzero ((*insn)->occ,    sizeof (int) * pow (2, bits+1));
        (*insn)->occ[(int)pow (2, bits + 1) - 1] = -1; //terminator

        (*insn)->nocc  = malloc (sizeof (int) * pow (2, bits+1));
        bzero ((*insn)->nocc,    sizeof (int) * pow (2, bits+1));
        (*insn)->nocc[(int)pow (2, bits + 1) - 1] = -1; //terminator

        return (*insn);
    }

    /* find last item on the list */
    temp = *insn;
    while (temp->next)
        temp = temp->next;

    /* add the item to the list */
    temp->next = malloc (sizeof (struct _insns));
    bzero (temp->next, sizeof (struct _insns));

    /* allocate 2^(bits+1) possible instructions */
    temp->next->desc = malloc (sizeof (char *) * (pow (2, bits + 1) + 1));
    bzero (temp->next->desc,   sizeof (char *) * (pow (2, bits + 1) + 1));
    temp->next->desc[0] = strdup (desc);

    temp->next->occ  = malloc (sizeof (int) * pow (2, bits+1));
    bzero (temp->next->occ,    sizeof (int) * pow (2, bits+1));
    temp->next->occ[(int)pow (2, bits + 1) - 1] = -1; //terminator

    temp->next->nocc  = malloc (sizeof (int) * pow (2, bits+1));
    bzero (temp->next->nocc,    sizeof (int) * pow (2, bits+1));
    temp->next->nocc[(int)pow (2, bits + 1) - 1] = -1; //terminator

    return temp->next;
}

struct _insns *_find_insn (struct _insns *insn, char *desc)
{
    while (insn)
    {
        if (!strcmp (insn->desc[0], desc))
            return insn;

        insn = insn->next;
    }

    //not found
    return NULL;
}

static void _do_stats (hdn_data_t *data, struct _insns **insns)
{
    uint32_t curr_pos = 0;
    uint32_t bits;
    hdn_disassembly_data_t dis;
    ZydisDecoder decoder;
    ZydisDecoderContext context;

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    while (curr_pos < data->sz)
    {
        bzero (&dis.insn, sizeof dis.insn);
        dis.memaddr = (uint8_t*) data->content + curr_pos;
        dis.status = insn_status_none;

        ZyanStatus status = ZydisDecoderDecodeInstruction(&decoder, &context, dis.memaddr, data->sz - curr_pos, &dis.insn.zydis);
        if (ZYAN_SUCCESS(status)) {
            dis.insn.size = dis.insn.zydis.length;
            memcpy(dis.insn.raw, dis.memaddr, dis.insn.size);
            dis.insn.type = (enum x86_insn_type) dis.insn.zydis.mnemonic;
            // dummy
            dis.insn.operands[0].type = op_register;
            dis.insn.operands[1].type = op_immediate;
            dis.insn.operands[2].type = op_register;
            dis.insn.operands[0].datatype = op_dword;
            dis.insn.operands[1].datatype = op_dword;
            dis.insn.operands[2].datatype = op_dword;
            dis.insn.flags_set = 0;
            dis.insn.flags_tested = 0;
        } else {
            dis.status = insn_status_bad;
            dis.insn.size = 1;
            dis.insn.raw[0] = dis.memaddr[0];
        }

        /* done */
        if ((curr_pos + dis.insn.size) > data->sz) return;


        if ( (bits = hdn_subst_insns_is_possible (&dis, 1, 0)) )
        {
            char *class_desc, *insn_desc;
            int val;
            struct _insns *curr_insn;

            class_desc =
                hdn_subst_insns_desc (&dis.insn, dis.memaddr, &insn_desc);

            /* do we already have it somewhere */
            if (!(curr_insn = _find_insn (*insns, class_desc)))
            {
                /* add it */
                curr_insn = _add_insn (insns, class_desc, bits);
            }

            val = hdn_subst_insns_val (&dis.insn, dis.memaddr, NULL);

            /* inc the occurrence of this value */
            curr_insn->occ[val] += bits;
            curr_insn->nocc[val] += bits * hdn_subst_insns_is_neg (&dis.insn,
                                                                   dis.memaddr);
            curr_insn->desc[val+1] = insn_desc;
        }

        if (dis.insn.size) curr_pos += dis.insn.size;
        else               curr_pos++; //unknown insn, move on
    }
}

int hdn_stats_main (int argc, char **argv)
{
    struct _insns *insns = NULL, *tmp_insns;
    hdn_data_t *host_data = NULL;
    hdn_sections_header_t *sh = NULL;
    hdn_sections_t *tmp_sections;

    uint32_t code_sz = 0, total_code_sz = 0;
    uint32_t num_fns = 0, total_num_fns = 0;
    uint32_t num_bits, num_fns_bits;
    uint32_t total_num_bits = 0, total_num_fns_bits = 0;
    uint32_t num_files = 0;

    /*
     * parse that shit
     */
    if (argc < 2)
        _usage ();



    argc--;
    while (argc)
    {
        argv++;
        argc--;

        /*
         * init
         */
        code_sz = num_fns = num_bits = 0;

        /*
         * read in the app
         */
        if (!(host_data = hdn_io_fileread (*argv)))
            goto out;

        /*
         * get the text segment
         */
        if (!(sh = hdn_exe_get_sections (host_data->content)))
        {
            HDN_WARN ("Error extracting .text segment from host file");
            goto out;
        }

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
            _do_stats (&tmp_sections->data, &insns);

        next:
            tmp_sections = tmp_sections->next;
        }

        /*
         * count the number of functions
         */
        num_fns = _count_fns (*argv);
        num_fns_bits = hdn_math_numbits_if_reordered (num_fns);

        /*
         * stats proper
         */
        total_num_bits     += num_bits;
        total_code_sz      += code_sz;
        total_num_fns      += num_fns;
        total_num_fns_bits += num_fns_bits;
        num_files++;

        printf ("File                  : %s\n", *argv);
        printf ("Code size             : %d bytes\n", code_sz);
        printf ("Embeddeable insns     : %u bytes\n", num_bits/8);
        printf ("Number of functions   : %d (%d bytes)\n",
                num_fns, num_fns_bits/8);
        printf ("-------> Encoding Rate: 1/%d (1/%d with fns)\n\n",
                code_sz / (num_bits/8 ?
                           num_bits/8 : INT_MAX),
                code_sz / ((num_bits + num_fns_bits)/8 ?
                           (num_bits + num_fns_bits)/8 : INT_MAX));

        printf ("Total embeddeable insns: %u bytes\n", total_num_bits/8);
        printf ("Total number of fns    : %d (%d bytes/file, %d bytes/total)\n",
                total_num_fns,
                total_num_fns_bits/8,
                hdn_math_numbits_if_reordered (total_num_fns)/8);
        printf ("Total encoding rate    : 1/%d (with fns: 1/%d/file - 1/%d/total)\n\n",
                total_code_sz / (total_num_bits/8 ?
                                 total_num_bits/8 : INT_MAX),
                total_code_sz / ((total_num_bits + total_num_fns_bits)/8 ?
                                 (total_num_bits + total_num_fns_bits)/8
                                 : INT_MAX),
                total_code_sz / ((total_num_bits +
                                  hdn_math_numbits_if_reordered (total_num_fns))/8 ?
                                 (total_num_bits +
                                  hdn_math_numbits_if_reordered (total_num_fns))/8
                                 : INT_MAX));

        tmp_insns = insns;
        while (tmp_insns)
        {
            int i;

            printf ("%s:\n", tmp_insns->desc[0]);
            for (i = 0; tmp_insns->occ[i] != -1; i++)
            {
                if (tmp_insns->occ[i])
                    printf ("\t%s: %d\n", tmp_insns->desc[i+1],
                            tmp_insns->occ[i]);
                if (tmp_insns->nocc[i])
                    printf ("\t\tof which are in the negative form: %d\n",
                            tmp_insns->nocc[i]);
            }

            tmp_insns = tmp_insns->next;
        }

        /*
         * cleanup
         */
      out:
        if (host_data)
        {
            free (host_data);
            host_data = NULL;
        }

        while (sh && sh->sections)
        {
            tmp_sections = sh->sections->next;
            free (sh->sections);
            sh->sections = tmp_sections;
        }
        if (sh) free (sh);
    }

    printf ("num files: %d\n", num_files);


    return 0;
}

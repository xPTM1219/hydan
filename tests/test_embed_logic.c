#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "hdn_common.h"
#include "hdn_crypto.h"
#include "hdn_subst_insns.h"

#define PREFIX_BYTES 4

static int failures = 0;

static void check(int cond, const char *label)
{
    if (cond)
    {
        printf("PASS: %s\n", label);
    }
    else
    {
        fprintf(stderr, "FAIL: %s\n", label);
        failures++;
    }
}

#define NUM_INSNS 4096

static void build_section(uint8_t *code, size_t code_sz)
{
    size_t pos = 0;
    uint32_t pat = 0;

    while (pos + 2 <= code_sz)
    {
        switch (pat % 4)
        {
            case 0:
                code[pos] = 0x85; code[pos+1] = 0xC0;
                break;
            case 1:
                code[pos] = 0x31; code[pos+1] = 0xC0;
                break;
            case 2:
                code[pos] = 0x89; code[pos+1] = 0xC0;
                break;
            default:
                code[pos] = 0x01; code[pos+1] = 0xC0;
                break;
        }
        pat++;
        pos += 2;
    }
}

static void embed_bits(hdn_disassembly_data_t *code, uint32_t num_elts,
                       hdn_data_t *mesg)
{
    uint32_t mesg_curr_pos = 0;
    uint8_t mesg_curr_bit = 0;
    uint32_t i;

    for (i = 0; (i < num_elts) && (mesg_curr_pos < mesg->sz); i++)
    {
        if (code[i].status != insn_status_valid)
            continue;

        if (!hdn_subst_insns_is_possible(code, num_elts, i))
            continue;

        mesg_curr_bit += hdn_subst_insns(&code[i].insn, code[i].memaddr,
                                         (uint8_t *) mesg->content + mesg_curr_pos,
                                         mesg_curr_bit);

        if (mesg_curr_bit >= 8) mesg_curr_pos += mesg_curr_bit / 8;
        mesg_curr_bit %= 8;
    }

    check(mesg_curr_pos == mesg->sz && !mesg_curr_bit, "embed consumed all bytes");
}

static void extract_bits(hdn_disassembly_data_t *code, uint32_t num_elts,
                         hdn_data_t *mesg)
{
    uint32_t mesg_curr_pos = 0;
    uint8_t mesg_curr_bit = 0;
    uint8_t is_len_extracted = 0;
    uint32_t i;

    for (i = 0; (i < num_elts) && (mesg_curr_pos < mesg->sz); i++)
    {
        if (code[i].status != insn_status_valid)
            continue;

        if (!hdn_subst_insns_is_possible(code, num_elts, i))
            continue;

        {
            int j, bitval, bits = 0;

            bitval = hdn_subst_insns_val(&code[i].insn, code[i].memaddr, &bits);

            for (j = 0; (j < bits) && (mesg_curr_pos < mesg->sz); j++)
            {
                if ((bitval << (8 - bits + j)) & 128)
                    *(mesg->content + mesg_curr_pos) |= 128 >> mesg_curr_bit;

                mesg_curr_bit++;
                mesg_curr_bit %= 8;
                if (!mesg_curr_bit) mesg_curr_pos++;
            }
        }

        if (!is_len_extracted && mesg_curr_pos >= PREFIX_BYTES)
        {
            uint32_t be_len, payload_len;

            memcpy(&be_len, mesg->content, PREFIX_BYTES);
            payload_len = ntohl(be_len);
            mesg->sz = PREFIX_BYTES + payload_len;
            is_len_extracted = 1;
        }
    }
}

static void run_roundtrip(const char *label, const uint8_t *msg, size_t len,
                          const char *pass)
{
    static uint8_t codebuf[NUM_INSNS * 2];
    hdn_sections_t *sect;
    hdn_sections_header_t sh;
    hdn_disassembly_data_t *code = NULL;
    hdn_data_t *mesg;
    uint32_t num_elts = 0;
    int decrypt_rc;

    memset(codebuf, 0xCC, sizeof codebuf);
    build_section(codebuf, sizeof codebuf);

    sect = calloc(1, sizeof(hdn_sections_t) + sizeof codebuf);
    sect->offset = 0;
    sect->address = (uint8_t *) 0x1000;
    sect->type = 1;
    sect->flags = 0x6;
    sect->data.sz = sizeof codebuf;
    memcpy(sect->data.content, codebuf, sizeof codebuf);

    sh.start_addr = 0x1000;
    sh.sections = sect;

    mesg = malloc(sizeof(hdn_data_t) + len);
    memcpy(mesg->content, msg, len);
    mesg->sz = len;

    check(hdn_crypto_encrypt(&mesg, (char *) pass) == 0, label);
    if (failures) { free(mesg); free(sect); return; }

    {
        uint32_t ct_len = mesg->sz;
        uint32_t total_len = PREFIX_BYTES + ct_len;
        uint32_t be_len = htonl(ct_len);
        hdn_data_t *nm = realloc(mesg, sizeof(hdn_data_t) + total_len);

        if (!nm) { failures++; free(sect); return; }
        mesg = nm;
        memmove(mesg->content + PREFIX_BYTES, mesg->content, ct_len);
        memcpy(mesg->content, &be_len, PREFIX_BYTES);
        mesg->sz = total_len;
    }

    code = hdn_disassemble_all(sh.sections, &num_elts);
    check(code != NULL && num_elts > 0, label);
    if (!code || !num_elts) { free(mesg); free(code); free(sect); return; }

    hdn_subst_insns_tag_valid(code, num_elts);
    embed_bits(code, num_elts, mesg);

    {
        hdn_disassembly_data_t *code2 = NULL;
        uint32_t num_elts2 = 0;
        hdn_data_t *dec;
        uint32_t payload_len;

        code2 = hdn_disassemble_all(sh.sections, &num_elts2);
        check(code2 != NULL && num_elts2 == num_elts, label);
        if (!code2 || !num_elts2)
        {
            free(code); free(mesg); free(sect);
            failures++;
            return;
        }

        hdn_subst_insns_tag_valid(code2, num_elts2);

        dec = malloc(sizeof(hdn_data_t) + sizeof codebuf);
        dec->sz = sizeof codebuf;
        memset(dec->content, 0, dec->sz);

        extract_bits(code2, num_elts2, dec);

        payload_len = dec->sz - PREFIX_BYTES;
        memmove(dec->content, dec->content + PREFIX_BYTES, payload_len);
        dec->sz = payload_len;

        decrypt_rc = hdn_crypto_decrypt(&dec, (char *) pass);
        check(decrypt_rc == 0, label);
        check(dec->sz == len && memcmp(dec->content, msg, len) == 0, label);

        free(dec);
        free(code2);
    }

    free(code);
    free(mesg);
    free(sect);
}

int main(void)
{
    uint8_t bin[16] = {0x00, 0xFF, 0x00, 0x13, 0x37, 0x00, 0xDE, 0xAD,
                       0xBE, 0xEF, 0x00, 0x42, 0x69, 0x00, 0x01, 0x02};
    static uint8_t big[256];
    size_t i;

    run_roundtrip("text roundtrip", (const uint8_t *)"in-memory hydan roundtrip!", 26,
                  "secret");

    run_roundtrip("binary roundtrip", bin, sizeof bin, "p4ss");

    run_roundtrip("empty msg roundtrip", (const uint8_t *)"", 0, "pw");

    for (i = 0; i < sizeof big; i++)
        big[i] = (uint8_t)(i * 31 + 5);
    run_roundtrip("256-byte roundtrip", big, sizeof big, "longerpassword");

    printf("%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}

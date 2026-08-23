#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Zydis/Zydis.h>
#include "hdn_common.h"
#include "hdn_subst_insns.h"

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

static uint32_t decode_buf(uint8_t *buf, size_t len, x86_insn_t *out,
                           hdn_disassembly_data_t *d)
{
    ZydisDecoder decoder;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
                     ZYDIS_STACK_WIDTH_32);

    bzero(out, sizeof(*out));
    bzero(d, sizeof(*d));
    d->memaddr = buf;
    d->effaddr = buf;
    d->status  = insn_status_none;

    ZyanStatus st = ZydisDecoderDecodeFull(&decoder, buf, (ZyanUSize) len,
                                           &out->zydis, ops);
    if (!ZYAN_SUCCESS(st))
        return 0;

    memcpy(out->raw, buf, out->zydis.length);
    hdn_populate_insn_from_zydis(out, &out->zydis, ops);

    d->insn = *out;
    return out->zydis.length;
}

struct subst_case
{
    const char *name;
    uint8_t     bytes[8];
    uint32_t    len;
    uint32_t    bits;
};

static struct subst_case cases[] =
{
    {"addsub32-1", {0x05, 0x78, 0x56, 0x34, 0x12}, 5, 1},
    {"addsub32-3", {0x83, 0xC0, 0x05},             3, 1},
    {"toac32",     {0x85, 0xC0},                   2, 2},
    {"xorsub32",   {0x31, 0xC0},                   2, 2},
    {"mov32",      {0x89, 0xC0},                   2, 1},
    {"add32",      {0x01, 0xC0},                   2, 1},
};

int main(void)
{
    size_t c;
    uint32_t v;

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
    {
        struct subst_case *sc = &cases[c];
        char label[256];
        uint8_t buf[16];
        x86_insn_t insn;
        hdn_disassembly_data_t d;
        uint32_t possible;
        int case_ok = 1;

        memcpy(buf, sc->bytes, sc->len);
        snprintf(label, sizeof label, "%s: decodes", sc->name);
        check(decode_buf(buf, sc->len, &insn, &d) != 0, label);
        if (failures) continue;

        possible = hdn_subst_insns_is_possible(&d, 1, 0);
        snprintf(label, sizeof label, "%s: is_possible == %u", sc->name,
                 sc->bits);
        check(possible == sc->bits, label);
        if (possible != sc->bits) continue;

        for (v = 0; v < (1u << sc->bits); v++)
        {
            uint8_t source[2] = {0, 0};
            x86_insn_t insn2;
            hdn_disassembly_data_t d2;
            int got_bits = -1;
            uint32_t got_val, embedded;

            if (!case_ok) break;

            memcpy(buf, sc->bytes, sc->len);
            decode_buf(buf, sc->len, &insn, &d);

            source[0] = (uint8_t)(v << (8 - sc->bits));
            embedded = hdn_subst_insns(&d.insn, d.memaddr, source, 0);

            decode_buf(buf, sc->len, &insn2, &d2);
            got_val = hdn_subst_insns_val(&d2.insn, d2.memaddr, &got_bits);

            snprintf(label, sizeof label,
                     "%s: roundtrip val=%u (embedded=%u bits, decoded=%u/%d)",
                     sc->name, v, embedded, got_val, got_bits);
            case_ok = (embedded == sc->bits && got_bits == (int) sc->bits &&
                       got_val == v);
            check(case_ok, label);
        }
    }

    {
        uint8_t nop[] = {0x90};
        x86_insn_t insn;
        hdn_disassembly_data_t d;
        hdn_disassembly_data_t arr[1];

        decode_buf(nop, sizeof nop, &insn, &d);
        arr[0] = d;
        hdn_subst_insns_tag_valid(arr, 1);
        check(hdn_subst_insns_is_possible(arr, 1, 0) == 0 &&
              arr[0].status != insn_status_valid,
              "nop is not embeddable");
    }

    {
        uint8_t mov[] = {0xB8, 0x00, 0x00, 0x00, 0x00};
        x86_insn_t insn;
        hdn_disassembly_data_t d;

        decode_buf(mov, sizeof mov, &insn, &d);
        check(hdn_subst_insns_is_possible(&d, 1, 0) == 0,
              "mov eax, imm32 is not embeddable");
    }

    printf("%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}

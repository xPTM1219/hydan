#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hdn_crypto.h"

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

static void roundtrip(const char *label, const uint8_t *msg, size_t len,
                      const char *pass)
{
    hdn_data_t *data = malloc(sizeof(hdn_data_t) + len);

    memcpy(data->content, msg, len);
    data->sz = len;

    check(hdn_crypto_encrypt(&data, (char *) pass) == 0, label);
    {
        char buf[256];

        snprintf(buf, sizeof buf, "%s [blob sz == pt + overhead]", label);
        check(data->sz == len + HDN_CRYPTO_OVERHEAD, buf);

        snprintf(buf, sizeof buf, "%s [decrypt ok]", label);
        check(hdn_crypto_decrypt(&data, (char *) pass) == 0, buf);

        snprintf(buf, sizeof buf, "%s [sz+bytes exact]", label);
        check(data->sz == len && memcmp(data->content, msg, len) == 0, buf);
    }

    free(data);
}

int main(void)
{
    uint8_t bin[10] = {0x00, 0x01, 0x02, 0x00, 0xFF, 0x00, 0xAB, 0xCD, 0xFE, 0x00};
    static uint8_t big[4096];
    size_t i;
    hdn_data_t *data;

    roundtrip("text msg", (const uint8_t *)"hello, hydan crypto", 19, "secret");

    roundtrip("binary msg with NUL bytes", bin, sizeof bin, "p4ssw0rd");

    roundtrip("empty msg", (const uint8_t *)"", 0, "emptypass");

    roundtrip("empty password", (const uint8_t *)"some message", 12, "");

    for (i = 0; i < sizeof big; i++)
        big[i] = (uint8_t)(i * 7 + (i >> 4));
    roundtrip("4096-byte msg", big, sizeof big, "bigpass");

    data = malloc(sizeof(hdn_data_t) + 5);
    memcpy(data->content, "abcde", 5);
    data->sz = 5;
    hdn_crypto_encrypt(&data, "secret");
    check(hdn_crypto_decrypt(&data, "wrongpass") != 0,
          "wrong password rejected");
    free(data);

    data = malloc(sizeof(hdn_data_t) + 5);
    memcpy(data->content, "abcde", 5);
    data->sz = 5;
    hdn_crypto_encrypt(&data, "secret");
    ((uint8_t *) data->content)[HDN_CRYPTO_OVERHEAD] ^= 0x01;
    check(hdn_crypto_decrypt(&data, "secret") != 0,
          "tampered ciphertext rejected (GCM tag)");
    free(data);

    data = malloc(sizeof(hdn_data_t) + 3);
    memcpy(data->content, "xyz", 3);
    data->sz = 3;
    check(hdn_crypto_encrypt(NULL, "pw") != 0 &&
          hdn_crypto_encrypt(&data, NULL) != 0,
          "NULL args rejected");
    free(data);

    printf("%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}

/*
 * $Id: hdn_crypto.h,v 1.2 2003/01/05 01:39:47 xvr Exp $
 * Created: 09/03/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 *
 * Message encryption for embed/decode.  AES-256-GCM with a key
 * derived from the passphrase via PBKDF2-HMAC-SHA256.
 *
 * Ciphertext framing is a pure binary blob (no base64, no delimiters,
 * binary-safe):
 *
 *     +----------+---------+---------+---------------------------+
 *     | salt(16) | iv (12) | tag(16) | ciphertext (== pt length) |
 *     +----------+---------+---------+---------------------------+
 *     |<------------- HDN_CRYPTO_OVERHEAD = 44 -------------------->|
 *
 * Because GCM is an authenticated stream cipher, ciphertext length
 * equals plaintext length; the tag authenticates blob + passphrase.
 * A wrong password or a corrupted host shows up as a decrypt failure.
 */

#ifndef _HDN_CRYPTO_H_
#define _HDN_CRYPTO_H_

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "hydan.h"

/* binary blob layout sizes */
#define HDN_CRYPTO_SALT_LEN   16
#define HDN_CRYPTO_IV_LEN     12
#define HDN_CRYPTO_TAG_LEN    16
#define HDN_CRYPTO_KEY_LEN    32
#define HDN_CRYPTO_OVERHEAD   (HDN_CRYPTO_SALT_LEN + HDN_CRYPTO_IV_LEN + HDN_CRYPTO_TAG_LEN)

/* refuse inputs larger than this (1 MiB) instead of over-allocating */
#define HDN_CRYPTO_MAX_INPUT  (1024 * 1024)

/*
 * encrypts data->content in place.  On success *data is realloc'd to
 * hold sz == plaintext + HDN_CRYPTO_OVERHEAD bytes of binary blob.
 * Returns 0 on success, -1 on error (including NULL args or input too
 * large).
 */
int hdn_crypto_encrypt(hdn_data_t **data, char *password);

/*
 * parses the binary blob in (*data)->content, verifies the GCM tag
 * and replaces *data with the plaintext.  Returns -1 on any parse,
 * size or authentication failure.
 */
int hdn_crypto_decrypt(hdn_data_t **data, char *password);

/*
 * returns a malloc'd SHA-256 digest of input_len bytes of `input`
 * (binary safe -- no strlen).  Caller frees.
 */
uint8_t *hdn_crypto_hash(const char *input, size_t input_len);

/*
 * seeds random() from the first 64 bits of SHA-256(pass); falls back
 * to time^pid when pass is unusable.  Used to derive the instruction
 * walk order (currently unused -- reserved for randomized embedding).
 */
void hdn_crypto_srandom(char *pass);

#endif

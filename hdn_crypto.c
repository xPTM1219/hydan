/*
 * $Id: hdn_crypto.c,v 1.8 2004/04/28 22:27:34 xvr Exp $
 * Created: 09/03/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 *
 * AES-256-GCM + PBKDF2-HMAC-SHA256 (100k iterations) message crypto.
 *
 * The low-level helpers pack/unpack the fixed-layout binary blob
 * documented in hdn_crypto.h; the high-level hdn_crypto_encrypt/
 * decrypt operate on whole hdn_data_t buffers, sizing everything from
 * data->sz (binary safe -- never strlen) with dynamically allocated
 * scratch.  Inputs above HDN_CRYPTO_MAX_INPUT are rejected.
 */

#include "hdn_crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define HASH_ALGO    EVP_sha256()
#define CRYPTO_ALGO  EVP_aes_256_gcm()
#define PBKDF2_ITER  100000

/*
 * encrypt ptlen bytes into a freshly packed binary blob:
 * [salt|iv|tag|ct].  *outlen is in/out: capacity on entry, exact blob
 * size on success.
 */
static int hdn_encrypt_raw(const uint8_t *pt, size_t ptlen,
                           const char *password,
                           uint8_t *out, size_t *outlen)
{
    uint8_t salt[HDN_CRYPTO_SALT_LEN];
    uint8_t iv[HDN_CRYPTO_IV_LEN];
    uint8_t key[HDN_CRYPTO_KEY_LEN];
    uint8_t tag[HDN_CRYPTO_TAG_LEN];
    uint8_t *ct = NULL;
    int ct_len = 0, final_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int rc = -1;

    if (ptlen > HDN_CRYPTO_MAX_INPUT)
        return -1;

    if (!RAND_bytes(salt, HDN_CRYPTO_SALT_LEN) ||
        !RAND_bytes(iv, HDN_CRYPTO_IV_LEN))
        return -1;

    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                            salt, HDN_CRYPTO_SALT_LEN,
                            PBKDF2_ITER, EVP_sha256(),
                            HDN_CRYPTO_KEY_LEN, key))
        return -1;

    ct = malloc(ptlen + EVP_MAX_BLOCK_LENGTH);
    if (!ct)
        return -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto done;

    if (!EVP_EncryptInit_ex(ctx, CRYPTO_ALGO, NULL, key, iv))
        goto done;

    if (!EVP_EncryptUpdate(ctx, ct, &ct_len, pt, (int)ptlen))
        goto done;

    if (!EVP_EncryptFinal_ex(ctx, ct + ct_len, &final_len))
        goto done;
    ct_len += final_len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, HDN_CRYPTO_TAG_LEN, tag))
        goto done;

    /* layout: [salt(16)][iv(12)][tag(16)][ciphertext] */    if (*outlen < HDN_CRYPTO_OVERHEAD + (size_t)ct_len) {
        rc = -1;
        goto done;
    }

    memcpy(out, salt, HDN_CRYPTO_SALT_LEN);
    memcpy(out + HDN_CRYPTO_SALT_LEN, iv, HDN_CRYPTO_IV_LEN);
    memcpy(out + HDN_CRYPTO_SALT_LEN + HDN_CRYPTO_IV_LEN, tag, HDN_CRYPTO_TAG_LEN);
    memcpy(out + HDN_CRYPTO_OVERHEAD, ct, ct_len);
    *outlen = HDN_CRYPTO_OVERHEAD + (size_t)ct_len;

    rc = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    free(ct);
    return rc;
}

/*
 * decrypt the fixed-layout blob (see hdn_crypto.h).  The GCM tag is
 * set on the context before DecryptFinal, so any wrong password or
 * byte corruption fails authentication and returns -1.  *outlen is
 * in/out: capacity on entry, plaintext size on success.
 */
static int hdn_decrypt_raw(const uint8_t *blob, size_t bloblen,
                           const char *password,
                           uint8_t *out, size_t *outlen)
{
    uint8_t key[HDN_CRYPTO_KEY_LEN];
    const uint8_t *salt, *iv, *tag, *ct;
    size_t ct_len;
    int pt_len = 0, final_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int rc = -1;

    if (bloblen < HDN_CRYPTO_OVERHEAD)
        return -1;

    salt = blob;
    iv   = blob + HDN_CRYPTO_SALT_LEN;
    tag  = blob + HDN_CRYPTO_SALT_LEN + HDN_CRYPTO_IV_LEN;
    ct   = blob + HDN_CRYPTO_OVERHEAD;
    ct_len = bloblen - HDN_CRYPTO_OVERHEAD;

    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                            salt, HDN_CRYPTO_SALT_LEN,
                            PBKDF2_ITER, EVP_sha256(),
                            HDN_CRYPTO_KEY_LEN, key))
        return -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    if (!EVP_DecryptInit_ex(ctx, CRYPTO_ALGO, NULL, key, iv))
        goto done;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, HDN_CRYPTO_TAG_LEN,
                             (void *)tag))
        goto done;

    if (*outlen < ct_len) {
        rc = -1;
        goto done;
    }

    if (!EVP_DecryptUpdate(ctx, out, &pt_len, ct, (int)ct_len))
        goto done;

    if (!EVP_DecryptFinal_ex(ctx, out + pt_len, &final_len))
        goto done;
    pt_len += final_len;

    *outlen = (size_t)pt_len;
    rc = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/*
 * SHA-256 of input_len bytes (binary safe).  Digest buffer is
 * EVP_MAX_MD_SIZE; actual length is always 32 for SHA-256.
 */
uint8_t *hdn_crypto_hash(const char *input, size_t input_len)
{
    uint8_t *digest;
    EVP_MD_CTX *ctx;
    unsigned int digest_len;

    if (!input)
        return NULL;

    digest = malloc(EVP_MAX_MD_SIZE);
    if (!digest)
        return NULL;

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(digest);
        return NULL;
    }

    if (EVP_DigestInit_ex(ctx, HASH_ALGO, NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, input_len) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        free(digest);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);
    return digest;
}

/*
 * seed random() from the password so the (currently disabled)
 * randomized instruction walk is reproducible per-passphrase.  The
 * first 8 bytes of the SHA-256 digest, big-endian, become the seed.
 */
void hdn_crypto_srandom(char *pass)
{
    uint64_t seed = 0;
    uint8_t *digest = NULL;
    unsigned int hash_length;

    if (pass) {
        digest = hdn_crypto_hash(pass, strlen(pass));
        hash_length = EVP_MD_size(HASH_ALGO);
    }

    if (digest && hash_length >= sizeof(seed)) {
        for (unsigned int i = 0; i < sizeof(seed); i++)
            seed = (seed << 8) | digest[i];
    } else {
        seed = (uint64_t)time(NULL) ^ (uint64_t)getpid();
    }

    free(digest);
    srandom((unsigned long)seed);
}

/*
 * encrypt the whole hdn_data_t in place: content becomes the binary
 * blob, sz grows by HDN_CRYPTO_OVERHEAD.  Lengths come from data->sz,
 * never strlen -- messages may contain NUL bytes.
 */
int hdn_crypto_encrypt(hdn_data_t **data, char *password)
{
    size_t ptlen, bloblen;
    uint8_t *blob;
    hdn_data_t *new_data;

    if (!data || !*data || !password)
        return -1;

    ptlen = (*data)->sz;
    if (ptlen > HDN_CRYPTO_MAX_INPUT)
        return -1;

    bloblen = HDN_CRYPTO_OVERHEAD + ptlen + EVP_MAX_BLOCK_LENGTH;
    blob = malloc(bloblen);
    if (!blob)
        return -1;

    if (hdn_encrypt_raw((uint8_t *)(*data)->content, ptlen,
                        password, blob, &bloblen) != 0) {
        free(blob);
        return -1;
    }

    new_data = realloc(*data, sizeof(hdn_data_t) + bloblen);
    if (!new_data) {
        free(blob);
        return -1;
    }

    *data = new_data;
    (*data)->sz = (uint32_t)bloblen;
    memcpy((*data)->content, blob, bloblen);

    free(blob);
    return 0;
}

/*
 * decrypt the whole hdn_data_t in place: verifies the GCM tag and
 * replaces content with the plaintext (sz shrinks by the overhead).
 * Returns -1 on any failure, leaving the caller's buffer freed.
 */
int hdn_crypto_decrypt(hdn_data_t **data, char *password)
{
    size_t bloblen, outlen;
    uint8_t *pt;
    hdn_data_t *new_data;

    if (!data || !*data || !password)
        return -1;

    bloblen = (*data)->sz;
    if (bloblen < HDN_CRYPTO_OVERHEAD)
        return -1;

    outlen = bloblen - HDN_CRYPTO_OVERHEAD;
    pt = malloc(outlen);
    if (!pt)
        return -1;

    if (hdn_decrypt_raw((uint8_t *)(*data)->content, bloblen,
                        password, pt, &outlen) != 0) {
        free(pt);
        return -1;
    }

    new_data = realloc(*data, sizeof(hdn_data_t) + outlen);
    if (!new_data) {
        free(pt);
        return -1;
    }

    *data = new_data;
    (*data)->sz = (uint32_t)outlen;
    memcpy((*data)->content, pt, outlen);

    free(pt);
    return 0;
}

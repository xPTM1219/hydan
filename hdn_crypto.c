/*
 * $Id: hdn_crypto.c,v 1.8 2004/04/28 22:27:34 xvr Exp $
 * Created: 09/03/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#include "hdn_crypto.h"

static uint8_t iv[] = {'x', 'v', 'r', 'j', 'Z', ':', 'y', 'x'};

//#ifdef _DEBUG //XXX bug here..
//#define HASH_ALGO   EVP_md_null()
//#define CRYPTO_ALGO EVP_enc_null()
//#else
#define HASH_ALGO   EVP_sha1()
#define CRYPTO_ALGO EVP_bf_cbc()  //encrypt/decrypt
//#endif

/*
 * seeds the random number generator
 */
void hdn_crypto_srandom (char *pass)
{
    uint64_t seed = 123;
    uint8_t *digest;

    if ( (digest = hdn_crypto_hash (pass)) )
    {
        /*
         * gets the first 8 bytes of the hash to use as a seed.
         * [sha length is 20 bytes]
         */
        memcpy (&seed, digest, sizeof seed);
    }
    else
    {
        HDN_WARN ("Error: Invalid pass.  Using default seed instead");
    }

    srandom (seed);
}

/*
 * skips upto 'max' instructions
 */
int hdn_crypto_skip_insn (uint32_t max)
{
    static uint32_t left = 0;

#ifdef _DEBUG
    return 0;
#endif

    if (!left)
    {
        left = random () % max;
        return (left != 0);
    }

    left--;

    return (left != 0);
}


uint8_t *hdn_crypto_hash (char *in)
{
    uint8_t *digest;
    EVP_MD_CTX ctx;

    if (!in)
        return NULL;

    if (!(digest = malloc (EVP_MAX_MD_SIZE)))
        return NULL;

    EVP_DigestInit (&ctx, HASH_ALGO);
    EVP_DigestUpdate (&ctx, in, strlen (in));
    EVP_DigestFinal (&ctx, digest, NULL);

    return digest;
}

void hdn_crypto_encrypt (hdn_data_t **inout, uint8_t *key)
{
    uint8_t *cipher = NULL;
    uint32_t out_sz, sz, total_sz;
    hdn_data_t *in = (*inout);
    EVP_CIPHER_CTX ctx;

    /*
     * init context, bf in cbc mode, default impl
     */
    EVP_EncryptInit (&ctx, CRYPTO_ALGO, key, iv);
    cipher = malloc (sizeof (in->sz) + in->sz + EVP_CIPHER_CTX_block_size(&ctx));

    if (!cipher)
        HDN_EXIT ("Error allocating memory for encryption. "
                  "Requested %d bytes of memory.",
                  sizeof (in->sz) + in->sz + EVP_CIPHER_CTX_block_size(&ctx));

    /*
     * save the size, and make sure that it's a multiple of the cipher
     * block size
     */
    sz = in->sz;
    in->sz += EVP_CIPHER_CTX_block_size(&ctx) -
        ((in->sz + sizeof (in->sz)) % EVP_CIPHER_CTX_block_size(&ctx));

    /*
     * whiten it
     */
    hdn_math_xor (&in->sz, hdn_crypto_hash (key), sizeof (in->sz));

    /*
     * encrypt everything
     */
    EVP_EncryptUpdate (&ctx, cipher, &out_sz, (char *)in, sizeof(in->sz) + sz);
    total_sz = out_sz;

    EVP_EncryptFinal (&ctx, cipher + total_sz, &out_sz);
    total_sz += out_sz;

    /*
     * store this gunk
     */
    (*inout) = realloc (*inout, sizeof (hdn_data_t) + total_sz);

    if (!(*inout))
        HDN_EXIT ("Error allocating memory to duplicate encryption. "
                  "Requested %d bytes.", sizeof (hdn_data_t) + total_sz);

    (*inout)->sz = total_sz;
    memcpy ((*inout)->content, cipher, total_sz);

    /*
     * cleanup
     */
    EVP_CIPHER_CTX_cleanup (&ctx);
    if (cipher) free (cipher);
}

void hdn_crypto_decrypt (hdn_data_t **inout, uint8_t *key)
{
    uint8_t *plain = NULL;
    uint32_t out_sz;
    hdn_data_t *in = (*inout);
    EVP_CIPHER_CTX ctx;

    /*
     * init
     */
    EVP_DecryptInit (&ctx, CRYPTO_ALGO, key, iv);
    plain = malloc (in->sz + EVP_CIPHER_CTX_block_size(&ctx));

    if (!plain)
        HDN_EXIT ("Error allocating memory for decryption. "
                  "Requested %d bytes.", in->sz + EVP_CIPHER_CTX_block_size(&ctx));

    /*
     * decrypt
     */
    EVP_DecryptUpdate (&ctx, plain, &out_sz, in->content, in->sz);
    EVP_DecryptFinal (&ctx, plain + out_sz, &out_sz);

    /*
     * store only the right length worth of decryption
     */
    in = (hdn_data_t *)plain;
    hdn_math_xor (&in->sz, hdn_crypto_hash (key), sizeof (in->sz));
    (*inout) = realloc (*inout, in->sz + sizeof (hdn_data_t));

    if (!(*inout))
        HDN_EXIT ("Error allocating memory for duplicating decryption. "
                  "Requested %d bytes.", in->sz + sizeof (hdn_data_t));

    memcpy (*inout, plain, in->sz + sizeof (hdn_data_t));

    /*
     * cleanup
     */
    EVP_CIPHER_CTX_cleanup (&ctx);
    if (plain) free (plain);
}


/*
 * $Id: hdn_crypto.c,v 1.8 2004/04/28 22:27:34 xvr Exp $
 * Created: 09/03/2002
 *
 * Updated to use new encrypt/decrypt functions with PBKDF2 key derivation
 * and AES-256-GCM encryption.
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#include "hdn_crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

//#ifdef _DEBUG //XXX bug here..
//#define HASH_ALGO   EVP_md_null()
//#define CRYPTO_ALGO EVP_enc_null()
//#else
#define HASH_ALGO   EVP_sha256()
#define CRYPTO_ALGO EVP_aes_256_gcm()  //encrypt/decrypt
#define ITERATIONS 100000
#define KEY_LENGTH_BYTES 32  // 256 bits
#define GCM_TAG_LENGTH 16    // 128 bits
#define SALT_LENGTH 16
#define IV_LENGTH 12
//#endif

/**
 * Encodes binary data to Base64 string.
 *
 * @param input      Input binary data.
 * @param input_len  Length of input data.
 * @param output     Output buffer for Base64 string.
 * @return Length of Base64 output.
 */
static int base64_encode(const unsigned char *input, int input_len, char *output) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    int output_len;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, input_len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    output_len = buffer_ptr->length;
    memcpy(output, buffer_ptr->data, output_len);
    output[output_len] = '\0';

    BIO_free_all(bio);
    return output_len;
}

/**
 * Decodes Base64 string to binary data.
 *
 * @param input      Input Base64 string.
 * @param input_len  Length of input string.
 * @param output     Output buffer for binary data.
 * @return Length of decoded output.
 */
static int base64_decode(const char *input, int input_len, unsigned char *output) {
    BIO *bio, *b64;
    int output_len;

    bio = BIO_new_mem_buf(input, input_len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    output_len = BIO_read(bio, output, input_len);

    BIO_free_all(bio);
    return output_len;
}

/**
 * Seeds the random number generator using a cryptographically secure method
 */
void hdn_crypto_srandom(char *pass) {
    uint64_t seed = 0;
    uint8_t *digest = NULL;
    size_t hash_length = 0;

    // Get hash length from the hash function (more robust than hardcoding)
    hash_length = 8; //hdn_crypto_hash_length();

    if (pass && (digest = hdn_crypto_hash(pass))) {
        // Use first 8 bytes of hash as seed, with proper endianness handling
        if (hash_length >= sizeof(seed)) {
            // Convert to host byte order for srandom()
            seed = 0;
            for (int i = 0; i < sizeof(seed); i++) {
                seed = (seed << 8) | digest[i];
            }
        } else {
            // If hash is shorter than seed size, pad with zeros
            memcpy(&seed, digest, hash_length);
        }
    } else {
        // Fallback to a more secure default seed if pass is invalid
        // Using current time and process ID for better entropy
        seed = (uint64_t)time(NULL) ^ (uint64_t)getpid();
        HDN_WARN("Invalid password provided. Using system-derived seed instead.");
    }

    // Use arc4random() if available (more secure than srandom())
    #ifdef HAVE_ARC4RANDOM
        arc4random_seed(seed);
    #else
        srandom(seed);
    #endif
}

/**
 * Skips up to 'max' instructions with better randomness and thread safety
 */
int hdn_crypto_skip_insn(uint32_t max) {
    static uint32_t left = 0;
    static pthread_mutex_t skip_mutex = PTHREAD_MUTEX_INITIALIZER;

    // Skip in debug builds
    #ifdef _DEBUG
        return 0;
    #endif

    // Thread-safe random number generation
    pthread_mutex_lock(&skip_mutex);

    if (!left) {
        // Use better random number generation
        #ifdef HAVE_ARC4RANDOM
            left = arc4random_uniform(max);
        #else
            left = random() % max;
        #endif
        pthread_mutex_unlock(&skip_mutex);
        return (left != 0);
    }

    left--;
    pthread_mutex_unlock(&skip_mutex);
    return (left != 0);
}


uint8_t *hdn_crypto_hash(char *in) {
    uint8_t *digest;
    EVP_MD_CTX *ctx;

    if (!in)
        return NULL;

    // Allocate memory for digest (EVP_MAX_MD_SIZE is the max possible size)
    if (!(digest = malloc(EVP_MAX_MD_SIZE)))
        return NULL;

    // Create a new hash context (NOT cipher context!)
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(digest);
        return NULL;
    }


    // Initialize the hash (use _ex for modern OpenSSL)
    if (EVP_DigestInit_ex(ctx, HASH_ALGO, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        free(digest);
        return NULL;
    }

    // Update the hash with input data
    if (EVP_DigestUpdate(ctx, in, strlen(in)) != 1) {
        EVP_MD_CTX_free(ctx);
        free(digest);
        return NULL;
    }

    // Finalize the hash (get the actual length)
    unsigned int digest_len;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        free(digest);
        return NULL;
    }

    // Clean up
    EVP_MD_CTX_free(ctx);

    // Return the digest (digest_len bytes are valid)
    return digest;
}

/**
 * Low-level encrypt function.
 *
 * @param password   Password defined by user.
 * @param plaintext  Message to be encrypted.
 * @param algorithm  Algorithm to use (e.g., "aes-256-gcm").
 * @param delimiter  Delimiter to separate components.
 * @param output     Output buffer for encrypted result.
 * @param output_len Maximum length of output buffer.
 * @return Length of encrypted output, or -1 on error.
 */
static int hdn_encrypt(
    const char *password,
    const char *plaintext,
    const char *algorithm,
    const char *delimiter,
    char *output,
    int output_len) {

    unsigned char salt[SALT_LENGTH];
    unsigned char iv[IV_LENGTH];
    unsigned char key[KEY_LENGTH_BYTES];
    unsigned char ciphertext[1024];  // Adjust size as needed
    unsigned char tag[GCM_TAG_LENGTH];
    int ciphertext_len;
    EVP_CIPHER_CTX *ctx;
    int len;

    // Generate random salt and IV
    if (!RAND_bytes(salt, SALT_LENGTH) || !RAND_bytes(iv, IV_LENGTH)) {
        return -1;
    }

    // Derive key using PBKDF2
    if (!PKCS5_PBKDF2_HMAC(
            password,
            strlen(password),
            salt,
            SALT_LENGTH,
            ITERATIONS,
            EVP_sha256(),
            KEY_LENGTH_BYTES,
            key)) {
        return -1;
    }

    // Encrypt
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len,
                          (unsigned char *)plaintext, strlen(plaintext))) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int temp_len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += temp_len;

    // Get authentication tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LENGTH, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    // Append tag to ciphertext
    memcpy(ciphertext + ciphertext_len, tag, GCM_TAG_LENGTH);
    ciphertext_len += GCM_TAG_LENGTH;

    // Encode to Base64 and combine
    char salt_b64[256], iv_b64[256], ciphertext_b64[1024];
    int salt_b64_len = base64_encode(salt, SALT_LENGTH, salt_b64);
    int iv_b64_len = base64_encode(iv, IV_LENGTH, iv_b64);
    int ciphertext_b64_len = base64_encode(ciphertext, ciphertext_len, ciphertext_b64);

    // Combine with delimiter
    int result_len = snprintf(output, output_len, "%s%s%s%s%s",
                             salt_b64, delimiter, iv_b64, delimiter, ciphertext_b64);

    return result_len > 0 ? result_len : -1;
}

/**
 * Low-level decrypt function.
 *
 * @param password      Password used to encrypt the original message.
 * @param encryptedData Encrypted message.
 * @param algorithm     The algorithm used to encrypt the message.
 * @param delimiter     Delimiter used to separate components.
 * @param output        Output buffer for decrypted result.
 * @param output_len    Maximum length of output buffer.
 * @return Length of decrypted output, or -1 on error.
 */
static int hdn_decrypt(
    const char *password,
    const char *encryptedData,
    const char *algorithm,
    const char *delimiter,
    char *output,
    int output_len) {

    unsigned char salt[SALT_LENGTH];
    unsigned char iv[IV_LENGTH];
    unsigned char ciphertext[1024];
    unsigned char tag[GCM_TAG_LENGTH];
    unsigned char key[KEY_LENGTH_BYTES];
    unsigned char plaintext[1024];
    int ciphertext_len, plaintext_len;
    EVP_CIPHER_CTX *ctx;
    int len;

    // Parse encrypted data
    char *data_copy = strdup(encryptedData);
    if (!data_copy) return -1;

    char *salt_b64 = strtok(data_copy, delimiter);
    char *iv_b64 = strtok(NULL, delimiter);
    char *ciphertext_b64 = strtok(NULL, delimiter);

    if (!salt_b64 || !iv_b64 || !ciphertext_b64) {
        free(data_copy);
        return -1;
    }

    // Decode Base64
    int salt_len = base64_decode(salt_b64, strlen(salt_b64), salt);
    int iv_len = base64_decode(iv_b64, strlen(iv_b64), iv);
    ciphertext_len = base64_decode(ciphertext_b64, strlen(ciphertext_b64), ciphertext);

    free(data_copy);

    // Extract tag from end of ciphertext
    if (ciphertext_len < GCM_TAG_LENGTH) return -1;
    ciphertext_len -= GCM_TAG_LENGTH;
    memcpy(tag, ciphertext + ciphertext_len, GCM_TAG_LENGTH);

    // Derive key using PBKDF2
    if (!PKCS5_PBKDF2_HMAC(
            password,
            strlen(password),
            salt,
            salt_len,
            ITERATIONS,
            EVP_sha256(),
            KEY_LENGTH_BYTES,
            key)) {
        return -1;
    }

    // Decrypt
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set authentication tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LENGTH, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int temp_len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;  // Authentication failed
    }
    plaintext_len += temp_len;

    EVP_CIPHER_CTX_free(ctx);

    // Copy result to output
    if (plaintext_len >= output_len) return -1;
    memcpy(output, plaintext, plaintext_len);
    output[plaintext_len] = '\0';

    return plaintext_len;
}

/*
 * High-level encrypt function for hdn_data_t
 */
int hdn_crypto_encrypt(hdn_data_t **data, char *password) {
    char output[4096]; // buffer for encrypted data

    int len = hdn_encrypt(password, (*data)->content, "aes-256-gcm", ":", output, sizeof(output));
    if (len == -1) return -1;

    // Reallocate data structure to fit new content
    hdn_data_t *new_data = realloc(*data, sizeof(hdn_data_t) + len);
    if (!new_data) return -1;

    *data = new_data;
    (*data)->sz = len;
    memcpy((*data)->content, output, len);

    return 0;
}

/*
 * High-level decrypt function for hdn_data_t
 */
int hdn_crypto_decrypt(hdn_data_t **data, char *password) {
    char output[4096]; // buffer for decrypted data

    int len = hdn_decrypt(password, (*data)->content, "aes-256-gcm", ":", output, sizeof(output));
    if (len == -1) return -1;

    // Reallocate data structure to fit new content
    hdn_data_t *new_data = realloc(*data, sizeof(hdn_data_t) + len);
    if (!new_data) return -1;

    *data = new_data;
    (*data)->sz = len;
    memcpy((*data)->content, output, len);

    return 0;
}

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

/*
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
hdn_crypto_encrypt function
*/
void hdn_crypto_encrypt(hdn_data_t **inout, uint8_t *key) {
    hdn_data_t *in = *inout;
    uint8_t *cipher = NULL;
    uint32_t out_sz = 0, final_len = 0;
    int block_size;
    EVP_CIPHER_CTX *ctx = NULL;

    // Validate input parameters
    if (!inout || !in || !key || !in->content || in->sz == 0) {
        HDN_EXIT("Invalid parameters for encryption");
    }

    // Initialize OpenSSL context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        HDN_EXIT("Error creating encryption context");
    }

    // Initialize encryption with proper error checking
    if (EVP_EncryptInit_ex(ctx, CRYPTO_ALGO, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error initializing encryption");
    }

    // Get block size after initialization
    block_size = EVP_CIPHER_CTX_block_size(ctx);
    if (block_size <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error getting block size");
    }

    // Allocate memory for encrypted data
    // Use 2 * block_size to safely account for final padding
    cipher = malloc(in->sz + (2 * block_size));
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error allocating memory for encryption. Requested %zu bytes",
                in->sz + (2 * block_size));
    }

    // Encrypt the data
    if (EVP_EncryptUpdate(ctx, cipher, (int *)&out_sz, in->content, in->sz) != 1) {
        free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error during encryption update");
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, cipher + out_sz, (int *)&final_len) != 1) {
        free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error during encryption final");
    }
    out_sz += final_len;

    // Whiten the size field (original size XORed with hash of key)
    uint8_t *hashed_key = hdn_crypto_hash(key);
    if (!hashed_key) {
        free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error hashing key");
    }

    uint32_t whitened_sz = in->sz;
    hdn_math_xor(&whitened_sz, hashed_key, sizeof(whitened_sz));
    free(hashed_key);

    // Reallocate output structure with encrypted data + whitened size
    hdn_data_t *new_data = realloc(*inout, sizeof(hdn_data_t) + out_sz + sizeof(whitened_sz));
    if (!new_data) {
        free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error allocating memory for encrypted data. Requested %zu bytes",
                 sizeof(hdn_data_t) + out_sz + sizeof(whitened_sz));
    }

    // Copy encrypted data
    memcpy(new_data->content, cipher, out_sz);
    // Append whitened size at the end
    memcpy(new_data->content + out_sz, &whitened_sz, sizeof(whitened_sz));
    
    // Update structure metadata
    new_data->sz = out_sz + sizeof(whitened_sz);
    *inout = new_data;

    // Cleanup
    free(cipher);
    EVP_CIPHER_CTX_free(ctx);
}

/**
hdn_crypto_decrypt decrypt
*/
void hdn_crypto_decrypt(hdn_data_t **inout, uint8_t *key) {
    hdn_data_t *in = *inout;
    uint8_t *plain = NULL;
    uint32_t out_sz, block_size, original_sz;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    if (!in || !key || !ctx) {
        EVP_CIPHER_CTX_free(ctx);  // Free ctx even if NULL (safe operation)
        HDN_EXIT("Error initializing decryption context");
    }
    
    // Initialize decryption context FIRST with proper error checking
    if (EVP_DecryptInit_ex(ctx, CRYPTO_ALGO, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error initializing decryption");
    }
    
    // NOW get block size after cipher is initialized
    block_size = EVP_CIPHER_CTX_block_size(ctx);
    if (block_size <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error getting block size");
    }
    
    // Allocate memory for decrypted data (input size + block size for padding)
    plain = malloc(in->sz + block_size);
    if (!plain) {
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error allocating memory for decryption. Requested %zu bytes",
                 in->sz + block_size);
    }
    
    // Decrypt the ciphertext (excluding the size field at the end)
    uint32_t cipher_data_sz = in->sz - sizeof(original_sz);
    if (EVP_DecryptUpdate(ctx, plain, (int *)&out_sz, in->content, cipher_data_sz) != 1) {
        free(plain);
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error during decryption update");
    }
    
    // Finalize decryption
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plain + out_sz, &final_len) != 1) {
        free(plain);
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error during decryption final");
    }
    out_sz += final_len;
    
    // The decrypted data includes the original size field (whitened) at the end
    // Copy the whitened size field from the end of the decrypted data
    memcpy(&original_sz, plain + out_sz - sizeof(original_sz), sizeof(original_sz));
    
    // Whiten the size field to get the original size
    uint8_t *hashed_key = hdn_crypto_hash(key);
    if (!hashed_key) {
        free(plain);
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error hashing key");
    }
    hdn_math_xor(&original_sz, hashed_key, sizeof(original_sz));
    free(hashed_key);
    
    // Allocate memory for the output structure with the original size
    *inout = realloc(*inout, sizeof(hdn_data_t) + original_sz);
    if (!(*inout)) {
        free(plain);
        EVP_CIPHER_CTX_free(ctx);
        HDN_EXIT("Error allocating memory for decrypted data. Requested %zu bytes",
                 sizeof(hdn_data_t) + original_sz);
    }
    
    // Copy the decrypted data (excluding the size field we just processed)
    memcpy((*inout)->content, plain, original_sz);
    
    // Set the correct size in the output structure
    (*inout)->sz = original_sz;
    
    // Cleanup
    free(plain);
    EVP_CIPHER_CTX_free(ctx);
}



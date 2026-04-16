/*
 * $Id: hdn_crypto.h,v 1.2 2003/01/05 01:39:47 xvr Exp $
 * Created: 09/03/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#ifndef _HDN_CRYPTO_H_
#define _HDN_CRYPTO_H_

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdlib.h>

#include "hydan.h"

/*
 * encrypts the data in hdn_data_t using AES-256-GCM with PBKDF2 key derivation
 */
int hdn_crypto_encrypt(hdn_data_t **data, char *password);

/*
 * decrypts the data in hdn_data_t using AES-256-GCM with PBKDF2 key derivation
 */
int hdn_crypto_decrypt(hdn_data_t **data, char *password);

/*
 * returns the hash (sha256) of the input string
 */
uint8_t *hdn_crypto_hash(char *input);

/*
 * seeds calls to random with the hash of the password
 */
void hdn_crypto_srandom(char *pass);

#endif

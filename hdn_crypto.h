/*
 * $Id: hdn_crypto.h,v 1.2 2003/01/05 01:39:47 xvr Exp $
 * Created: 09/03/2002
 *
 * xvr (c) 2002-2004
 * xvr@xvr.net
 */

#ifndef _HDN_CRYPTO_H_
#define _HDN_CRYPTO_H_

#include "hydan.h"

/*
 * encrypts or decrypts the data in place
 */
void hdn_crypto_encrypt (hdn_data_t **inout, uint8_t *key);
void hdn_crypto_decrypt (hdn_data_t **inout, uint8_t *key);

/*
 * returns the hash (sha1) of the input string
 */
uint8_t *hdn_crypto_hash (char *input);

/*
 * seeds calls to random with the hash of the password
 */
void hdn_crypto_srandom (char *pass);

/*
 * skip a certain number of instructions, upto max.
 */
int hdn_crypto_skip_insn (uint32_t max);

#endif

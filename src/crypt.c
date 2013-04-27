/*
 * $Id$
 *
 * Copyright (C) 2013 Andreia Gaita <shana@spoiledcat.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#include "crypt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>


EVP_CIPHER_CTX enc, dec;

int _init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
			 EVP_CIPHER_CTX *d_ctx);
unsigned char *_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
unsigned char *_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int _init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
			 EVP_CIPHER_CTX *d_ctx)
{
	int i, nrounds = 1;
	unsigned char key[32], iv[32];
	const EVP_CIPHER *cipher;
	const EVP_MD *dgst = NULL;


	OpenSSL_add_all_algorithms();

    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if(!cipher) { fprintf(stderr, "no such cipher\n"); return 1; }

    dgst = EVP_get_digestbyname("sha1");
    if(!dgst) { fprintf(stderr, "no such digest\n"); return 1; }

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 * nrounds is the number of times the we hash the material. More rounds are more secure but
	 * slower.
	 */
	i = EVP_BytesToKey (cipher, dgst, salt, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) {
	  printf("Key size is %d bits - should be 256 bits\n", i);
	  return -1;
	}
/*
	printf ("KEY:");
	for (i = 0; i < strlen(key); i++)
		printf ("%02x", key[i]);
	printf("\n");

	printf ("IV:");
	for (i = 0; i < strlen(iv); i++)
		printf ("%02x", iv[i]);
	printf("\n");
*/
	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
	*len is the size of plaintext in bytes */
	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}

int aes_init (unsigned char* key, unsigned char* salt)
{
	return _init (key, strlen(key), (unsigned char *)&salt, &enc, &dec);
}

unsigned char *aes_encrypt(unsigned char *text, int* len)
{
	return _encrypt (&enc, text, len);
}

unsigned char *aes_decrypt(unsigned char *text, int *len)
{
	return _decrypt (&dec, text, len);
}

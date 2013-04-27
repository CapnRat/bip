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

#ifndef __CRYPT_H__
#define __CRYPT_H__


int aes_init (unsigned char* key, unsigned char* salt);
unsigned char *aes_encrypt(unsigned char *text, int* len);
unsigned char *aes_decrypt(unsigned char *text, int *len);


#endif
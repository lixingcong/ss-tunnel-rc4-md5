/*
 * stream.c - Manage stream ciphers
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "crypto-xor.h"
#include "common.h"
#include "jhash.h"
#include "utils.h"

#define CRYPTO_MAX_KEY_SIZE 32

static char crypto_key[CRYPTO_MAX_KEY_SIZE];

/* An arbitrary initial parameter */
#define JHASH_INITVAL 0xdeadbeef

#ifdef XXXX // 2024年12月02日 17:09:24
void crypto_xor_init(const char* password)
{
	uint32_t     loopCount      = CRYPTO_MAX_KEY_SIZE / sizeof(uint32_t);
	uint32_t*    pOut32         = crypto_key;
	uint32_t     hashVal        = JHASH_INITVAL;
	const uint32_t passwordLength = min(strlen(password), CRYPTO_MAX_KEY_SIZE);

	memset(crypto_key, 0xff, sizeof(crypto_key));
	memcpy(crypto_key, password, passwordLength);

	while (loopCount--) {
		*pOut32 = jhash_1word(*pOut32, hashVal);
		++pOut32;
		++hashVal;
	}
}

void crypto_xor_encrypt(const void* in, void* out, uint32_t* dlen)
{
	uint32_t               i    = 0;
	const unsigned char* pIn  = in;
	unsigned char*       pOut = out;
	for (; i < *dlen; ++i)
		*(pOut++) = *(pIn++) ^ crypto_key[i % CRYPTO_MAX_KEY_SIZE];
}
#endif

void xor_cipher_ctx_init(cipher_ctx_t *ctx, int method, int enc) {}

void xor_ctx_release(cipher_ctx_t *cipher_ctx)
{
	if (cipher_ctx->chunk != NULL) {
		bfree(cipher_ctx->chunk);
		ss_free(cipher_ctx->chunk);
		cipher_ctx->chunk = NULL;
	}
}

int xor_encrypt_all(buffer_t *plaintext, cipher_t *cipher, size_t capacity)
{
	return CRYPTO_OK;
}

int xor_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
	return CRYPTO_OK;
}

int xor_decrypt_all(buffer_t *ciphertext, cipher_t *cipher, size_t capacity)
{
	return CRYPTO_OK;
}

int xor_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
	return CRYPTO_OK;
}

void xor_ctx_init(cipher_t *cipher, cipher_ctx_t *cipher_ctx, int enc) {}

cipher_t *xor_key_init(int method, const char *pass, const char *key) {}

cipher_t *xor_init(const char *pass, const char *key, const char *method) {}

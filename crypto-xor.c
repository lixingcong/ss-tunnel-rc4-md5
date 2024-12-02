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
#include <string.h>
//#include <assert.h>

#define XOR_KEY_SIZE 32
#define XOR_NONCE_SIZE 4

/* An arbitrary initial parameter */
#define JHASH_INITVAL 0xdeadbeef

static inline void xor_impl(const void* in, void* out, size_t dataLen, const uint8_t* key, size_t keyLen)
{
	size_t               i    = 0;
	const unsigned char* pIn  = in;
	unsigned char*       pOut = out;
	for (; i < dataLen; ++i)
		*(pOut++) = *(pIn++) ^ key[i % keyLen];
}

static inline void xor_cipher_impl(const void* in, void* out, size_t dataLen, const cipher_ctx_t* ctx)
{
	const cipher_t* cipher = ctx->cipher;
	xor_impl(in, out, dataLen, cipher->key, cipher->key_len);
	xor_impl(out, out, dataLen, ctx->nonce, cipher->nonce_len);
}

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
	cipher_ctx_t cipher_ctx;
	xor_ctx_init(cipher, &cipher_ctx, 1);

	static buffer_t tmp = {0, 0, 0, NULL}; // static

	const size_t nonce_len = cipher->nonce_len;
	const size_t data_len  = plaintext->len;

	brealloc(&tmp, nonce_len + data_len, capacity);
	buffer_t* ciphertext = &tmp;
	ciphertext->len      = nonce_len + data_len;

	memcpy(ciphertext->data, cipher_ctx.nonce, nonce_len);
	xor_cipher_impl(plaintext->data, ciphertext->data + nonce_len, data_len, &cipher_ctx);
	xor_ctx_release(&cipher_ctx);

	brealloc(plaintext, ciphertext->len, capacity);
	memcpy(plaintext->data, ciphertext->data, ciphertext->len);
	plaintext->len = ciphertext->len;

	return CRYPTO_OK;
}

int xor_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
	if (!cipher_ctx)
		return CRYPTO_ERROR;

	static buffer_t tmp = {0, 0, 0, NULL};

	size_t nonce_len = 0;
	if (!cipher_ctx->init) {
		nonce_len = cipher_ctx->cipher->nonce_len;
	}

	const size_t data_len   = plaintext->len;
	brealloc(&tmp, nonce_len + data_len, capacity);
	buffer_t*    ciphertext = &tmp;
	ciphertext->len         = nonce_len + data_len;

	if (!cipher_ctx->init) {
		memcpy(ciphertext->data, cipher_ctx->nonce, nonce_len);
		cipher_ctx->init    = 1;
	}

	xor_cipher_impl(plaintext->data, ciphertext->data + nonce_len, data_len, cipher_ctx);

	brealloc(plaintext, ciphertext->len, capacity);
	memcpy(plaintext->data, ciphertext->data, ciphertext->len);
	plaintext->len = ciphertext->len;

	return CRYPTO_OK;
}

int xor_decrypt_all(buffer_t *ciphertext, cipher_t *cipher, size_t capacity)
{
	const size_t nonce_len = cipher->nonce_len;

	if (ciphertext->len <= nonce_len)
		return CRYPTO_ERROR;

	cipher_ctx_t cipher_ctx;
	xor_ctx_init(cipher, &cipher_ctx, 0);
	memcpy(cipher_ctx.nonce, ciphertext->data, nonce_len);

	static buffer_t tmp = { 0, 0, 0, NULL };
	brealloc(&tmp, ciphertext->len, capacity);
	buffer_t *plaintext = &tmp;
	plaintext->len = ciphertext->len - nonce_len;

	xor_cipher_impl(ciphertext->data + nonce_len, plaintext->data, plaintext->len, &cipher_ctx);
	xor_ctx_release(&cipher_ctx);

	brealloc(ciphertext, plaintext->len, capacity);
	memcpy(ciphertext->data, plaintext->data, plaintext->len);
	ciphertext->len = plaintext->len;

	return CRYPTO_OK;
}

int xor_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
	if (!cipher_ctx)
		return CRYPTO_ERROR;

	cipher_t* cipher = cipher_ctx->cipher;

	static buffer_t tmp = {0, 0, 0, NULL};
	brealloc(&tmp, ciphertext->len, capacity);
	buffer_t* plaintext = &tmp;
	plaintext->len      = ciphertext->len;

	if (!cipher_ctx->init) {
		if (!cipher_ctx->chunk) {
			cipher_ctx->chunk = (buffer_t*) ss_malloc(sizeof(buffer_t));
			memset(cipher_ctx->chunk, 0, sizeof(buffer_t));
			balloc(cipher_ctx->chunk, cipher->nonce_len);
		}

		const size_t left_len = min(cipher->nonce_len - cipher_ctx->chunk->len, ciphertext->len);
		if (left_len > 0) {
			memcpy(cipher_ctx->chunk->data + cipher_ctx->chunk->len, ciphertext->data, left_len);
			memmove(ciphertext->data, ciphertext->data + left_len, ciphertext->len - left_len);
			cipher_ctx->chunk->len += left_len;
			ciphertext->len -= left_len;
		}

		if (cipher_ctx->chunk->len < cipher->nonce_len)
			return CRYPTO_NEED_MORE;

		plaintext->len -= left_len;

		memcpy(cipher_ctx->nonce, cipher_ctx->chunk->data, cipher->nonce_len);
		cipher_ctx->init = 1;
	}

	if (ciphertext->len <= 0)
		return CRYPTO_NEED_MORE;

	xor_cipher_impl(ciphertext->data, plaintext->data, ciphertext->len, cipher_ctx);

	brealloc(ciphertext, plaintext->len, capacity);
	memcpy(ciphertext->data, plaintext->data, plaintext->len);
	ciphertext->len = plaintext->len;

	return CRYPTO_OK;
}

void xor_ctx_init(cipher_t* cipher, cipher_ctx_t* cipher_ctx, int enc)
{
	memset(cipher_ctx, 0, sizeof(cipher_ctx_t));
	cipher_ctx->cipher = cipher;

	if (enc) {
		rand_bytes(cipher_ctx->nonce, cipher->nonce_len);
	}
}

cipher_t* xor_init(const char* pass, const char* /*key*/, const char* /*method*/)
{
	if (!pass || 0 == *pass)
		return NULL;

	cipher_t* cipher = (cipher_t*) ss_malloc(sizeof(cipher_t));
	memset(cipher, 0, sizeof(cipher_t));

	cipher->key_len   = XOR_KEY_SIZE;
	cipher->nonce_len = XOR_NONCE_SIZE;

	{
		// init the xor key
		uint32_t       loopCount      = cipher->key_len / sizeof(uint32_t);
		uint32_t*      pOut32         = (uint32_t*)&cipher->key[0];
		uint32_t       hashVal        = JHASH_INITVAL;
		const uint32_t passwordLength = min(strlen(pass), cipher->key_len);

		memset(cipher->key, 0xff, sizeof(cipher->key));
		memcpy(cipher->key, pass, passwordLength);

		while (loopCount--) {
			*pOut32 = jhash_1word(*pOut32, hashVal);
			++pOut32;
			++hashVal;
		}
	}

	return cipher;
}

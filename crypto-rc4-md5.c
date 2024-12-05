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

#include "crypto-rc4-md5.h"
#include "crypto_utils.h"
#include "common.h"
#include "utils.h"
#include <string.h>
//#include <assert.h>

#define RC4_KEY_SIZE 16
#define RC4_NONCE_SIZE 16

static inline void rc4_md5_ks(cipher_ctx_t *cipher_ctx)
{
	uint8_t key_nonce[RC4_KEY_SIZE + RC4_NONCE_SIZE];
	memcpy(key_nonce, cipher_ctx->cipher->key, RC4_KEY_SIZE);
	memcpy(key_nonce + RC4_KEY_SIZE, cipher_ctx->nonce, RC4_NONCE_SIZE);

	uint8_t true_key[16]; // md5 length
	crypto_md5(key_nonce, true_key, RC4_KEY_SIZE + RC4_NONCE_SIZE);

	rc4_ks(&cipher_ctx->rc4, true_key, sizeof(true_key));
}

void rc4_md5_ctx_release(cipher_ctx_t *cipher_ctx)
{
	if (cipher_ctx->chunk != NULL) {
		bfree(cipher_ctx->chunk);
		ss_free(cipher_ctx->chunk);
		cipher_ctx->chunk = NULL;
	}
}

int rc4_md5_encrypt_all(buffer_t *plaintext, cipher_t *cipher, size_t capacity)
{
	cipher_ctx_t cipher_ctx;
	rc4_md5_ctx_init(cipher, &cipher_ctx, 1);

	static buffer_t tmp = {0, 0, 0, NULL}; // static

	const size_t nonce_len = cipher->nonce_len;
	const size_t data_len  = plaintext->len;

	brealloc(&tmp, nonce_len + data_len, capacity);
	buffer_t *ciphertext = &tmp;
	ciphertext->len      = nonce_len + data_len;

	rc4_md5_ks(&cipher_ctx);
	memcpy(ciphertext->data, cipher_ctx.nonce, nonce_len);
	rc4_encrypt(&cipher_ctx.rc4, plaintext->data, ciphertext->data + nonce_len, data_len);
	rc4_md5_ctx_release(&cipher_ctx);

	brealloc(plaintext, ciphertext->len, capacity);
	memcpy(plaintext->data, ciphertext->data, ciphertext->len);
	plaintext->len = ciphertext->len;

	return CRYPTO_OK;
}

int rc4_md5_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
	if (!cipher_ctx)
		return CRYPTO_ERROR;

	static buffer_t tmp = {0, 0, 0, NULL};

	size_t nonce_len = 0;
	if (!cipher_ctx->init) {
		nonce_len = cipher_ctx->cipher->nonce_len;
	}

	const size_t data_len = plaintext->len;
	brealloc(&tmp, nonce_len + data_len, capacity);
	buffer_t *ciphertext = &tmp;
	ciphertext->len      = 0;

	if (!cipher_ctx->init) {
		rc4_md5_ks(cipher_ctx);
		memcpy(ciphertext->data, cipher_ctx->nonce, nonce_len);
		ciphertext->len += nonce_len;
		cipher_ctx->init    = 1;
	}

	rc4_encrypt(&cipher_ctx->rc4, plaintext->data, ciphertext->data + ciphertext->len, data_len);

	ciphertext->len += data_len;
	brealloc(plaintext, ciphertext->len, capacity);
	memcpy(plaintext->data, ciphertext->data, ciphertext->len);
	plaintext->len = ciphertext->len;

	return CRYPTO_OK;
}

int rc4_md5_decrypt_all(buffer_t *ciphertext, cipher_t *cipher, size_t capacity)
{
	const size_t nonce_len = cipher->nonce_len;

	if (ciphertext->len <= nonce_len)
		return CRYPTO_ERROR;

	cipher_ctx_t cipher_ctx;
	rc4_md5_ctx_init(cipher, &cipher_ctx, 0);

	// copy nonce from buffer
	memcpy(cipher_ctx.nonce, ciphertext->data, nonce_len);
	rc4_md5_ks(&cipher_ctx);

	static buffer_t tmp = {0, 0, 0, NULL};
	brealloc(&tmp, ciphertext->len, capacity);
	buffer_t *plaintext = &tmp;
	plaintext->len      = ciphertext->len - nonce_len;

	rc4_encrypt(&cipher_ctx.rc4, ciphertext->data+nonce_len, plaintext->data, plaintext->len);
	rc4_md5_ctx_release(&cipher_ctx);

	brealloc(ciphertext, plaintext->len, capacity);
	memcpy(ciphertext->data, plaintext->data, plaintext->len);
	ciphertext->len = plaintext->len;

	return CRYPTO_OK;
}

int rc4_md5_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
	if (!cipher_ctx)
		return CRYPTO_ERROR;

	cipher_t *cipher = cipher_ctx->cipher;

	static buffer_t tmp = {0, 0, 0, NULL};
	brealloc(&tmp, ciphertext->len, capacity);
	buffer_t *plaintext = &tmp;
	plaintext->len      = ciphertext->len;

	if (!cipher_ctx->init) {
		if (!cipher_ctx->chunk) {
			cipher_ctx->chunk = (buffer_t *) ss_malloc(sizeof(buffer_t));
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
		rc4_md5_ks(cipher_ctx);
		cipher_ctx->init    = 1;
	}

	if (ciphertext->len <= 0)
		return CRYPTO_NEED_MORE;

	rc4_encrypt(&cipher_ctx->rc4, ciphertext->data, plaintext->data, ciphertext->len);

	brealloc(ciphertext, plaintext->len, capacity);
	memcpy(ciphertext->data, plaintext->data, plaintext->len);
	ciphertext->len = plaintext->len;

	return CRYPTO_OK;
}

void rc4_md5_ctx_init(cipher_t* cipher, cipher_ctx_t* cipher_ctx, int enc)
{
	memset(cipher_ctx, 0, sizeof(cipher_ctx_t));
	cipher_ctx->cipher = cipher;
	rc4_ks(&cipher_ctx->rc4, cipher->key, cipher->key_len);

	if (enc) {
		rand_bytes(cipher_ctx->nonce, cipher->nonce_len);
	}
}

cipher_t* rc4_md5_init(const char* pass, const char* /*key*/, const char* /*method*/)
{
	if (!pass || 0 == *pass)
		return NULL;

	cipher_t* cipher = (cipher_t*) ss_malloc(sizeof(cipher_t));
	memset(cipher, 0, sizeof(cipher_t));

	cipher->key_len   = RC4_KEY_SIZE;
	cipher->nonce_len = RC4_NONCE_SIZE;

	if (crypto_derive_key(pass, cipher->key, cipher->key_len) != cipher->key_len) {
		ss_free(cipher);
		return NULL;
	}

	return cipher;
}

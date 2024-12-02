/*
 * crypto.h
 *
 * FIXME: 功能简要概述
 *
 * Created on: 2024年 12月 2日
 *
 * Author: lixingcong
 */

#ifndef CRYPTO_XOR_H
#define CRYPTO_XOR_H

#include "crypto.h"
#include <stdint.h>

int xor_encrypt_all(buffer_t *, cipher_t *, size_t);
int xor_decrypt_all(buffer_t *, cipher_t *, size_t);
int xor_encrypt(buffer_t *, cipher_ctx_t *, size_t);
int xor_decrypt(buffer_t *, cipher_ctx_t *, size_t);

void xor_ctx_init(cipher_t *, cipher_ctx_t *, int);
void xor_ctx_release(cipher_ctx_t *);

cipher_t *xor_init(const char *pass, const char *key, const char *method);

#endif // CRYPTO_XOR_H

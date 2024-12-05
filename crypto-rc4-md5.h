/*
 * crypto-rc4-md5.h
 *
 * FIXME: 功能简要概述
 *
 * Created on: 2024年 12月 2日
 *
 * Author: lixingcong
 */

#ifndef CRYPTO_RC4_MD5_H
#define CRYPTO_RC4_MD5_H

#include "crypto.h"
#include <stdint.h>

int rc4_md5_encrypt_all(buffer_t *, cipher_t *, size_t);
int rc4_md5_decrypt_all(buffer_t *, cipher_t *, size_t);
int rc4_md5_encrypt(buffer_t *, cipher_ctx_t *, size_t);
int rc4_md5_decrypt(buffer_t *, cipher_ctx_t *, size_t);

void rc4_md5_ctx_init(cipher_t *, cipher_ctx_t *, int);
void rc4_md5_ctx_release(cipher_ctx_t *);

cipher_t *rc4_md5_init(const char *pass, const char *key, const char *method);

#endif // CRYPTO_RC4_MD5_H

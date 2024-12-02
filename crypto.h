/*
 * crypto.h - Define the enryptor's interface
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
 * You should have recenonceed a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

#ifndef __MINGW32__
#include <sys/socket.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define MAX_KEY_LENGTH 64
#define MAX_NONCE_LENGTH 32
#define ADDRTYPE_MASK 0xF

#define CRYPTO_ERROR     -2
#define CRYPTO_NEED_MORE -1
#define CRYPTO_OK         0

typedef struct buffer {
    size_t idx;
    size_t len;
    size_t capacity;
    char   *data;
} buffer_t;

typedef struct {
    size_t nonce_len;
    size_t key_len;
    uint8_t key[MAX_KEY_LENGTH];
} cipher_t;

typedef struct {
    uint32_t init;
    cipher_t *cipher;
    buffer_t *chunk;
    uint8_t nonce[MAX_NONCE_LENGTH];
} cipher_ctx_t;

typedef struct {
    cipher_t *cipher;

    int(*const encrypt_all) (buffer_t *, cipher_t *, size_t);
    int(*const decrypt_all) (buffer_t *, cipher_t *, size_t);
    int(*const encrypt) (buffer_t *, cipher_ctx_t *, size_t);
    int(*const decrypt) (buffer_t *, cipher_ctx_t *, size_t);

    void(*const ctx_init) (cipher_t *, cipher_ctx_t *, int);
    void(*const ctx_release) (cipher_ctx_t *);
} crypto_t;

int balloc(buffer_t *, size_t);
int brealloc(buffer_t *, size_t, size_t);
int bprepend(buffer_t *, buffer_t *, size_t);
void bfree(buffer_t *);
int rand_bytes(void *, int);

crypto_t *crypto_init(const char *, const char *, const char *);

extern struct cache *nonce_cache;

#endif // _CRYPTO_H

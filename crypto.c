/*
 * crypto.c - Manage the global crypto
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(__linux__) && defined(HAVE_LINUX_RANDOM_H)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/random.h>
#endif

#include <stdint.h>
// #include "base64.h"
#include "crypto.h"
// #include "stream.h"
// #include "aead.h"
#include "utils.h"
#include "common.h"
#include <string.h>

int
balloc(buffer_t *ptr, size_t capacity)
{
    memset(ptr, 0, sizeof(buffer_t));
    ptr->data     = ss_malloc(capacity);
    ptr->capacity = capacity;
    return capacity;
}

int
brealloc(buffer_t *ptr, size_t len, size_t capacity)
{
    if (ptr == NULL)
        return -1;
    size_t real_capacity = max(len, capacity);
    if (ptr->capacity < real_capacity) {
        ptr->data     = ss_realloc(ptr->data, real_capacity);
        ptr->capacity = real_capacity;
    }
    return real_capacity;
}

void
bfree(buffer_t *ptr)
{
    if (ptr == NULL)
        return;
    ptr->idx      = 0;
    ptr->len      = 0;
    ptr->capacity = 0;
    if (ptr->data != NULL) {
        ss_free(ptr->data);
    }
}

int
bprepend(buffer_t *dst, buffer_t *src, size_t capacity)
{
    brealloc(dst, dst->len + src->len, capacity);
    memmove(dst->data + src->len, dst->data, dst->len);
    memcpy(dst->data, src->data, src->len);
    dst->len = dst->len + src->len;
    return dst->len;
}

int
rand_bytes(void *output, int len)
{
	unsigned char *p = output;
	while (len--)
		*(p++) = rand();
	return 0;
}

static void
entropy_check(void)
{
#if defined(__linux__) && defined(HAVE_LINUX_RANDOM_H) && defined(RNDGETENTCNT)
    int fd;
    int c;

    if ((fd = open("/dev/random", O_RDONLY)) != -1) {
        if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
            LOGI("This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
                 "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
                 "On virtualized Linux environments, also consider using virtio-rng.\n"
                 "The service will not start until enough entropy has been collected.\n");
        }
        close(fd);
    }
#endif
}

crypto_t *
crypto_init(const char *password, const char *key, const char *method)
{
    entropy_check();

    if (method != NULL) {
		LOGI("Stream ciphers are insecure, therefore deprecated, and should be almost always avoided.");
#ifdef XXXX // 2024年12月02日 16:59:48
		cipher_t *cipher = stream_init(password, key, method);
#else
		cipher_t *cipher = 0;
#endif
		if (cipher == NULL)
			return NULL;
		crypto_t *crypto = (crypto_t *)ss_malloc(sizeof(crypto_t));
#ifdef XXXX // 初始化套件 2024年12月02日 16:52:53
		crypto_t tmp     = {
		        .cipher      = cipher,
		        .encrypt_all = &stream_encrypt_all,
		        .decrypt_all = &stream_decrypt_all,
		        .encrypt     = &stream_encrypt,
		        .decrypt     = &stream_decrypt,
		        .ctx_init    = &stream_ctx_init,
		        .ctx_release = &stream_ctx_release,
        };
		memcpy(crypto, &tmp, sizeof(crypto_t));
#endif
		return crypto;
	}

    LOGE("invalid cipher name: %s", method);
    return NULL;
}



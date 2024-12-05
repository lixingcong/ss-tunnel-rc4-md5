/*
 * crypto_utils.c
 *
 * FIXME: 功能简要概述
 *
 * Created on: 2024年 12月 4日
 *
 * Author: lixingcong
 */
#include "crypto_utils.h"
#include <string.h>
#include "md5.h"

#define MAX_MD_SIZE 64

int crypto_derive_key(const char *pass, uint8_t *key, size_t key_len)
{
	if (!pass)
		return key_len;

	const size_t  datal = strlen(pass);
	unsigned char md_buf[MAX_MD_SIZE];
	int           addmd;
	unsigned int  i, j;
	const size_t  mds = 16; // Md5 128bit

	MD5Context ctx;

	for (j = 0, addmd = 0; j < key_len; addmd++) {
		md5Init(&ctx);
		if (addmd) {
			md5Update(&ctx, md_buf, mds);
		}
		md5Update(&ctx, (uint8_t *) pass, datal);
		md5Finalize(&ctx);

		memcpy(md_buf, ctx.digest, mds);

		for (i = 0; i < mds; i++, j++) {
			if (j >= key_len)
				break;
			key[j] = md_buf[i];
		}
	}

	return key_len;
}

void crypto_md5(const void *in, uint8_t *out, size_t len)
{
	MD5Context ctx;
	md5Init(&ctx);
	md5Update(&ctx, (uint8_t *) in, len);
	md5Finalize(&ctx);
	memcpy(out, ctx.digest, 16);
}

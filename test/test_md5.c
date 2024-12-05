/*
 * test_md5.c
 *
 * FIXME: 功能简要概述
 *
 * Created on: 2024年 12月 5日
 *
 * Author: lixingcong
 */
#include "../md5.h"
#include "tap.h"
#include <string.h>

void testMd5()
{
	printf("test md5\n");

	const char*  input = "1234567890";
	const size_t len   = strlen(input);

#define MD5_LENGTH 16
	const char expect[MD5_LENGTH] = {0xe8, 0x07, 0xf1, 0xfc, 0xf8, 0x2d, 0x13, 0x2f, 0x9b, 0xb0, 0x18, 0xca, 0x67, 0x38, 0xa1, 0x9f};

	MD5Context ctx;
	md5Init(&ctx);
	md5Update(&ctx, input, len);
	md5Finalize(&ctx);

	cmp_mem(expect, ctx.digest, MD5_LENGTH, "same hash");
}

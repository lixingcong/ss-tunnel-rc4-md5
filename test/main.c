/*
 * main.c
 *
 * FIXME: 功能简要概述
 *
 * Created on: 2024年 12月 4日
 *
 * Author: lixingcong
 */

#include "tap.h"

extern void testRC4();
extern void testMd5();
extern void testCrypoRc4Md5();
extern void testCryptoUtils();

int main()
{
	plan(NO_PLAN);

	testRC4();
	testMd5();
	testCrypoRc4Md5();
	testCryptoUtils();


	printf("Summary: ");
	done_testing();
	return 0;
}

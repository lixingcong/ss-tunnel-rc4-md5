/*
 * common.c
 *
 * FIXME: 功能简要概述
 *
 * Created on: 2024年 12月 2日
 *
 * Author: lixingcong
 */
#include "common.h"

int balloc(buffer_t *ptr, size_t capacity)
{
	memset(ptr, 0, sizeof(buffer_t));
	ptr->data     = ss_malloc(capacity);
	ptr->capacity = capacity;
	return capacity;
}

void bfree(buffer_t *ptr)
{
	if (!ptr)
		return;
	ptr->idx      = 0;
	ptr->len      = 0;
	ptr->capacity = 0;
	if (ptr->data) {
		ss_free(ptr->data);
	}
}

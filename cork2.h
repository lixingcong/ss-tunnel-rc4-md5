/*
 * cork2.h
 *
 * FIXME: 功能简要概述
 *
 * Created on: 2024年 12月 2日
 *
 * Author: lixingcong
 */

#ifndef CORK2_H
#define CORK2_H

// Return values:
// 4: ipv4
// 6: ipv6
// -1: invliad
int cork_check_ip_version(const char* str);

/* Return a pointer to a @c struct, given a pointer to one of its fields. */
#define cork_container_of(field, struct_type, field_name) ((struct_type *) (-offsetof(struct_type, field_name) + (void *) (field)))

#endif // CORK2_H

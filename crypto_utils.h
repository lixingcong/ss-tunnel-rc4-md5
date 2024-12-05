#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <stddef.h>

int crypto_derive_key(const char* pass, uint8_t* key, size_t key_len);

void crypto_md5(const void* in, uint8_t* out, size_t len);

#endif // CRYPTO_UTILS_H

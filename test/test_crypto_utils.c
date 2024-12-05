#include "../crypto_utils.h"
#include "tap.h"

void testCryptoUtils()
{
	printf("test crypto utils\n");

	const char* password      = "hello";
	const char  expectKey[16] = {0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92};
	char        actualKey[16];
	const int   k = crypto_derive_key(password, actualKey, 16);

	cmp_ok(k, "==", 16, "crypto_derive_key() return value");
	cmp_mem(expectKey, actualKey, 16, "crypto_derive_key() generated key");
}

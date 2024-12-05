#include "../crypto.h"
#include "tap.h"

#define BUFSIZE 4096
#define LEN_LONG 2048
#define LEN_SHORT 100

void testCrypoRc4Md5()
{
	// init plainText
	char PLAINTEXT_LONG[LEN_LONG];
	char PLAINTEXT_SHORT[LEN_SHORT];

	int i;

	for (i = 0; i < LEN_LONG; ++i)
		PLAINTEXT_LONG[i] = '0' + (i % 10);
	for (i = 0; i < LEN_SHORT; ++i)
		PLAINTEXT_SHORT[i] = '0' + (i % 10);

	crypto_t* c = crypto_init("password", NULL, NULL);
	ok(c, "init crypto");

	if(1){
		printf("test udp: encrypt/decrypt all\n");
		const char* str[2] = {PLAINTEXT_LONG, PLAINTEXT_SHORT};
		const int   len[2] = {LEN_LONG, LEN_SHORT};

		buffer_t buf;
		balloc(&buf, BUFSIZE);

		for (int i = 0; i < 2; ++i) {
			const char* plainText  = str[i];
			const int   dataLength = len[i];

			// copy plaintext
			memcpy(buf.data, plainText, dataLength);
			buf.len = dataLength;

			c->encrypt_all(&buf, c->cipher, buf.len);
			c->decrypt_all(&buf, c->cipher, buf.len);

			cmp_ok(buf.len, "==", dataLength, "udp same length");
			cmp_mem(buf.data, plainText, dataLength, "udp same content");
		}
		bfree(&buf);
	}

	if(1){
		printf("test tcp: one shot\n");
		const char* str[2] = {PLAINTEXT_LONG, PLAINTEXT_SHORT};
		const int   len[2] = {LEN_LONG, LEN_SHORT};

		buffer_t buf;
		balloc(&buf, BUFSIZE);

		for (int i = 0; i < 2; ++i) {
			cipher_ctx_t e_ctx, d_ctx;
			c->ctx_init(c->cipher, &e_ctx, 1);
			c->ctx_init(c->cipher, &d_ctx, 0);

			const char* plainText  = str[i];
			const int   dataLength = len[i];

			// copy plaintext
			memcpy(buf.data, plainText, dataLength);
			buf.len = dataLength;

			c->encrypt(&buf, &e_ctx, buf.len);
			c->decrypt(&buf, &d_ctx, buf.len);

			cmp_ok(buf.len, "==", dataLength, "tcp one-shot: same length");
			cmp_mem(buf.data, plainText, dataLength, "tcp one-shot: same content");

			c->ctx_release(&e_ctx);
			c->ctx_release(&d_ctx);
		}
		bfree(&buf);
	}

	if(1){
		// test tcp: many shots(chunks)
#define CHUNK_LENGTH_CASE 6
		const int   ChunkLengthArr[CHUNK_LENGTH_CASE] = {1, 2, 3, 4, 9, 65};
		const char* str[2]                            = {PLAINTEXT_LONG, PLAINTEXT_SHORT};
		const int   len[2]                            = {LEN_LONG, LEN_SHORT};

		for (int chunkCase = 0; chunkCase < CHUNK_LENGTH_CASE; ++chunkCase) {
			const int ChunkLength = ChunkLengthArr[chunkCase];
			printf("tcp test chunk size = %d\n", ChunkLength);

			for (int i = 0; i < 2; ++i) {
				cipher_ctx_t e_ctx, d_ctx;
				c->ctx_init(c->cipher, &e_ctx, 1);
				c->ctx_init(c->cipher, &d_ctx, 0);

				const char* plainText  = str[i];
				const int   dataLength = len[i];

				buffer_t chunkBuf, encryptedBuf, decryptedBuf;
				memset(&chunkBuf, 0, sizeof(buffer_t));
				memset(&encryptedBuf, 0, sizeof(buffer_t));
				memset(&decryptedBuf, 0, sizeof(buffer_t));
				balloc(&chunkBuf, BUFSIZE);
				balloc(&encryptedBuf, BUFSIZE);
				balloc(&decryptedBuf, BUFSIZE);

				// encrypt piece by piece
				for (int offset = 0; offset + ChunkLength <= dataLength; offset += ChunkLength) {
					// copy plaintext to chunk
					memcpy(chunkBuf.data, plainText + offset, ChunkLength);
					chunkBuf.len = ChunkLength;

					// encrypt
					c->encrypt(&chunkBuf, &e_ctx, chunkBuf.len);

					// copy chunk to encrypted
					memcpy(encryptedBuf.data + encryptedBuf.len, chunkBuf.data, chunkBuf.len);
					encryptedBuf.len += chunkBuf.len;
				}

				// encrypt last chunk of plaintext
				if (dataLength % ChunkLength > 0) {
					const int remainLength = dataLength % ChunkLength;

					// copy plaintext to chunk
					const int offset = dataLength - remainLength;
					memcpy(chunkBuf.data, plainText + offset, remainLength);
					chunkBuf.len = remainLength;

					// encrypt
					c->encrypt(&chunkBuf, &e_ctx, chunkBuf.len);

					// copy chunk to encrypted
					memcpy(encryptedBuf.data + encryptedBuf.len, chunkBuf.data, chunkBuf.len);
					encryptedBuf.len += chunkBuf.len;
				}

				// decrypt piece by piece
				for (int offset = 0; offset + ChunkLength <= encryptedBuf.len; offset += ChunkLength) {
					// copy encrypted to chunk
					memcpy(chunkBuf.data, encryptedBuf.data + offset, ChunkLength);
					chunkBuf.len = ChunkLength;

					// decrypt
					if (CRYPTO_OK == c->decrypt(&chunkBuf, &d_ctx, chunkBuf.len)) {
						// copy chunk to decrypted
						memcpy(decryptedBuf.data + decryptedBuf.len, chunkBuf.data, chunkBuf.len);
						decryptedBuf.len += chunkBuf.len;
					}
				}

				// decrypt last chunk of ciphertext
				if (encryptedBuf.len % ChunkLength > 0) {
					const int remainLength = encryptedBuf.len % ChunkLength;

					// copy ciphertext to chunk
					const int offset = encryptedBuf.len - remainLength;
					memcpy(chunkBuf.data, encryptedBuf.data + offset, remainLength);
					chunkBuf.len = remainLength;

					// decrypt
					if (CRYPTO_OK == c->decrypt(&chunkBuf, &d_ctx, chunkBuf.len)) {
						// copy chunk to decrypted
						memcpy(decryptedBuf.data + decryptedBuf.len, chunkBuf.data, chunkBuf.len);
						decryptedBuf.len += chunkBuf.len;
					}
				}

				cmp_ok(decryptedBuf.len, "==", dataLength, "tcp chunks: same length");
				cmp_mem(decryptedBuf.data, plainText, dataLength, "tcp chunks: same content");

				c->ctx_release(&e_ctx);
				c->ctx_release(&d_ctx);

				bfree(&chunkBuf);
				bfree(&encryptedBuf);
				bfree(&decryptedBuf);
			}
		}
	}

	if (c) {
		free(c->cipher);
		free(c);
	}
}

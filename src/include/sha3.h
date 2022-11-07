/*
 *
 * Copyright (c) 2022 Yanis Mammar <yanis.mammar@epita.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef uint64_t SHA_LONG64;

typedef struct keccak1600_st {
	SHA_LONG64 state[25];
	char buf[168];
	size_t bufsz;
} SHA3_CTX;

int SHA3_224_Init(SHA3_CTX *c);
int SHA3_224_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_224_Final(unsigned char *md, SHA3_CTX *c);
unsigned char *SHA3_224(unsigned char *md, const void *data, size_t len);

int SHA3_256_Init(SHA3_CTX *c);
int SHA3_256_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_256_Final(unsigned char *md, SHA3_CTX *c);
unsigned char *SHA3_256(unsigned char *md, const void *data, size_t len);

int SHA3_384_Init(SHA3_CTX *c);
int SHA3_384_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_384_Final(unsigned char *md, SHA3_CTX *c);
unsigned char *SHA3_384(unsigned char *md, const void *data, size_t len);

int SHA3_512_Init(SHA3_CTX *c);
int SHA3_512_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_512_Final(unsigned char *md, SHA3_CTX *c);
unsigned char *SHA3_512(unsigned char *md, const void *data, size_t len);

#ifdef SHA3_XOF
int SHAKE128_Init(SHA3_CTX *c);
int SHAKE128_Update(SHA3_CTX *c, const void *data, size_t len);
int SHAKE128_Final(unsigned char *md, size_t mdlen, SHA3_CTX *c);
unsigned char *SHAKE128(
	unsigned char *md, size_t mdlen, const void *data, size_t len);

int SHAKE256_Init(SHA3_CTX *c);
int SHAKE256_Update(SHA3_CTX *c, const void *data, size_t len);
int SHAKE256_Final(unsigned char *md, size_t mdlen, SHA3_CTX *c);
unsigned char *SHAKE256(
	unsigned char *md, size_t mdlen, const void *data, size_t len);
#endif

#pragma once

#include <stddef.h>
#include <stdint.h>

#define SHA_LONG64 uint64_t

typedef struct keccak1600_st
{
    SHA_LONG64      state[25];
    size_t          blocksz;
    char            buf[1600 / 8 - 32];
    size_t          bufsz;
    unsigned char   pad;
    unsigned char   finalized : 1;
} SHA3_CTX;

int SHA3_224_Init(SHA3_CTX *c);
int SHA3_224_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_224_Final(unsigned char *md, SHA3_CTX *c);

int SHA3_256_Init(SHA3_CTX *c);
int SHA3_256_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_256_Final(unsigned char *md, SHA3_CTX *c);

int SHA3_384_Init(SHA3_CTX *c);
int SHA3_384_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_384_Final(unsigned char *md, SHA3_CTX *c);

int SHA3_512_Init(SHA3_CTX *c);
int SHA3_512_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_512_Final(unsigned char *md, SHA3_CTX *c);

int SHAKE128_Init(SHA3_CTX *c);
int SHAKE128_Update(SHA3_CTX *c, const void *data, size_t len);
int SHAKE128_Final(unsigned char *md, size_t mdlen, SHA3_CTX *c);

int SHAKE256_Init(SHA3_CTX *c);
int SHAKE256_Update(SHA3_CTX *c, const void *data, size_t len);
int SHAKE256_Final(unsigned char *md, size_t mdlen, SHA3_CTX *c);

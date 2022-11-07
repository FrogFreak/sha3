/*
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
#include <stddef.h>
#include <string.h>

#include "keccak.h"
#include "sha3.h"

#define MIN(a, b) (((a) > (b)) ? (b) : (a))

static inline size_t
sha3_block_fill(SHA3_CTX *c, const char *data, size_t len, size_t blocksz)
{
	size_t n = MIN(blocksz - c->bufsz, len);

	if (n != 0) {
		memcpy(c->buf + c->bufsz, data, n);
		c->bufsz += n;
	}
	return n;
}

static int
sha3_init(SHA3_CTX *c)
{
	memset(c, 0, sizeof(*c));
	return 1;
}

static int
sha3_update(SHA3_CTX *c, const char *data, size_t len, size_t blocksz)
{
	size_t n;

	if (c->bufsz) {
		n = sha3_block_fill(c, data, len, blocksz);
		data += n, len -= n;
		if (c->bufsz == blocksz) {
			Keccak1600_Absorb(c->state, c->buf, blocksz, blocksz);
			c->bufsz = 0;
		}
	}
	n = Keccak1600_Absorb(c->state, data, len, blocksz);
	if (n)
		sha3_block_fill(c, data + len - n, n, blocksz);
	return 1;
}

static int
sha3_final(unsigned char *md, size_t mdlen, SHA3_CTX *c, unsigned char suffix,
	size_t blocksz)
{
	Keccak1600_Pad(c->buf, c->bufsz, suffix, blocksz);
	Keccak1600_Absorb(c->state, c->buf, blocksz, blocksz);
	Keccak1600_Squeeze(md, mdlen, c->state, blocksz);
	return 1;
}

#define DEFSHA3_INIT(Name)                                                  \
	int Name##_Init(SHA3_CTX *c) { return sha3_init(c); }

#define DEFSHA3_UPDATE(Name, Bits)                                          \
	int Name##_Update(SHA3_CTX *c, const void *data, size_t len)            \
	{                                                                       \
		return sha3_update(c, data, len, 200 - Bits / 4);                   \
	}

#define DEFSHA3_FINAL(Name, Bits, Pad)                                      \
	int Name##_Final(unsigned char *md, SHA3_CTX *c)                        \
	{                                                                       \
		return sha3_final(md, Bits / 8, c, Pad, 200 - Bits / 4);            \
	}

#define DEFSHA3_FINALXOF(Name, Bits, Pad)                                   \
	int Name##_Final(unsigned char *md, size_t mdlen, SHA3_CTX *c)          \
	{                                                                       \
		return sha3_final(md, mdlen, c, Pad, 200 - Bits / 4);               \
	}

#define DEFSHA3_ONESHOT(Name, Bits, Pad)                                    \
    unsigned char * Name(unsigned char *md, const void *data, size_t len) \
    {                                                                       \
        SHA3_CTX c;                                                         \
        sha3_init(&c);                                                      \
        sha3_update(&c, data, len, 200 - Bits / 4);                         \
        sha3_final(md, Bits / 8, &c, Pad, 200 - Bits / 4);                  \
        return md;                                                          \
    }

#define DEFSHA3_ONESHOTXOF(Name, Bits, Pad)                                                 \
    unsigned char * Name(unsigned char *md, size_t mdlen, const void *data, size_t len)     \
    {                                                                                       \
        SHA3_CTX c;                                                                         \
        sha3_init(&c);                                                                      \
        sha3_update(&c, data, len, 200 - Bits / 4);                                         \
        sha3_final(md, mdlen, &c, Pad, 200 - Bits / 4);                                     \
        return md;                                                                          \
    }


#define DEFSHA3(Bits)                                                       \
	DEFSHA3_INIT(SHA3_##Bits)                                               \
	DEFSHA3_UPDATE(SHA3_##Bits, Bits)                                       \
	DEFSHA3_FINAL(SHA3_##Bits, Bits, 0x06)                                  \
    DEFSHA3_ONESHOT(SHA3_##Bits, Bits, 0x06)                                

#define DEFSHAKE(Bits)                                                      \
	DEFSHA3_INIT(SHAKE##Bits)                                               \
	DEFSHA3_UPDATE(SHAKE##Bits, Bits)                                       \
	DEFSHA3_FINALXOF(SHAKE##Bits, Bits, 0x1F)                               \
    DEFSHA3_ONESHOTXOF(SHAKE##Bits, Bits, 0x1F)

DEFSHA3(224)
DEFSHA3(256)
DEFSHA3(384)
DEFSHA3(512)
#ifdef SHA3_XOF
DEFSHAKE(128)
DEFSHAKE(256)
#endif

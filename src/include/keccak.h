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

#ifndef HEADER_KECCAK_H 
#define HEADER_KECCAK_H 

#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef uint64_t KECCAK_U64;

size_t
Keccak1600_Absorb(KECCAK_U64 state[25], const char *data, size_t len, size_t blocksz);

void
Keccak1600_Pad(char *m, size_t mlen, unsigned char suffix, size_t blocksz);

void
Keccak1600_Squeeze(unsigned char *md, size_t mdlen, KECCAK_U64 state[25], size_t blocksz);

#ifdef  __cplusplus
}
#endif

#endif

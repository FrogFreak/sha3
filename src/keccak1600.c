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
#include <stdint.h>
#include <string.h>

#include "keccak.h"

#define U8(x) (unsigned char)(x)
#define ROL64(qword, n)                                                      \
	((((KECCAK_U64)(qword)) << (n))                                      \
		^ (((KECCAK_U64)(qword)) >> (64 - (n))))
#define MIN(a, b) (((a) > (b)) ? (b) : (a))

/*
 * Load 64 bits from the memory pointed by `a`;
 */
static inline KECCAK_U64
loadu64(const void *a)
{
	KECCAK_U64 l;
	memcpy(&l, a, 8);
	return l;
}

/*
 * Loop unrolling helpers macro.
 */
#define REPEAT5(e) e e e e e
#define REPEAT24(e) REPEAT5(e e e e) e e e e
#define UNROLL5(ctr, step, expr)                                             \
	ctr = 0;                                                             \
	REPEAT5(expr; ctr += step;)
#define UNROLL24(ctr, step, expr)                                            \
	ctr = 0;                                                             \
	REPEAT24(expr; ctr += step;)

/*
 * Keccakf[1600] permutations constants.
 */

static const unsigned KeccakRho[25] = { 0, 1, 62, 28, 27, 36, 44, 6, 55, 20,
	3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };

static const unsigned KeccakPi[25] = { 0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1,
	7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21 };

static const KECCAK_U64 KeccakIota[24] = { 0x0000000000000001UL,
	0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
	0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL,
	0x8000000000008009UL, 0x000000000000008AUL, 0x0000000000000088UL,
	0x0000000080008009UL, 0x000000008000000AUL, 0x000000008000808BUL,
	0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
	0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL,
	0x800000008000000AUL, 0x8000000080008081UL, 0x8000000000008080UL,
	0x0000000080000001UL, 0x8000000080008008UL };

/*
 * Keccakf[1600] permutations.
 * The 1600 bits state is represented by lanes of 64 bits.
 */

static inline void
theta(KECCAK_U64 state[25])
{
	KECCAK_U64 C[5];
	KECCAK_U64 Dx;
	size_t x, y;

	UNROLL5(x, 1, C[x] = 0; UNROLL5(y, 5, C[x] ^= state[x + y];))

	UNROLL5(x, 1, Dx = ROL64(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
		UNROLL5(y, 5, state[x + y] ^= Dx;))
}

static inline void
rho(KECCAK_U64 state[25])
{
	size_t x, y;

	UNROLL5(x, 5,
		UNROLL5(y, 1,
			state[x + y]
			= ROL64(state[x + y], KeccakRho[x + y]);))
}

static inline void
pi(KECCAK_U64 state[25])
{
	KECCAK_U64 s1;
	size_t x;

	x = 1;
	s1 = state[1];
	REPEAT24(state[x] = state[KeccakPi[x]]; x = KeccakPi[x];)
	state[10] = s1;
}

static inline void
chi(KECCAK_U64 state[25])
{
	KECCAK_U64 C[5];
	size_t x, y;

	UNROLL5(y, 5,
		UNROLL5(x, 1, C[x] = state[x + y];) UNROLL5(
			x, 1,
			state[x + y] ^= (~C[(x + 1) % 5]) & C[(x + 2) % 5];))
}

static inline void
iota(KECCAK_U64 state[25], size_t r)
{
	state[0] ^= KeccakIota[r];
}

/*
 * Keccakf[1600] sponge function.
 */

static inline void
keccakf1600(KECCAK_U64 state[25])
{
	size_t r;

	UNROLL24(r, 1, theta(state); rho(state); pi(state); chi(state);
		 iota(state, r);)
}

size_t
Keccak1600_Absorb(
	KECCAK_U64 state[25], const char *data, size_t len, size_t blocksz)
{
	size_t n;

	while (len >= blocksz) {
		for (n = 0; n < blocksz / 8; n++, data += 8, len -= 8) {
			state[n] ^= loadu64(data);
		}
		keccakf1600(state);
	}
	return len;
}

void
Keccak1600_Pad(char *m, size_t mlen, unsigned char suffix, size_t blocksz)
{
	size_t pad = blocksz - mlen % blocksz;
	if (pad != 0)
		memset(m + mlen, 0, pad);
	m[mlen] = suffix;
	m[blocksz - 1] |= 0x80;
}

void
Keccak1600_Squeeze(
	unsigned char *md, size_t mdlen, KECCAK_U64 state[25], size_t blocksz)
{
	size_t n, i;

	while (mdlen) {
		for (n = 0; n < blocksz / 8 && mdlen;
			n++, md += i, mdlen -= i) {
			for (i = 0; i < MIN(mdlen, 8); i++)
				md[i] = (unsigned char)(state[n] >> (i * 8));
		}
		if (mdlen)
			keccakf1600(state);
	}
}

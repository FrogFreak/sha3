#include "sha3.h"
#include <stdint.h>
#include <string.h>
#include <stddef.h>

typedef uint64_t KECCAK_U64;
typedef struct keccak1600_st KECCAK1600_CTX;

#define U8(x)           (unsigned char)(x)
#define U64(x)          (KECCAK_U64)(x)
#define ROL64(qword, n) ((((KECCAK_U64)(qword)) << (n)) ^ (((SHA_LONG64)(qword)) >> (64 - (n))))

#define MIN(a, b)       (((a) > (b)) ? (b) : (a))

/*
 * Loop unrolling helpers macro.
 */
#define REPEAT5(e)      e e e e e
#define REPEAT24(e)     REPEAT5(e e e e) e e e e
#define UNROLL5(ctr, step, expr)        \
    ctr = 0;                            \
    REPEAT5(expr; ctr += step;)
#define UNROLL24(ctr, step, expr)       \
    ctr = 0;                            \
    REPEAT24(expr; ctr += step;)


/*
 * Keccakf[1600] permutations constants.
 */

static const unsigned KeccakRho[25] =
{
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static const unsigned KeccakPi[25] =
{
     0,  6, 12, 18, 24,
     3,  9, 10, 16, 22,
     1,  7, 13, 19, 20,
     4,  5, 11, 17, 23,
     2,  8, 14, 15, 21
};

static const KECCAK_U64 KeccakIota[24] =
{
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};


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

    UNROLL5(x, 1,
        C[x] = 0;
        UNROLL5(y, 5,
           C[x] ^= state[x + y];
        )
    )

    UNROLL5(x, 1,
        Dx = ROL64(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
        UNROLL5(y, 5,
            state[x + y] ^= Dx;
        )
    )
}

static inline void
rho(KECCAK_U64 state[25])
{
    size_t x, y;

    UNROLL5(x, 5,
        UNROLL5(y, 1,
            state[x + y] = ROL64(state[x + y], KeccakRho[x + y]);
        )
    )
}

static inline void
pi(KECCAK_U64 state[25])
{
    KECCAK_U64 s1;
    size_t x;

    x = 1;
    s1 = state[1];
    REPEAT24(
        state[x] = state[KeccakPi[x]];
        x = KeccakPi[x];
    )
    state[10] = s1;
}

static inline void
chi(KECCAK_U64 state[25])
{
    KECCAK_U64 C[5];
    size_t x, y;

    UNROLL5(y, 5,
        UNROLL5(x, 1,
           C[x] = state[x + y];
        )
        UNROLL5(x, 1,
            state[x + y] ^= (~C[(x + 1) % 5]) & C[(x + 2) % 5];
        )
    )
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

    UNROLL24(r, 1,
        theta(state);
        rho(state);
        pi(state);
        chi(state);
        iota(state, r);
    )
}

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


static int
keccak1600_init(KECCAK1600_CTX *c, size_t r, unsigned char d)
{
    memset(c, 0, sizeof(*c));
    c->blocksz = r/8; 
    c->pad = d;
    return 1;
}

static int
keccak1600_update(KECCAK1600_CTX *c, const char *data, size_t len)
{
    size_t n;

    if (c->bufsz)
    {
        n = MIN(c->blocksz - c->bufsz, len);
    
        memcpy(c->buf + c->bufsz, data, n);
        c->bufsz += n, data += n, len -= n;
        if (c->bufsz == c->blocksz)
        {
            c->bufsz = 0;
            keccak1600_update(c, c->buf, c->blocksz);
        }
    }

    while (len >= c->blocksz)
    {
        for (n = 0; n < c->blocksz / 8; n++, data += 8, len -= 8)
        {
            c->state[n] ^= loadu64(data);
        }
        keccakf1600(c->state);
    }

    if (len)
    {
        memcpy(c->buf, data, len);
        c->bufsz = len;
    }

    return 1;
}

static int
keccak1600_final(unsigned char *md, size_t mdlen, KECCAK1600_CTX *c)
{
    size_t n, i;

    /* 
     * Add padded message to leftover block.
     */
    memset(c->buf + c->bufsz, 0, c->blocksz - c->bufsz);
    c->buf[c->bufsz] = c->pad;
    c->buf[c->blocksz - 1] |= 0x80;
    c->bufsz = 0;
    keccak1600_update(c, c->buf, c->blocksz);

    while (mdlen)
    {
        for (n = 0; n < c->blocksz/8 && mdlen; n++, md += i, mdlen -= i)
        {
            for (i = 0; i < MIN(mdlen, 8); i++)
                md[i] = U8(c->state[n] >> (i*8));
        }
        if (mdlen)
            keccakf1600(c->state); 
    }

    return 1;
}

#define SHA3_DEF(Bits)                                                  \
    int                                                                 \
    SHA3_##Bits##_Init(SHA3_CTX *c)                                     \
    {                                                                   \
        return keccak1600_init(c, 1600 - Bits * 2, 0x06);               \
    }                                                                   \
                                                                        \
    int                                                                 \
    SHA3_##Bits##_Update(SHA3_CTX *c, const void *data, size_t len)     \
    {                                                                   \
        return keccak1600_update(c, data, len);                         \
    }                                                                   \
                                                                        \
    int                                                                 \
    SHA3_##Bits##_Final(unsigned char *md, SHA3_CTX *c)                 \
    {                                                                   \
        return keccak1600_final(md, Bits/8, c);                         \
    }                                                                     

#define SHAKE_DEF(Bits)                                                 \
    int                                                                 \
    SHAKE##Bits##_Init(SHA3_CTX *c)                                     \
    {                                                                   \
        return keccak1600_init(c, 1600 - Bits * 2, 0x1F);               \
    }                                                                   \
                                                                        \
    int                                                                 \
    SHAKE##Bits##_Update(SHA3_CTX *c, const void *data, size_t len)     \
    {                                                                   \
        return keccak1600_update(c, data, len);                         \
    }                                                                   \
                                                                        \
    int                                                                 \
    SHAKE##Bits##_Final(unsigned char *md, size_t mdlen, SHA3_CTX *c)   \
    {                                                                   \
        return keccak1600_final(md, mdlen, c);                          \
    }                                                                     


/* FIPS 202 Instances */
SHA3_DEF    (224)
SHA3_DEF    (256)
SHA3_DEF    (384)
SHA3_DEF    (512)
SHAKE_DEF   (128)
SHAKE_DEF   (256)

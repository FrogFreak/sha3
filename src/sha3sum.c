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
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#define PACKAGE        "sha3sum"

#include "sha3.h"

/*
 * Command line usages and arguments
 */
static const char *usages =
    "Usage: " PACKAGE " [OPTIONS]... [FILE]...\n"
    "Print or check SHA-3/SHAKE checksums.\n"  
    "With no FILE, or when FILE is -, read standard input.\n"
    "\n"
    "   -a, --algorithm     SHA3:  224 (default), 256, 384, 512\n"
#ifdef SHA3_XOF
    "                       SHAKE: 128, 256\n"
    "   -d, --dlen          digest length in bits when using SHAKE128 or SHAKE256\n"
#endif
    "   -h, --help          display this help and exit\n"
; 

enum {
    OPT_UNKNOWN     = '?',
    OPT_HELP        = 'h',
    OPT_ALGORITHM   = 'a',
    OPT_DIGESTLEN   = 'd'
};

static const char *short_opts = "ha:d:" ;

static const struct option long_opts[] = {
    { "help",       no_argument,        NULL, 'h' },
    { "algorithm",  required_argument,  NULL, 'a' },
    { "dlen",       required_argument,  NULL, 'd' },
    { NULL, 0, NULL, 0 }
};

/*
 * SHA3 functions and checksum
 */

typedef struct {
    /* to optimize call and buffering */
    size_t      blocksz;
    size_t      dlen;
    unsigned    xof: 1;
    int         (*init)(SHA3_CTX *);
    int         (*update)(SHA3_CTX *, const void *, size_t);
    union {
        int     (*final)(unsigned char *, SHA3_CTX *);
        int     (*final_xof)(unsigned char *, size_t, SHA3_CTX *);
    };
} sha3func_t;

static sha3func_t sha3 = {0};


#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define ECHO_DIGEST(md, mdlen)              \
    for (size_t i = 0; i < mdlen; i++)      \
    {                                       \
        fprintf(stdout, "%02x", md[i]);     \
    }

static int
sha3sum(const char *filename)
{
    SHA3_CTX ctx;
#define MAXBLOCKSZ  200 - 128/4
    unsigned char md[MAXBLOCKSZ];
#define BUFSZ       4096
    char buf[BUFSZ];
    size_t r;
    FILE *fp;
 
    if (filename[0] == '-' && filename[1] == '\0')
        fp = stdin;
    else
        fp = fopen(filename, "rt");

    sha3.init(&ctx);
    while ((r = fread(buf, 1, BUFSZ - (BUFSZ % sha3.blocksz), fp)) != 0)
    {
        sha3.update(&ctx, buf, r);
    }

    if (sha3.xof)
    {
        for (size_t i = 0; i < sha3.dlen; i += r)
        {
            r = MIN(sha3.dlen - i, sha3.blocksz); 
            sha3.final_xof(md, r, &ctx);
            ECHO_DIGEST(md, r);
        }
    }
    else
    {
        sha3.final(md, &ctx);
        ECHO_DIGEST(md, sha3.dlen);
    }

    fprintf(stdout, "  %s\n", filename);
    if (fp != stdin)
        fclose(fp);
    return EXIT_SUCCESS;
}

int
main(int argc, char *argv[])
{
    unsigned opt_bits = 224;
    size_t opt_dlen = 0;
    int opt;

    /* Parse CLI options */
    do {
        opt = getopt_long(argc, argv, short_opts, long_opts, NULL);
        switch(opt)
        {
        case OPT_ALGORITHM:
            opt_bits = atoi(optarg);
            break;
        case OPT_DIGESTLEN:
            opt_dlen = atoi(optarg)/8;
            break;
        case OPT_HELP:
            fprintf(stdout, usages);
            return EXIT_SUCCESS;
        case OPT_UNKNOWN:
            goto exit_error;
        }
    } while (opt != -1);

    /* Get FIPS202 Instance */
    switch(opt_bits)
    {
# define SHA3(bits) (sha3func_t) {              \
        .init       = SHA3_##bits##_Init,       \
        .update     = SHA3_##bits##_Update,     \
        .final      = SHA3_##bits##_Final,      \
        .blocksz    = 200 - bits/4,             \
        .dlen       = bits/8,                   \
        .xof        = 0                         \
    }
#ifndef SHA3_XOF
# define SHAKE(bits) (sha3func_t) {0}
#else
# define SHAKE(bits) (sha3func_t) {             \
        .init       = SHAKE##bits##_Init,       \
        .update     = SHAKE##bits##_Update,     \
        .final_xof  = SHAKE##bits##_Final,      \
        .blocksz    = 200 - bits/4,             \
        .dlen       = bits/8,                   \
        .xof        = 1                         \
    }
    case 128:
        sha3 = SHAKE(128);
        break;
#endif
    case 224:
        sha3 = SHA3(224);
        break;
    case 256:
        sha3 = (opt_dlen) ? SHAKE(256) : SHA3(256); 
        break;
    case 384:
        sha3 = SHA3(384);
        break;
    case 512:
        sha3 = SHA3(512);
        break;
    default:
        fprintf(stderr, PACKAGE ": invalid algorithm\n");
        return EXIT_FAILURE;
    }

    if (opt_dlen)
    {
        if (!sha3.xof)
        {
            fprintf(stderr, PACKAGE ": digest length argument is only valid for SHAKE functions\n");
            goto exit_error;
        }
        sha3.dlen = opt_dlen;
    }

    /* Compute and print files digest */
    if (optind == argc)
    {
        sha3sum("-");
    }

    for (; optind < argc; optind++)
    {
        sha3sum(argv[optind]);
    }

    return EXIT_SUCCESS;

exit_error:
    fprintf(stderr, "Type " PACKAGE " -h for help\n");
    return EXIT_FAILURE;
}

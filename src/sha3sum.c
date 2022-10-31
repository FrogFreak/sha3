#include "sha3.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>

#define PACKAGE "sha3sum"

typedef struct {
    unsigned    xof : 1;
    int         (*init)(SHA3_CTX *);
    int         (*update)(SHA3_CTX *, const void *, size_t);
    union {
        int     (*final)(unsigned char *, SHA3_CTX *);
        int     (*final_xof)(unsigned char *, size_t, SHA3_CTX *);
    };
} SHA3_Instance;

static const char *errmsg;
static const char *usages =
    "Usage: " PACKAGE " [OPTIONS]... [FILE]...\n"
    "Print or check SHA-3 checksums.\n"  
    "With no FILE, or when FILE is -, read standard input.\n"
    "\n"
    "   -a, --algorithm   224 (default), 256, 384, 512, 128000, 256000\n"
    "   -x, --xof         number\n"
    "   -h, --help        display this help and exit\n"
    ; 

enum {
    OPT_UNKNOWN     = '?',
    OPT_HELP        = 'h',
    OPT_ALGORITHM   = 'a'
};
static const char *short_opts = "ha:";
static const struct option long_opts[] = {
    { "help",       no_argument,        NULL, 'h' },
    { "algorithm",  required_argument,  NULL, 'a' },
    { NULL, 0, NULL, 0 }
};


static int
sha3sum(unsigned bits, unsigned char *md, size_t mdlen, FILE *fp)
{
#define BUFSZ 1024
    char buf[BUFSZ];
    ssize_t r;

    SHA3_CTX C;
    SHA3_Instance H;
    H.xof = bits == 128 || bits == 256;
    switch(bits)
    {
#define SHAKE_CASE(b)                                                                           \
        H.init = SHAKE##b##_Init, H.update = SHAKE##b##_Update, H.final_xof = SHAKE##b##_Final
#define SHA3_CASE(b)                                                                            \
        H.init = SHA3_##b##_Init, H.update = SHA3_##b##_Update, H.final = SHA3_##b##_Final  
    case 224:
        SHA3_CASE(224);
        break;
    case 256:
        if (H.xof)
            SHAKE_CASE(256);
        else
            SHA3_CASE(256);
        break;
    case 384:
        SHA3_CASE(384);
        break;
    case 512:
        SHA3_CASE(512);
        break;
    case 128:
        if (H.xof)
        {
            SHAKE_CASE(128);
            break;
        }
    __attribute__((fallthrough));
    default:
        errmsg = "invalid sha3 instance";
        return 1;
    }

    H.init(&C);
    while ((r = fread(buf, 1, BUFSZ, fp)) != 0)
    {
        H.update(&C, buf, r);
    }
    if (H.xof)
        H.final_xof(md, mdlen, &C);
    else
        H.final(md, &C);

    return 0;
}

#define ECHO_DIGEST(md, mdlen, filename)    \
    for (size_t i = 0; i < mdlen; i++)      \
    {                                       \
        fprintf(stdout, "%02x", md[i]);     \
    }                                       \
    fprintf(stdout, "  %s\n", filename); 

int
main(int argc, char *argv[])
{
    FILE *fp;
#define MAX_MDLEN 64
    unsigned char md[MAX_MDLEN] = {0};
    unsigned bits = 224;
    int opt;

    do {
        opt = getopt_long(argc, argv, short_opts, long_opts, NULL);
        switch(opt)
        {
        case OPT_UNKNOWN:
            errmsg = "Type sha3sum -h for help";
            goto exit_error;
        case OPT_HELP:
            fprintf(stdout, usages);
            return 0;
        case OPT_ALGORITHM:
            bits = atoi(optarg);
            break;
        }
    } while (opt != -1);

    if (optind == argc)
    {
       sha3sum(bits, md, bits/8, stdin);
       ECHO_DIGEST(md, bits/8, "-");
    }

    for (; optind < argc; optind++)
    {
        fp = fopen(argv[optind], "rt");
        sha3sum(bits, md, bits/8, fp);
        ECHO_DIGEST(md, bits/8, argv[optind]);
        fclose(fp);
    }

    return 0;

exit_error:
    fprintf(stderr, errmsg);
    return 1;
}

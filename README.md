## EPITA, Applied Cryptography course project

This repository implements FIPS 202 instances of Keccak sponge function and more specifically :
* The SHA3 family with digest size: 224, 256, 384 and 512.
* The SHAKE family (XOF): 128 and 256.

It also provides a `sha3sum` utility program.

### Compilation

```bash
# Static library
make libsha3.a

# Binary
make sha3sum
```

### Test
```bash
make check
Testfile /tmp/tmp.IzYGEnqRMP (1MiB)

real	0m0.009s
user	0m0.007s
sys	0m0.002s
RESULT:		ac917722b3dbdc9dab97b29b5f1bd976a87c645d68270aa7a9a1a885  /tmp/tmp.IzYGEnqRMP

real	0m0.032s
user	0m0.029s
sys	0m0.002s
EXPECTED:	ac917722b3dbdc9dab97b29b5f1bd976a87c645d68270aa7a9a1a885  /tmp/tmp.IzYGEnqRMP
```

### Example usages

__Help menu__
```bash
sha3sum -h
Usage: sha3sum [OPTIONS]... [FILE]...
Print or check SHA-3/SHAKE checksums.
With no FILE, or when FILE is -, read standard input.

   -a, --algorithm     SHA3:  224 (default), 256, 384, 512
                       SHAKE: 128, 256
   -d, --dlen          digest length in bits when using SHAKE128 or SHAKE256
   -h, --help          display this help and exit
```

__SHA3-384__
```bash
echo -n "EPITA" | ./sha3sum -a 224
a32cfceb60af4d72b1ceea51a6e1d97470a6b11639a8b741509b1408  -
```

__SHAKE256 with 1000 bits of digest__
```bash
eecho -n "EPITA" | ./sha3sum -a 256 --dlen 1000
9bff75f73809923c274dd4909581c13a7b9ba2c0f2996e721505ab5f0d8fa5ee31653045422561aaae431acfb8b35ab04fa650d55b90abc631071922bbbbed2068539bd4f3ef6af735710c5f74c95ca2a1b7b7143fd6331f2301f22162443fd8ce1b8c761445ab1d0f19432615427db84290b3ca49c0bab8c218cb6f8e  -
```

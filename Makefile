CC = gcc
CFLAGS = -Wextra -Wall
CFLAGS += -DSHA3_XOF
LDFLAGS = -I./src/include

OBJS = src/keccak1600.o src/sha3.o src/sha3sum.o

all: sha3sum libsha3.a

libsha3.a: $(OBJS)
	ar rcs $@ $^

sha3sum: CFLAGS += -std=c99 -O3
sha3sum: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $^ -o $@

check: sha3sum
	$(eval TMP := $(shell mktemp))
	@dd if=/dev/urandom of=$(TMP) bs=1M count=1 2>/dev/null
	@echo "Testfile $(TMP) (1MiB)"
	@echo -e "RESULT:\t\t$$(time ./sha3sum $(TMP))"
	@echo -e "EXPECTED:\t$$(time sha3sum $(TMP))"

.PHONY: clean all
clean:
	rm -f $(OBJS) sha3sum libsha3.a

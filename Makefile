CC = gcc
CFLAGS = -I./src/include -g -Wextra -Wall -fsanitize=address -std=c99
BIN = sha3sum
OBJS = src/sha3.o src/sha3sum.o

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@
.PHONY: clean all

clean:
	rm -f $(BIN) $(OBJS)

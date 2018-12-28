DEPS_SRC:=$(shell find . -name "*.c" -not -name "test.c")
DEPS:=$(DEPS_SRC:.c=.o)
BIN=libkvmchan.so

CFLAGS=-Wall -fpic -fvisibility=hidden -std=gnu99 -g -I.
LIBS=-lrt -pthread

.PHONY all: library test

library: $(DEPS)
	$(CC) -shared $(CFLAGS) $(DEPS) -o $(BIN) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(DEPS)
	rm -f $(BIN)

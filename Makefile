DEPS_SRC:=$(shell find . -name "*.c" -not -name "test.c")
DEPS:=$(DEPS_SRC:.c=.o)
BIN:=libkvmchan.so
TEST_DEPS:=test.o
TEST_BIN:=test

CFLAGS=-O2 -Wall -fpic -fvisibility=hidden -std=gnu99 -g -I. \
	   -fstack-protector-strong -D_FORITY_SOURCE=2 -fstack-clash-protection
LIBS=-lrt -pthread

.PHONY all: library test

library: $(DEPS)
	$(CC) -shared $(CFLAGS) $(DEPS) -o $(BIN) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

test: $(DEPS) $(TEST_DEPS)
	$(CC) $(CFLAGS) $(DEPS) $(TEST_DEPS) -o $(TEST_BIN) $(LIBS)

clean:
	rm -f $(DEPS)
	rm -f $(BIN)
	rm -f $(TEST_BIN)
	rm -f $(TEST_DEPS)

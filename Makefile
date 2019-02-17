DEPS:=library.o ringbuf.o
BIN:=libkvmchan.so
LIBS=-lrt -pthread

DAEMON_DEPS:=daemon/daemon.o daemon/libvirt.o daemon/util.o
DAEMON_BIN:=kvmchand
DAEMON_LIBS:=$(shell pkg-config --libs libvirt)

TEST_DEPS:=test.o
TEST_BIN:=test
TEST_LIBS:=$(shell pkg-config --cflags --libs check)

CFLAGS=-O2 -Wall -fpic -fvisibility=hidden -std=gnu99 -g -I. \
	   -fstack-protector-strong -D_FORITY_SOURCE=2

COMPILER_NAME:=$(shell $(CC) --version |cut -d' ' -f1 |head -n1)
ifneq ($(COMPILER_NAME),clang)
# This flag is GCC-only
CFLAGS += -fstack-clash-protection
endif


.PHONY all: library daemon

library: $(DEPS)
	$(CC) -shared $(CFLAGS) $(DEPS) -o $(BIN) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

daemon: $(DAEMON_DEPS) $(DEPS)
	$(CC) $(CFLAGS) $(DAEMON_DEPS) $(DEPS) -o $(DAEMON_BIN) $(LIBS) $(DAEMON_LIBS)

build_test: $(DEPS) $(TEST_DEPS)
	$(CC) $(CFLAGS) $(DEPS) $(TEST_DEPS) -o $(TEST_BIN) $(LIBS) $(TEST_LIBS)

test: build_test
	./$(TEST_BIN)

clean:
	rm -f $(DEPS)
	rm -f $(BIN)
	rm -f $(DAEMON_DEPS)
	rm -f $(DAEMON_BIN)
	rm -f $(TEST_BIN)
	rm -f $(TEST_DEPS)

print-%  : ; @echo $* = $($*)

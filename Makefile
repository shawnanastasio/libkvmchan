SRCS:=library.c ringbuf.c
DEPS:=$(SRCS:.c=.o)
BIN:=libkvmchan.so
LIBS=-lrt -pthread
DEBUG:=true

SYSTEMD ?= 0

DAEMON_SRCS:=daemon/daemon.c daemon/libvirt.c daemon/util.c daemon/ivshmem.c daemon/vfio.c \
	daemon/ipc.c daemon/connections.c daemon/localhandler.c
DAEMON_DEPS:=$(DAEMON_SRCS:.c=.daemon.o)
DAEMON_BIN:=kvmchand
DAEMON_LIBS:=-lrt -pthread $(shell pkg-config --libs libvirt libvirt-qemu libxml-2.0)
DAEMON_CFLAGS:=$(shell pkg-config --cflags libxml-2.0)
ifeq ($(SYSTEMD),1)
DAEMON_CFLAGS += -DHAVE_SYSTEMD
DAEMON_LIBS += `pkg-config --libs libsystemd || pkg-config --libs libsystemd-daemon`
endif

TEST_SRCS:=test.c
TEST_DEPS:=$(TEST_SRCS:.c=.o)
TEST_BIN:=test
TEST_LIBS:=$(shell pkg-config --cflags --libs check)

TEST_LIBRARY_SRCS:=test_library.c
TEST_LIBRARY_BIN:=test_library

CFLAGS=-D_GNU_SOURCE=1 -O2 -Wall -Wextra -Wvla -fpic -fvisibility=hidden -std=gnu99 -I. \
	   -fstack-protector-strong -D_FORITY_SOURCE=2

ifneq ($(DEBUG),false)
CFLAGS += -g
endif

COMPILER_NAME:=$(shell $(CC) --version |cut -d' ' -f1 |head -n1)
ifneq ($(COMPILER_NAME),clang)
# This flag is GCC-only
CFLAGS += -fstack-clash-protection
endif

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

.PHONY all: library daemon build_test $(TEST_LIBRARY_BIN) kvmchan.pc

library: $(DEPS)
	$(CC) -shared $(CFLAGS) $(DEPS) -o $(BIN) $(LIBS)

%.daemon.o: %.c
	$(CC) $(CFLAGS) $(DAEMON_CFLAGS) -o $@ -c $<

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

daemon: $(DAEMON_DEPS) $(DEPS)
	$(CC) $(CFLAGS) $(DAEMON_DEPS) $(DEPS) -o $(DAEMON_BIN) $(LIBS) $(DAEMON_LIBS)

build_test: $(DEPS) $(TEST_DEPS)
	$(CC) $(CFLAGS) $(DEPS) $(TEST_DEPS) -o $(TEST_BIN) $(LIBS) $(TEST_LIBS)

test: build_test
	./$(TEST_BIN)

$(TEST_LIBRARY_BIN): library
	$(CC) $(CFLAGS) -fvisibility=default $(TEST_LIBRARY_SRCS)  -lkvmchan -L. -o $(TEST_LIBRARY_BIN) 

kvmchan.pc: kvmchan.pc.in
	sed -e "s/@VERSION@/`cat version`/" \
		-e "s:@PREFIX@:$(PREFIX):" \
		-e "s:@LIBDIR@:$(LIBDIR):" \
		-e "s:@INCLUDEDIR@:$(INCLUDEDIR):" \
		$< > $@

install: all
	install $(DAEMON_BIN) $(PREFIX)/bin
	install $(BIN) $(LIBDIR)
	install libkvmchan.h libkvmchan-priv.h $(INCLUDEDIR)
	install kvmchan.pc $(LIBDIR)/pkgconfig

clean:
	rm -f $(DEPS)
	rm -f $(BIN)
	rm -f $(DAEMON_DEPS)
	rm -f $(DAEMON_BIN)
	rm -f $(TEST_BIN)
	rm -f $(TEST_DEPS)

print-%  : ; @echo $* = $($*)

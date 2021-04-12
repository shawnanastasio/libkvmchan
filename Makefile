SRCS:=library.c ringbuf.c daemon/util.c
DEPS:=$(SRCS:.c=.o)
BIN:=libkvmchan.so
LIBS:=-lrt -pthread
LIB_CFLAGS:=-DUTIL_NO_ASSERT_ON_FAILURE -DKVMCHAN_LIBRARY

# Build options
DEBUG ?= 1
SYSTEMD ?= 0
USE_ASAN ?= 0
USE_PRIVSEP ?= 1
GUEST_ONLY ?= 0

# Build-time behavior configuration
PRIVSEP_USER ?= kvmchand
PRIVSEP_GROUP ?= kvmchand

DAEMON_ALL_SRCS:=daemon/daemon.c daemon/libvirt.c daemon/util.c daemon/ivshmem.c daemon/vfio.c \
	daemon/ipc.c daemon/connections.c daemon/localhandler.c daemon/page_allocator.c ringbuf.c
DAEMON_GUEST_SRCS:=daemon/daemon.c daemon/util.c daemon/vfio.c daemon/ipc.c daemon/localhandler.c \
	ringbuf.c
DAEMON_BIN:=kvmchand
DAEMON_CFLAGS:=
DAEMON_LIBS:=

ifeq ($(SYSTEMD),1)
DAEMON_CFLAGS += -DHAVE_SYSTEMD
DAEMON_LIBS += `pkg-config --libs libsystemd || pkg-config --libs libsystemd-daemon`
endif

ifeq ($(GUEST_ONLY),1)
DAEMON_CFLAGS += -DGUEST_ONLY
DAEMON_DEPS:=$(DAEMON_GUEST_SRCS:.c=.daemon.o)
else
DAEMON_LIBS +=-lrt -pthread $(shell pkg-config --libs libvirt libvirt-qemu)
DAEMON_CFLAGS +=$(shell pkg-config --cflags libvirt libvirt-qemu)
DAEMON_DEPS:=$(DAEMON_ALL_SRCS:.c=.daemon.o)
endif

ifeq ($(USE_PRIVSEP),1)
DAEMON_CFLAGS += -DUSE_PRIVSEP -DPRIVSEP_USER=\"$(PRIVSEP_USER)\" -DPRIVSEP_GROUP=\"$(PRIVSEP_GROUP)\"
endif


TEST_SRCS:=test.c
TEST_DEPS:=$(TEST_SRCS:.c=.o)
TEST_BIN:=test
TEST_LIBS:=$(shell pkg-config --cflags --libs check)

TEST_LIBRARY_SRCS:=test_library.c
TEST_LIBRARY_BIN:=test_library

CFLAGS=-D_GNU_SOURCE=1 -O2 -Wall -Wextra -Wvla -fpic -fvisibility=hidden -std=gnu99 -I. \
	   -fstack-protector-strong -D_FORITY_SOURCE=2

ifeq ($(DEBUG),1)
CFLAGS += -g
endif

ifeq ($(USE_ASAN),1)
CFLAGS += -fsanitize=address
endif

COMPILER_NAME:=$(shell $(CC) --version |cut -d' ' -f1 |head -n1)
ifneq ($(COMPILER_NAME),clang)
# This flag is GCC-only
CFLAGS += -fstack-clash-protection

# -Wstringop-truncation results in false-positives w/ strncpy and explicit null termination
CFLAGS += -Wno-stringop-truncation
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
	$(CC) $(CFLAGS) $(LIB_CFLAGS) -o $@ -c $<

daemon: $(DAEMON_DEPS)
	$(CC) $(CFLAGS) $(DAEMON_DEPS) -o $(DAEMON_BIN) $(LIBS) $(DAEMON_LIBS)

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

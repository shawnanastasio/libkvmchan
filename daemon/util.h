/**
 * Copyright 2018-2019 Shawn Anastasio
 *
 * This file is part of libkvmchan.
 *
 * libkvmchan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libkvmchan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libkvmchan.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef KVMCHAND_UTIL_H
#define KVMCHAND_UTIL_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <sys/types.h>

#define ARRAY_SIZE(x) (sizeof((x)) / sizeof(*(x)))

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

// Old glibc doesn't have <sys/memfd.h>, just declare memfd_create manually
#if __has_include(<sys/memfd.h>)
#include <sys/memfd.h>
#else
int memfd_create(const char *name, unsigned int flags);
#endif

extern long SYSTEM_PAGE_SIZE;

enum log_level {
    LOGL_INFO,
    LOGL_WARN,
    LOGL_ERROR,
    LOGL_BUG // Internal use only through log_BUG
};

enum loop_msg_type {
    LOOP_MSG_MAIN, // Message from main loop
    LOOP_MSG_LIBVIRT, // Message from libvirt loop
    LOOP_MSG_IVSHMEM, // Message from ivshmem loop
};

#define log(level, fmt, ...) log_impl(level, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define log_BUG(fmt, ...) do { log(LOGL_BUG, fmt, ##__VA_ARGS__); bail_out(); } while (0)

void log_impl(enum log_level level, const char *file, int line, const char *fmt, ...);

#define vec_template_proto(Tname, T) \
typedef int (*Tname ## _comparator)(T, T); \
struct vec_## Tname { \
    T *data; \
    size_t size; \
    size_t count; \
    void (*destructor)(T); \
}; \
bool vec_ ## Tname ## _init(struct vec_ ## Tname *v, size_t initial_size, void (*destructor)(T)); \
bool vec_ ## Tname ## _push_back(struct vec_ ## Tname *v, T element); \
T vec_ ## Tname ## _at(struct vec_ ## Tname *v, size_t i); \
void vec_ ## Tname ## _remove(struct vec_ ## Tname *v, size_t i); \
void vec_ ## Tname ## _destroy(struct vec_ ## Tname *v); \
bool vec_ ## Tname ## _contains(struct vec_ ## Tname *v, T element, Tname ## _comparator comparator);

vec_template_proto(voidp, void*)
vec_template_proto(int, int)
vec_template_proto(u32, uint32_t)

void free_destructor(void *element);
bool str_is_number(const char *str);

// Malloc wrapper that will crash on failure
#define malloc_w(n) ({ \
    void *ret = malloc((n)); \
    if (!ret) {\
        log(LOGL_ERROR, "malloc failed!"); \
        bail_out(); \
    } \
    ret; \
})

// Modified EINTR wrapper from chromium
#define HANDLE_EINTR(x) ({ \
    typeof(x) eintr_wrapper_result; \
    do { \
        eintr_wrapper_result = (x); \
    } while (eintr_wrapper_result == -1 && errno == EINTR); \
    eintr_wrapper_result; \
})

#define ASSERT(x) do { \
    if (!(x)) { \
        log(LOGL_ERROR, "Assertion failed: %s", #x); \
        bail_out(); \
    } \
} while (0)

int add_epoll_fd(int epoll_fd, int fd, int event);
int del_epoll_fd(int epoll_fd, int fd);

bool install_exit_callback(void (*func)(void*), void *arg);
void run_exit_callbacks(void);
__attribute__((noreturn)) void bail_out(void);


ssize_t socmsg_send(int socfd, void *data, size_t len, int fd);
ssize_t socmsg_recv(int socfd, void *buf, size_t len, int *fd_out);

#endif // KVMCHAND_UTIL_H

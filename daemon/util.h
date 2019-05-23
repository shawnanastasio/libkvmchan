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

#include <stdlib.h>
#include <stdbool.h>

#define ARRAY_SIZE(x) (sizeof((x)) / sizeof(*(x)))

#define IVSHMEM_SOCK_PATH "/tmp/kvmchand_ivshmem"

enum log_level {
    LOGL_INFO,
    LOGL_WARN,
    LOGL_ERROR
};

enum loop_msg_type {
    LOOP_MSG_MAIN, // Message from main loop
    LOOP_MSG_LIBVIRT, // Message from libvirt loop
    LOOP_MSG_IVSHMEM, // Message from ivshmem loop
};

#ifdef __GNUC__
#define log(level, fmt, ...) log_impl(level, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define log(level, fmt, ...) log_impl(level, __FILE__, __LINE__, __VA_ARGS__)
#endif

void log_impl(enum log_level level, const char *file, int line, const char *fmt, ...);

typedef void * voidp;

#define vec_template_proto(T) \
typedef int (*T ## _comparator)(T, T); \
struct vec_## T { \
    T *data; \
    size_t size; \
    size_t count; \
    void (*destructor)(T); \
}; \
bool vec_ ## T ## _init(struct vec_ ## T *v, size_t initial_size, void (*destructor)(T)); \
bool vec_ ## T ## _push_back(struct vec_ ## T *v, T element); \
T vec_ ## T ## _at(struct vec_ ## T *v, size_t i); \
void vec_ ## T ## _remove(struct vec_ ## T *v, size_t i); \
void vec_ ## T ## _destroy(struct vec_ ## T *v); \
bool vec_ ## T ## _contains(struct vec_ ## T *v, T element, T ## _comparator comparator);

vec_template_proto(voidp)
vec_template_proto(int)

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

int add_epoll_fd(int epoll_fd, int fd, int event);
int del_epoll_fd(int epoll_fd, int fd);

bool install_exit_callback(void (*func)(void*), void *arg);
void run_exit_callbacks(void);
void bail_out(void);

#endif // KVMCHAND_UTIL_H

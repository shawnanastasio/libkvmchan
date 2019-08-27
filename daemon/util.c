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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>

#include "util.h"

long SYSTEM_PAGE_SIZE;

__attribute__((constructor))
void initialize_util(void) {
    SYSTEM_PAGE_SIZE = sysconf(_SC_PAGESIZE);
    ASSERT(SYSTEM_PAGE_SIZE);
}

#define vec_template(Tname, T) \
bool vec_ ## Tname ## _init(struct vec_ ## Tname *v, size_t initial_size, void (*destructor)(T)) { \
    if (initial_size < 10) \
        initial_size = 10; \
\
    v->data = calloc(initial_size, sizeof(T)); \
    if (!(v->data)) \
        return false; \
\
    v->size = initial_size; \
    v->count = 0; \
    v->destructor = destructor; \
    return true; \
}; \
\
bool vec_ ## Tname ## _push_back(struct vec_ ## Tname *v, T element) { \
    if (v->size == v->count) { \
        /* double array size */ \
        size_t new_size = v->size * 2; \
        void *new_data = reallocarray(v->data, new_size, sizeof(T)); \
        if (!new_data) \
            return false; \
        v->data = new_data; \
        v->size = new_size; \
    } \
    /* insert element into array */ \
    v->data[v->count++] = element; \
    return true; \
} \
\
T vec_ ## Tname ## _at(struct vec_ ## Tname *v, size_t i) { \
    assert(i < v->count); \
    return v->data[i]; \
} \
\
void vec_ ## Tname ## _remove(struct vec_ ## Tname *v, size_t i) { \
    assert(i < v->count); \
\
    if (v->destructor) \
        v->destructor(v->data[i]); \
\
    if (i != (v->count - 1)) \
        memmove(v->data + i, v->data + i + 1, sizeof(T) * (v->count - i - 1)); \
    v->count -= 1; \
} \
void vec_ ## Tname ## _destroy(struct vec_ ## Tname *v) { \
    size_t s = v->count; \
    while (s-- > 0) { \
        vec_ ## Tname ## _remove(v, s); \
    } \
    free(v->data); \
} \
bool vec_ ## Tname ## _contains(struct vec_ ## Tname *v, T element, Tname ## _comparator comparator) { \
    for (size_t i=0; i<v->count; i++) { \
        if (comparator && !comparator(v->data[i], element)) \
            return true; \
        else if (!comparator && (v->data[i] == element)) \
            return true; \
    } \
    return false; \
}

vec_template(voidp, void*)
vec_template(int, int)
vec_template(u32, uint32_t)

void free_destructor(void *element) {
    free(element);
}

// Determines if a given string is purely numerical ('0'-'9')
bool str_is_number(const char *str) {
    char c;
    while((c = *str++))
        if (!isdigit(c))
            return false;

    return true;
}

const char *log_level_names[] = {
    "[INFO]",
    "[WARN]",
    "[ERROR]",
    "[BUG]"
};

void log_impl(enum log_level level, const char *file, int line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, "%s %s:%d: ", log_level_names[level], file, line);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);

    va_end(args);
}

int add_epoll_fd(int epoll_fd, int fd, int event) {
    struct epoll_event ep_event = {
        .events = event,
        .data = {
            .fd = fd
        }
    };

    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ep_event);
}

int del_epoll_fd(int epoll_fd, int fd) {
    struct epoll_event ep_event = {
        .data = {
            .fd = fd
        }
    };

    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ep_event);
}


// A callback to be executed at program exit
struct exit_callback {
    void (*func)(void *);
    void *arg;
};

static struct vec_voidp callbacks;

bool install_exit_callback(void (*func)(void*), void *arg) {
    static bool init_done = false;
    if (!init_done) {
        if (!vec_voidp_init(&callbacks, 5, NULL))
            return false;

        init_done = true;
    }

    struct exit_callback *cb = malloc_w(sizeof(struct exit_callback));
    if (!cb)
        return false;
    cb->func = func;
    cb->arg = arg;

    vec_voidp_push_back(&callbacks, cb);
    return true;
}

void run_exit_callbacks(void) {
    for(size_t i=0; i<callbacks.count; i++) {
        struct exit_callback *cb = callbacks.data[i];
        cb->func(cb->arg);
    }
}

__attribute__((noreturn)) void bail_out(void) {
    // TODO: Check if in parent or child process
    run_exit_callbacks();
    _exit(EXIT_FAILURE);
}

ssize_t socmsg_send(int socfd, void *data, size_t len, int fd) {
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;

    struct cmsghdr *cmsg;
    struct iovec iov = { .iov_base = data, .iov_len = len };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_flags = 0,
        .msg_control = (fd > 0) ? u.cmsgbuf : NULL,
        .msg_controllen = (fd > 0) ? CMSG_LEN(sizeof(int)) : 0,
    };

    /* Initialize the control message to hand off the fd */
    if (fd > 0) {
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)CMSG_DATA(cmsg) = fd;
    }

    return sendmsg(socfd, &msg, 0);
}

ssize_t socmsg_recv(int socfd, void *buf, size_t len, int *fd_out) {
    ssize_t s;
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;

    struct cmsghdr *cmsg;
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_flags = 0,
        .msg_control = u.cmsgbuf,
        .msg_controllen = CMSG_LEN(sizeof(int))
    };

    if ((s = recvmsg(socfd, &msg, 0)) < 0)
        return s;

    if (fd_out) {
        cmsg = CMSG_FIRSTHDR(&msg);
        if (msg.msg_controllen != CMSG_LEN(sizeof(int))) {
            *fd_out = -1;
            goto out;
        }

        *fd_out = *((int *)CMSG_DATA(cmsg));
    }

out:
    return s;
}


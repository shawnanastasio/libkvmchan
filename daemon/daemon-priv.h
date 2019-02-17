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

#ifndef KVMCHAN_DAEMON_PRIV_H
#define KVMCHAN_DAEMON_PRIV_H

#include <stdlib.h>
#include <stdbool.h>

enum log_level {
    LOGL_INFO,
    LOGL_WARN,
    LOGL_ERROR
};

#ifdef __GNUC__
#define log(level, fmt, ...) log_impl(level, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define log(level, fmt, ...) log_impl(level, __FILE__, __LINE__, __VA_ARGS__)
#endif

struct vec {
    void **data;
    size_t size;
    size_t count;
    void (*destructor)(void *);
};

void log_impl(enum log_level level, const char *file, int line, const char *fmt, ...);

bool vec_init(struct vec *v, size_t initial_size, void (*destructor)(void *));
bool vec_push_back(struct vec *v, void *element);
void *vec_at(struct vec *v, size_t i);
void vec_remove(struct vec *v, size_t i);

int run_libvirt_loop(const char *);

#endif // KVMCHAN_DAEMON_PRIV_H

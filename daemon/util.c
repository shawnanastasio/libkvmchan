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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#include "daemon-priv.h"

bool vec_init(struct vec *v, size_t initial_size, void (*destructor)(void *)) {
    if (initial_size < 10)
        initial_size = 10;

    v->data = calloc(initial_size, sizeof(void *));
    if (!(v->data))
        return false;

    v->size = initial_size;
    v->count = 0;
    v->destructor = destructor;
    return true;
};

bool vec_push_back(struct vec *v, void *element) {
    if (v->size == v->count) {
        /* double array size */
        size_t new_size = v->size * 2;
        void *new_data = reallocarray(v->data, new_size, sizeof(void *));
        if (!new_data)
            return false;
        v->data = new_data;
        v->size = new_size;
    }
    /* insert element into array */
    v->data[v->count++] = element;
    return true;
}


void *vec_at(struct vec *v, size_t i) {
    assert(i < v->count);
    return v->data[i];
}

void vec_remove(struct vec *v, size_t i) {
    assert(i < v->count);

    if (v->destructor)
        v->destructor(v->data[i]);

    if (i != (v->count - 1))
        memmove(v->data + i, v->data + i + 1, sizeof(void *) * (v->count - i - 1));
    v->count -= 1;
}

const char *log_level_names[] = {
    "[INFO]",
    "[WARN]",
    "[ERROR]"
};

void log_impl(enum log_level level, const char *file, int line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, "%s %s:%d: ", log_level_names[level], file, line);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);

    va_end(args);
}



/**
 * Copyright 2018 Shawn Anastasio
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

#ifndef LIBKVMCHAN_RINGBUF_H
#define LIBKVMCHAN_RINGBUF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <pthread.h>

struct ringbuf {
    bool relative;
    size_t size;
    uint8_t *start; // abs. addr of data buffer (used if relative=false)
    intptr_t offset; // offset of the data buffer ptr from this struct (used if relative=true)

    size_t pos_start; // inc
    size_t pos_end; // exc

    // private. Don't access directly
    int eventfd;
    pthread_t eventfd_thread;
    volatile bool kill_thread;
};

void ringbuf_init(struct ringbuf *rb, void *start, size_t size, bool relative);
bool ringbuf_write(struct ringbuf *rb, void *data, size_t size);
bool ringbuf_read(struct ringbuf *rb, void *out, size_t size);
bool ringbuf_read_blocking(struct ringbuf *rb, void *out, size_t size);
int  ringbuf_get_eventfd(struct ringbuf *rb);
void ringbuf_clear_eventfd(struct ringbuf *rb);

// Returns number of bytes in the ringbuffer
size_t ringbuf_available(struct ringbuf *rb);

#endif // LIBKVMCHAN_RINGBUF_H

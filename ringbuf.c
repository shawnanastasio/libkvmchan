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

#include "ringbuf.h"

#include <assert.h>
#include <string.h>

#include <sys/eventfd.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX(x, y) ((x > y) ? (x) : (y))
#define MIN(x, y) ((x > y) ? (y) : (x))

static inline size_t ringbuf_capacity(struct ringbuf *rb) {
    return rb->size;
}

static inline size_t ringbuf_free_space(struct ringbuf *rb) {
    if (rb->pos_start <= rb->pos_end) {
        return ringbuf_capacity(rb) - (rb->pos_end - rb->pos_start);
    } else {
        return (rb->pos_start - rb->pos_end);
    }
}

size_t ringbuf_available(struct ringbuf *rb) {
    return rb->size - ringbuf_free_space(rb);
}

void ringbuf_init(struct ringbuf *rb, void *start, size_t size, bool relative) {
    rb->relative = relative;
    rb->offset = relative ? (uint8_t *)start - (uint8_t *)rb : 0;
    rb->size = size;
    rb->start = start;

    rb->pos_start = 0;
    rb->pos_end = 0;
    rb->eventfd = -1;
}

bool ringbuf_write(struct ringbuf *rb, void *data, size_t size) {
    bool res;
    void *real_start = rb->relative ? ((uint8_t *)rb + rb->offset) : rb->start;
    size_t space_left = ringbuf_free_space(rb);
    if (space_left < size) {
        res = false;
        goto done;
    }

    if (rb->pos_start <= rb->pos_end) {
        // Write from [pos_end,end) and if required,
        // write the rest from [start, pos_start).
        size_t first_left = rb->size - rb->pos_end;
        size_t first = MIN(first_left, size);
        memcpy(real_start + rb->pos_end, data, first);
        rb->pos_end += first;

        if (first_left >= size) {
            res = true;
            goto done;
        }

        size_t second = size - first_left;
        memcpy(real_start, (uint8_t *)data + first, second);
        rb->pos_end = second;
        res = true;
        goto done;
    } else {
        // Write from [pos_end, pos_start)
        size_t first_left = rb->pos_start - rb->pos_end;
        assert(size <= first_left);
        memcpy(real_start + rb->pos_end, data, size);
        rb->pos_end += size;
        res = true;
        goto done;
    }

done:
    // Update ready flag
    return res;
}

bool ringbuf_read(struct ringbuf *rb, void *out, size_t size) {
    bool res;
    void *real_start = rb->relative ? ((uint8_t *)rb + rb->offset) : rb->start;
    if (ringbuf_capacity(rb) - ringbuf_free_space(rb) < size) {
        res = false;
        goto done;
    }

    if (rb->pos_start <= rb->pos_end) {
        // Read from [pos_start, pos_end)
        size_t avail = rb->pos_end - rb->pos_start;
        assert(avail >= size);
        memcpy(out, real_start + rb->pos_start, size);
        rb->pos_start += size;
        res = true;
        goto done;
    } else {
        // Read from [pos_start, end) and if required,
        // read the rest from [start, pos_end)
        size_t first_avail = rb->size - rb->pos_start;
        size_t first = MIN(first_avail, size);
        memcpy(out, real_start + rb->pos_start, first);
        rb->pos_start += size;

        if (first_avail >= size) {
            res = true;
            goto done;
        }

        size_t second = size - first_avail;
        memcpy((uint8_t *)out + first, real_start, second);
        rb->pos_start = second;
        res = true;
        goto done;
    }

done:
    return res;
}

bool ringbuf_read_blocking(struct ringbuf *rb, void *out, size_t size) {
    while (ringbuf_available(rb) < size)
        usleep(1);

    return ringbuf_read(rb, out, size);
}


static void *_eventfd_thread_handler(void *_rb) {
    struct ringbuf *rb = _rb;

    // Busywait for bytes and notify eventfd
    while (!rb->kill_thread && !ringbuf_available(rb))
        usleep(1);

    if (rb->kill_thread)
        return NULL;

    // Set the eventfd
    uint64_t buf = 1;
    write(rb->eventfd, &buf, sizeof(uint64_t));

    return NULL;
}

int ringbuf_get_eventfd(struct ringbuf *rb) {
    // Spawn a thread that will poll the ringbuf and notify the eventfd
    // when data is available to read

    // Create eventfd if it doesn't exist
    if (rb->eventfd < 0) {
        rb->eventfd = eventfd(0, 0);
        if (rb->eventfd < 0) {
            return -1;
        }
    }


    // If data is already available, take a shortcut and just notify
    if (ringbuf_available(rb)) {
        uint64_t buf = 1;
        write(rb->eventfd, &buf, sizeof(buf));
        return rb->eventfd;
    }

    rb->kill_thread = false;
    int ret = pthread_create(&rb->eventfd_thread, NULL, _eventfd_thread_handler, rb);
    if (ret)
        return -1;

    return rb->eventfd;
}

void ringbuf_clear_eventfd(struct ringbuf *rb) {
    // Kill thread if it's still running
    rb->kill_thread = true;
    usleep(1);

    // Temporarily disable blocking and reset the eventfd's counter
    uint64_t buf;
    int fd_flags = fcntl(rb->eventfd, F_GETFL, 0);
    fcntl(rb->eventfd, F_SETFL, fd_flags | O_NONBLOCK);
    read(rb->eventfd, &buf, sizeof(uint64_t));
    fcntl(rb->eventfd, F_SETFL, fd_flags);
}

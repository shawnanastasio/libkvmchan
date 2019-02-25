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

#ifndef LIBKVMCHAN_RINGBUF_H
#define LIBKVMCHAN_RINGBUF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <pthread.h>

#define RINGBUF_FLAG_RELATIVE (1 << 0)
#define RINGBUF_FLAG_BLOCKING (1 << 1)
#define RINGBUF_FLAG_SEC_COPY (1 << 2)

// Return codes for ringbuf functions.
typedef enum ringbuf_ret {
    RB_SUCCESS,   // Success
    RB_NOSPACE,   // No space in ringbuffer
    RB_NODATA,    // No data in ringbuffer to read
    RB_OOM,       // Out of memory (malloc failed)
    RB_SEC_FAIL,  // Security verification failed
} ringbuf_ret_t;

/**
 * A struct that contains ringbuffer metadata.
 * Must not exposed in shared memory.
 *
 * For shared ring buffers, ringbuf_sec* functions
 * should be used in conjunction with struct ringbuf_pub,
 * which contains a subset of the information in this
 * struct that can safely be shared (with bounds checks).
 */
typedef struct ringbuf {
    uint8_t flags;
    size_t size; // Number of usable bytes (buffer size + 1)
    uint8_t *start; // abs. addr of data buffer (used if relative=false)
    intptr_t offset; // offset of the data buffer ptr from this struct (used if relative=true)

    size_t pos_start; // inc
    size_t pos_end; // exc

    // eventfd data storage
    int eventfd;
    pthread_t eventfd_thread;
    bool kill_thread;
} ringbuf_t;

typedef struct ringbuf_pub {
    /**
     * Trusted reader, untrusted writer
     *   - reader will use their priv pos_start and flush it here on operation end
     *   - reader will use this pos_end after bounds checks
     *
     * Trusted writer, untrusted reader
     *   - writer will use their priv pos_end and flush it here on operation end
     *   - writer will use this pos_start after bounds checks
     */
    size_t pos_start_untrusted;
    size_t pos_end_untrusted;

    // The flags that the ringbuf was supposedly created with.
    // The client should do some sanity checks and then immediately copy it
    // into a private structure.
    uint8_t flags_untrusted;
} ringbuf_pub_t;

// Security functions
ringbuf_ret_t ringbuf_sec_init(ringbuf_t *priv, ringbuf_pub_t *pub, void *start, size_t size,
                 uint8_t flags);
ringbuf_ret_t ringbuf_sec_infer_priv(ringbuf_t *priv, ringbuf_pub_t *pub, void *start,
                                  size_t size, uint8_t flags_mask);
ringbuf_ret_t ringbuf_sec_write(ringbuf_t *priv, ringbuf_pub_t *pub, const void *data, size_t size);
ringbuf_ret_t ringbuf_sec_read(ringbuf_t *priv, ringbuf_pub_t *pub, void *buf, size_t size);

// Ringbuf I/O functions
ringbuf_ret_t ringbuf_init(ringbuf_t *rb, void *start, size_t size, uint8_t flags);
ringbuf_ret_t ringbuf_write(ringbuf_t *rb, const void *data, size_t size);
ringbuf_ret_t ringbuf_read(ringbuf_t *rb, void *out, size_t size);
int  ringbuf_get_eventfd(ringbuf_t *rb, ringbuf_pub_t *pub);
void ringbuf_clear_eventfd(ringbuf_t *rb);

#endif // LIBKVMCHAN_RINGBUF_H

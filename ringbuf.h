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
 * In situations where one of the ring buffer clients is untrusted,
 * the following security precautions must be taken
 * (Note the assumption that only one client is writing and one is reading):
 *
 * Trusted writer, untrusted reader:
 *   - a copy of flags, size, start, offset, pos_end must be stored in a
 *     non-shared region and compared to this struct on each operation.
 *
 *   - pos_start is controlled by attacker, bounds check it
 *
 *   - pos_end in reference struct must be updated by us on each read
 *
 *
 * Trusted reader, untrusted writer:
 *   - flags, size, start, offset, pos_start must be stored in a
 *     non-shared region and compared to this struct on each operation.
 *
 *   - pos_end must be bounds checked
 *
 *   - pos_start in reference struct must be updated by us on each read
 *
 *   - eventfd data must be stored out of reach (TODO)
 */
typedef struct ringbuf {
    uint8_t flags;
    size_t size;
    uint8_t *start; // abs. addr of data buffer (used if relative=false)
    intptr_t offset; // offset of the data buffer ptr from this struct (used if relative=true)

    size_t pos_start; // inc
    size_t pos_end; // exc

    // eventfd data storage
    int eventfd;
    pthread_t eventfd_thread;
    volatile bool kill_thread;
} ringbuf_t;

typedef struct ringbuf_sec_context {
    ringbuf_t *untrusted;
    ringbuf_t *reference;
} ringbuf_sec_context_t;

/// Security functions
ringbuf_ret_t ringbuf_sec_validate_untrusted_reader(ringbuf_sec_context_t *sec,
                                                    ringbuf_t *validated_out);
ringbuf_ret_t ringbuf_sec_validate_untrusted_writer(ringbuf_sec_context_t *sec,
                                                    ringbuf_t *validated_out);
ringbuf_ret_t ringbuf_sec_infer_context(ringbuf_t *untrusted, uint8_t flags_mask, size_t size,
                                         intptr_t offset, ringbuf_sec_context_t **sec_out);
void ringbuf_sec_flush_write(ringbuf_sec_context_t *sec, ringbuf_t *validated);
void ringbuf_sec_flush_read(ringbuf_sec_context_t *sec, ringbuf_t *validated);
ringbuf_ret_t ringbuf_write_sec(ringbuf_sec_context_t *sec, void *data, size_t size);
ringbuf_ret_t ringbuf_read_sec(ringbuf_sec_context_t *sec, void *out, size_t size);

// Ringbuf I/O functions
ringbuf_ret_t ringbuf_init(ringbuf_t *rb, void *start, size_t size, uint8_t flags, ringbuf_sec_context_t **sec_out);
//ringbuf_ret_t ringbuf_write(ringbuf_t *rb, void *data, size_t size);
//ringbuf_ret_t ringbuf_read(ringbuf_t *rb, void *out, size_t size);
int  ringbuf_get_eventfd(ringbuf_t *rb);
void ringbuf_clear_eventfd(ringbuf_t *rb);

#endif // LIBKVMCHAN_RINGBUF_H

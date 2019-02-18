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

#include "ringbuf.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <sys/eventfd.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX(x, y) ((x > y) ? (x) : (y))
#define MIN(x, y) ((x > y) ? (y) : (x))

// A way to temporarily yield to the OS while waiting for a blocking operation
// TODO: is this optimal performance-wise?
#define BUSYWAIT_YIELD_TO_OS() usleep(1)

// Ignore unused variable/return warnings. Especially for eventfd actions that can't fail.
// This macro was taken from gnulib.
#if 3 < __GNUC__ + (4 <= __GNUC_MINOR__)
# define ignore_value(x) \
    (__extension__ ({ __typeof__ (x) __x = (x); (void) __x; }))
#else
# define ignore_value(x) ((void) (x))
#endif

static inline size_t ringbuf_available(ringbuf_t *rb);
static inline size_t ringbuf_free_space(ringbuf_t *rb);

/// Security-related operations
ringbuf_ret_t ringbuf_sec_validate_untrusted_reader(ringbuf_sec_context_t *sec,
                                                    ringbuf_t *validated_out) {
    // Validate all security-critical values in a ringbuf that
    // is meant to be read by an untrusted client.

    // First, make a copy of the untrusted struct so that it can't be
    // modified by an attacker during validation.
    ringbuf_t untrusted_copy;
    memcpy(&untrusted_copy, sec->untrusted, sizeof(ringbuf_t));

    ringbuf_t *reference = sec->reference;
    // Validate against reference
    if (untrusted_copy.flags != reference->flags)
        return RB_SEC_FAIL;
    if (untrusted_copy.size != reference->size)
        return RB_SEC_FAIL;
    if (untrusted_copy.start != reference->start)
        return RB_SEC_FAIL;
    if (untrusted_copy.offset != reference->offset)
        return RB_SEC_FAIL;
    if (untrusted_copy.pos_end != reference->pos_end)
        return RB_SEC_FAIL;

    // Ensure that pos_start is within bounds
    if (untrusted_copy.pos_start >= reference->size) {
        return RB_SEC_FAIL;
    }

    // Successfully validated, write validated structure.
    memcpy(validated_out, &untrusted_copy, sizeof(ringbuf_t));

    // In the case of RINGBUF_FLAG_RELATIVE, we must convert the returned
    // validated structure to use absolute addressing instead of relative addressing, since
    // the relative offset was calculated from the original (untrusted) struct
    // and will be meaningless in a copy that lies elsewhere in memory.
    //void *real_start = (rb->flags & RINGBUF_FLAG_RELATIVE) ? ((uint8_t *)rb + rb->offset) : rb->start;
    if (reference->flags & RINGBUF_FLAG_RELATIVE) {
        validated_out->start = (uint8_t *)sec->untrusted + reference->offset;
        validated_out->flags &= ~RINGBUF_FLAG_RELATIVE;
    }

    // Set the SEC_COPY flag on the output copy
    validated_out->flags |= RINGBUF_FLAG_SEC_COPY;

    return RB_SUCCESS;
}

ringbuf_ret_t ringbuf_sec_validate_untrusted_writer(ringbuf_sec_context_t *sec,
                                                    ringbuf_t *validated_out) {
    // Validate all security-critical values in a ringbuf that
    // is meant to be written to by an untrusted client.

    // First, make a copy of the untrusted struct so that it can't be
    // modified by an attacker during validation.
    ringbuf_t untrusted_copy;
    memcpy(&untrusted_copy, sec->untrusted, sizeof(ringbuf_t));

    ringbuf_t *reference = sec->reference;
    // Validate against reference
    if (untrusted_copy.flags != reference->flags)
        return RB_SEC_FAIL;
    if (untrusted_copy.size != reference->size)
        return RB_SEC_FAIL;
    if (untrusted_copy.start != reference->start)
        return RB_SEC_FAIL;
    if (untrusted_copy.offset != reference->offset)
        return RB_SEC_FAIL;
    if (untrusted_copy.pos_start != reference->pos_start)
        return RB_SEC_FAIL;

    // Ensure that pos_end is within bounds
    if (untrusted_copy.pos_end >= reference->size) {
        return RB_SEC_FAIL;
    }

    // Successfully validated, write validated structure.
    memcpy(validated_out, &untrusted_copy, sizeof(ringbuf_t));

    // In the case of RINGBUF_FLAG_RELATIVE, we must convert the returned
    // validated structure to use absolute addressing instead of relative addressing, since
    // the relative offset was calculated from the original (untrusted) struct
    // and will be meaningless in a copy that lies elsewhere in memory.
    //void *real_start = (rb->flags & RINGBUF_FLAG_RELATIVE) ? ((uint8_t *)rb + rb->offset) : rb->start;
    if (reference->flags & RINGBUF_FLAG_RELATIVE) {
        validated_out->start = (uint8_t *)sec->untrusted + reference->offset;
        validated_out->flags &= ~RINGBUF_FLAG_RELATIVE;
    }

    // Set the SEC_COPY flag on the output copy
    validated_out->flags |= RINGBUF_FLAG_SEC_COPY;

    return RB_SUCCESS;
}

void ringbuf_sec_flush_write(ringbuf_sec_context_t *sec, ringbuf_t *validated) {
    // pos_end must be updated in the untrusted and reference structs
    sec->reference->pos_end = validated->pos_end;
    sec->untrusted->pos_end = validated->pos_end;

    // Full must be flushed to the untrusted struct
    sec->untrusted->full = validated->full;
}

void ringbuf_sec_flush_read(ringbuf_sec_context_t *sec, ringbuf_t *validated) {
    // pos_start must be updated in the untrusted and reference structs
    sec->reference->pos_start = validated->pos_start;
    sec->untrusted->pos_start = validated->pos_start;

    // Full must be flushed to the untrusted struct
    sec->untrusted->full = validated->full;
}

// Wrapper for ringbuf_write that performs security validation
ringbuf_ret_t ringbuf_write_sec(ringbuf_sec_context_t *sec, const void *data, size_t size) {
    // If the reference is marked as blocking, busywait until the untrusted struct
    // has enough free space. This is safe since the data will be validated before writing.
    if (sec->reference->flags & RINGBUF_FLAG_BLOCKING) {
        while (ringbuf_free_space(sec->untrusted) < size) {
            BUSYWAIT_YIELD_TO_OS();
        }
    }


    // Before writing, validate that the other party (the reader) hasn't
    // tampered with the ring buffer
    ringbuf_t validated;
    ringbuf_ret_t ret = ringbuf_sec_validate_untrusted_reader(sec, &validated);
    if (ret != RB_SUCCESS)
        return ret;

    // Perform the write operation on the validated ringbuffer
    ret = ringbuf_write(&validated, data, size);
    if (ret != RB_SUCCESS)
        return ret;

    // Flush the changes we made to our validated struct
    ringbuf_sec_flush_write(sec, &validated);
    return RB_SUCCESS;
}

// Wrapper for ringbuf_read that performs security validation
ringbuf_ret_t ringbuf_read_sec(ringbuf_sec_context_t *sec, void *out, size_t size) {
    // If the reference is marked as blocking, busywait until the untrusted struct
    // has enough data in it.
    if (sec->reference->flags & RINGBUF_FLAG_BLOCKING) {
        while (ringbuf_available(sec->untrusted) < size) {
            BUSYWAIT_YIELD_TO_OS();
        }
    }

    // Before reading, validate that the other party (the writer) hasn't
    // tampered with the ring buffer
    ringbuf_t validated;
    ringbuf_ret_t ret = ringbuf_sec_validate_untrusted_writer(sec, &validated);
    if (ret != RB_SUCCESS)
        return ret;

    // Perform the read operation on the validated ringbuffer
    ret = ringbuf_read(&validated, out, size);
    if (ret != RB_SUCCESS)
        return ret;

    // Flush the changes
    ringbuf_sec_flush_read(sec, &validated);
    return RB_SUCCESS;
}

/**
 * Create a security context from the given ring buffer if the fields
 * match the values provided.
 *
 * If the untrusted struct fails validation against the provided fields,
 * no security context is created.
 *
 * @param untrusted already-initialized ring buffer to create security context from
 * @param flags_mask mask of all flags the ring buffer is allowed to have
 * @param size       size of the ring buffer's data region
 * @param offset     offset from the untrusted struct that the buffer exists at
 * @param sec_out    on success, a pointer to the created security context is written
 * @return           ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_infer_context(ringbuf_t *untrusted, uint8_t flags_mask, size_t size,
                                         intptr_t offset, ringbuf_sec_context_t **sec_out) {
    // Make a copy of the untrusted struct to prevent an attacker
    // from modifying it during verification
    ringbuf_t untrusted_copy;
    memcpy(&untrusted_copy, untrusted, sizeof(ringbuf_t));

    // For now, only validate relative ringbufs
    if (!(flags_mask & RINGBUF_FLAG_RELATIVE) || !(untrusted_copy.flags & RINGBUF_FLAG_RELATIVE))
        return RB_SEC_FAIL;

    if (untrusted_copy.flags & ~flags_mask)
        return RB_SEC_FAIL;
    if (untrusted_copy.size != size)
        return RB_SEC_FAIL;
    if (untrusted_copy.offset != offset)
        return RB_SEC_FAIL;

    // Validate pointers
    if (untrusted_copy.pos_start >= size)
        return RB_SEC_FAIL;
    if (untrusted_copy.pos_end >= size)
        return RB_SEC_FAIL;

    // Create a security context and return success
    ringbuf_sec_context_t *sec = malloc(sizeof(ringbuf_sec_context_t));
    if (!sec)
        return RB_OOM;

    sec->untrusted = untrusted;

    sec->reference = malloc(sizeof(ringbuf_t));
    if (!sec->reference) {
        free(sec);
        return RB_OOM;
    }

    // Copy the now validated untrusted_copy to the reference
    memcpy(sec->reference, &untrusted_copy, sizeof(ringbuf_t));

    *sec_out = sec;

    return RB_SUCCESS;
}

/// Ring buffer implementation

static inline size_t ringbuf_free_space(ringbuf_t *rb) {
    if (rb->pos_start == rb->pos_end)
        return rb->full ? 0 : rb->size;
    else if (rb->pos_start < rb->pos_end)
        return rb->size - (rb->pos_end - rb->pos_start);
    else // rb->pos_start > rb->pos_end
        return rb->pos_start - rb->pos_end;
}

static inline size_t ringbuf_available(ringbuf_t *rb) {
    return rb->size - ringbuf_free_space(rb);
}

/**
 * Initialize a new ringbuf.
 * @param rb ringbuffer structure to initialize
 * @param start start address of the data region to use
 * @param size  size of the data region to use
 * @param flags flags. See RINGBUF_FLAG_BLOCKING
 * @param sec_reference if not NULL, a pointer to copy of the initialized rb struct will be written here.
 *                      See ringbuf.h for more information.
 *
 * @return success?
 */
ringbuf_ret_t ringbuf_init(ringbuf_t *rb, void *start, size_t size, uint8_t flags, ringbuf_sec_context_t **sec_out) {
    ringbuf_t *new_rb = rb;
    if (sec_out) {
        // Initialize the reference struct first to prevent
        // a malicious client from writing to the potentially shared `rb` struct
        // as we initialize it
        new_rb = malloc(sizeof(ringbuf_t));
        if (!new_rb)
            return RB_OOM;
    }


    new_rb->flags = flags;
    new_rb->offset = (flags & RINGBUF_FLAG_RELATIVE) ? (uint8_t *)start - (uint8_t *)rb : 0;
    new_rb->size = size;
    new_rb->start = start;
    new_rb->full = false;

    new_rb->pos_start = 0;
    new_rb->pos_end = 0;
    new_rb->eventfd = -1;

    if (sec_out) {
        // Copy reference to rb and create a new sec_context
        memcpy(rb, new_rb, sizeof(ringbuf_t));

        ringbuf_sec_context_t *sec = malloc(sizeof(ringbuf_sec_context_t));
        if (!sec) {
            free(new_rb);
            return RB_OOM;
        }
        sec->reference = new_rb;
        sec->untrusted = rb;
        *sec_out = sec;
    }

    return RB_SUCCESS;
}

ringbuf_ret_t ringbuf_write(ringbuf_t *rb, const void *data, size_t size) {
    // If this rb is blocking (and isn't a sec copy), wait for space to become available.
    // Sec copies handle blocking in their respective wrapper functions.
    if (!(rb->flags & RINGBUF_FLAG_SEC_COPY) && rb->flags & RINGBUF_FLAG_BLOCKING) {
        while (ringbuf_free_space(rb) < size)
            BUSYWAIT_YIELD_TO_OS();
    } else if (ringbuf_free_space(rb) < size) {
        return RB_NOSPACE;
    }

    void *real_start = (rb->flags & RINGBUF_FLAG_RELATIVE) ? ((uint8_t *)rb + rb->offset) : rb->start;
    if (size == ringbuf_free_space(rb)) {
        rb->full = true;
    }

    if (rb->pos_start <= rb->pos_end) {
        // Write from [pos_end,end) and if required,
        // write the rest from [start, pos_start).
        size_t first_left = rb->size - rb->pos_end;
        size_t first = MIN(first_left, size);
        memcpy(real_start + rb->pos_end, data, first);
        rb->pos_end += first;

        if (first_left >= size) {
            return RB_SUCCESS;
        }

        size_t second = size - first_left;
        memcpy(real_start, (uint8_t *)data + first, second);
        rb->pos_end = second;
        return RB_SUCCESS;
    } else {
        // Write from [pos_end, pos_start)
        size_t first_left = rb->pos_start - rb->pos_end;
        assert(size <= first_left);
        memcpy(real_start + rb->pos_end, data, size);
        rb->pos_end += size;
        return RB_SUCCESS;
    }
}

ringbuf_ret_t ringbuf_read(ringbuf_t *rb, void *out, size_t size) {
    // If this rb is blocking (and isn't a sec copy), wait for data.
    // Sec copies handle blocking in their respective wrapper functions.
    if (!(rb->flags & RINGBUF_FLAG_SEC_COPY) && rb->flags & RINGBUF_FLAG_BLOCKING) {
        while (ringbuf_available(rb) < size)
            BUSYWAIT_YIELD_TO_OS();
    } else if (rb->size - ringbuf_free_space(rb) < size) {
        return RB_NODATA;
    }

    void *real_start = (rb->flags & RINGBUF_FLAG_RELATIVE) ? ((uint8_t *)rb + rb->offset) : rb->start;
    rb->full = false;

    if (rb->pos_start < rb->pos_end) {
        // Read from [pos_start, pos_end)
        size_t avail = rb->pos_end - rb->pos_start;
        assert(avail >= size);
        memcpy(out, real_start + rb->pos_start, size);
        rb->pos_start += size;
        return RB_SUCCESS;
    } else {
        // Read from [pos_start, end) and if required,
        // read the rest from [start, pos_end)
        size_t first_avail = rb->size - rb->pos_start;
        size_t first = MIN(first_avail, size);
        memcpy(out, real_start + rb->pos_start, first);
        rb->pos_start += size;

        if (first_avail >= size)
            return RB_SUCCESS;

        size_t second = size - first_avail;
        memcpy((uint8_t *)out + first, real_start, second);
        rb->pos_start = second;
        return RB_SUCCESS;
    }
}

static void *_eventfd_thread_handler(void *_rb) {
    ringbuf_t *rb = _rb;

    // Busywait for bytes and notify eventfd
    while (!rb->kill_thread && !ringbuf_available(rb))
        BUSYWAIT_YIELD_TO_OS();

    if (rb->kill_thread)
        return NULL;

    // Set the eventfd
    uint64_t buf = 1;
    ignore_value(write(rb->eventfd, &buf, sizeof(uint64_t)));

    return NULL;
}

int ringbuf_get_eventfd(ringbuf_t *rb) {
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
        ignore_value(write(rb->eventfd, &buf, sizeof(buf)));
        return rb->eventfd;
    }

    rb->kill_thread = false;
    int ret = pthread_create(&rb->eventfd_thread, NULL, _eventfd_thread_handler, rb);
    if (ret)
        return -1;

    return rb->eventfd;
}

void ringbuf_clear_eventfd(ringbuf_t *rb) {
    // Kill thread if it's still running
    rb->kill_thread = true;
    pthread_join(rb->eventfd_thread, NULL);

    // Temporarily disable blocking and reset the eventfd's counter
    uint64_t buf;
    int fd_flags = fcntl(rb->eventfd, F_GETFL, 0);
    fcntl(rb->eventfd, F_SETFL, fd_flags | O_NONBLOCK);
    ignore_value(read(rb->eventfd, &buf, sizeof(uint64_t)));
    fcntl(rb->eventfd, F_SETFL, fd_flags);
}

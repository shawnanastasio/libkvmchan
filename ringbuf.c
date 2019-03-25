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

// The usable space (size of ringbuf - 1)
#define USABLE(rb) ((rb)->size - 1)

const char *ringbuf_ret_names[] = {
    "RB_SUCCESS",
    "RB_NOSPACE",
    "RB_NODATA",
    "RB_OOM",
    "RB_SEC_FAIL",
};

static inline size_t ringbuf_available(ringbuf_t *rb);
static inline size_t ringbuf_free_space(ringbuf_t *rb);

/// Security-related operations

/**
 * Initialize a new sec ring buffer.
 * Used in situations where the ring buffer is to be accessed by multiple processes,
 * as is the primary use case for libkvmchan. The ring buffer metadata is split into two
 * structures, ringbuf_t and ringbuf_pub_t. The latter contains data that may be placed
 * in a shared memory region for sharing with the other process.
 *
 * Future operations on a sec ring buffer /MUST/ be done with the relevant
 * ringbuf_sec_* function, rather than the regular ringbuf_ functions.
 * Failure to do so will leave the buffer in an undefined state and compromise
 * all security guarantees.
 *
 * @param[out] priv  private structure to initialize
 * @param[out] pub   public (shared) structure to initialize
 * @param      start start address of ring buffer data region
 * @param      size  size of ring buffer data region
 * @param      flags ring buffer flags
 * @return     ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_init(ringbuf_t *priv, ringbuf_pub_t *pub, void *start, size_t size,
                 uint8_t flags) {
    // Initialize priv
    flags |= RINGBUF_FLAG_SEC_COPY;
    priv->flags = flags;
    priv->size = size;
    priv->offset = (flags & RINGBUF_FLAG_RELATIVE) ? (uint8_t *)start - (uint8_t *)priv : 0;
    priv->start = start;
    priv->pos_start = 0;
    priv->pos_end = 0;
    priv->eventfd = -1;

    // Initialize pub
    pub->pos_start_untrusted = 0;
    pub->pos_end_untrusted = 0;
    pub->flags_untrusted = flags;

    return RB_SUCCESS;
}

/**
 * Infer a ringbuf_priv_t from an already initialized ringbuf_pub_t.
 *
 * Used by clients to establish a handle to an existing ring buffer.
 * Requires the caller to know some key information about the ring buffer
 * which must have been obtained from a trusted source.
 *
 * @param[out] priv       ringbuf_t to initialize
 * @param      pub        public structure to infer from
 * @param      start      start address of the ringbuffer's data
 * @param      size       size of the ringbuffer
 * @param      flags_mask bitmask of allowed flags
 * @return     ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_infer_priv(ringbuf_t *priv, ringbuf_pub_t *pub, void *start,
                                     size_t size, uint8_t flags_mask) {
    // Validate the data in pub
    // Create a copy so an attacker can't modify it mid-validation
    ringbuf_pub_t pub_copy;
    memcpy(&pub_copy, pub, sizeof(ringbuf_pub_t));

    // Add FLAG_SEC_COPY to the allowed flags mask
    flags_mask |= RINGBUF_FLAG_SEC_COPY;

    // Only support absolute addressing
    if (flags_mask & RINGBUF_FLAG_RELATIVE)
        return RB_SEC_FAIL;

    if (pub_copy.pos_start_untrusted > size)
        return RB_SEC_FAIL;
    if (pub_copy.pos_end_untrusted > size)
        return RB_SEC_FAIL;
    if (pub_copy.flags_untrusted & ~flags_mask)
        return RB_SEC_FAIL;

    // Initialize the priv struct
    priv->flags = pub_copy.flags_untrusted;
    priv->size = size;
    priv->start = start;
    priv->pos_start = pub_copy.pos_start_untrusted;
    priv->pos_end = pub_copy.pos_end_untrusted;
    priv->eventfd = -1;

    return RB_SUCCESS;
}

/**
 * Write to a sec ringbuffer.
 *
 * @param priv  private ring buffer data to act on
 * @param pub   public ring buffer data to act on
 * @param data  buffer of data to write to ring buffer
 * @param size  amount of data to write
 * @return      ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_write(ringbuf_t *priv, ringbuf_pub_t *pub, const void *data,
                                size_t size) {
    // Flush pos_start from public struct
    priv->pos_start = pub->pos_start_untrusted;
    if (priv->pos_start > priv->size) {
        return RB_SEC_FAIL;
    }

    size_t free_space = ringbuf_free_space(priv);

    // If blocking is enabled, busy wait for space
    if (priv->flags & RINGBUF_FLAG_BLOCKING) {
        while (free_space < size) {
            // Flush pos_start and check free space
            priv->pos_start = pub->pos_start_untrusted;
            if (priv->pos_start > priv->size)
                return RB_SEC_FAIL;

            free_space = ringbuf_free_space(priv);

            BUSYWAIT_YIELD_TO_OS();
        }
    }

    // Perform the write
    ringbuf_ret_t ret = ringbuf_write(priv, data, size);
    if (ret != RB_SUCCESS)
        return ret;

    // Flush pos_end to the public struct
    pub->pos_end_untrusted = priv->pos_end;

    return RB_SUCCESS;
}

/**
 * Read from a sec ringbuffer.
 *
 * @param priv  private ring buffer data to act on
 * @param pub   public ring buffer data to act on
 * @param buf   buffer to read data into
 * @param size  amount of data to read
 * @return      ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_read(ringbuf_t *priv, ringbuf_pub_t *pub, void *buf, size_t size) {
    // Flush pos_end from public struct
    priv->pos_end = pub->pos_end_untrusted;
    if (priv->pos_end > priv->size) {
        return RB_SEC_FAIL;
    }

    size_t available = ringbuf_available(priv);

    // If blocking is enabled, busy wait for data
    if (priv->flags & RINGBUF_FLAG_BLOCKING) {
        while(available < size) {
            // Flush pos_end and check available
            priv->pos_end = pub->pos_end_untrusted;
            if (priv->pos_end > priv->size)
                return RB_SEC_FAIL;

            available = ringbuf_available(priv);

            BUSYWAIT_YIELD_TO_OS();
        }
    }

    // Perform the read
    ringbuf_ret_t ret = ringbuf_read(priv, buf, size);
    if (ret != RB_SUCCESS)
        return ret;

    pub->pos_start_untrusted = priv->pos_start;

    return RB_SUCCESS;
}

/// Ring buffer implementation

static inline size_t ringbuf_free_space(ringbuf_t *rb) {
    if (rb->pos_start == rb->pos_end)
        return USABLE(rb);
    else if (rb->pos_end == rb->pos_start - 1)
        return 0;
    else if (rb->pos_start < rb->pos_end)
        return USABLE(rb) - (rb->pos_end - rb->pos_start);
    else // rb->pos_start > rb->pos_end
        return rb->pos_start - rb->pos_end;
}

static inline size_t ringbuf_available(ringbuf_t *rb) {
    return USABLE(rb) - ringbuf_free_space(rb);
}

/**
 * Initialize a new ringbuf.
 * @param rb ringbuffer structure to initialize
 * @param start start address of the data region to use
 * @param size  size of the data region to use
 * @param flags flags. See RINGBUF_FLAG_BLOCKING
 *
 * @return success?
 */
ringbuf_ret_t ringbuf_init(ringbuf_t *rb, void *start, size_t size, uint8_t flags) {
    rb->flags = flags;
    rb->offset = (flags & RINGBUF_FLAG_RELATIVE) ? (uint8_t *)start - (uint8_t *)rb : 0;
    rb->size = size;
    rb->start = start;

    rb->pos_start = 0;
    rb->pos_end = 0;
    rb->eventfd = -1;

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

    // If local eventfd is enabled, notify it
    if ((rb->flags & RINGBUF_FLAG_LOCAL_EVENTFD) && rb->eventfd > 0) {
        uint64_t buf = 1;
        ignore_value(write(rb->eventfd, &buf, 8));
    }

    void *real_start = (rb->flags & RINGBUF_FLAG_RELATIVE) ? ((uint8_t *)rb + rb->offset) : rb->start;

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
    } else if (ringbuf_available(rb) - ringbuf_free_space(rb) < size) {
        return RB_NODATA;
    }

    void *real_start = (rb->flags & RINGBUF_FLAG_RELATIVE) ? ((uint8_t *)rb + rb->offset) : rb->start;

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

struct eventfd_thread_data {
    ringbuf_t *rb;
    ringbuf_pub_t *pub;
};

static void *_eventfd_thread_handler(void *_data) {
    struct eventfd_thread_data *data = _data;

    // Busywait for bytes and notify eventfd
    if (!data->pub) {
        // No pub, just poll on the rb
        while (!data->rb->kill_thread && !ringbuf_available(data->rb))
            BUSYWAIT_YIELD_TO_OS();
    } else {
        // pub available, flush pos_end on each loop (and bounds check it)
        size_t available;
        do {
            data->rb->pos_end = data->pub->pos_end_untrusted;
            if (data->rb->pos_end > data->rb->size)
                goto out;

            available = ringbuf_available(data->rb);

            BUSYWAIT_YIELD_TO_OS();
        } while (!data->rb->kill_thread && !available);
    }

    if (data->rb->kill_thread)
        goto out;

    // Set the eventfd
    uint64_t buf = 1;
    ignore_value(write(data->rb->eventfd, &buf, sizeof(uint64_t)));

out:
    free(data);
    return NULL;
}

/**
 * Return an eventfd that will notify when data is available to read
 * from the given ringbuffer. If provided, data from the ringbuf_pub_t
 * structure will be used to determine available space.
 *
 * @param rb ringbuf_t structure to notify on
 * @param pub ringbuf_pub_t to fetch pos_end from, or NULL to use `rb`
 * @return file descriptor for eventfd, or -1 on failure
 */
int ringbuf_get_eventfd(ringbuf_t *rb, ringbuf_pub_t *pub) {
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

    // If we're using a local eventfd, just return it
    if (rb->flags & RINGBUF_FLAG_LOCAL_EVENTFD)
        return rb->eventfd;

    // Allocate data to pass to thread
    struct eventfd_thread_data *data = malloc(sizeof(struct eventfd_thread_data));
    if (!data)
        return -1;
    data->rb = rb;
    data->pub = pub;

    rb->kill_thread = false;
    int ret = pthread_create(&rb->eventfd_thread, NULL, _eventfd_thread_handler, data);
    if (ret) {
        free(data);
        return -1;
    }

    return rb->eventfd;
}

void ringbuf_clear_eventfd(ringbuf_t *rb) {
    if (!(rb->flags & RINGBUF_FLAG_LOCAL_EVENTFD)) {
        // Kill thread if it's still running
        rb->kill_thread = true;
        pthread_join(rb->eventfd_thread, NULL);
    }

    // Temporarily disable blocking and reset the eventfd's counter
    uint64_t buf;
    int fd_flags = fcntl(rb->eventfd, F_GETFL, 0);
    fcntl(rb->eventfd, F_SETFL, fd_flags | O_NONBLOCK);
    ignore_value(read(rb->eventfd, &buf, sizeof(uint64_t)));
    fcntl(rb->eventfd, F_SETFL, fd_flags);
}

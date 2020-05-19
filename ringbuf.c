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

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <sys/eventfd.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

#include "ringbuf.h"
#include "libkvmchan-priv.h"
#define MAX(x, y) ((x > y) ? (x) : (y))
#define MIN(x, y) ((x > y) ? (y) : (x))

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

/// Notification helpers

static void block_on_eventfd(int eventfd) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(eventfd, &rfds);
    ignore_value(select(eventfd + 1, &rfds, NULL, NULL, NULL));
}

static void clear_eventfd(int fd) {
    // Temporarily disable blocking and reset the eventfd's counter
    uint64_t buf;
    int fd_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fd_flags | O_NONBLOCK);
    ignore_value(read(fd, &buf, sizeof(uint64_t)));
    if (!(fd_flags & O_NONBLOCK))
        fcntl(fd, F_SETFL, fd_flags);
}

static ringbuf_ret_t block_read(ringbuf_t *priv, ringbuf_pub_t *pub, size_t size,
                                bool stream_mode, size_t *size_out) {
    int eventfd = priv->incoming_eventfd;

    assert(eventfd > 0);
    assert(priv->direction != RINGBUF_DIRECTION_WRITE);

    size_t avail = 0;
    for(;;) {
        // If pub was provided, validate and flush data
        if (pub) {
            priv->pos_end = pub->pos_end_untrusted;
            if (priv->pos_end > priv->size)
                return RB_SEC_FAIL;
        }

        avail = ringbuf_available(priv);
        if (stream_mode && (avail >= 1)) {
            // Stream mode, wait for >=1 bytes
            if (avail < size)
                size = avail;
            goto success;
        } else if (!stream_mode && (avail >= size)) {
            // Packet mode, we need to wait for at least `size` bytes
            goto success;
        }

        uint64_t buf;
        block_on_eventfd(eventfd);
        ignore_value(read(eventfd, &buf, 8));
    }

success:
    if (size_out)
        *size_out = size;
    clear_eventfd(eventfd);
    return RB_SUCCESS;
}

static void notify_read(ringbuf_t *priv) {
    int eventfd = (priv->direction == RINGBUF_DIRECTION_LOCAL) ?
                    priv->incoming_eventfd : priv->outgoing_eventfd;

    assert(eventfd > 0);
    assert(priv->direction != RINGBUF_DIRECTION_WRITE);

    uint64_t buf = 1;
    ignore_value(write(eventfd, &buf, 8));
}

static ringbuf_ret_t block_write(ringbuf_t *priv, ringbuf_pub_t *pub, size_t size,
                                 bool stream_mode, size_t *size_out) {
    int eventfd = priv->incoming_eventfd;

    assert(eventfd > 0);
    assert(priv->direction != RINGBUF_DIRECTION_READ);

    size_t free_space = 0;
    for(;;) {
        // If pub was provided, validate and flush data
        if (pub) {
            priv->pos_start = pub->pos_start_untrusted;
            if (priv->pos_start > priv->size) {
                return RB_SEC_FAIL;
            }
        }

        free_space = ringbuf_free_space(priv);
        if (stream_mode && (free_space >= 1)) {
            // Stream mode, wait for >= 1 bytes of free space
            if (free_space < size)
                size = free_space;
            goto success;
        } else if (!stream_mode && (free_space >= size)) {
            // Stream mode, wait for >= `size` bytes of free space
            goto success;
        }

        uint64_t buf;
        block_on_eventfd(eventfd);
        ignore_value(read(eventfd, &buf, 8));
    }

success:
    if (size_out)
        *size_out = size;
    clear_eventfd(eventfd);
    return RB_SUCCESS;
}

static void notify_write(ringbuf_t *priv) {
    int eventfd = (priv->direction == RINGBUF_DIRECTION_LOCAL) ?
                    priv->incoming_eventfd : priv->outgoing_eventfd;

    assert(eventfd > 0);
    assert(priv->direction != RINGBUF_DIRECTION_READ);

    uint64_t buf = 1;
    ignore_value(write(eventfd, &buf, 8));
}

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
 * @param[out] priv      private structure to initialize
 * @param[out] pub       public (shared) structure to initialize
 * @param      start     start address of ring buffer data region
 * @param      size      size of ring buffer data region
 * @param      flags     ring buffer flags
 * @param      direction direction of ring buffer (read or write)
 * @param      in_efd    incoming eventfd
 * @param      out_efd   outgoing eventfd
 * @return     ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_init(ringbuf_t *priv, ringbuf_pub_t *pub, void *start, size_t size,
                               uint8_t flags, uint8_t direction, int in_efd, int out_efd) {
    // Validate flags
    if ((flags & RINGBUF_FLAG_BLOCKING) && ((in_efd < 0) ||
                                            (out_efd < 0)))
        return RB_INVALID;

    // Initialize priv
    flags |= RINGBUF_FLAG_SEC_COPY;
    priv->flags = flags;
    priv->size = size;
    priv->offset = (flags & RINGBUF_FLAG_RELATIVE) ? (uint8_t *)start - (uint8_t *)priv : 0;
    priv->start = start;
    priv->pos_start = 0;
    priv->pos_end = 0;
    priv->direction = direction;
    priv->incoming_eventfd = in_efd;
    priv->outgoing_eventfd = out_efd;

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
 * @param      direction  direction of ring buffer (read or write)
 * @param      in_efd     incoming eventfd
 * @param      out_efd    outgoing eventfd
 * @return     ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_infer_priv(ringbuf_t *priv, ringbuf_pub_t *pub, void *start,
                                     size_t size, uint8_t flags_mask, uint8_t direction,
                                     int in_efd, int out_efd) {
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

    // Validate flags
    if ((pub_copy.flags_untrusted & RINGBUF_FLAG_BLOCKING) && ((in_efd < 0) ||
                                                               (out_efd < 0)))
        return RB_INVALID;

    // Initialize the priv struct
    priv->flags = pub_copy.flags_untrusted;
    priv->size = size;
    priv->start = start;
    priv->pos_start = pub_copy.pos_start_untrusted;
    priv->pos_end = pub_copy.pos_end_untrusted;
    priv->direction = direction;
    priv->incoming_eventfd = in_efd;
    priv->outgoing_eventfd = out_efd;

    return RB_SUCCESS;
}
/**
 * Write to a sec ringbuffer.
 * Private implementation of sec_write and sec_send
 *
 * @param priv          private ring buffer data to act on
 * @param pub           public ring buffer data to act on
 * @param data          buffer of data to write to ring buffer
 * @param size          amount of data to write
 * @param stream_mode   whether or not to use stream semantics
 * @param[out] size_out amount of data written (stream only)
 * @return              ring buffer return code
 */
static ringbuf_ret_t ringbuf_sec_write_impl(ringbuf_t *priv, ringbuf_pub_t *pub, const void *data, size_t size,
                                     bool stream_mode, size_t *size_out) {
    if (!(priv->flags & RINGBUF_FLAG_BLOCKING)) {
        // Flush pos_start from public struct
        priv->pos_start = pub->pos_start_untrusted;
        if (priv->pos_start > priv->size) {
            return RB_SEC_FAIL;
        }

        size_t free_space = ringbuf_free_space(priv);
        if (stream_mode) {
            // Stream mode, write as long as 1 byte is free
            if (free_space == 0)
                return RB_NOSPACE;

            if (free_space < size)
                size = free_space;
        } else {
            // Packet mode, write only if `size` bytes are free
            if (free_space < size)
                return RB_NOSPACE;
        }
    } else {
        ringbuf_ret_t rret;
        if ((rret = block_write(priv, pub, size, stream_mode, &size)) != RB_SUCCESS)
            return rret;
    }

    // Perform the write
    ringbuf_ret_t ret = ringbuf_write(priv, data, size);
    if (ret != RB_SUCCESS)
        return ret;

    // Flush pos_end to the public struct
    pub->pos_end_untrusted = priv->pos_end;

    // Notify
    if (priv->flags & RINGBUF_FLAG_BLOCKING)
        notify_write(priv);

    if (size_out)
        *size_out = size;

    return RB_SUCCESS;
}

/**
 * Write to a sec ringbuffer. (Packet mode)
 *
 * @param priv  private ring buffer data to act on
 * @param pub   public ring buffer data to act on
 * @param data  buffer of data to write to ring buffer
 * @param size  amount of data to write
 * @return      ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_write(ringbuf_t *priv, ringbuf_pub_t *pub, const void *data, size_t size) {
    return ringbuf_sec_write_impl(priv, pub, data, size, false, NULL);
}

/**
 * Write to a sec ringbuffer. (Stream mode)
 *
 * @param priv          private ring buffer data to act on
 * @param pub           public ring buffer data to act on
 * @param data          buffer of data to write to ring buffer
 * @param size          maximum amount of data to write
 * @param[out] size_out amount of data actually written
 * @return              ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_write_stream(ringbuf_t *priv, ringbuf_pub_t *pub, const void *data, size_t size,
                                       size_t *size_out) {
    return ringbuf_sec_write_impl(priv, pub, data, size, true, size_out);
}

/**
 * Private implementation of sec_read and sec_recv.
 *
 * @param priv          private ring buffer data to act on
 * @param pub           public ring buffer data to act on
 * @param buf           buffer to read data into
 * @param size          amount of data to read
 * @param stream_mode   whether or not to use stream semantics
 * @param[out] size_out amount of data read (stream only)
 * @return              ring buffer return code
 */
static ringbuf_ret_t ringbuf_sec_read_impl(ringbuf_t *priv, ringbuf_pub_t *pub, void *buf, size_t size,
                                           bool stream_mode, size_t *size_out) {
    if (!(priv->flags & RINGBUF_FLAG_BLOCKING)) {
        // Flush pos_end from public struct
        priv->pos_end = pub->pos_end_untrusted;
        if (priv->pos_end > priv->size) {
            return RB_SEC_FAIL;
        }

        size_t available = ringbuf_available(priv);
        if (stream_mode) {
            // Stream mode, read as long as 1 byte is available
            if (available == 0)
                return RB_NOSPACE;

            if (available < size)
                size = available;
        } else {
            // Packet mode, read only if `size` bytes are available
            if (available < size)
                return RB_NOSPACE;
        }
    } else {
        ringbuf_ret_t rret;
        if ((rret = block_read(priv, pub, size, stream_mode, &size)) != RB_SUCCESS)
            return rret;
    }


    // Perform the read
    ringbuf_ret_t ret = ringbuf_read(priv, buf, size);
    if (ret != RB_SUCCESS)
        return ret;

    pub->pos_start_untrusted = priv->pos_start;

    // Notify
    if (priv->flags & RINGBUF_FLAG_BLOCKING)
        notify_read(priv);

    if (size_out)
        *size_out = size;

    return RB_SUCCESS;
}

/**
 * Read from a sec ringbuffer. (Packet mode)
 *
 * @param priv  private ring buffer data to act on
 * @param pub   public ring buffer data to act on
 * @param buf   buffer to read data into
 * @param size  amount of data to read
 * @return      ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_read(ringbuf_t *priv, ringbuf_pub_t *pub, void *buf, size_t size) {
    return ringbuf_sec_read_impl(priv, pub, buf, size, false, NULL);
}

/**
 * Read from a sec ringbuffer. (Stream mode)
 *
 * @param priv          private ring buffer data to act on
 * @param pub           public ring buffer data to act on
 * @param buf           buffer to read data into
 * @param size          maximum amount of data to read
 * @param[out] size_out the amount of data that was actually read
 * @return              ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_read_stream(ringbuf_t *priv, ringbuf_pub_t *pub, void *buf, size_t size,
                                      size_t *size_out) {
    return ringbuf_sec_read_impl(priv, pub, buf, size, true, size_out);
}

/**
 * Determine the amount of available bytes to read in a sec ringbuffer.
 *
 * @param priv               private ring buffer data to act on
 * @param pub                public ring buffer data to act on
 * @param[out] available_out number of available bytes will be written here on success
 * @return                   ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_available(ringbuf_t *priv, ringbuf_pub_t *pub, size_t *available_out) {
    // Flush pos_end from public struct
    priv->pos_end = pub->pos_end_untrusted;
    if (priv->pos_end > priv->size) {
        return RB_SEC_FAIL;
    }

    *available_out = ringbuf_available(priv);
    return RB_SUCCESS;
}

/**
 * Determine the amount of free bytes to write in a sec ringbuffer.
 *
 * @param priv          private ring buffer data to act on
 * @param pub           public ring buffer data to act on
 * @param[out] free_out number of free bytes will be written here on success
 * @return              ring buffer return code
 */
ringbuf_ret_t ringbuf_sec_free_space(ringbuf_t *priv, ringbuf_pub_t *pub, size_t *free_out) {
    // Flush pos_start from public struct
    priv->pos_start = pub->pos_start_untrusted;
    if (priv->pos_start > priv->size) {
        return RB_SEC_FAIL;
    }

    *free_out = ringbuf_free_space(priv);
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
 * @param rb        ringbuffer structure to initialize
 * @param start     start address of the data region to use
 * @param size      size of the data region to use
 * @param flags     flags. See RINGBUF_FLAG_BLOCKING
 * @param direction direction of ring buffer (read or write)
 * @param in_efd    incoming eventfd tied to another ringbuf's outgoing, or -1
 * @param out_efd   outgoing eventfd tied to another ringbuf's incoming, or -1
 *
 * @return success?
 */
ringbuf_ret_t ringbuf_init(ringbuf_t *rb, void *start, size_t size, uint8_t flags, uint8_t direction,
                           int in_efd, int out_efd) {
    // Validate flags
    if ((flags & RINGBUF_FLAG_BLOCKING) && ((in_efd < 0) ||
            (out_efd < 0 && direction != RINGBUF_DIRECTION_LOCAL)))
        return RB_INVALID;

    rb->flags = flags;
    rb->offset = (flags & RINGBUF_FLAG_RELATIVE) ? (uint8_t *)start - (uint8_t *)rb : 0;
    rb->size = size;
    rb->start = start;

    rb->pos_start = 0;
    rb->pos_end = 0;

    rb->direction = direction;
    rb->incoming_eventfd = in_efd;
    rb->outgoing_eventfd = out_efd;

    return RB_SUCCESS;
}

ringbuf_ret_t ringbuf_write(ringbuf_t *rb, const void *data, size_t size) {
    if (!size)
        return RB_SUCCESS;
    if (size > USABLE(rb))
        return RB_NOSPACE;

    // If this rb is blocking (and isn't a sec copy), wait for space to become available.
    // Sec copies handle blocking in their respective wrapper functions.
    if ((rb->flags & RINGBUF_FLAG_BLOCKING) && !(rb->flags & RINGBUF_FLAG_SEC_COPY)) {
        block_write(rb, NULL, size, false, NULL);
    } else if (ringbuf_free_space(rb) < size) {
        return RB_NOSPACE;
    }

    void *real_start = (rb->flags & RINGBUF_FLAG_RELATIVE) ? ((uint8_t *)rb + rb->offset) : rb->start;

    if (rb->pos_start <= rb->pos_end) {
        // Write from [pos_end,end) and if required,
        // write the rest from [start, pos_start).
        size_t first_left = rb->size - rb->pos_end;
        size_t first = MIN(first_left, size);
        memcpy(real_start + rb->pos_end, data, first);
        rb->pos_end += first;

        if (first_left >= size)
            goto out;

        size_t second = size - first_left;
        memcpy(real_start, (uint8_t *)data + first, second);
        rb->pos_end = second;

        goto out;
    } else {
        // Write from [pos_end, pos_start)
        size_t first_left = rb->pos_start - rb->pos_end;
        assert(size <= first_left);
        memcpy(real_start + rb->pos_end, data, size);
        rb->pos_end += size;

        goto out;
    }
out:
    if ((rb->flags & RINGBUF_FLAG_BLOCKING) && !(rb->flags & RINGBUF_FLAG_SEC_COPY))
        notify_write(rb);

    return RB_SUCCESS;
}

ringbuf_ret_t ringbuf_read(ringbuf_t *rb, void *out, size_t size) {
    if (!size)
        return RB_SUCCESS;
    if (size > USABLE(rb))
        return RB_NOSPACE;

    // If this rb is blocking (and isn't a sec copy), wait for data.
    // Sec copies handle blocking in their respective wrapper functions.
    if ((rb->flags & RINGBUF_FLAG_BLOCKING) && !(rb->flags & RINGBUF_FLAG_SEC_COPY)) {
        block_read(rb, NULL, size, false, NULL);
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
        goto out;
    } else {
        // Read from [pos_start, end) and if required,
        // read the rest from [start, pos_end)
        size_t first_avail = rb->size - rb->pos_start;
        size_t first = MIN(first_avail, size);
        memcpy(out, real_start + rb->pos_start, first);
        rb->pos_start += size;

        if (first_avail >= size)
            goto out;

        size_t second = size - first_avail;
        memcpy((uint8_t *)out + first, real_start, second);
        rb->pos_start = second;
        goto out;
    }
out:
    if ((rb->flags & RINGBUF_FLAG_BLOCKING) && !(rb->flags & RINGBUF_FLAG_SEC_COPY))
        notify_read(rb);

    return RB_SUCCESS;
}

/**
 * Return an eventfd that will notify when data is available to read
 * from the given ringbuffer.
 *
 * @param rb ringbuf_t structure to notify on
 * @return file descriptor for eventfd, or -1 on failure
 */
int ringbuf_get_eventfd(ringbuf_t *rb) {
    if (rb->incoming_eventfd > 0 && rb->direction == RINGBUF_DIRECTION_READ) {
        return rb->incoming_eventfd;
    }

    // Can't read from this rb
    return -1;
}

void ringbuf_clear_eventfd(ringbuf_t *rb) {
    int fd = ringbuf_get_eventfd(rb);
    if (fd >= 0)
        clear_eventfd(fd);
}

void ringbuf_close(ringbuf_t *rb) {
    close(rb->incoming_eventfd);
    if (!(rb->flags & RINGBUF_DIRECTION_LOCAL))
        close(rb->outgoing_eventfd);
}

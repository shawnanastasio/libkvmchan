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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "libkvmchan.h"
#include "ringbuf.h"

#define ARRAY_SIZE(x) (sizeof((x))/ sizeof(*(x)))

// A private data structure present at the beginning of all libkvmchan
// shared memory objects.
#define SHMEM_MAGIC 0xDEADBEEFCAFEBABA
typedef struct shmem_hdr {
    uint64_t magic;
    ringbuf_pub_t host_to_client_pub;
    ringbuf_pub_t client_to_host_pub;
} shmem_hdr_t;


// Main struct. Users only get opaque pointers.
typedef struct libkvmchan {
    // flags. See LIBKVM_FLAG_*
    uint32_t flags;

    // pointer to memory region that is shared between host/client
    void *shm;

    // size of shared memory region
    size_t shm_size;

    // Private ring buffer control structures
    ringbuf_t host_to_client_rb;
    ringbuf_t client_to_host_rb;
} libkvmchan_t;

/**
 * Get a handle to a POSIX shared memory region.
 *
 * Sets errno on failure.
 *
 * @param handle handle struct to populate on success
 * @param name POSIX shared memory object name, must begin with a /
 * @return success?
 */
bool libkvmchan_shm_open_posix(libkvmchan_shm_handle_t *handle, const char *name) {
    // Attempt to open the shm object whose name was passed to us
    int shm_fd = shm_open(name, O_RDWR, 0);
    if (shm_fd < 0)
        goto fail;

    // Determine the size and mmap it
    struct stat shm_stat;
    if (fstat(shm_fd, &shm_stat) < 0)
        goto fail_shm_open;
    void *mem = mmap(NULL, shm_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (mem == (void *)-1)
        goto fail_shm_open;

    // Populate handle
    handle->shm = mem;
    handle->size = shm_stat.st_size;
    return true;

fail_shm_open:
    close(shm_fd);
fail:
    return false;
}

/**
 * Get a handle to an ivshmem-uio shared memory region.
 * See: https://github.com/shawnanastasio/ivshmem-uio
 *
 * Sets errno on failure.
 *
 * @param handle  handle struct to populate on success
 * @param devname uio device name. Generally "uio0"
 * @return success?
 */
bool libkvmchan_shm_open_uio(libkvmchan_shm_handle_t *handle, const char *devname) {
    // The ivshmem uio driver places the shared memory region in map 1 of the uio device.
    // Attempt to read map1's size from the file at /sys/class/uio/<devname>/maps/map1/size
    if (strlen(devname) > 255) {
        errno = EINVAL;
        goto fail;
    }
    char path_buf[300];
    snprintf(path_buf, ARRAY_SIZE(path_buf), "/sys/class/uio/%s/maps/map1/size", devname);
    int size_fd = open(path_buf, O_RDONLY);
    if (size_fd < 0)
        goto fail;

    // Read in the size as a string as a 64bit hex value prefixed with 0x
    char size_buf[19]; // "0x", 16 hexadecimal digits, null terminator
    ssize_t n;
    if ((n = read(size_fd, size_buf, 18)) != 18) {
        // Unexpected number of bytes read! No choice but to bail out.
        errno = EINVAL;
        goto fail_open_size;
    }
    size_buf[n] = '\0';

    // Interpret the size as an integer
    char *endptr;
    long long size = strtoll(size_buf, &endptr, 16);
    if (*endptr != '\0') {
        // Strtoll failed to parse the integer!
        goto fail_open_size;
    }

    // Finally we have a size. Map region 1 of the uio device and return.
    // To map region N, an offset of N * getpagesize() must be passed as an mmap offset.
    // For more information, see the linux UIO documentation.
    snprintf(path_buf, ARRAY_SIZE(path_buf), "/dev/%s", devname);
    int uio_fd = open(path_buf, O_RDWR);
    if (uio_fd < 0)
        goto fail_open_size;
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, uio_fd, 1 * getpagesize());
    if (mem == (void *)-1)
        goto fail_open_uio;


    // Fill in the handle struct and return
    handle->shm = mem;
    handle->size = size;
    return true;

fail_open_uio:
    close(uio_fd);
fail_open_size:
    close(size_fd);
fail:
    return false;
}

/**
 * Establishes a libkvmchan shared memory host using the given
 * libkvmchan_shm_handle_t.
 *
 * Note that a host must be established before clients attempt to connect.
 *
 * Sets errno on failure.
 *
 * @param handle An initialized libkvmchan_shm_handle_t. See libkvmchan_shm_open_* functions.
 * @return A libkvmchan_t struct, or NULL on error
 */
libkvmchan_t *libkvmchan_host_open(libkvmchan_shm_handle_t *handle) {
    // Allocate a libkvmchan_t structure
    libkvmchan_t *chan = malloc(sizeof(libkvmchan_t));
    if (!chan)
        goto fail;

    // Init kvmchan struct and return
    chan->flags = LIBKVM_FLAG_HOST;
    chan->shm = handle->shm;
    chan->shm_size = handle->size;

    // Write a shmem header object
    shmem_hdr_t *hdr = chan->shm;
    hdr->magic = SHMEM_MAGIC;

    // Determine positions and sizes of ringbuffers.
    // Reserve first 0x1000 for header. The rest is split in half
    // for each ringbuffer. Assume 0x1000 per ringbuffer is needed.
    if (chan->shm_size < 0x1000 + (0x1000 * 2)) {
        errno = ENOMEM;
        goto fail_malloc;
    }
    void *data_base = (uint8_t *)chan->shm + 0x1000;
    size_t rb_size = (chan->shm_size - 0x1000) / 2;

    ringbuf_ret_t rret;
    rret = ringbuf_sec_init(&chan->host_to_client_rb, &hdr->host_to_client_pub, data_base,
                            rb_size, RINGBUF_FLAG_RELATIVE | RINGBUF_FLAG_BLOCKING);
    if (rret != RB_SUCCESS) {
        errno = ENOMEM;
        goto fail_malloc;
    }

    rret = ringbuf_sec_init(&chan->client_to_host_rb, &hdr->client_to_host_pub,
                            data_base + rb_size, rb_size,
                            RINGBUF_FLAG_RELATIVE | RINGBUF_FLAG_BLOCKING);
    if (rret != RB_SUCCESS) {
        errno = ENOMEM;
        goto fail_malloc;
    }

    return chan;

fail_malloc:
    free(chan);
fail:
    return NULL;
}


/**
 * Establishes a libkvmchan shared memory client using the given
 * libkvmchan_shm_handle_t.
 *
 * Note that a host must be established before clients attempt to connect.
 *
 * Sets errno on failure.
 *
 * @param handle An initialized libkvmchan_shm_handle_t. See libkvmchan_shm_open_* functions.
 * @return A libkvmchan_t struct, or NULL on error
 */
libkvmchan_t *libkvmchan_client_open(libkvmchan_shm_handle_t *handle) {
    ringbuf_ret_t rret;

    // Allocate libkvmchan_t struct
    libkvmchan_t *ret = malloc(sizeof(libkvmchan_t));
    if (!ret)
        return NULL;

    // Init libkvmchan_t and return
    ret->flags = 0;
    ret->shm = handle->shm;
    ret->shm_size = handle->size;

    shmem_hdr_t *hdr = ret->shm;

    // Create a reference struct for each ring buffer.
    // Since we know what parameters the ringbufs should have, we can validate the
    // fields.
    intptr_t data_base = (intptr_t)((uint8_t *)ret->shm + 0x1000);
    size_t rb_size = (ret->shm_size - 0x1000) / 2;

    // Initialize host_to_client ringbuf priv
    rret = ringbuf_sec_infer_priv(&ret->host_to_client_rb, &hdr->host_to_client_pub,
                                  (void *)data_base, rb_size,
                                  RINGBUF_FLAG_RELATIVE | RINGBUF_FLAG_BLOCKING);
    if (rret != RB_SUCCESS)
        goto fail;


    // Initialize client_to_host ringbuf priv
    rret = ringbuf_sec_infer_priv(&ret->client_to_host_rb, &hdr->client_to_host_pub,
                                  (void *)(data_base + rb_size), rb_size,
                                  RINGBUF_FLAG_RELATIVE | RINGBUF_FLAG_BLOCKING);
    if (rret != RB_SUCCESS)
        goto fail;

    return ret;
fail:
    if (rret == RB_OOM)
        errno = ENOMEM;
    else if (rret == RB_SEC_FAIL)
        errno = EPERM;
    else
        errno = EINVAL;

    return NULL;
}

/**
 * Write to the appropriate ring buffer.
 *
 * @param chan libkvmchan_t instance to act on
 * @param data buffer containing data to write
 * @param size number of bytes to write
 * @return success
 */
bool libkvmchan_write(libkvmchan_t *chan, const void *data, size_t size) {
    shmem_hdr_t *hdr = chan->shm;
    if (chan->flags & LIBKVM_FLAG_HOST) {
        // Use host_to_client ringbuffer
        return ringbuf_sec_write(&chan->host_to_client_rb, &hdr->host_to_client_pub,
                                 data, size) == RB_SUCCESS;
    } else {
        // Use client_to_host ringbuffer
        return ringbuf_sec_write(&chan->client_to_host_rb, &hdr->client_to_host_pub,
                                 data, size) == RB_SUCCESS;
    }
}

/**
 * Read data from the appropriate ring buffer.
 * If the requested amount of data isn't available, the operation will
 * block until the request can be fulfilled.
 *
 * @param chan libkvmchan_t instance to act on
 * @param out  output buffer to write data to
 * @param size number of bytes to read from the ring buffer
 * @return success
 */
bool libkvmchan_read(libkvmchan_t *chan, void *out, size_t size) {
    shmem_hdr_t *hdr = chan->shm;
    if (chan->flags & LIBKVM_FLAG_HOST) {
        return ringbuf_sec_read(&chan->client_to_host_rb, &hdr->client_to_host_pub,
                                out, size) == RB_SUCCESS;
    } else {
        return ringbuf_sec_read(&chan->host_to_client_rb, &hdr->host_to_client_pub,
                                out, size) == RB_SUCCESS;
    }
}

/**
 * Get a file descriptor that will unblock when data is available
 * to read from the appropriate ring buffer.
 *
 * This can be used with select() or poll().
 * libkvmchan_clear_eventfd MUST be used before requesting another eventfd!
 *
 * @param chan libkvmchan_t instance to act on
 * @return eventfd, or -1 on error
 */
int libkvmchan_get_eventfd(libkvmchan_t *chan) {
    shmem_hdr_t *shmem = chan->shm;
    if (chan->flags & LIBKVM_FLAG_HOST) {
        return ringbuf_get_eventfd(&chan->client_to_host_rb, &shmem->client_to_host_pub);
    } else {
        return ringbuf_get_eventfd(&chan->host_to_client_rb, &shmem->host_to_client_pub);
    }
}

/**
 * Invalidate an eventfd acquired from libkvmchan_get_eventfd.
 *
 * @param chan libkvmchan_t instance to act on
 */
void libkvmchan_clear_eventfd(libkvmchan_t *chan) {
    if (chan->flags & LIBKVM_FLAG_HOST) {
        return ringbuf_clear_eventfd(&chan->client_to_host_rb);
    } else {
        return ringbuf_clear_eventfd(&chan->host_to_client_rb);
    }
}

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

#undef LIBKVMCHAN_TEST

void test_ringbufs(libkvmchan_t *chan);

// A private data structure present at the beginning of all libkvmchan
// shared memory objects.
#define SHMEM_MAGIC 0xDEADBEEFCAFEBABA
typedef struct shmem_hdr {
    uint64_t magic;
    struct ringbuf host_to_client_rb;
    struct ringbuf client_to_host_rb;
} shmem_hdr_t;


// Private. Initializes a shared memory object as a part of the host init process.
static bool host_initialize(libkvmchan_t *chan, void *mem, size_t size) {
    // Initialize the libkvmchan_t
    chan->flags = LIBKVM_FLAG_HOST;
    chan->shm = mem;
    chan->shm_size = size;

    // Write a shmem header object
    shmem_hdr_t *hdr = chan->shm;
    hdr->magic = SHMEM_MAGIC;

    // Determine positions and sizes of ringbuffers.
    // Reserve first 0x1000 for header. The rest is split in half
    // for each ringbuffer. Assume 0x1000 per ringbuffer is needed.
    if (size < 0x1000 + (0x1000 * 2)) {
        errno = ENOMEM;
        return false;
    }
    void *data_base = (uint8_t *)mem + 0x1000;
    size_t rb_size = (size - 0x1000) / 2;

    ringbuf_init(&hdr->host_to_client_rb, data_base, rb_size, true);
    ringbuf_init(&hdr->client_to_host_rb, data_base + rb_size, rb_size, true);

#ifdef LIBKVMCHAN_TEST
    test_ringbufs(chan);
#endif

    return true;
}


/**
 * Establishes a libkvmchan shared memory host using the given
 * POSIX shared memory name.
 *
 * Note that a host must be established before clients attempt to connect.
 *
 * Sets errno on failure.
 *
 * @param name POSIX shared memory name, must begin with a /
 * @return A libkvmchan_t struct, or NULL on error
 */
libkvmchan_t *libkvmchan_host_open(const char *name) {
    // Allocate a libkvmchan_t structure
    libkvmchan_t *chan = malloc(sizeof(libkvmchan_t));
    if (!chan)
        goto fail;

    // Attempt to open the shm object whose name was passed to us
    int shm_fd = shm_open(name, O_RDWR, 0);
    if (shm_fd < 0)
        goto fail_malloc;

    // Determine the size and mmap it
    struct stat shm_stat;
    if (fstat(shm_fd, &shm_stat) < 0)
        goto fail_shm_open;

    void *mem = mmap(NULL, shm_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (mem == (void *)-1)
        goto fail_shm_open;

    // Init kvmchan struct and return
    if (!host_initialize(chan, mem, shm_stat.st_size))
        goto fail_mmap;

    return chan;

fail_mmap:
    munmap(mem, shm_stat.st_size);
fail_shm_open:
    close(shm_fd);
fail_malloc:
    free(chan);
fail:
    return NULL;
}

/**
 * Establishes a libkvmchan shared memory client using the given uio device.
 *
 * Note that a host must be established before clients attempt to connect.
 *
 * Sets errno on failure.
 *
 * @param devname uio device name. Should correspond to a chardev in /dev. Ex. "uio0"
 * @return A libkvmchan_t struct, or NULL on error
 */
libkvmchan_t *libkvmchan_client_open(const char *devname) {
    // Allocate libkvmchan_t struct
    libkvmchan_t *ret = malloc(sizeof(libkvmchan_t));
    if (!ret)
        goto fail;

    // The ivshmem uio driver places the shared memory region in map 1 of the uio device.
    // Attempt to read map1's size from the file at /sys/class/uio/<devname>/maps/map1/size
    if (strlen(devname) > 255) {
        errno = EINVAL;
        goto fail_malloc;
    }
    char path_buf[300];
    snprintf(path_buf, 300, "/sys/class/uio/%s/maps/map1/size", devname);
    int size_fd = open(path_buf, O_RDONLY);
    if (size_fd < 0)
        goto fail_malloc;

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
    snprintf(path_buf, 300, "/dev/%s", devname);
    int uio_fd = open(path_buf, O_RDWR);
    if (uio_fd < 0)
        goto fail_open_size;
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, uio_fd, 1 * getpagesize());
    if (mem == (void *)-1)
        goto fail_open_uio;

    ret->flags = 0;
    ret->shm = mem;
    return ret;

fail_open_uio:
    close(uio_fd);
fail_open_size:
    close(size_fd);
fail_malloc:
    free(ret);
fail:
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
bool libkvmchan_write(libkvmchan_t *chan, void *data, size_t size) {
    shmem_hdr_t *shmem = chan->shm;
    if (chan->flags & LIBKVM_FLAG_HOST) {
        // Use host_to_client ringbuffer
        return ringbuf_write(&shmem->host_to_client_rb, data, size);
    } else {
        // Use client_to_host ringbuffer
        return ringbuf_write(&shmem->client_to_host_rb, data, size);
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
    shmem_hdr_t *shmem = chan->shm;
    if (chan->flags & LIBKVM_FLAG_HOST) {
        return ringbuf_read_blocking(&shmem->client_to_host_rb, out, size);
    } else {
        return ringbuf_read_blocking(&shmem->host_to_client_rb, out, size);
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
        return ringbuf_get_eventfd(&shmem->client_to_host_rb);
    } else {
        return ringbuf_get_eventfd(&shmem->host_to_client_rb);
    }
}

/**
 * Invalidate an eventfd acquired from libkvmchan_get_eventfd.
 *
 * @param chan libkvmchan_t instance to act on
 */
void libkvmchan_clear_eventfd(libkvmchan_t *chan) {
    shmem_hdr_t *shmem = chan->shm;
    if (chan->flags & LIBKVM_FLAG_HOST) {
        return ringbuf_clear_eventfd(&shmem->client_to_host_rb);
    } else {
        return ringbuf_clear_eventfd(&shmem->host_to_client_rb);
    }
}


/// TEST
#ifdef LIBKVMCHAN_TEST
uint8_t *get_random_bytes(size_t num) {
    uint8_t *buf = malloc(num);
    static int fd = -1;
    if (fd < 0) {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            free(buf);
            return NULL;
        }
    }
    read(fd, buf, num);
    return buf;
}

void test_ringbufs(libkvmchan_t *chan) {
    shmem_hdr_t *hdr = chan->shm;
    assert(hdr->host_to_client_rb.size == hdr->client_to_host_rb.size);
    size_t rb_size = hdr->host_to_client_rb.size;

    // Write `size` bytes to both rbs and read back
    uint8_t *buf = malloc(rb_size);
    uint8_t *r1 = get_random_bytes(rb_size);
    uint8_t *r2 = get_random_bytes(rb_size);
    ringbuf_write(&hdr->host_to_client_rb, r1, rb_size);
    ringbuf_write(&hdr->client_to_host_rb, r2, rb_size);

    ringbuf_read(&hdr->host_to_client_rb, buf, rb_size);
    assert(memcmp(buf, r1, rb_size) == 0);

    ringbuf_read(&hdr->client_to_host_rb, buf, rb_size);
    assert(memcmp(buf, r2, rb_size) == 0);

    free(r1); free(r2);
}
#endif

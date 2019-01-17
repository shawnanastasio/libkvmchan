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

#ifndef LIBKVMCHAN_H
#define LIBKVMCHAN_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define LIBKVMCHAN_EXPORTED __attribute__((__visibility__("default")))

#define LIBKVM_FLAG_HOST (1 << 0)

// A handle to an opened shared memory region.
typedef struct libkvmchan_shm_handle {
    void *shm; // Raw pointer to virtual memory region
    size_t size; // Size of memory region
} libkvmchan_shm_handle_t;

// Struct representing an open libkvmchan instance. Opaque to user.
typedef struct libkvmchan libkvmchan_t;

LIBKVMCHAN_EXPORTED bool libkvmchan_shm_open_posix(libkvmchan_shm_handle_t *handle, const char *name);
LIBKVMCHAN_EXPORTED bool libkvmchan_shm_open_uio(libkvmchan_shm_handle_t *handle, const char *devname);
LIBKVMCHAN_EXPORTED libkvmchan_t *libkvmchan_host_open(libkvmchan_shm_handle_t *handle);
LIBKVMCHAN_EXPORTED libkvmchan_t *libkvmchan_client_open(libkvmchan_shm_handle_t *handle);
LIBKVMCHAN_EXPORTED bool libkvmchan_write(libkvmchan_t *chan, void *data, size_t size);
LIBKVMCHAN_EXPORTED bool libkvmchan_read(libkvmchan_t *chan, void *out, size_t size);
LIBKVMCHAN_EXPORTED int libkvmchan_get_eventfd(libkvmchan_t *chan);
LIBKVMCHAN_EXPORTED void libkvmchan_clear_eventfd(libkvmchan_t *chan);

#endif // LIBKVMCHAN_H

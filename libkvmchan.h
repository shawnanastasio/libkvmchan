/**
 * Copyright 2018-2021 Shawn Anastasio
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

/* vchan state values from libkvmchan_get_state */
#define VCHAN_DISCONNECTED 0 /* remote disconnected or remote domain dead */
#define VCHAN_CONNECTED    1 /* connected */
#define VCHAN_WAITING      2 /* vchan server initialized, waiting for client to connect */

#define LIBKVMCHAN_EXPORTED __attribute__((__visibility__("default")))

//
// vchan API
//

struct libkvmchan;

LIBKVMCHAN_EXPORTED struct libkvmchan *libkvmchan_server_init(uint32_t domain, uint32_t port, size_t read_min,
                                                              size_t write_min);

LIBKVMCHAN_EXPORTED struct libkvmchan *libkvmchan_client_init(uint32_t domain, uint32_t port);

LIBKVMCHAN_EXPORTED int libkvmchan_recv(struct libkvmchan *chan, void *data, size_t size);
LIBKVMCHAN_EXPORTED int libkvmchan_send(struct libkvmchan *chan, void *data, size_t size);
LIBKVMCHAN_EXPORTED int libkvmchan_read(struct libkvmchan *chan, void *data, size_t size);
LIBKVMCHAN_EXPORTED int libkvmchan_write(struct libkvmchan *chan, void *data, size_t size);
LIBKVMCHAN_EXPORTED int libkvmchan_get_eventfd(struct libkvmchan *chan);
LIBKVMCHAN_EXPORTED void libkvmchan_clear_eventfd(struct libkvmchan *chan);
LIBKVMCHAN_EXPORTED bool libkvmchan_close(struct libkvmchan *chan);
LIBKVMCHAN_EXPORTED size_t libkvmchan_data_ready(struct libkvmchan *chan);
LIBKVMCHAN_EXPORTED size_t libkvmchan_buffer_space(struct libkvmchan *chan);
LIBKVMCHAN_EXPORTED int libkvmchan_get_state(struct libkvmchan *chan);

//
// Shared memory API
//

struct libkvmchan_shmem;

LIBKVMCHAN_EXPORTED struct libkvmchan_shmem *libkvmchan_shmem_start(void);
LIBKVMCHAN_EXPORTED void *libkvmchan_shmem_region_create(struct libkvmchan_shmem *handle, uint32_t client_dom,
                                                         size_t page_count, uint32_t *region_id_out);

#endif // LIBKVMCHAN_H

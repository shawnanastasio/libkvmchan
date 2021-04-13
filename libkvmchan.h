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

/**
 * Open a `libkvmchan_shmem` handle to use shared memory functions.
 */
LIBKVMCHAN_EXPORTED struct libkvmchan_shmem *libkvmchan_shmem_start(void);

/**
 * Close a previously opened `libkvmchan_shmem` handle.
 */
LIBKVMCHAN_EXPORTED void libkvmchan_shmem_end(struct libkvmchan_shmem *handle);

/**
 * Allocate memory to share with the provided domain.
 *
 * @param handle              previously opened `libkvmchan_shmem` handle
 * @param client_dom          domain # to share memory with
 * @param page_count          number of shared pages to allocate
 * @param[out] region_id_out  allocated region ID for new shared memory
 * @return                    pointer to allocated shared memory region, or NULL on failure
 */
LIBKVMCHAN_EXPORTED void *libkvmchan_shmem_region_create(struct libkvmchan_shmem *handle, uint32_t client_dom,
                                                         uint32_t page_count, uint32_t *region_id_out);

/**
 * Connect to and map a shared memory region created by the provided domain.
 *
 * @param handle      previously opened `libkvmchan_shmem` handle
 * @param server_dom  domain # of server that allocated the region
 * @param region_id   ID of shmem region to connect to
 * @return            pointer to shared memory region, or NULL on failure
 */
LIBKVMCHAN_EXPORTED void *libkvmchan_shmem_region_connect(struct libkvmchan_shmem *handle, uint32_t server_dom, uint32_t region_id);

/**
 * Close a previously opened shared memory region.
 *
 * In the case of a server, the region will no longer be mappable by the client domain after close,
 * but existing client mappings will still be open.
 *
 * In the case of a client, the region will be unmapped locally but can be re-mapped again so long as
 * the server does not close the region.
 *
 * @param handle  previously opened `libkvmchan_shmem` handle
 * @param ptr     pointer to opened shared memory region, obtained from either `libkvmchan_shmem_region_create`
 *                OR `libkvmchan_shmem_region_connect`
 * @return        0 on success, -1 on failure
 */
LIBKVMCHAN_EXPORTED int libkvmchan_shmem_region_close(struct libkvmchan_shmem *handle, void *ptr);

/**
 * Same as `libkvmchan_shmem_region_close` but accepts a peer domain number and region ID instead of
 * a pointer to the mapped region.
 *
 * @param handle     previously opened `libkvmchan_shmem` handle
 * @param peer_dom   domain # that this region is shared with
 * @param region_di  ID of the shared region
 */
LIBKVMCHAN_EXPORTED int libkvmchan_shmem_region_close_by_id(struct libkvmchan_shmem *handle, uint32_t peer_dom, uint32_t region_id);

#endif // LIBKVMCHAN_H

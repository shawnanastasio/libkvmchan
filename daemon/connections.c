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

/**
 * This file contains bookkeeping functions for established connections
 * between VMs and the host.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

#include <unistd.h>
#include <sys/types.h>

#include "util.h"
#include "connections.h"
#include "libkvmchan-priv.h"

static struct vec_voidp connections;

bool connections_init(void) {
    if (!vec_voidp_init(&connections, 10, NULL))
        return false;

    return true;
}

struct connection *connections_get_by_server_dom(uint32_t dom, uint32_t port) {
    for (size_t i=0; i<connections.count; i++) {
        struct connection *cur = connections.data[i];
        if (cur->server.dom == dom && cur->port == port) {
            return cur;
        }
    }

    return NULL;
}

bool connections_add(struct connection *conn) {
    struct connection *conn_h = malloc_w(sizeof(struct connection));
    memcpy(conn_h, conn, sizeof(struct connection));

    if (!vec_voidp_push_back(&connections, conn_h)) {
        free(conn_h);
        return false;
    }

    return true;
}

/**
 * High-level vchan API
 */

/**
 * Initialize a new vchan.
 * args[0] - (u32) domain # of server
 * args[1] - (u32) domain # of allowed client
 * args[2] - (u32) port
 * args[3] - (u64) read_min
 * args[4] - (u64) write_min
 */


bool vchan_init(uint32_t server_dom, uint32_t client_dom, uint32_t port,
                uint64_t read_min, uint64_t write_min) {
    // Validate read/write ring sizes. Ring size is usable space + 1.
    if (read_min + 1 > MAX_RING_SIZE || write_min + 1 > MAX_RING_SIZE) {
        log(LOGL_WARN, "Rejecting new vchan: rings too big."
                        " read: %"PRIu64" write: %"PRIu64,
                        read_min, write_min);
        return false;
    }

    // Make sure that there isn't already a vchan on this server/port
    if (connections_get_by_server_dom(server_dom, port))
        return false;


    // Calculate size of shm and allocate it
    size_t size = sizeof(shmem_hdr_t) + read_min + write_min;
    size = ROUND_UP(size, SYSTEM_PAGE_SIZE);

    int memfd = memfd_create("kvmchand_shm", 0);
    if (memfd < 0) {
        log(LOGL_ERROR, "Failed to allocate memfd: %m");
        return false;
    }

    if (ftruncate(memfd, size) < 0) {
        log(LOGL_ERROR, "Failed to resize memfd: %m");
        goto fail_memfd;
    }

    // Record this connection
    //struct

fail_memfd:
    close(memfd);
    return false;
}

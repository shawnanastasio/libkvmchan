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
#include "ipc.h"
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

static bool connections_add(struct connection *conn) {
    struct connection *conn_h = malloc_w(sizeof(struct connection));
    memcpy(conn_h, conn, sizeof(struct connection));

    if (!vec_voidp_push_back(&connections, conn_h)) {
        free(conn_h);
        return false;
    }

    return true;
}

static pid_t get_domain_pid(uint32_t dom) {
    struct ipc_message response;
    struct ipc_message msg = {
        .type = IPC_TYPE_CMD,
        .cmd = {
            .command = LIBVIRT_IPC_CMD_GET_PID_BY_ID,
            .args = { dom }
        },

        .dest = IPC_DEST_LIBVIRT,
        .flags = IPC_FLAG_WANTRESP
    };

    if (!ipc_send_message(&msg, &response))
        return -1;
    if (response.resp.error)
        return -1;

    return (pid_t)response.resp.ret;
}

/**
 * High-level vchan API
 */

/**
 * Inititalize a new vchan between two domains.
 * @param server_dom            Domain number of server
 * @param client_dom            Domain number of client
 * @param port                  Port number
 * @param read_min              Minimum size of client->server ring buffer
 * @param write_min             Minimum size of server->client ring buffer
 * @param[out] server_ivpos_out Newly allocated ivposition for server
 * @return                      IVPosition of server, or 0 on failure
 */
bool vchan_init(uint32_t server_dom, uint32_t client_dom, uint32_t port,
                uint64_t read_min, uint64_t write_min, uint32_t *server_ivpos_out) {
    log(LOGL_INFO, "vchan_init called! server_dom: %u, client_dom: %u, port %u, read_min: %lu, write_min: %lu",
            server_dom, client_dom, port, read_min, write_min);

    if (server_dom == client_dom)
        goto fail;

    // Validate read/write ring sizes. Ring size is usable space + 1.
    if (read_min + 1 > MAX_RING_SIZE || write_min + 1 > MAX_RING_SIZE) {
        log(LOGL_WARN, "Rejecting new vchan: rings too big."
                        " read: %"PRIu64" write: %"PRIu64,
                        read_min, write_min);
        goto fail;
    }

    // Make sure that there isn't already a vchan on this server/port
    if (connections_get_by_server_dom(server_dom, port)) {
        log(LOGL_WARN, "Rejecting duplicate vchan on server %"PRIu64" port %"PRIu32, server_dom, port);
        goto fail;
    }

    // Calculate size of shm and allocate it
    size_t size = sizeof(shmem_hdr_t) + read_min + write_min + 32 /* 16-byte alignment for both rings */;

    /**
     * The size needs to be a power of 2 for now due to a restriction with
     * the way ivshmem is implemented in QEMU. Though the PCI spec requires
     * power of 2 BAR sizes, ivshmem could likely round up for us and fake
     * all reads/writes, but it does not do this.
     *
     * Since this is the case, round up to the nearest power of 2
     * with fun gcc intrinsics.
     */
    size = 1 << (64 - __builtin_clzl(size - 1));

    int memfd = memfd_create("kvmchand_shm", 0);
    if (memfd < 0) {
        log(LOGL_ERROR, "Failed to allocate memfd: %m");
        goto fail;
    }

    if (ftruncate(memfd, size) < 0) {
        log(LOGL_ERROR, "Failed to resize memfd: %m");
        goto fail_memfd;
    }

    // Validate any remote domain IDs
    pid_t server_pid = -1, client_pid = -1;
    if (server_dom > 0 && (server_pid = get_domain_pid(server_dom)) < 0) {
        log(LOGL_WARN, "Tried to create vchan with invalid server domain %"PRIu32
            ". Ignoring...", server_dom);
        goto fail_memfd;
    }

    if (client_dom > 0 && (client_pid = get_domain_pid(client_dom)) < 0) {
        log(LOGL_WARN, "Tried to create vchan with invalid client domain %"PRIu32
            ". Ignoring...", client_dom);
        goto fail_memfd;
    }

    // Inform ivshmem of any new connections it will receive
    struct ipc_message resp, msg = {
        .type = IPC_TYPE_CMD,
        .cmd = {
            .command = IVSHMEM_IPC_CMD_REGISTER_CONN,
            .args = {
                server_pid,
                client_pid
            }
        },
        .dest = IPC_DEST_IVSHMEM,
        .flags = IPC_FLAG_FD | IPC_FLAG_WANTRESP,
        .fd = memfd
    };
    if (!ipc_send_message(&msg, &resp)) {
        log(LOGL_ERROR, "Failed to send IPC message to IVSHMEM: %m.");
        goto fail_memfd;
    }

    if (resp.resp.error) {
        log(LOGL_ERROR, "IVSHMEM rejected new connection. Ignoring...");
        goto fail_memfd;
    }

    // Extract IVPosition(s) from result
    uint64_t ivposition_packed = resp.resp.ret;
    uint32_t server_ivposition = ivposition_packed >> 32;
    uint32_t client_ivposition = ivposition_packed & 0xFFFFFFFF;

    // Tell libvirt to attach a new ivshmem device to any remote domains
    msg.cmd.command = LIBVIRT_IPC_CMD_ATTACH_IVSHMEM;
    msg.cmd.args[0] = (server_dom > 0) ? server_dom : -1;
    msg.cmd.args[1] = (client_dom > 0) ? client_dom : -1;
    msg.dest = IPC_DEST_LIBVIRT;
    msg.flags = IPC_FLAG_WANTRESP;
    if (!ipc_send_message(&msg, &resp)) {
        log(LOGL_ERROR, "Failed to send IPC message to libvirt: %m.");
        goto fail_register_conn;
    }

    // Check if any remote domains failed
    if (server_dom > 0 && (resp.resp.ret & (1 << 0))) {
        log(LOGL_ERROR, "Failed to attach ivshmem device to server domain %"PRIu32".", server_dom);
        goto fail_register_conn;
    }

    if (client_dom > 0 && (resp.resp.ret & (1 << 1))) {
        log(LOGL_ERROR, "Failed to attach ivshmem device to client domain %"PRIu32".", client_dom);
        goto fail_register_conn;
    }

    // Record this connection
    struct connection conn = {
        .server = { .dom = server_dom, .pid = server_pid, .ivposition = server_ivposition },
        .client = { .dom = client_dom, .pid = client_pid, .ivposition = client_ivposition },
        .port = port,
        .memfd = memfd
    };
    if (!connections_add(&conn)) {
        log(LOGL_ERROR, "Failed to record new vchan: %m.");
        goto fail_register_conn;
    }

    *server_ivpos_out = server_ivposition;
    return true;

fail_register_conn:
    // TODO: don't leak the pending connection in the ivshmem process
fail_memfd:
    close(memfd);
fail:
    return false;
}

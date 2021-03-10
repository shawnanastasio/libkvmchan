/**
 * Copyright 2018-2020 Shawn Anastasio
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
#include <sys/eventfd.h>

#include "util.h"
#include "ipc.h"
#include "connections.h"
#include "libkvmchan-priv.h"
#include "libkvmchan.h"

static struct vec_voidp connections;

static void connection_destructor(void *conn_) {
    struct connection *conn = conn_;
    close(conn->memfd);
    for (size_t i=0; i<ARRAY_SIZE(conn->eventfds); i++)
        close(conn->eventfds[i]);
}

bool connections_init(void) {
    if (!vec_voidp_init(&connections, 10, connection_destructor))
        return false;

    return true;
}

static struct connection *connections_get_by_dom(uint32_t server_dom, uint32_t client_dom, uint32_t port,
                                          size_t *conn_i_out) {
    for (size_t i=0; i<connections.count; i++) {
        struct connection *cur = connections.data[i];
        if (cur->server.dom == server_dom && cur->client.dom == client_dom && cur->port == port) {
            if (conn_i_out)
                *conn_i_out = i;
            return cur;
        }
    }

    return NULL;
}

static struct connection *connections_get_free(uint32_t server_dom, uint32_t client_dom, uint64_t read_min,
                                               uint64_t write_min) {
    for (size_t i=0; i<connections.count; i++) {
        struct connection *cur = connections.data[i];
        if (cur->state == CONNECTION_STATE_FREE &&
                (cur->server.dom == server_dom || cur->server.dom == client_dom) &&
                (cur->client.dom == client_dom || cur->client.dom == server_dom) &&
                cur->write_min >= write_min && cur->read_min >= read_min) {
            // Found a free connection that is big enough to service this request
            return cur;
        }
    }

    return NULL;
}

static void connections_swap_for_reuse(struct connection *conn, uint32_t server_dom, uint32_t client_dom) {
    ASSERT(conn->server.dom == server_dom || conn->server.dom == client_dom);
    ASSERT(conn->client.dom == client_dom || conn->client.dom == server_dom);
    if (conn->server.dom == server_dom)
        // No swapping necessary
        return;

    // Swap server and client
    struct peer tmp;
    memcpy(&tmp, &conn->server, sizeof(struct peer));
    memcpy(&conn->server, &conn->client, sizeof(struct peer));
    memcpy(&conn->client, &tmp, sizeof(struct peer));
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
 * @param[out] ivpos_out        Newly allocated ivposition for server, or client if server is remote
 * @param[out] client_pid_out   qemu PID of client, if remote
 * @return                      IVPosition of server, or 0 on failure
 */
bool vchan_init(uint32_t server_dom, uint32_t client_dom, uint32_t port,
                uint64_t read_min, uint64_t write_min, uint32_t *ivpos_out,
                pid_t *client_pid_out) {
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

    // Make sure that there isn't already an active connection on this server/port
    struct connection *existing = connections_get_by_dom(server_dom, client_dom, port, NULL);
    if (existing && existing->state != CONNECTION_STATE_FREE) {
        log(LOGL_WARN, "Rejecting duplicate vchan on server %"PRIu64" port %"PRIu32, server_dom, port);
        goto fail;
    }

    // See if there is an existing connection that can be reused
    existing = connections_get_free(server_dom, client_dom, read_min, write_min);
    if (existing) {
        // Re-use this connection
        log(LOGL_INFO, "Reusing existing vchan connection (previous port: %u)", existing->port);
        existing->port = port;
        existing->server_connected = true;
        existing->client_connected = false;
        existing->state = CONNECTION_STATE_WAITING;

        // Sometimes we may be re-using a connection with swapped server/client domains, so
        // swap them again to match this connection.
        connections_swap_for_reuse(existing, server_dom, client_dom);

        *ivpos_out = (server_dom > 0) ? existing->server.ivposition : existing->client.ivposition;
        if (client_dom > 0)
            *client_pid_out = existing->client.pid;

        return true;
    }

    // Calculate size of shm and allocate it
    size_t size = sizeof(shmem_hdr_t) + read_min + write_min + 32 /* 16-byte alignment for both rings */;

    // Size needs to be page aligned
    unsigned long page_mask = SYSTEM_PAGE_SIZE - 1;
    if ((size & ~page_mask) != size)
        size = (size + page_mask) & ~page_mask;

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

    // Allocate eventfds
    int eventfds[4] = {-1, -1, -1, -1};
    for (size_t i=0; i<ARRAY_SIZE(eventfds); i++) {
        if ((eventfds[i] = eventfd(0, 0)) < 0)
            goto fail_eventfds;
    }

    // Validate any remote domain IDs
    pid_t server_pid = -1, client_pid = -1;
    if (server_dom > 0 && (server_pid = get_domain_pid(server_dom)) < 0) {
        log(LOGL_WARN, "Tried to create vchan with invalid server domain %"PRIu32
            ". Ignoring...", server_dom);
        goto fail_eventfds;
    }

    if (client_dom > 0 && (client_pid = get_domain_pid(client_dom)) < 0) {
        log(LOGL_WARN, "Tried to create vchan with invalid client domain %"PRIu32
            ". Ignoring...", client_dom);
        goto fail_eventfds;
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
        .fd_count = 5,
        .fds = {memfd, eventfds[0], eventfds[1], eventfds[2], eventfds[3]}
    };
    if (!ipc_send_message(&msg, &resp)) {
        log(LOGL_ERROR, "Failed to send IPC message to IVSHMEM: %m.");
        goto fail_eventfds;
    }

    if (resp.resp.error) {
        log(LOGL_ERROR, "IVSHMEM rejected new connection. Ignoring...");
        goto fail_eventfds;
    }

    // Extract IVPosition(s) from result
    uint32_t server_ivposition = resp.resp.ret;
    uint32_t client_ivposition = resp.resp.ret2;

    // Tell libvirt to attach a new ivshmem device to any remote domains
    msg.cmd.command = LIBVIRT_IPC_CMD_ATTACH_IVSHMEM;
    msg.cmd.args[0] = (server_dom == 0) ? -1 : (int64_t)server_dom;
    msg.cmd.args[1] = (client_dom == 0) ? -1 : (int64_t)client_dom;
    msg.cmd.args[2] = (int64_t)server_ivposition;
    msg.cmd.args[3] = (int64_t)client_ivposition;
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
        .read_min = read_min,
        .write_min = write_min,
        .server_connected = true,
        .client_connected = false,
        .state = CONNECTION_STATE_WAITING,
        .memfd = memfd,
        .eventfds = {eventfds[0], eventfds[1], eventfds[2], eventfds[3]}
    };
    if (!connections_add(&conn)) {
        log(LOGL_ERROR, "Failed to record new vchan: %m.");
        goto fail_register_conn;
    }

    *ivpos_out = (server_dom > 0) ? server_ivposition : client_ivposition;
    if (client_dom > 0)
        *client_pid_out = client_pid;

    return true;

fail_register_conn:
    // TODO: don't leak the pending connection in the ivshmem process
fail_eventfds:
    for (size_t i=0; i<ARRAY_SIZE(eventfds); i++)
        if (eventfds[i] > 0)
            close(eventfds[i]);
fail_memfd:
    close(memfd);
fail:
    return false;
}

/**
 * Connect to an existing vchan.
 *
 * @param      server_dom domain number of vchan's server
 * @param      client_dom domain number of vchan's client
 * @param      port       port number
 * @param[out] ivpos_out  client ivposition
 * @param[out] pid_out    qemu PID of client, or of server client is dom 0
 * @return                connections_error status code
 */
enum connections_error vchan_conn(uint32_t server_dom, uint32_t client_dom, uint32_t port,
                                  uint32_t *ivpos_out, pid_t *pid_out) {
    // Make sure server_dom is online if it's not dom0
    if (server_dom != 0 && get_domain_pid(server_dom) < 0) {
        log(LOGL_INFO, "Tried to connect to offline server domain %"PRIu32, server_dom);
        return CONNECTIONS_ERROR_DOM_OFFLINE;
    }

    // Find corresponding vchan
    struct connection *conn = connections_get_by_dom(server_dom, client_dom, port, NULL);
    if (!conn || conn->state == CONNECTION_STATE_FREE) {
        log(LOGL_INFO, "Tried to connect to non-existent vchan at dom %"PRIu32" port %"PRIu32,
            server_dom, port);
        return CONNECTIONS_ERROR_BAD_PORT;
    }

    if (client_dom == 0) {
        // Called from dom 0, return the ivpos+pid of the server so that
        // the conn fds for this connection can be looked up by the caller
        *ivpos_out = conn->server.ivposition;
        *pid_out = conn->server.pid;
    } else {
        // Called from guest, return the guest's ivpos+pid which can be looked up directly
        *ivpos_out = conn->client.ivposition;
        *pid_out = conn->client.pid;
    }

    conn->client_connected = true;
    conn->state = CONNECTION_STATE_CONNECTED;

    return CONNECTIONS_ERROR_NONE;
}

/**
 * Close an existing vchan.
 *
 * @param server_dom domain number of vchan's server
 * @param client_dom domain number of vchan's client
 * @param port       port number
 * @return           success?
 */
bool vchan_close(uint32_t server_dom, uint32_t client_dom, uint32_t port) {
    log(LOGL_INFO, "Recorded vchan close at server dom %"PRIu32", client dom %"PRIu32", port %"PRIu32,
        server_dom, client_dom, port);
    size_t conn_i;
    struct connection *conn = connections_get_by_dom(server_dom, client_dom, port, &conn_i);
    if (!conn) {
        log(LOGL_WARN, "Tried to close non-existent vchan at dom %"PRIu32" port %"PRIu32,
            server_dom, port);
        return false;
    }
    if (conn->state == CONNECTION_STATE_FREE) {
        log(LOGL_WARN, "BUG? Tried to close already-closed vchan at dom %"PRIu32" port %"PRIu32,
            server_dom, port);
        return false;
    }

    conn->server_connected = false;
    conn->state = CONNECTION_STATE_DISCONNECTED;

    // If both ends are disconnected, mark the connection as free so that it can be reused.
    // This means that vchans are only truly destroyed when a guest involved shuts down
    // which is fine for now, but may need to be changed eventually.
    if (!conn->client_connected) {
        log(LOGL_INFO, "vchan_close: vchan now marked as free\n");
        conn->state = CONNECTION_STATE_FREE;
    }

    return true;
}

/**
 * Remove a closed domain from all bookkeeping data. Close all corresponding vchans.
 */
bool vchan_unregister_domain(pid_t pid) {
    size_t i = connections.count;
    while (i-- > 0) {
        struct connection *cur = connections.data[i];

        if (cur->server.pid == pid || cur->client.pid == pid) {
            // Either the server or client shut down, destroy this connection.
            vec_voidp_remove(&connections, i);
            log(LOGL_INFO, "Removed vchan between dom %u (server) and dom %u, (client)",
                    cur->server.dom, cur->client.dom);
            return true;
        }
    }

    log(LOGL_INFO, "No active connections found for pid %d", pid);
    return false;
}

/**
 * Record that a client has disconnected from a given vchan
 */
enum connections_error vchan_client_disconnect(uint32_t server_dom, uint32_t client_dom, uint32_t port) {
    log(LOGL_INFO, "Recorded vchan client disconnect at server dom %"PRIu32", client dom %"PRIu32", port %"PRIu32,
        server_dom, client_dom, port);
    struct connection *conn = connections_get_by_dom(server_dom, client_dom, port, NULL);
    if (!conn || conn->state == CONNECTION_STATE_FREE)
        return CONNECTIONS_ERROR_NOT_FOUND;

    if (!conn->client_connected) {
        log(LOGL_WARN, "Client tried to disconnect from a vchan they weren't connected to at"
                       " server dom %"PRIu32", client dom %"PRIu32", port %"PRIu32,
            server_dom, client_dom, port);
        return CONNECTIONS_ERROR_INVALID_OP;
    }

    conn->client_connected = false;
    conn->state = CONNECTION_STATE_DISCONNECTED;

    // If both ends are disconnected, mark the connection as free so that it can be reused.
    // This means that vchans are only truly destroyed when a guest involved shuts down
    // which is fine for now, but may need to be changed eventually.
    if (!conn->server_connected) {
        log(LOGL_INFO, "vchan_client_disconnect: vchan now marked as free\n");
        conn->state = CONNECTION_STATE_FREE;
    }

    return CONNECTIONS_ERROR_NONE;
}

/**
 * Get the state of a given vchan.
 */
int vchan_get_state(uint32_t server_dom, uint32_t client_dom, uint32_t port) {
    struct connection *conn = connections_get_by_dom(server_dom, client_dom, port, NULL);
    if (!conn || conn->state == CONNECTION_STATE_FREE)
        return VCHAN_DISCONNECTED;

    switch (conn->state) {
        case CONNECTION_STATE_WAITING:
            return VCHAN_WAITING;
        case CONNECTION_STATE_CONNECTED:
            return VCHAN_CONNECTED;
        case CONNECTION_STATE_DISCONNECTED:
            return VCHAN_DISCONNECTED;
    }

    log(LOGL_WARN, "BUG? Unknown state for vchan at server dom %"PRIu32", client_dom %"PRIu32", port %"PRIu32,
        server_dom, client_dom, port);
    return VCHAN_DISCONNECTED;
}

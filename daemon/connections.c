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

/**
 * This file contains bookkeeping functions for established connections
 * between VMs and the host.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "util.h"
#include "connections.h"
#include "ipc.h"
#include "libkvmchan-priv.h"
#include "libkvmchan.h"

struct connection {
    uint32_t server_dom;
    uint32_t server_ivposition; // IVPosition if guest, or 0
    uint32_t client_dom;
    uint32_t client_ivposition; // IVPosition if guest, or 0
    bool server_connected;
    bool client_connected;

    int state;
#define CONNECTION_STATE_FREE         0
#define CONNECTION_STATE_WAITING      1
#define CONNECTION_STATE_CONNECTED    2
#define CONNECTION_STATE_DISCONNECTED 3
#define CONNECTION_STATE_UNUSABLE     4

    int type;
#define CONNECTION_TYPE_MOVED 0
#define CONNECTION_TYPE_VCHAN 1
#define CONNECTION_TYPE_SHMEM 2

    // Type-specific fields
    union {
        struct {
            int memfd; // memfd backing shared memory region
            uint32_t port;
            uint64_t read_min;
            uint64_t write_min;
            int eventfds[4]; // Notification eventfds
        } vchan;

        struct {
            uint32_t region_id;
        } shmem;
    };
};
static void connection_destructor(struct connection *conn);
DECLARE_LLIST_FOR_TYPE(connection, struct connection, connection_destructor)

struct domain {
    uint32_t dom;        // Domain ID
    pid_t pid;           // PID of QEMU if remote, or -1
    uint32_t page_size;  // Peer's page size if known, or 0

    // Connections in which this domain is the server
    struct llist_connection hosted_connections;
};
static void domain_destructor(struct domain *domain);
DECLARE_LLIST_FOR_TYPE(domain, struct domain, domain_destructor)

//
// Database of domains and their vchan/shmem connections
//
struct connections_db {
    struct llist_domain domains;
};
static struct connections_db connections;

static void connection_destructor(struct connection *conn) {
    switch (conn->type) {
        case CONNECTION_TYPE_MOVED:
            break;

        case CONNECTION_TYPE_VCHAN:
            close(conn->vchan.memfd);
            for (size_t i=0; i<ARRAY_SIZE(conn->vchan.eventfds); i++)
                close(conn->vchan.eventfds[i]);
            break;

        case CONNECTION_TYPE_SHMEM:
            break;

        default:
            log_BUG("Tried to destroy connection with unknown type %"PRIu32"!", conn->type);
    }
}

static void domain_destructor(struct domain *domain) {
    llist_connection_destroy(&domain->hosted_connections);
}

void connections_init(void) {
    llist_domain_init(&connections.domains, NULL);
}

static struct domain *connections_get_dom(uint32_t dom) {
    llist_for_each(struct domain, cur, &connections.domains) {
        if (cur->dom == dom)
            return cur;
    }
    return NULL;
}

static struct domain *connections_get_dom_by_pid(pid_t pid) {
    llist_for_each(struct domain, cur, &connections.domains) {
        if (cur->pid == pid)
            return cur;
    }
    return NULL;
}

static struct connection *connections_get_vchan_by_dom(uint32_t server_dom, uint32_t client_dom, uint32_t port) {
    struct domain *server = connections_get_dom(server_dom);
    if (!server) {
        return NULL;
    }

    // Iterate through all connections hosted by this domain
    llist_for_each(struct connection, cur_conn, &server->hosted_connections) {
        if (cur_conn->type == CONNECTION_TYPE_VCHAN && cur_conn->client_dom == client_dom &&
                cur_conn->vchan.port == port) {
            return cur_conn;
        }
    }
    return NULL;
}

static struct connection *connections_get_free_vchan(uint32_t server_dom, uint32_t client_dom, uint64_t read_min,
                                                     uint64_t write_min) {
    // First try iterating through connections owned by the provided server dom
    struct domain *server = connections_get_dom(server_dom);
    if (!server) {
        log(LOGL_INFO, "connections_get_free_vchan: no such server");
        return NULL;
    }

    llist_for_each(struct connection, cur, &server->hosted_connections) {
        if (cur->type == CONNECTION_TYPE_VCHAN && cur->state == CONNECTION_STATE_FREE &&
                cur->client_dom == client_dom && cur->vchan.write_min >= write_min &&
                cur->vchan.read_min >= read_min) {
            // Found a free connection owned by the server that is big enough
            log(LOGL_INFO, "connections_get_free_vchan: found from server!");
            return cur;
        }
    }

    // Next try iterating through connections owned by the provided client dom
    struct domain *client = connections_get_dom(client_dom);
    if (!client) {
        log(LOGL_INFO, "connections_get_free_vchan: no such client");
        return NULL;
    }

    llist_for_each(struct connection, cur, &client->hosted_connections) {
        if (cur->type == CONNECTION_TYPE_VCHAN && cur->state == CONNECTION_STATE_FREE &&
                cur->client_dom == server_dom && cur->vchan.write_min >= write_min &&
                cur->vchan.read_min >= read_min) {
            // Found a free connection owned by the client that is big enough
            log(LOGL_INFO, "connections_get_free_vchan: found from client!");
            return cur;
        }
    }

    log(LOGL_INFO, "connections_get_free_vchan: no eligible connections found");
    return NULL;
}

static void connections_swap_for_reuse(struct connection **conn_ptr, uint32_t server_dom, uint32_t client_dom) {
    struct connection *conn = *conn_ptr;
    struct domain *client = connections_get_dom(client_dom);
    struct domain *server = connections_get_dom(server_dom);
    if (!client || !server) {
        log(LOGL_ERROR, "BUG? Tried to re-use a connection between domains but at least one end is offline!"
                "(server %"PRIu32", client %"PRIu32"). Leaking connection.", server_dom, client_dom);
        conn->state = CONNECTION_STATE_UNUSABLE;
        return;
    }

    ASSERT(conn->type == CONNECTION_TYPE_VCHAN);
    ASSERT(conn->server_dom == server_dom || conn->server_dom == client_dom);
    ASSERT(conn->client_dom == client_dom || conn->client_dom == server_dom);
    if (conn->server_dom == server_dom)
        // No swapping necessary
        return;

    // We need to swap the connection's server/client and reparent it. The easiest way is to just create a copy,
    // delete the the old one, and move the copy to the new server's list.
    struct connection copy;
    memcpy(&copy, conn, sizeof(struct connection));
    copy.server_dom = server_dom;
    copy.client_dom = client_dom;

    uint32_t tmp = copy.server_ivposition;
    copy.server_ivposition = copy.client_ivposition;
    copy.client_ivposition = tmp;

    // Set the old conn's type to MOVED so that the destructor won't release its resources and delete it
    conn->type = CONNECTION_TYPE_MOVED;
    llist_connection_remove(&client->hosted_connections, conn);

    // Create new connection on server's list
    struct connection *new_conn = llist_connection_new_at_front(&server->hosted_connections);
    memcpy(new_conn, &copy, sizeof(struct connection));

    // Update the caller's conn pointer to point to the re-parented copy
    *conn_ptr = new_conn;
}

static bool connections_register(struct connection *conn, pid_t server_pid, pid_t client_pid) {
    struct domain *server = connections_get_dom(conn->server_dom);
    if (!server) {
        log(LOGL_INFO, "Registering vchan server domain %"PRIu32, conn->server_dom);
        server = llist_domain_new_at_front(&connections.domains);
        server->dom = conn->server_dom;
        server->pid = server_pid;
        server->page_size = 0; // Unknown at this point
        llist_connection_init(&server->hosted_connections);
    }

    struct domain *client = connections_get_dom(conn->client_dom);
    if (!client) {
        log(LOGL_INFO, "Registering vchan client domain %"PRIu32, conn->client_dom);
        client = llist_domain_new_at_front(&connections.domains);
        client->dom = conn->client_dom;
        client->pid = client_pid;
        client->page_size = 0; // Unknown at this point
        llist_connection_init(&client->hosted_connections);
    }

    struct connection *new_conn = llist_connection_new_at_front(&server->hosted_connections);
    memcpy(new_conn, conn, sizeof(struct connection));
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
 * Zero out a memfd's memory region so that it can be re-used for a new vchan
 */
static bool clear_memfd_for_reuse(int memfd) {
    bool res = false;

    struct stat statbuf;
    if (fstat(memfd, &statbuf) < 0)
        goto out;
    if (statbuf.st_size == 0)
        goto out;

    void *region = mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, memfd, 0);
    if (region == (void *)-1)
        goto out;

    // Use explicit_bzero to clear the shared memory region.
    // This should guarantee that we don't get optimized away.
    explicit_bzero(region, statbuf.st_size);

    if (munmap(region, statbuf.st_size) < 0)
        goto out;

    res = true;
out:
    if (!res)
        log(LOGL_ERROR, "BUG? Failed to clear memfd for reuse! (errno=%m)");
    return res;
}

static bool conn_is_in_use(struct connection *conn) {
    return conn->state != CONNECTION_STATE_FREE && conn->state != CONNECTION_STATE_UNUSABLE;
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
 * @param[out] ivpos_out        Newly allocated ivposition for server, or client if server is dom0
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
    struct connection *existing = connections_get_vchan_by_dom(server_dom, client_dom, port);
    if (existing && existing->state != CONNECTION_STATE_FREE) {
        log(LOGL_WARN, "Rejecting duplicate vchan on server %"PRIu64" port %"PRIu32, server_dom, port);
        goto fail;
    }

    // See if there is an existing connection that can be reused
    existing = connections_get_free_vchan(server_dom, client_dom, read_min, write_min);
    if (existing) {
        // Re-use this connection
        log(LOGL_INFO, "Reusing existing vchan connection (previous port: %"PRIu32", new port: %"PRIu32")",
                existing->vchan.port, port);

        // Clear the data
        if (!clear_memfd_for_reuse(existing->vchan.memfd)) {
            // Failed to securely wipe the old connection's shared memory region,
            // mark the connection as unusable and fail
            log(LOGL_WARN, "Marking old connection (server dom %"PRIu32
                           ", client dom %"PRIu32", port %"PRIu32") as UNUSABLE!",
                           existing->server_dom, existing->client_dom, existing->vchan.port);
            existing->state = CONNECTION_STATE_UNUSABLE;
            return false;
        }

        existing->vchan.port = port;
        existing->server_connected = true;
        existing->client_connected = false;
        existing->state = CONNECTION_STATE_WAITING;

        // Sometimes we may be re-using a connection with swapped server/client domains, so
        // swap them again to match this connection.
        connections_swap_for_reuse(&existing, server_dom, client_dom);

        *ivpos_out = (server_dom > 0) ? existing->server_ivposition : existing->client_ivposition;
        if (client_dom > 0) {
            struct domain *client = connections_get_dom(client_dom);
            ASSERT(client);
            *client_pid_out = client->pid;
        }

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
        .server_dom = server_dom,
        .server_ivposition = server_ivposition,
        .client_dom = client_dom,
        .client_ivposition = client_ivposition,
        .server_connected = true,
        .client_connected = false,
        .state = CONNECTION_STATE_WAITING,
        .type = CONNECTION_TYPE_VCHAN,
        .vchan = {
            .memfd = memfd,
            .port = port,
            .read_min = read_min,
            .write_min = write_min,
            .eventfds = {eventfds[0], eventfds[1], eventfds[2], eventfds[3]}
        }
    };
    if (!connections_register(&conn, server_pid, client_pid)) {
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
    log(LOGL_INFO, "vchan_conn called! server_dom: %"PRIu32", client_dom: %"PRIu32", port %"PRIu32,
            server_dom, client_dom, port);
    // Make sure server_dom is online if it's not dom0
    if (server_dom != 0 && get_domain_pid(server_dom) < 0) {
        log(LOGL_INFO, "Tried to connect to offline server domain %"PRIu32, server_dom);
        return CONNECTIONS_ERROR_DOM_OFFLINE;
    }

    // Find corresponding vchan
    struct connection *conn = connections_get_vchan_by_dom(server_dom, client_dom, port);
    if (!conn || !conn_is_in_use(conn)) {
        log(LOGL_INFO, "Tried to connect to non-existent vchan at dom %"PRIu32" port %"PRIu32,
            server_dom, port);
        return CONNECTIONS_ERROR_BAD_PORT;
    }

    if (client_dom == 0) {
        // Called from dom 0, return the ivpos+pid of the server so that
        // the conn fds for this connection can be looked up by the caller
        struct domain *server = connections_get_dom(conn->server_dom);
        ASSERT(server);
        *ivpos_out = conn->server_ivposition;
        *pid_out = server->pid;
    } else {
        // Called from guest, return the guest's ivpos+pid which can be looked up directly
        struct domain *client = connections_get_dom(conn->client_dom);
        ASSERT(client);
        *ivpos_out = conn->client_ivposition;
        *pid_out = client->pid;
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
    struct connection *conn = connections_get_vchan_by_dom(server_dom, client_dom, port);
    if (!conn) {
        log(LOGL_WARN, "Tried to close non-existent vchan at dom %"PRIu32" port %"PRIu32,
            server_dom, port);
        return false;
    }
    if (!conn_is_in_use(conn)) {
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
    struct domain *dom = connections_get_dom_by_pid(pid);
    if (!dom) {
        log(LOGL_INFO, "Ignoring request to unregister unknown domain pid %d", pid);
        return false;
    }

    llist_domain_remove(&connections.domains, dom);
    return true;
}

/**
 * Record that a client has disconnected from a given vchan
 */
enum connections_error vchan_client_disconnect(uint32_t server_dom, uint32_t client_dom, uint32_t port) {
    log(LOGL_INFO, "Recorded vchan client disconnect at server dom %"PRIu32", client dom %"PRIu32", port %"PRIu32,
        server_dom, client_dom, port);
    struct connection *conn = connections_get_vchan_by_dom(server_dom, client_dom, port);
    if (!conn || !conn_is_in_use(conn))
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
    struct connection *conn = connections_get_vchan_by_dom(server_dom, client_dom, port);
    if (!conn || !conn_is_in_use(conn))
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

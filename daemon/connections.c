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
#include "page_allocator.h"

static pid_t get_domain_pid(uint32_t dom);
struct domain;

#define SWAP(x, y) ({ __typeof__((x)) tmp = (x); (x) = (y); (y) = tmp; })

// vchan/shmem server-client connection states
#define CONNECTION_STATE_FREE         0
#define CONNECTION_STATE_WAITING      1
#define CONNECTION_STATE_CONNECTED    2
#define CONNECTION_STATE_DISCONNECTED 3
#define CONNECTION_STATE_UNUSABLE     4

struct connection {
    struct domain *server;
    uint32_t server_ivposition; // IVPosition if guest, or 0
    struct domain *client;
    uint32_t client_ivposition; // IVPosition if guest, or 0
    bool server_connected;
    bool client_connected;

    int memfd;       // memfd backing shared memory region
    size_t size;     // Size of the memfd's storage
    int eventfds[4]; // Notification eventfds

    int type;
#define CONNECTION_TYPE_VCHAN 1
#define CONNECTION_TYPE_SHMEM 2

    // Type-specific fields
    union {
        struct {
            int state;
            uint32_t port;
            uint64_t read_min;
            uint64_t write_min;
        } vchan;

        struct {
            struct page_allocator allocator;
        } shmem;
    };
};
static void connection_destroy(struct connection *conn);
DECLARE_LLIST_FOR_TYPE(connection, struct connection, connection_destroy)
DECLARE_LLIST_FOR_TYPE(connection_p, struct connection *, NULL)

struct shmem_region_descriptor {
    uint32_t peer_dom; // Domain number of peer
    uint32_t id;       // Shared memory region id
};

struct domain {
    uint32_t dom;        // Domain ID
    pid_t pid;           // PID of QEMU if remote, or -1
    uint32_t page_size;  // Peer's page size if known, or 0
    uint32_t last_shmem_region_id;

    // Shared memory regions
    struct vec_voidp shmem_region_ids;
};
static void dom_init(struct domain *dom, uint32_t dom_nr, pid_t pid, uint32_t page_size);
static void dom_destroy(struct domain *domain);
DECLARE_LLIST_FOR_TYPE(domain, struct domain, dom_destroy)

//
// Database of domains and their vchan/shmem connections
//
struct connections_db {
    struct llist_domain domains;
    struct llist_connection connections;
};
static struct connections_db connections;

static void connection_destroy(struct connection *conn) {
    if (conn->memfd == 1)
        log(LOGL_ERROR, "CLOSING FD 1!");
    close(conn->memfd);
    for (size_t i=0; i<ARRAY_SIZE(conn->eventfds); i++) {
        if (conn->eventfds[i] == 1)
            log(LOGL_ERROR, "CLOSING FD 1!");
        close(conn->eventfds[i]);
    }

    switch (conn->type) {
        case CONNECTION_TYPE_VCHAN:
            break;

        case CONNECTION_TYPE_SHMEM:
            page_allocator_destroy(&conn->shmem.allocator);
            break;

        default:
            log_BUG("Tried to destroy connection with unknown type %"PRIu32"!", conn->type);
    }
}

//
// Connections database helpers
//

#if 0
static void dump_connections(void) {
    printf("CONNS: {");
    llist_for_each(struct connection, cur, &connections.connections) {
        printf("(server=%u, client=%u, port=%d, server_conn?=%s, client_conn?=%s, type=%d), ",
                cur->server->dom, cur->client->dom, cur->vchan.port, cur->server_connected ? "T" : "F",
                cur->client_connected ? "T" : "F", cur->type);
    }
    printf("}\n");
}
#endif

void connections_init(void) {
    llist_domain_init(&connections.domains, NULL);
    llist_connection_init(&connections.connections, NULL);
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

    llist_for_each(struct connection, cur_conn, &connections.connections) {
        if (cur_conn->type == CONNECTION_TYPE_VCHAN && cur_conn->server->dom == server_dom &&
                cur_conn->client->dom == client_dom && cur_conn->vchan.port == port) {
            return cur_conn;
        }
    }
    return NULL;
}

static struct connection *connections_get_free_vchan(uint32_t server_dom, uint32_t client_dom, uint64_t read_min,
                                                     uint64_t write_min) {
    // First try iterating through connections owned by the provided server dom
    struct domain *server = connections_get_dom(server_dom);
    struct domain *client = connections_get_dom(client_dom);
    if (!server || !client) {
        log(LOGL_INFO, "connections_get_free_vchan: no such server/client");
        return NULL;
    }

    llist_for_each(struct connection, cur, &connections.connections) {
        if (cur->type == CONNECTION_TYPE_VCHAN && cur->vchan.state == CONNECTION_STATE_FREE &&
                cur->server->dom == server_dom && cur->client->dom == client_dom &&
                cur->vchan.write_min >= write_min && cur->vchan.read_min >= read_min) {
            // Found a free connection owned by the server that is big enough
            log(LOGL_INFO, "connections_get_free_vchan: found from server!");
            return cur;
        }

        if (cur->type == CONNECTION_TYPE_VCHAN && cur->vchan.state == CONNECTION_STATE_FREE &&
                cur->server->dom == client_dom && cur->client->dom == server_dom &&
                cur->vchan.write_min >= write_min && cur->vchan.read_min >= read_min) {
            // Found a free connection owned by the client that is big enough
            log(LOGL_INFO, "connections_get_free_vchan: found from client!");
            return cur;
        }
    }

    log(LOGL_INFO, "connections_get_free_vchan: no eligible connections found");
    return NULL;
}

static void connections_swap_for_reuse(struct connection *conn, uint32_t server_dom, uint32_t client_dom) {
    struct domain *client = connections_get_dom(client_dom);
    struct domain *server = connections_get_dom(server_dom);
    if (!client || !server) {
        log(LOGL_ERROR, "BUG? Tried to re-use a connection between domains but at least one end is offline!"
                "(server %"PRIu32", client %"PRIu32"). Leaking connection.", server_dom, client_dom);
        conn->vchan.state = CONNECTION_STATE_UNUSABLE;
        return;
    }

    ASSERT(conn->type == CONNECTION_TYPE_VCHAN);
    ASSERT(conn->server->dom == server_dom || conn->server->dom == client_dom);
    ASSERT(conn->client->dom == client_dom || conn->client->dom == server_dom);
    if (conn->server->dom != server_dom) {
        // Swap server and client
        SWAP(conn->server, conn->client);
        SWAP(conn->server_ivposition, conn->client_ivposition);
        // TODO: should probably swap read/write sizes as well, and the caller needs to validate
        // that the vchan is still big enough.
    }
}

static struct domain *connections_get_dom_or_create_new(uint32_t dom) {
    struct domain *domain = connections_get_dom(dom);
    if (!domain) {
        // Make sure this domain is online and get its pid
        pid_t pid = -1;
        if (dom != 0 && ((pid = get_domain_pid(dom))) < 0)
            return NULL;

        domain = llist_domain_new_at_front(&connections.domains);
        dom_init(domain, dom, pid, 0);
    }
    return domain;
}

//
// Domain helpers
//

static void dom_init(struct domain *dom, uint32_t dom_nr, pid_t pid, uint32_t page_size) {
    dom->dom = dom_nr;
    dom->pid = pid;
    dom->page_size = page_size;
    dom->last_shmem_region_id = 0;
    ASSERT(vec_voidp_init(&dom->shmem_region_ids, 10, free_destructor));
}

static void dom_destroy(struct domain *domain) {
    // Destroy any connections involving this domain
    llist_for_each(struct connection, conn, &connections.connections) {
        if (conn->server == domain || conn->client == domain) {
            llist_connection_remove(&connections.connections, conn);
        }
    }

    vec_voidp_destroy(&domain->shmem_region_ids);
}

static struct shmem_region_descriptor *dom_get_shmem_descriptor_by_id(struct domain *domain, uint32_t region_id,
                                                                      size_t *idx_out) {
    for (size_t i = 0; i < domain->shmem_region_ids.count; i++) {
        struct shmem_region_descriptor *cur = domain->shmem_region_ids.data[i];
        if (cur->id == region_id) {
            if (idx_out)
                *idx_out = i;
            return cur;
        }
    }
    return NULL;
}

static uint32_t dom_allocate_region_id(struct domain *server, uint32_t client_dom) {
    if (server->shmem_region_ids.count >= UINT32_MAX - 1)
        return 0;

    // Find the first free ID starting at the last id + 1
    uint32_t cur_id;
    for (cur_id = server->last_shmem_region_id + 1;
            cur_id == 0 || dom_get_shmem_descriptor_by_id(server, cur_id, NULL);
            cur_id++)
        ;

    server->last_shmem_region_id = cur_id;

    // Allocate and insert a descriptor for the new region id
    struct shmem_region_descriptor *desc = malloc_w(sizeof(struct shmem_region_descriptor));
    desc->peer_dom = client_dom;
    desc->id = cur_id;
    ASSERT(vec_voidp_push_back(&server->shmem_region_ids, desc));

    return cur_id;
}

static void dom_release_region_id(struct domain *server, uint32_t region_id) {
    size_t desc_idx;
    if (!dom_get_shmem_descriptor_by_id(server, region_id, &desc_idx)) {
        log(LOGL_WARN, "BUG? Tried to release unused shmem region id %"PRIu32" under server dom %"PRIu32,
                region_id, server->dom);
        return;
    }
    vec_voidp_remove(&server->shmem_region_ids, desc_idx);
}

//
// General helpers
//

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

static bool vchan_conn_is_in_use(struct connection *conn) {
    ASSERT(conn->type == CONNECTION_TYPE_VCHAN);
    return conn->vchan.state != CONNECTION_STATE_FREE && conn->vchan.state != CONNECTION_STATE_UNUSABLE;
}

static bool create_new_shared_memory(struct domain *server, struct domain *client, size_t min_size, int *memfd_out,
                                     int eventfds_out[4], uint32_t *server_ivposition_out, uint32_t *client_ivposition_out,
                                     size_t *real_size_out) {
    size_t page_size = server->page_size ? server->page_size : 0x10000 /* 64k fallback */;
    unsigned long page_mask = page_size - 1;
    size_t size = min_size;

    // Size needs to be page aligned
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

    // Inform ivshmem of any new connections it will receive
    struct ipc_message resp, msg = {
        .type = IPC_TYPE_CMD,
        .cmd = {
            .command = IVSHMEM_IPC_CMD_REGISTER_CONN,
            .args = {
                server->pid,
                client->pid
            }
        },
        .dest = IPC_DEST_IVSHMEM,
        .flags = IPC_FLAG_FD | IPC_FLAG_WANTRESP,
        .fd_count = 5,
        .fds = {memfd, eventfds[0], eventfds[1], eventfds[2], eventfds[3]}
    };
    if (!ipc_send_message(&msg, &resp))
        goto fail_eventfds;
    if (resp.resp.error)
        goto fail_eventfds;

    // Extract IVPosition(s) from result
    uint32_t server_ivposition = resp.resp.ret;
    uint32_t client_ivposition = resp.resp.ret2;

    // Tell libvirt to attach a new ivshmem device to any remote domains
    msg.cmd.command = LIBVIRT_IPC_CMD_ATTACH_IVSHMEM;
    msg.cmd.args[0] = (server->dom == 0) ? -1 : (int64_t)server->dom;
    msg.cmd.args[1] = (client->dom == 0) ? -1 : (int64_t)client->dom;
    msg.cmd.args[2] = (int64_t)server_ivposition;
    msg.cmd.args[3] = (int64_t)client_ivposition;
    msg.dest = IPC_DEST_LIBVIRT;
    msg.flags = IPC_FLAG_WANTRESP;
    if (!ipc_send_message(&msg, &resp))
        goto fail_register_conn;

    // Check if any remote domains failed
    if (server->dom > 0 && (resp.resp.ret & (1 << 0))) {
        log(LOGL_ERROR, "Failed to attach ivshmem device to server domain %"PRIu32".", server->dom);
        goto fail_register_conn;
    }

    if (client->dom > 0 && (resp.resp.ret & (1 << 1))) {
        log(LOGL_ERROR, "Failed to attach ivshmem device to client domain %"PRIu32".", client->dom);
        goto fail_register_conn;
    }

    // Write out parameters and return success
    *memfd_out = memfd;
    memcpy(eventfds_out, eventfds, sizeof(eventfds));
    *server_ivposition_out = server_ivposition;
    *client_ivposition_out = client_ivposition;
    *real_size_out = size;
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

//
// High-level vchan API
//

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
        return false;

    // Validate read/write ring sizes. Ring size is usable space + 1.
    if (read_min + 1 > MAX_RING_SIZE || write_min + 1 > MAX_RING_SIZE) {
        log(LOGL_WARN, "Rejecting new vchan: rings too big."
                        " read: %"PRIu64" write: %"PRIu64,
                        read_min, write_min);
        return false;
    }

    // Make sure that there isn't already an active connection on this server/port
    struct connection *existing = connections_get_vchan_by_dom(server_dom, client_dom, port);
    if (existing && existing->vchan.state != CONNECTION_STATE_FREE) {
        log(LOGL_WARN, "Rejecting duplicate vchan on server %"PRIu64" port %"PRIu32, server_dom, port);
        return false;
    }

    // See if there is an existing connection that can be reused
    existing = connections_get_free_vchan(server_dom, client_dom, read_min, write_min);
    if (existing) {
        // Re-use this connection
        log(LOGL_INFO, "Reusing existing vchan connection (previous port: %"PRIu32", new port: %"PRIu32")",
                existing->vchan.port, port);

        // Clear the data
        if (!clear_memfd_for_reuse(existing->memfd)) {
            // Failed to securely wipe the old connection's shared memory region,
            // mark the connection as unusable and fail
            log(LOGL_WARN, "Marking old connection (server dom %"PRIu32
                           ", client dom %"PRIu32", port %"PRIu32") as UNUSABLE!",
                           existing->server->dom, existing->client->dom, existing->vchan.port);
            existing->vchan.state = CONNECTION_STATE_UNUSABLE;
            return false;
        }

        existing->vchan.port = port;
        existing->vchan.state = CONNECTION_STATE_WAITING;
        existing->server_connected = true;
        existing->client_connected = false;

        // Sometimes we may be re-using a connection with swapped server/client domains, so
        // swap them again to match this connection.
        connections_swap_for_reuse(existing, server_dom, client_dom);

        *ivpos_out = (server_dom > 0) ? existing->server_ivposition : existing->client_ivposition;
        if (client_dom > 0) {
            struct domain *client = connections_get_dom(client_dom);
            ASSERT(client);
            *client_pid_out = client->pid;
        }

        return true;
    }

    // Calculate minimum size of shm and allocate it
    size_t min_size = sizeof(shmem_hdr_t) + read_min + write_min + 32 /* 16-byte alignment for both rings */;

    // Validate any remote domain IDs
    struct domain *server = connections_get_dom_or_create_new(server_dom);
    if (!server) {
        log(LOGL_WARN, "Tried to create vchan with invalid server domain %"PRIu32
            ". Ignoring...", server_dom);
        return false;
    }

    struct domain *client = connections_get_dom_or_create_new(client_dom);
    if (!client) {
        log(LOGL_WARN, "Tried to create vchan with invalid client domain %"PRIu32
            ". Ignoring...", client_dom);
        return false;
    }

    // Create and register shared memory with all involved domains
    int memfd;
    int eventfds[4];
    uint32_t server_ivposition;
    uint32_t client_ivposition;
    size_t real_size;
    if (!create_new_shared_memory(server, client, min_size, &memfd, eventfds, &server_ivposition,
            &client_ivposition, &real_size)) {
        log(LOGL_ERROR, "Failed to create and register shared memory.");
        return false;
    }

    // Record this connection
    struct connection *conn_p = llist_connection_new_at_front(&connections.connections);
    conn_p->server = server;
    conn_p->server_ivposition = server_ivposition;
    conn_p->client = client;
    conn_p->client_ivposition = client_ivposition;
    conn_p->server_connected = true;
    conn_p->client_connected = false;
    conn_p->type = CONNECTION_TYPE_VCHAN;
    conn_p->memfd = memfd;
    conn_p->size = real_size;
    memcpy(conn_p->eventfds, eventfds, sizeof(eventfds));
    conn_p->vchan.port = port;
    conn_p->vchan.state = CONNECTION_STATE_WAITING;
    conn_p->vchan.read_min = read_min;
    conn_p->vchan.write_min = write_min;

    *ivpos_out = (server_dom > 0) ? server_ivposition : client_ivposition;
    if (client_dom > 0)
        *client_pid_out = client->pid;

    return true;
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
    if (!conn || !vchan_conn_is_in_use(conn)) {
        log(LOGL_INFO, "Tried to connect to non-existent vchan at dom %"PRIu32" port %"PRIu32,
            server_dom, port);
        return CONNECTIONS_ERROR_BAD_PORT;
    }

    if (client_dom == 0) {
        // Called from dom 0, return the ivpos+pid of the server so that
        // the conn fds for this connection can be looked up by the caller
        *ivpos_out = conn->server_ivposition;
        *pid_out = conn->server->pid;
    } else {
        // Called from guest, return the guest's ivpos+pid which can be looked up directly
        *ivpos_out = conn->client_ivposition;
        *pid_out = conn->client->pid;
    }

    conn->client_connected = true;
    conn->vchan.state = CONNECTION_STATE_CONNECTED;

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
    if (!vchan_conn_is_in_use(conn)) {
        log(LOGL_WARN, "BUG? Tried to close already-closed vchan at dom %"PRIu32" port %"PRIu32,
            server_dom, port);
        return false;
    }

    conn->server_connected = false;
    conn->vchan.state = CONNECTION_STATE_DISCONNECTED;

    // If both ends are disconnected, mark the connection as free so that it can be reused.
    // This means that vchans are only truly destroyed when a guest involved shuts down
    // which is fine for now, but may need to be changed eventually.
    if (!conn->client_connected) {
        log(LOGL_INFO, "vchan_close: vchan now marked as free");
        conn->vchan.state = CONNECTION_STATE_FREE;
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
    if (!conn || !vchan_conn_is_in_use(conn))
        return CONNECTIONS_ERROR_NOT_FOUND;

    if (!conn->client_connected) {
        log(LOGL_WARN, "Client tried to disconnect from a vchan they weren't connected to at"
                       " server dom %"PRIu32", client dom %"PRIu32", port %"PRIu32,
            server_dom, client_dom, port);
        return CONNECTIONS_ERROR_INVALID_OP;
    }

    conn->client_connected = false;
    conn->vchan.state = CONNECTION_STATE_DISCONNECTED;

    // If both ends are disconnected, mark the connection as free so that it can be reused.
    // This means that vchans are only truly destroyed when a guest involved shuts down
    // which is fine for now, but may need to be changed eventually.
    if (!conn->server_connected) {
        log(LOGL_INFO, "vchan_client_disconnect: vchan now marked as free");
        conn->vchan.state = CONNECTION_STATE_FREE;
    }

    return CONNECTIONS_ERROR_NONE;
}

/**
 * Get the state of a given vchan.
 */
int vchan_get_state(uint32_t server_dom, uint32_t client_dom, uint32_t port) {
    struct connection *conn = connections_get_vchan_by_dom(server_dom, client_dom, port);
    if (!conn || !vchan_conn_is_in_use(conn))
        return VCHAN_DISCONNECTED;

    switch (conn->vchan.state) {
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

/**
 * High-level Shared Memory API
 */

#define MAX_PAGE_COUNT 65536 /* 256MiB w/ 4k pages, 2GiB w/ 64k pages */
#define MIN_PAGE_COUNT 64    /* 256KiB w/ 4k pages, 4MiB w/ 64k pages */
static const uint32_t valid_page_sizes[] = {0x1000 /* 4k */, 0x4000 /* 16k */, 0x10000 /* 64k */};

struct shmem_region_tag {
    uint32_t server_dom;
    uint32_t id;
    int state; // CONNECTION_STATE_*
};

static struct shmem_region_tag *build_shmem_region_tag(uint32_t server_dom, uint32_t id) {
    struct shmem_region_tag *tag = malloc_w(sizeof(struct shmem_region_tag));
    tag->server_dom = server_dom;
    tag->id = id;
    tag->state = CONNECTION_STATE_WAITING;
    return tag;
}

static bool allocate_shmem_region(struct domain *server, struct domain *client, size_t region_size, uint32_t region_id,
                                  struct connection **conn_out, size_t *start_offset_out) {
    struct shmem_region_tag *tag = build_shmem_region_tag(server->dom, region_id);

    // First: Try to allocate pages in any existing connection between the two domains
    llist_for_each(struct connection, cur, &connections.connections) {
        if (cur->type != CONNECTION_TYPE_SHMEM)
            continue;
        if ((cur->server != server && cur->server != client) ||
            (cur->client != client && cur->client != server))
            continue;

        // Try to allocate `page_count` pages
        log(LOGL_INFO, "allocating shmem region in existing connection");
        size_t start_offset = page_allocator_allocate(&cur->shmem.allocator, region_size, tag);
        if (start_offset != (size_t)-1) {
            // Allocation successful
            *conn_out = cur;
            *start_offset_out = start_offset;
            return true;
        }
    }

    // Fallback: create a new connection
    log(LOGL_INFO, "allocating shmem region in new connection");
    ASSERT(server->page_size);
    size_t min_size = MAX(MIN_PAGE_COUNT * server->page_size, region_size);

    int memfd;
    int eventfds[4];
    uint32_t server_ivposition;
    uint32_t client_ivposition;
    size_t real_size;
    if (!create_new_shared_memory(server, client, min_size, &memfd, eventfds, &server_ivposition,
            &client_ivposition, &real_size)) {
        log(LOGL_ERROR, "Failed to create and register shared memory.");
        goto fail_tag;
    }

    // Record the connection
    struct connection *conn_p = llist_connection_new_at_front(&connections.connections);
    conn_p->server = server;
    conn_p->server_ivposition = server_ivposition;
    conn_p->client = client;
    conn_p->client_ivposition = client_ivposition;
    conn_p->server_connected = true;
    conn_p->client_connected = false;
    conn_p->type = CONNECTION_TYPE_SHMEM;
    conn_p->memfd = memfd;
    conn_p->size = real_size;
    memcpy(conn_p->eventfds, eventfds, sizeof(eventfds));
    page_allocator_init(&conn_p->shmem.allocator, real_size, free_destructor);

    // Allocate the pages in the newly created region
    size_t start_offset = page_allocator_allocate(&conn_p->shmem.allocator, region_size, tag);
    if (start_offset == (size_t)-1) {
        log(LOGL_WARN, "BUG? Unable to allocate shared memory in newly created region!");
        goto fail_tag;
    }

    *conn_out = conn_p;
    *start_offset_out = start_offset;
    return true;

fail_tag:
    free(tag);
    return false;
}

/**
 * Create a shared memory region between domains, using an existing connection if possible
 * or creating a new one otherwise.
 * @param server_dom            Domain number of server
 * @param client_dom            Domain number of client
 * @param page_size             Page size of requesting domain
 * @param page_count            Number of pages to allocate for this region
 * @param[out] ivpos_out        Newly allocated ivposition for server, or client if server is dom0
 * @param[out] client_pid_out   qemu PID of client, if client is remote
 * @param[out] region_id_out    ID of newly created shmem region
 * @param[out] start_off_out    Offset into memfd/ivshmem_bar2 where the allocated pages start
 * @return                      IVPosition of server, or 0 on failure
 */
enum connections_error shmem_create(uint32_t server_dom, uint32_t client_dom, uint32_t page_size, size_t page_count,
                                    uint32_t *ivpos_out, pid_t *client_pid_out, uint32_t *region_id_out,
                                    size_t *start_off_out) {
    log(LOGL_INFO, "shmem_create called! server_dom: %"PRIu32", client_dom %"PRIu32", page_count: %"PRIu64
                   ", page_size: %"PRIu32, server_dom, client_dom, page_count, page_size);

    if (server_dom == client_dom)
        return CONNECTIONS_ERROR_INVALID_OP;

    // Validate size and page size
    if (page_count > MAX_PAGE_COUNT)
        return CONNECTIONS_ERROR_INVALID_OP;

    bool valid_page_size = false;
    for (size_t i = 0; i < ARRAY_SIZE(valid_page_sizes); i++)
        if (valid_page_sizes[i] == page_size)
            valid_page_size = true;
    if (!valid_page_size)
        return CONNECTIONS_ERROR_INVALID_OP;

    struct domain *server = connections_get_dom_or_create_new(server_dom);
    struct domain *client = connections_get_dom_or_create_new(client_dom);
    if (!server || !client)
        return CONNECTIONS_ERROR_DOM_OFFLINE;

    if (server->page_size == 0) {
        server->page_size = page_size;
    } else if (server->page_size != page_size) {
        // Server changed page size - we choose not to support this
        log(LOGL_WARN, "Domain %"PRIu32" changed its page size from %"PRIu32" to %"PRIu32
                ". The new page size will not be accepted until the domain is shut down.",
                server_dom, server->page_size, page_size);
        return CONNECTIONS_ERROR_INVALID_OP;
    }

    if (client->page_size != 0 && client->page_size != page_size) {
        log(LOGL_INFO, "Rejecting shmem creation between domains with differing page sizes (%"PRIu32" vs %"PRIu32")",
                page_size, client->page_size);
        return CONNECTIONS_ERROR_INVALID_OP;
    }

    // Allocate a region id for the server
    uint32_t region_id = dom_allocate_region_id(server, client_dom);
    if (!region_id) {
        log(LOGL_WARN, "Failed to allocate shmem region id for domain %"PRIu32, server_dom);
        return CONNECTIONS_ERROR_INVALID_OP;
    }

    // Find or create a suitable connection between the two domains
    struct connection *conn;
    size_t region_start_offset;
    if (!allocate_shmem_region(server, client, page_size * page_count, region_id, &conn, &region_start_offset)) {
        log(LOGL_WARN, "Failed to allocate shmem pages");
        goto fail_region_id;
    }

    *ivpos_out = (server_dom > 0) ? conn->server_ivposition : conn->client_ivposition;
    *client_pid_out = (client_dom > 0) ? client->pid : -1;
    *region_id_out = region_id;
    *start_off_out = region_start_offset;

    log(LOGL_INFO, "shmem_create successfully allocated region. ivpos=%u, pid=%d, id=%u, start=%zu",
            *ivpos_out, *client_pid_out, region_id, region_start_offset);

    return CONNECTIONS_ERROR_NONE;

fail_region_id:
    dom_release_region_id(server, region_id);
    return CONNECTIONS_ERROR_ALLOC_FAIL;
}
